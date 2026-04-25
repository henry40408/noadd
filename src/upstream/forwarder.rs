use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, FirstAnswer, Protocol};
use hickory_resolver::config::{NameServerConfig, ResolverOpts};
use hickory_resolver::name_server::{NameServer, TokioConnectionProvider};
use hickory_resolver::proto::DnsHandle;
use thiserror::Error;
use tracing::warn;

use super::strategy::UpstreamStrategy;

/// EMA smoothing factor. 0.3 means 30% weight for new observations.
const EMA_ALPHA: f64 = 0.3;

/// Minimum upstream timeout. Mobile clients (NAT rebinding, Wi-Fi↔cellular
/// switches) routinely need more than 2s for the first query after a
/// network transition.
const MIN_TIMEOUT_MS: u64 = 5000;

/// UDP send attempts per query (1 original + N-1 retransmits) before the
/// transport layer gives up on this upstream.
const UDP_ATTEMPTS: usize = 2;

/// Configuration for upstream DNS servers.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Upstream server addresses. Each entry may be:
    /// - `IP:port` — plain UDP (e.g. `1.1.1.1:53`, `[::1]:53`)
    /// - `tls://host[:port]` — DNS-over-TLS, default port 853
    /// - `https://host[:port][/path]` — DNS-over-HTTPS, default port 443
    ///   and default path `/dns-query`
    pub servers: Vec<String>,
    /// Timeout in milliseconds for each upstream attempt.
    pub timeout_ms: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                "1.1.1.1:53".into(),
                "9.9.9.9:53".into(),
                // Mullvad's `194.242.2.2:53` plain-UDP endpoint is not a
                // recursive resolver from arbitrary networks (returns
                // REFUSED), so use their DoT endpoint instead.
                "tls://dns.mullvad.net:853".into(),
            ],
            timeout_ms: 5000,
        }
    }
}

/// Parsed transport kind for an upstream entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum UpstreamKind {
    Udp,
    Tls { sni: String },
    Https { sni: String, path: String },
}

/// A syntactically validated upstream entry, prior to address resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UpstreamSpec {
    /// Hostname (DoT/DoH) or IP literal (UDP) used for both display
    /// and the address-resolution step.
    host: String,
    port: u16,
    kind: UpstreamKind,
}

impl UpstreamSpec {
    /// Parse an upstream entry string. Recognizes the `tls://` and
    /// `https://` URL schemes; everything else is treated as plain
    /// `IP:port` UDP and validated by `SocketAddr` to preserve the
    /// existing v4/v6 behavior.
    fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err("empty upstream entry".into());
        }

        if let Some(rest) = trimmed.strip_prefix("tls://") {
            let (host, port) = parse_host_port(rest, 853)?;
            Ok(Self {
                host: host.clone(),
                port,
                kind: UpstreamKind::Tls { sni: host },
            })
        } else if let Some(rest) = trimmed.strip_prefix("https://") {
            let (hostport, path) = match rest.find('/') {
                Some(i) => (&rest[..i], rest[i..].to_string()),
                None => (rest, "/dns-query".to_string()),
            };
            let (host, port) = parse_host_port(hostport, 443)?;
            Ok(Self {
                host: host.clone(),
                port,
                kind: UpstreamKind::Https { sni: host, path },
            })
        } else {
            let addr: SocketAddr = trimmed
                .parse()
                .map_err(|e| format!("invalid UDP upstream {trimmed:?}: {e}"))?;
            Ok(Self {
                host: addr.ip().to_string(),
                port: addr.port(),
                kind: UpstreamKind::Udp,
            })
        }
    }
}

/// Parse a `host[:port]` fragment, returning a default port when omitted.
/// Handles bracketed IPv6 literals (`[::1]:853`).
fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
    if s.is_empty() {
        return Err("missing host".into());
    }
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| "unclosed `[` in IPv6 literal".to_string())?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse().map_err(|e| format!("invalid port {p:?}: {e}"))?
        } else if after.is_empty() {
            default_port
        } else {
            return Err(format!("unexpected text after IPv6 literal: {after:?}"));
        };
        return Ok((host.to_string(), port));
    }
    if let Some(colon) = s.rfind(':') {
        let host = &s[..colon];
        let port_str = &s[colon + 1..];
        if host.is_empty() {
            return Err("missing host".into());
        }
        let port: u16 = port_str
            .parse()
            .map_err(|e| format!("invalid port {port_str:?}: {e}"))?;
        Ok((host.to_string(), port))
    } else {
        Ok((s.to_string(), default_port))
    }
}

/// Errors that can occur during DNS forwarding.
#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("all upstreams failed")]
    AllFailed,
    #[error("malformed query")]
    BadQuery,
}

/// A persistent NameServer connection paired with its display label.
struct UpstreamEntry {
    label: String,
    name_server: NameServer<TokioConnectionProvider>,
}

/// Sentinel "no observation yet" value for [`UpstreamForwarder::latencies`].
/// Sorts last under `total_cmp`, so an unobserved upstream is naturally
/// the worst choice for `LowestLatency`.
const NO_LATENCY: f64 = f64::INFINITY;

/// Forwards DNS queries to upstream servers with configurable strategy.
///
/// Transport (UDP retransmit, socket reuse, txid validation, automatic
/// TCP-on-error fallback) is delegated to hickory's `NameServer`. This
/// type owns the per-upstream selection strategy and latency tracking.
///
/// Upstreams are addressed by index (matching `config.servers`) — looking
/// them up by label-string used to allocate a `String` per query and was
/// the dominant per-query allocation outside the cache hot path.
pub struct UpstreamForwarder {
    config: UpstreamConfig,
    /// Same length and order as `config.servers`. `None` for entries
    /// whose address parse / DNS lookup failed during construction.
    entries: Vec<Option<UpstreamEntry>>,
    strategy: ArcSwap<UpstreamStrategy>,
    rr_counter: AtomicUsize,
    /// EMA latencies (milliseconds), bit-packed into `AtomicU64`. Reads
    /// and writes are lock-free; concurrent updates use a CAS loop so
    /// the EMA computation is atomic with respect to the previous value.
    /// Same length and order as `entries`.
    latencies: Vec<AtomicU64>,
}

impl UpstreamForwarder {
    /// Create a new forwarder with the given configuration.
    ///
    /// Hostname-bearing entries (`tls://`, `https://`) are resolved to
    /// `SocketAddr` via `tokio::net::lookup_host`. The first address
    /// returned is used; geo-routed providers like Mullvad therefore
    /// pin to the PoP that DNS picks at startup.
    pub async fn new(config: UpstreamConfig) -> Self {
        let timeout = Duration::from_millis(config.timeout_ms.max(MIN_TIMEOUT_MS));

        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = UDP_ATTEMPTS;
        opts.try_tcp_on_error = true;
        opts.validate = false;
        opts.preserve_intermediates = false;

        let provider = TokioConnectionProvider::default();

        // Resolve all upstream hosts concurrently — geo-routed providers and
        // slow DNS can otherwise make startup linear in the number of
        // upstreams. Each task reports its config index so we can place
        // the result back into the parallel `entries` Vec without a
        // post-hoc sort.
        let mut lookup_set = tokio::task::JoinSet::new();
        for (idx, server) in config.servers.iter().enumerate() {
            let spec = match UpstreamSpec::parse(server) {
                Ok(s) => s,
                Err(e) => {
                    warn!(server = %server, error = %e, "skipping unparseable upstream entry");
                    continue;
                }
            };
            let server = server.clone();
            let lookup_target = format!("{}:{}", spec.host, spec.port);
            lookup_set.spawn(async move {
                let addrs = tokio::net::lookup_host(lookup_target)
                    .await
                    .map(|it| it.collect::<Vec<_>>());
                (idx, server, spec, addrs)
            });
        }

        let mut entries: Vec<Option<UpstreamEntry>> =
            (0..config.servers.len()).map(|_| None).collect();
        while let Some(joined) = lookup_set.join_next().await {
            let (idx, server, spec, addrs) = match joined {
                Ok(t) => t,
                Err(e) => {
                    warn!(error = %e, "upstream resolve task join failed");
                    continue;
                }
            };
            let addr = match addrs {
                Ok(list) => match list.into_iter().next() {
                    Some(a) => a,
                    None => {
                        warn!(server = %server, "no addresses returned for upstream");
                        continue;
                    }
                },
                Err(e) => {
                    warn!(server = %server, error = %e, "failed to resolve upstream host");
                    continue;
                }
            };

            let ns_cfg = match &spec.kind {
                UpstreamKind::Udp => NameServerConfig::new(addr, Protocol::Udp),
                UpstreamKind::Tls { sni } => {
                    let mut c = NameServerConfig::new(addr, Protocol::Tls);
                    c.tls_dns_name = Some(sni.clone());
                    c
                }
                UpstreamKind::Https { sni, path } => {
                    let mut c = NameServerConfig::new(addr, Protocol::Https);
                    c.tls_dns_name = Some(sni.clone());
                    c.http_endpoint = Some(path.clone());
                    c
                }
            };

            let name_server = NameServer::new(ns_cfg, opts.clone(), provider.clone());
            entries[idx] = Some(UpstreamEntry {
                label: server,
                name_server,
            });
        }

        let latencies = (0..config.servers.len())
            .map(|_| AtomicU64::new(NO_LATENCY.to_bits()))
            .collect();

        Self {
            config,
            entries,
            strategy: ArcSwap::from_pointee(UpstreamStrategy::default()),
            rr_counter: AtomicUsize::new(0),
            latencies,
        }
    }

    /// Get the current strategy.
    pub fn strategy(&self) -> UpstreamStrategy {
        **self.strategy.load()
    }

    /// Set the active strategy.
    pub fn set_strategy(&self, strategy: UpstreamStrategy) {
        self.strategy.store(std::sync::Arc::new(strategy));
    }

    /// Return the server try-order for the current strategy as indices
    /// into `config.servers` / `entries`. Indices are returned (not
    /// labels) to avoid a per-query allocation; callers that need a
    /// label can read `entries[idx].label`.
    pub fn server_order(&self) -> Vec<usize> {
        let len = self.entries.len();
        if len == 0 {
            return vec![];
        }

        match self.strategy() {
            UpstreamStrategy::Sequential => (0..len).collect(),
            UpstreamStrategy::RoundRobin => {
                let start = self.rr_counter.load(Ordering::Relaxed) % len;
                (0..len).map(|i| (start + i) % len).collect()
            }
            UpstreamStrategy::LowestLatency => {
                let mut order: Vec<usize> = (0..len).collect();
                order.sort_by(|&a, &b| {
                    let la = self.latency_ms_at(a);
                    let lb = self.latency_ms_at(b);
                    la.total_cmp(&lb)
                });
                order
            }
        }
    }

    /// Read the EMA latency for the upstream at `idx`, in milliseconds.
    /// Returns `f64::INFINITY` when no observation has been recorded yet.
    fn latency_ms_at(&self, idx: usize) -> f64 {
        f64::from_bits(self.latencies[idx].load(Ordering::Relaxed))
    }

    /// Update the EMA latency for the upstream at `idx`. Concurrent
    /// updates on the same index race via a CAS loop so the EMA is
    /// always computed from the most recent stored value rather than a
    /// stale local copy.
    pub fn update_latency(&self, idx: usize, ms: f64) {
        let cell = &self.latencies[idx];
        let mut prev_bits = cell.load(Ordering::Relaxed);
        loop {
            let prev = f64::from_bits(prev_bits);
            let next = if prev.is_infinite() {
                ms
            } else {
                EMA_ALPHA * ms + (1.0 - EMA_ALPHA) * prev
            };
            match cell.compare_exchange_weak(
                prev_bits,
                next.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => prev_bits = actual,
            }
        }
    }

    /// Get a snapshot of current EMA latencies, keyed by server label.
    /// Servers without any observation yet are omitted (matches the
    /// previous `Mutex<HashMap>`-backed behavior).
    pub fn latencies(&self) -> HashMap<String, f64> {
        self.config
            .servers
            .iter()
            .enumerate()
            .filter_map(|(i, label)| {
                let ms = self.latency_ms_at(i);
                if ms.is_finite() {
                    Some((label.clone(), ms))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Forward a DNS query using the current strategy.
    ///
    /// Returns `(response_bytes, upstream_address)` on success.
    pub async fn forward(&self, query_bytes: &[u8]) -> Result<(Vec<u8>, String), ForwardError> {
        // Parse incoming wire bytes once. We need a hickory `Message` to
        // build a `DnsRequest`; the caller has already parsed this once
        // in the handler, but the forwarder API stays bytes-in / bytes-out
        // so the handler doesn't have to know about transport details.
        let request_msg = Message::from_vec(query_bytes).map_err(|_| ForwardError::BadQuery)?;
        let client_id = request_msg.id();

        let order = self.server_order();
        if self.strategy() == UpstreamStrategy::RoundRobin {
            self.rr_counter.fetch_add(1, Ordering::Relaxed);
        }

        for &idx in &order {
            let Some(entry) = self.entries[idx].as_ref() else {
                continue;
            };

            let request = DnsRequest::new(request_msg.clone(), DnsRequestOptions::default());
            let start = std::time::Instant::now();

            match entry.name_server.send(request).first_answer().await {
                Ok(response) => {
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    self.update_latency(idx, ms);

                    // hickory rewrites txids for connection multiplexing,
                    // so the response message we get back may not echo the
                    // client's original id. Restore it before re-encoding.
                    let mut msg: Message = response.into();
                    msg.set_id(client_id);

                    match msg.to_bytes() {
                        Ok(bytes) => return Ok((bytes, entry.label.clone())),
                        Err(e) => {
                            warn!(upstream = %entry.label, error = %e, "failed to re-encode upstream response");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    warn!(upstream = %entry.label, error = %e, "upstream forward failed");
                    continue;
                }
            }
        }

        Err(ForwardError::AllFailed)
    }

    /// Health check all configured upstream servers.
    /// Returns a list of (server, status, latency_ms).
    pub async fn health_check(&self) -> Vec<(String, bool, u64)> {
        let mut results = Vec::with_capacity(self.config.servers.len());
        for (idx, server) in self.config.servers.iter().enumerate() {
            let Some(entry) = self.entries[idx].as_ref() else {
                results.push((server.clone(), false, 0));
                continue;
            };
            let start = std::time::Instant::now();
            let ok = self.probe(entry).await.is_ok();
            let ms = start.elapsed().as_millis() as u64;
            results.push((server.clone(), ok, ms));
        }
        results
    }

    /// Probe all servers and update EMA latencies. Used by background task.
    pub async fn probe_all(&self) {
        for (idx, entry) in self.entries.iter().enumerate() {
            let Some(entry) = entry else { continue };
            let start = std::time::Instant::now();
            if self.probe(entry).await.is_ok() {
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                self.update_latency(idx, ms);
            }
        }
    }

    /// Send a root "." NS query to a single upstream and return on success.
    ///
    /// NS is used (not A) because the root has no A record: a "." A query
    /// comes back as NOERROR with zero answers, which hickory's
    /// `ProtoError::from_response` translates into a `NoRecordsFound`
    /// error and makes every probe look like a failure. The root NS set
    /// is always populated on any recursive resolver, so NS gives a
    /// reliable liveness signal without hitting an authoritative zone.
    async fn probe(&self, entry: &UpstreamEntry) -> Result<(), ()> {
        let name = Name::root();
        let mut msg = Message::new();
        msg.set_id(rand::random::<u16>());
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(name, RecordType::NS));

        let request = DnsRequest::new(msg, DnsRequestOptions::default());
        entry
            .name_server
            .send(request)
            .first_answer()
            .await
            .map(|_| ())
            .map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_forwarder(strategy: UpstreamStrategy) -> UpstreamForwarder {
        // Use real-looking IP:port so NameServer construction succeeds; tests
        // here only exercise ordering and EMA, never actually send. Plain
        // IP literals don't trigger any DNS lookup in `tokio::net::lookup_host`.
        let config = UpstreamConfig {
            servers: vec![
                "10.0.0.1:53".into(),
                "10.0.0.2:53".into(),
                "10.0.0.3:53".into(),
            ],
            timeout_ms: 1000,
        };
        let f = UpstreamForwarder::new(config).await;
        f.set_strategy(strategy);
        f
    }

    #[tokio::test]
    async fn test_sequential_order() {
        let f = make_forwarder(UpstreamStrategy::Sequential).await;
        assert_eq!(f.server_order(), vec![0, 1, 2]);
    }

    #[tokio::test]
    async fn test_round_robin_rotates() {
        let f = make_forwarder(UpstreamStrategy::RoundRobin).await;
        assert_eq!(f.server_order(), vec![0, 1, 2]);

        f.rr_counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(f.server_order(), vec![1, 2, 0]);

        f.rr_counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(f.server_order(), vec![2, 0, 1]);
    }

    #[tokio::test]
    async fn test_lowest_latency_order() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency).await;

        f.update_latency(0, 50.0);
        f.update_latency(1, 10.0);
        f.update_latency(2, 30.0);

        // Sorted ascending by EMA: idx 1 (10ms) → 2 (30ms) → 0 (50ms)
        assert_eq!(f.server_order(), vec![1, 2, 0]);
    }

    #[tokio::test]
    async fn test_lowest_latency_no_data_uses_config_order() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency).await;
        // All entries are NO_LATENCY (INFINITY); sort is stable so the
        // original config order survives.
        assert_eq!(f.server_order(), vec![0, 1, 2]);
    }

    #[tokio::test]
    async fn test_ema_update() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency).await;

        f.update_latency(0, 100.0);
        assert!((f.latency_ms_at(0) - 100.0).abs() < 0.001);

        // EMA = 0.3 * 40 + 0.7 * 100 = 82.0
        f.update_latency(0, 40.0);
        assert!((f.latency_ms_at(0) - 82.0).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_latencies_snapshot_preserves_labels() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency).await;
        f.update_latency(0, 12.5);
        f.update_latency(2, 99.0);

        let snap = f.latencies();
        // Unobserved (idx 1) is omitted from the snapshot.
        assert_eq!(snap.len(), 2);
        assert!((snap["10.0.0.1:53"] - 12.5).abs() < 0.001);
        assert!((snap["10.0.0.3:53"] - 99.0).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_set_strategy() {
        let f = make_forwarder(UpstreamStrategy::Sequential).await;
        assert_eq!(f.strategy(), UpstreamStrategy::Sequential);

        f.set_strategy(UpstreamStrategy::RoundRobin);
        assert_eq!(f.strategy(), UpstreamStrategy::RoundRobin);

        f.set_strategy(UpstreamStrategy::LowestLatency);
        assert_eq!(f.strategy(), UpstreamStrategy::LowestLatency);
    }

    #[test]
    fn parse_plain_udp_v4() {
        let s = UpstreamSpec::parse("1.1.1.1:53").unwrap();
        assert_eq!(s.host, "1.1.1.1");
        assert_eq!(s.port, 53);
        assert_eq!(s.kind, UpstreamKind::Udp);
    }

    #[test]
    fn parse_plain_udp_v6() {
        let s = UpstreamSpec::parse("[::1]:53").unwrap();
        assert_eq!(s.host, "::1");
        assert_eq!(s.port, 53);
        assert_eq!(s.kind, UpstreamKind::Udp);
    }

    #[test]
    fn parse_dot_default_port() {
        let s = UpstreamSpec::parse("tls://dns.mullvad.net").unwrap();
        assert_eq!(s.host, "dns.mullvad.net");
        assert_eq!(s.port, 853);
        assert_eq!(
            s.kind,
            UpstreamKind::Tls {
                sni: "dns.mullvad.net".into(),
            }
        );
    }

    #[test]
    fn parse_dot_explicit_port() {
        let s = UpstreamSpec::parse("tls://dns.mullvad.net:8853").unwrap();
        assert_eq!(s.port, 8853);
    }

    #[test]
    fn parse_doh_default_path_and_port() {
        let s = UpstreamSpec::parse("https://dns.mullvad.net").unwrap();
        assert_eq!(s.host, "dns.mullvad.net");
        assert_eq!(s.port, 443);
        assert_eq!(
            s.kind,
            UpstreamKind::Https {
                sni: "dns.mullvad.net".into(),
                path: "/dns-query".into(),
            }
        );
    }

    #[test]
    fn parse_doh_custom_path() {
        let s = UpstreamSpec::parse("https://dns.example.com/custom-dns").unwrap();
        assert_eq!(s.port, 443);
        assert_eq!(
            s.kind,
            UpstreamKind::Https {
                sni: "dns.example.com".into(),
                path: "/custom-dns".into(),
            }
        );
    }

    #[test]
    fn parse_doh_with_port_and_path() {
        let s = UpstreamSpec::parse("https://dns.example.com:8443/dns-query").unwrap();
        assert_eq!(s.port, 8443);
        assert_eq!(
            s.kind,
            UpstreamKind::Https {
                sni: "dns.example.com".into(),
                path: "/dns-query".into(),
            }
        );
    }

    #[test]
    fn parse_invalid_udp_returns_error() {
        assert!(UpstreamSpec::parse("not an address").is_err());
    }

    #[test]
    fn parse_empty_returns_error() {
        assert!(UpstreamSpec::parse("").is_err());
        assert!(UpstreamSpec::parse("   ").is_err());
    }

    #[test]
    fn parse_dot_invalid_port() {
        assert!(UpstreamSpec::parse("tls://dns.example.com:abc").is_err());
    }

    #[test]
    fn parse_dot_unclosed_ipv6() {
        assert!(UpstreamSpec::parse("tls://[::1:853").is_err());
    }
}
