use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use hickory_proto::op::{
    DnsRequest, DnsRequestOptions, Edns, Message, OpCode, Query, ResponseCode,
};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};
use thiserror::Error;
use tracing::warn;

use super::strategy::UpstreamStrategy;

/// EMA smoothing factor. 0.3 means 30% weight for new observations.
const EMA_ALPHA: f64 = 0.3;

/// Minimum upstream timeout. Mobile clients (NAT rebinding, Wi-Fi↔cellular
/// switches) routinely need more than 2s for the first query after a
/// network transition.
const MIN_TIMEOUT_MS: u64 = 5000;

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

/// Parse textarea / CSV upstream input into validated server strings.
/// Splits on newlines and commas, trims, drops blanks, and validates each
/// entry via [`UpstreamSpec::parse`]. Returns the cleaned strings in order,
/// or an error naming the first offending entry. Empty input is an error —
/// a resolver with zero upstreams is non-functional.
pub fn parse_upstreams(input: &str) -> Result<Vec<String>, String> {
    let mut servers = Vec::new();
    for raw in input.split(['\n', ',']) {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        UpstreamSpec::parse(entry)?;
        servers.push(entry.to_string());
    }
    if servers.is_empty() {
        return Err("at least one upstream server is required".to_string());
    }
    Ok(servers)
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

/// A single-upstream connection pool paired with its display label.
///
/// Each pool wraps exactly one upstream server; hickory's `NameServerPool`
/// owns the per-server connection management (lazy connect, UDP retransmit
/// within the timeout, reconnect for DoT/DoH) while [`UpstreamForwarder`]
/// keeps the cross-upstream selection strategy and latency tracking.
struct UpstreamEntry {
    label: String,
    pool: NameServerPool<TokioRuntimeProvider>,
}

/// EDNS UDP payload advertised when forcing DO. 1232 is the DNS-flag-day
/// recommendation that avoids IP fragmentation of larger signed responses.
const DNSSEC_UDP_PAYLOAD: u16 = 1232;

/// Upsert an EDNS(0) OPT on `msg` with the DNSSEC-OK (DO) bit set, preserving
/// any existing OPT and its options. Never produces a second OPT record.
fn ensure_dnssec_ok(msg: &mut Message) {
    if let Some(edns) = msg.edns.as_mut() {
        edns.set_dnssec_ok(true);
        if edns.max_payload() < DNSSEC_UDP_PAYLOAD {
            edns.set_max_payload(DNSSEC_UDP_PAYLOAD);
        }
    } else {
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_dnssec_ok(true);
        edns.set_max_payload(DNSSEC_UDP_PAYLOAD);
        msg.set_edns(edns);
    }
}

/// Sentinel "no observation yet" value for [`UpstreamForwarder::latencies`].
/// Sorts last under `total_cmp`, so an unobserved upstream is naturally
/// the worst choice for `LowestLatency`.
const NO_LATENCY: f64 = f64::INFINITY;

/// Forwards DNS queries to upstream servers with configurable strategy.
///
/// Transport (UDP retransmit, socket handling, txid validation/rewrite) is
/// delegated to a per-upstream hickory `NameServerPool`. This type owns the
/// per-upstream selection strategy and latency tracking.
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
    /// When true, force the DO bit on upstream requests (DNSSEC transparency).
    /// Runtime-switchable so the admin-UI toggle takes effect without restart.
    dnssec_enabled: AtomicBool,
}

impl UpstreamForwarder {
    /// Create a new forwarder with the given configuration.
    ///
    /// Hostname-bearing entries (`tls://`, `https://`) are resolved to
    /// `SocketAddr` via `tokio::net::lookup_host`. The first address
    /// returned is used; geo-routed providers like Mullvad therefore
    /// pin to the `PoP` that DNS picks at startup.
    pub async fn new(config: UpstreamConfig) -> Self {
        let timeout = Duration::from_millis(config.timeout_ms.max(MIN_TIMEOUT_MS));

        // Only `timeout` is honoured on the `NameServerPool` path used below:
        // it bounds each upstream attempt and feeds the per-connection I/O
        // timeout. `attempts` / `preserve_intermediates` only affect the full
        // `Resolver` (RetryDnsHandle / CachingClient), which we don't use —
        // this forwarder owns retry and caching itself. UDP retransmit is
        // handled inside hickory's transport (every ~333ms within `timeout`).
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;

        let provider = TokioRuntimeProvider::default();
        // Shared connection context for every upstream pool: holds the resolver
        // options plus the default (aws-lc-rs–backed) rustls client config used
        // for DoT/DoH. The provider selects aws-lc-rs explicitly, so this does
        // not depend on a process-wide rustls crypto provider being installed.
        let cx = Arc::new(PoolContext::new(
            opts,
            TlsConfig::new().expect("failed to build default rustls TLS config"),
        ));

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
                Ok(list) => {
                    if let Some(a) = list.into_iter().next() {
                        a
                    } else {
                        warn!(server = %server, "no addresses returned for upstream");
                        continue;
                    }
                }
                Err(e) => {
                    warn!(server = %server, error = %e, "failed to resolve upstream host");
                    continue;
                }
            };

            // One NameServerConfig per upstream, with a single connection of the
            // requested transport — matching the pre-0.26 behavior (a truncated
            // UDP response is relayed to the client, which retries over TCP
            // itself). DoT/DoH carry the SNI / HTTP path inside the
            // per-connection ProtocolConfig. The resolved address' port is
            // propagated onto the connection.
            let ns_cfg = match &spec.kind {
                UpstreamKind::Udp => {
                    let mut udp = ConnectionConfig::udp();
                    udp.port = addr.port();
                    NameServerConfig::new(addr.ip(), true, vec![udp])
                }
                UpstreamKind::Tls { sni } => {
                    let mut c = ConnectionConfig::tls(Arc::from(sni.as_str()));
                    c.port = addr.port();
                    NameServerConfig::new(addr.ip(), true, vec![c])
                }
                UpstreamKind::Https { sni, path } => {
                    let mut c = ConnectionConfig::https(
                        Arc::from(sni.as_str()),
                        Some(Arc::from(path.as_str())),
                    );
                    c.port = addr.port();
                    NameServerConfig::new(addr.ip(), true, vec![c])
                }
            };

            // Connections are established lazily on first use, so constructing
            // the pool performs no network I/O here.
            let pool = NameServerPool::from_config([ns_cfg], cx.clone(), provider.clone());
            entries[idx] = Some(UpstreamEntry {
                label: server,
                pool,
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
            dnssec_enabled: AtomicBool::new(true),
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

    /// Enable/disable forcing the DO bit on upstream requests.
    pub fn set_dnssec_enabled(&self, enabled: bool) {
        self.dnssec_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Whether DO forcing is currently enabled.
    pub fn dnssec_enabled(&self) -> bool {
        self.dnssec_enabled.load(Ordering::Relaxed)
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
        let mut request_msg =
            Message::from_vec(query_bytes).map_err(|_err| ForwardError::BadQuery)?;
        let client_id = request_msg.metadata.id;
        if self.dnssec_enabled() {
            ensure_dnssec_ok(&mut request_msg);
        }

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

            match entry.pool.send(request).first_answer().await {
                Ok(response) => {
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    self.update_latency(idx, ms);

                    // hickory rewrites txids for connection multiplexing,
                    // so the response message we get back may not echo the
                    // client's original id. Restore it before re-encoding.
                    let mut msg: Message = response.into();
                    msg.metadata.id = client_id;

                    match msg.to_bytes() {
                        Ok(bytes) => return Ok((bytes, entry.label.clone())),
                        Err(e) => {
                            warn!(upstream = %entry.label, error = %e, "failed to re-encode upstream response");
                        }
                    }
                }
                Err(e) => {
                    // NXDOMAIN / NoError-with-no-records is a valid authoritative
                    // response, not an upstream failure.  hickory converts it to a
                    // ProtoError so we reconstruct a proper DNS response and return
                    // it immediately so the query gets logged by the handler.
                    if e.is_no_records_found() {
                        let rcode = match &e {
                            NetError::Dns(DnsError::NoRecordsFound(no_records)) => {
                                no_records.response_code
                            }
                            _ => ResponseCode::NXDomain,
                        };
                        let ms = start.elapsed().as_secs_f64() * 1000.0;
                        self.update_latency(idx, ms);
                        // Reconstruct a minimal DNS response for NXDOMAIN / NODATA.
                        // The AD bit is NOT set here even if the upstream validated the
                        // negative answer: hickory's `NoRecordsFound` struct does not
                        // expose an authentic-data field (see docs/superpowers/specs/
                        // 2026-06-28-dnssec-transparency-design.md "Known limitations").
                        let mut response = Message::response(client_id, OpCode::Query);
                        response.metadata.response_code = rcode;
                        response.metadata.recursion_desired = true;
                        response.metadata.recursion_available = true;
                        for q in &request_msg.queries {
                            response.add_query(q.clone());
                        }
                        if let Ok(bytes) = response.to_bytes() {
                            return Ok((bytes, entry.label.clone()));
                        }
                    }
                    warn!(upstream = %entry.label, error = %e, "upstream forward failed");
                }
            }
        }

        Err(ForwardError::AllFailed)
    }

    /// Health check all configured upstream servers.
    /// Returns a list of (server, status, `latency_ms`).
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
    ///
    /// The send is retried once on failure. A persistent DoT/DoH connection
    /// can be closed by the server's idle timeout (or invalidated by an
    /// anycast reroute when the client's network changes), so the first send
    /// on a connection that went stale between health checks fails before
    /// hickory's `NameServerPool` transparently reconnects. The forward path
    /// hides this behind cross-upstream failover; the single-upstream probe
    /// has no such fallback, so it retries the same upstream once to give the
    /// connection a chance to rebuild.
    async fn probe(&self, entry: &UpstreamEntry) -> Result<(), ()> {
        // 1 original send + 1 retry. `send` consumes the `DnsRequest`, so the
        // query is rebuilt per attempt (cheap, and a fresh id avoids a late
        // reply to the first attempt being matched against the second).
        const PROBE_ATTEMPTS: usize = 2;
        for attempt in 0..PROBE_ATTEMPTS {
            // `Message::query()` assigns a fresh random transaction id and sets
            // MessageType::Query / OpCode::Query, so a late reply to a previous
            // attempt won't be matched against this one.
            let mut msg = Message::query();
            msg.metadata.recursion_desired = true;
            msg.add_query(Query::query(Name::root(), RecordType::NS));

            let request = DnsRequest::new(msg, DnsRequestOptions::default());
            match entry.pool.send(request).first_answer().await {
                Ok(_) => return Ok(()),
                // Log the real transport error the old probe used to swallow.
                // The first failed attempt is the expected stale-connection
                // signal that the retry recovers from; only a failure on the
                // final attempt actually marks the upstream down.
                Err(e) => warn!(
                    upstream = %entry.label,
                    attempt = attempt + 1,
                    attempts = PROBE_ATTEMPTS,
                    error = %e,
                    "upstream health probe attempt failed"
                ),
            }
        }
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_dnssec_ok_adds_opt_when_absent() {
        let mut msg = Message::query();
        msg.add_query(Query::query(Name::root(), RecordType::A));
        ensure_dnssec_ok(&mut msg);
        let edns = msg.edns.as_ref().expect("OPT added");
        assert!(edns.flags().dnssec_ok);
        assert_eq!(edns.max_payload(), 1232);
    }

    #[test]
    fn ensure_dnssec_ok_upserts_existing_opt_without_duplicating() {
        let mut msg = Message::query();
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(4096);
        msg.set_edns(edns);
        ensure_dnssec_ok(&mut msg);
        let edns = msg.edns.as_ref().unwrap();
        assert!(edns.flags().dnssec_ok);
        // existing larger payload preserved (>= 1232)
        assert_eq!(edns.max_payload(), 4096);
    }

    #[tokio::test]
    async fn dnssec_toggle_defaults_on_and_flips() {
        let f = make_forwarder(UpstreamStrategy::Sequential).await;
        assert!(f.dnssec_enabled());
        f.set_dnssec_enabled(false);
        assert!(!f.dnssec_enabled());
    }

    async fn make_forwarder(strategy: UpstreamStrategy) -> UpstreamForwarder {
        // Use real-looking IP:port so pool construction succeeds; tests
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

    #[test]
    fn parse_upstreams_accepts_newlines_and_commas() {
        let out = parse_upstreams(
            "1.1.1.1:53\ntls://dns.mullvad.net:853, https://dns.quad9.net/dns-query",
        )
        .unwrap();
        assert_eq!(
            out,
            vec![
                "1.1.1.1:53".to_string(),
                "tls://dns.mullvad.net:853".to_string(),
                "https://dns.quad9.net/dns-query".to_string(),
            ]
        );
    }

    #[test]
    fn parse_upstreams_rejects_empty() {
        assert!(parse_upstreams("").is_err());
        assert!(parse_upstreams("   \n  ").is_err());
    }

    #[test]
    fn parse_upstreams_reports_bad_entry() {
        let err = parse_upstreams("1.1.1.1:53\nnot an address").unwrap_err();
        assert!(
            err.contains("not an address"),
            "error should name the bad entry: {err}"
        );
    }
}
