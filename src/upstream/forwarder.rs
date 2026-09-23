use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Edns, Message, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use hickory_resolver::net::{DnsError, NetError, NoRecords};
use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};
use thiserror::Error;
use tracing::warn;

use super::strategy::UpstreamStrategy;

/// EMA smoothing factor. 0.3 means 30% weight for new observations.
const EMA_ALPHA: f64 = 0.3;

/// Minimum upstream timeout: mobile clients often need more than 2s for the
/// first query after a network switch.
const MIN_TIMEOUT_MS: u64 = 5000;

/// Configuration for upstream DNS servers.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Upstream server addresses. Each entry may be:
    /// - `IP[:port]` — plain UDP, default port 53 (e.g. `1.1.1.1`,
    ///   `1.1.1.1:53`, `::1`, `[::1]:53`)
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
                // Mullvad's plain-UDP endpoint answers REFUSED from arbitrary
                // networks; its DoT endpoint does not.
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
    /// Hostname (DoT/DoH) or IP literal (UDP).
    host: String,
    port: u16,
    kind: UpstreamKind,
}

impl UpstreamSpec {
    /// Parse an upstream entry: `tls://`, `https://`, or plain UDP
    /// (`IP:port` or a bare IP on port 53).
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
        } else if let Ok(addr) = trimmed.parse::<SocketAddr>() {
            Ok(Self {
                host: addr.ip().to_string(),
                port: addr.port(),
                kind: UpstreamKind::Udp,
            })
        } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
            // Parse as `IpAddr` rather than testing for `:`, which would
            // misread every bare IPv6 literal as carrying a port.
            Ok(Self {
                host: ip.to_string(),
                port: 53,
                kind: UpstreamKind::Udp,
            })
        } else {
            Err(format!(
                "invalid UDP upstream {trimmed:?}: expected an IP address, \
                 optionally with a port (e.g. `1.1.1.1`, `1.1.1.1:53`, `[::1]:53`)"
            ))
        }
    }

    /// Canonical entry string: port and path explicit, IPv6 bracketed. Stored
    /// instead of the typed form so `1.1.1.1` and `1.1.1.1:53` are one upstream.
    fn canonical(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let port = self.port;
        match &self.kind {
            UpstreamKind::Udp => format!("{host}:{port}"),
            UpstreamKind::Tls { .. } => format!("tls://{host}:{port}"),
            UpstreamKind::Https { path, .. } => format!("https://{host}:{port}{path}"),
        }
    }
}

/// Parse newline/comma-separated upstream input into canonical entries
/// (see [`UpstreamSpec::canonical`]), deduplicated in first-seen order.
/// Errors on the first invalid entry, or on empty input.
///
/// Dedup runs on canonical forms so equivalent spellings collapse to one
/// upstream rather than being health-checked and latency-ranked twice.
pub fn parse_upstreams(input: &str) -> Result<Vec<String>, String> {
    let mut servers: Vec<String> = Vec::new();
    for raw in input.split(['\n', ',']) {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let canonical = UpstreamSpec::parse(entry)?.canonical();
        if !servers.contains(&canonical) {
            servers.push(canonical);
        }
    }
    if servers.is_empty() {
        return Err("at least one upstream server is required".to_string());
    }
    Ok(servers)
}

/// Parse `host[:port]` (including `[::1]:853`), defaulting the port.
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

/// A one-server hickory `NameServerPool` (connection management) plus its
/// label; selection and latency tracking stay in [`UpstreamForwarder`].
struct UpstreamEntry {
    label: String,
    pool: NameServerPool<TokioRuntimeProvider>,
}

/// EDNS UDP payload when forcing DO: the DNS-flag-day value, avoiding IP
/// fragmentation of signed responses.
const DNSSEC_UDP_PAYLOAD: u16 = 1232;

/// Set DO on `msg`'s OPT, adding one only if absent (never a second OPT).
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

/// Fit an upstream response to what the client's request advertised.
///
/// DO may have been forced upstream: RFC 3225 requires stripping DNSSEC
/// records for a non-DO client, and RFC 6891 ties OPT presence to the client's
/// request. A fresh minimal OPT also keeps upstream EDNS options out of the
/// shared cache.
fn prepare_response_for_client(mut response: Message, client_request: &Message) -> Message {
    let client_dnssec_ok = client_request
        .edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok);

    response = response.maybe_strip_dnssec_records(client_dnssec_ok);
    response.metadata.checking_disabled = client_request.metadata.checking_disabled;
    // RFC 6840 §5.7: no AD for a client that did not request DNSSEC.
    if !client_dnssec_ok {
        response.metadata.authentic_data = false;
    }

    let upstream_rcode_high = response.edns.as_ref().map_or(0, Edns::rcode_high);
    response.edns = client_request.edns.as_ref().map(|_| {
        let mut edns = Edns::new();
        edns.set_rcode_high(upstream_rcode_high);
        edns.set_version(0);
        edns.set_dnssec_ok(client_dnssec_ok);
        edns.set_max_payload(DNSSEC_UDP_PAYLOAD);
        edns
    });

    response
}

/// Rebuild an NXDOMAIN/NODATA answer that hickory surfaced as [`NoRecords`].
///
/// Keeps the authority section (SOA, NSEC/RRSIG) so clients can negative-cache
/// per [RFC 2308]; without the SOA, iOS re-queries always-NODATA AAAA/HTTPS
/// names on nearly every connection. OPT follows the client per
/// [RFC 6891 §6.1.1]. AD stays unset: [`NoRecords`] has no AD field.
///
/// [RFC 2308]: https://www.rfc-editor.org/rfc/rfc2308
/// [RFC 6891 §6.1.1]: https://www.rfc-editor.org/rfc/rfc6891#section-6.1.1
fn build_negative_response(client_id: u16, no_records: &NoRecords, request: &Message) -> Message {
    let mut response = Message::response(client_id, OpCode::Query);
    response.metadata.response_code = no_records.response_code;
    // RFC 1035 §4.1.1: RD is set by the client and copied into the response.
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    for q in &request.queries {
        response.add_query(q.clone());
    }

    // `soa` is extracted from `authorities`, so use one or the other to add
    // the SOA exactly once.
    if let Some(authorities) = no_records.authorities.as_deref() {
        for record in authorities {
            response.add_authority(record.clone());
        }
    } else if let Some(soa) = no_records.soa.as_deref() {
        response.add_authority(soa.clone().into_record_of_rdata());
    }

    prepare_response_for_client(response, request)
}

/// "No observation yet" latency; sorts last under `total_cmp`, so
/// `LowestLatency` tries unobserved upstreams last.
const NO_LATENCY: f64 = f64::INFINITY;

/// Fold `ms` into the EMA in `cell` via a CAS loop.
///
/// Takes a cell, not an index, so callers write through the snapshot they
/// hold rather than indexing a live one a concurrent `reconfigure` may have
/// replaced.
fn update_latency_cell(cell: &AtomicU64, ms: f64) {
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

/// The reconfigurable upstream set. Swapped atomically by `reconfigure`.
/// `config.servers`, `entries`, and `latencies` are index-aligned.
struct Upstreams {
    config: UpstreamConfig,
    /// `None` for entries whose parse / DNS lookup failed at build time.
    entries: Vec<Option<UpstreamEntry>>,
    /// EMA latencies (ms), bit-packed into `AtomicU64`; `NO_LATENCY` until observed.
    latencies: Vec<AtomicU64>,
}

/// Resolve hosts concurrently and build one lazy `NameServerPool` per server.
async fn build_upstreams(config: UpstreamConfig) -> Upstreams {
    let timeout = Duration::from_millis(config.timeout_ms.max(MIN_TIMEOUT_MS));

    // Only `timeout` matters on the `NameServerPool` path; `attempts` etc.
    // apply to hickory's full `Resolver`, which we don't use. UDP retransmit
    // happens inside hickory's transport (every ~333ms within `timeout`).
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;

    let provider = TokioRuntimeProvider::default();
    // The TLS config selects aws-lc-rs explicitly, so no process-wide rustls
    // crypto provider is needed.
    let cx = Arc::new(PoolContext::new(
        opts,
        TlsConfig::new().expect("failed to build default rustls TLS config"),
    ));

    // Concurrent, so slow lookups don't make startup linear in upstream
    // count. Each task carries its config index to slot into `entries`.
    let mut lookup_set = tokio::task::JoinSet::new();
    for (idx, server) in config.servers.iter().enumerate() {
        let spec = match UpstreamSpec::parse(server) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    event = "upstream.spec_invalid",
                    server = %server,
                    error = %e,
                    "skipping unparseable upstream entry"
                );
                continue;
            }
        };
        let server = server.clone();
        let lookup_target = format!("{}:{}", spec.host, spec.port);
        lookup_set.spawn(async move {
            let addrs = tokio::net::lookup_host(lookup_target)
                .await
                .map(std::iter::Iterator::collect::<Vec<_>>);
            (idx, server, spec, addrs)
        });
    }

    let mut entries: Vec<Option<UpstreamEntry>> = (0..config.servers.len()).map(|_| None).collect();
    while let Some(joined) = lookup_set.join_next().await {
        let (idx, server, spec, addrs) = match joined {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    event = "upstream.resolve_join_failed",
                    error = %e,
                    "upstream resolve task join failed"
                );
                continue;
            }
        };
        let addr = match addrs {
            Ok(list) => {
                if let Some(a) = list.into_iter().next() {
                    a
                } else {
                    warn!(
                        event = "upstream.resolve_empty",
                        server = %server,
                        "no addresses returned for upstream"
                    );
                    continue;
                }
            }
            Err(e) => {
                warn!(
                    event = "upstream.resolve_failed",
                    server = %server,
                    error = %e,
                    "failed to resolve upstream host"
                );
                continue;
            }
        };

        // A single connection of the requested transport, no TCP fallback: a
        // truncated UDP response is relayed and the client retries over TCP.
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

        let pool = NameServerPool::from_config([ns_cfg], cx.clone(), provider.clone());
        entries[idx] = Some(UpstreamEntry {
            label: server,
            pool,
        });
    }

    let latencies = (0..config.servers.len())
        .map(|_| AtomicU64::new(NO_LATENCY.to_bits()))
        .collect();

    Upstreams {
        config,
        entries,
        latencies,
    }
}

/// Forwards DNS queries to upstreams by strategy; transport is delegated to
/// per-upstream hickory pools.
///
/// Upstreams are addressed by index into `config.servers`, avoiding a
/// per-query label allocation.
pub struct UpstreamForwarder {
    upstreams: ArcSwap<Upstreams>,
    strategy: ArcSwap<UpstreamStrategy>,
    rr_counter: AtomicUsize,
    /// Force DO on upstream requests (DNSSEC transparency); runtime-switchable.
    dnssec_enabled: AtomicBool,
}

impl UpstreamForwarder {
    /// Create a forwarder. Hostnames resolve once, to their first address, so
    /// geo-routed providers pin to the `PoP` picked at startup.
    pub async fn new(config: UpstreamConfig) -> Self {
        Self {
            upstreams: ArcSwap::from_pointee(build_upstreams(config).await),
            strategy: ArcSwap::from_pointee(UpstreamStrategy::default()),
            rr_counter: AtomicUsize::new(0),
            dnssec_enabled: AtomicBool::new(true),
        }
    }

    /// Atomically replace the upstream set, keeping the timeout. Hosts that fail
    /// to resolve are logged and left unavailable, as in `new`.
    pub async fn reconfigure(&self, servers: Vec<String>) {
        let timeout_ms = self.upstreams.load().config.timeout_ms;
        let next = build_upstreams(UpstreamConfig {
            servers,
            timeout_ms,
        })
        .await;
        self.upstreams.store(Arc::new(next));
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

    /// Try-order for the current strategy, as indices into `config.servers`.
    pub fn server_order(&self) -> Vec<usize> {
        let up = self.upstreams.load();
        let len = up.entries.len();
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
                    let la = f64::from_bits(up.latencies[a].load(Ordering::Relaxed));
                    let lb = f64::from_bits(up.latencies[b].load(Ordering::Relaxed));
                    la.total_cmp(&lb)
                });
                order
            }
        }
    }

    /// EMA latency (ms) at `idx`; `f64::INFINITY` if unobserved.
    #[cfg(test)]
    fn latency_ms_at(&self, idx: usize) -> f64 {
        let up = self.upstreams.load();
        f64::from_bits(up.latencies[idx].load(Ordering::Relaxed))
    }

    /// Update the EMA latency at `idx`. An `idx` a concurrent `reconfigure`
    /// shrank away is a no-op, not a panic.
    pub fn update_latency(&self, idx: usize, ms: f64) {
        let up = self.upstreams.load();
        if let Some(cell) = up.latencies.get(idx) {
            update_latency_cell(cell, ms);
        }
    }

    /// EMA latencies by server label; unobserved servers are omitted.
    pub fn latencies(&self) -> HashMap<String, f64> {
        let up = self.upstreams.load();
        up.config
            .servers
            .iter()
            .enumerate()
            .filter_map(|(i, label)| {
                // One snapshot, index-aligned: in range whatever `reconfigure` does.
                let ms = f64::from_bits(up.latencies[i].load(Ordering::Relaxed));
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
    /// Returns `(response_bytes, upstream_label, authenticated_data)`, where
    /// `authenticated_data` is the upstream's AD bit read *before* it is
    /// stripped for non-DO clients, so the query log still sees it.
    pub async fn forward(
        &self,
        query_bytes: &[u8],
    ) -> Result<(Vec<u8>, String, bool), ForwardError> {
        // `load_full` (Arc, not Guard) so the snapshot can be held across `.await`.
        let up = self.upstreams.load_full();
        // The handler parsed this already; re-parsing keeps the API bytes-in /
        // bytes-out.
        let client_request_msg =
            Message::from_vec(query_bytes).map_err(|_err| ForwardError::BadQuery)?;
        let client_id = client_request_msg.metadata.id;
        // Clone only when forcing DO; otherwise send the client query as-is.
        let forced_request_msg = if self.dnssec_enabled() {
            let mut msg = client_request_msg.clone();
            ensure_dnssec_ok(&mut msg);
            Some(msg)
        } else {
            None
        };
        let upstream_request_msg = forced_request_msg.as_ref().unwrap_or(&client_request_msg);

        let order = self.server_order();
        if self.strategy() == UpstreamStrategy::RoundRobin {
            self.rr_counter.fetch_add(1, Ordering::Relaxed);
        }

        for &idx in &order {
            let Some(entry) = up.entries.get(idx).and_then(|e| e.as_ref()) else {
                continue;
            };

            let request =
                DnsRequest::new(upstream_request_msg.clone(), DnsRequestOptions::default());
            let start = std::time::Instant::now();

            match entry.pool.send(request).first_answer().await {
                Ok(response) => {
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    // Write through `up`, not the live snapshot; a post-swap
                    // write lands harmlessly in the old `Arc`.
                    if let Some(cell) = up.latencies.get(idx) {
                        update_latency_cell(cell, ms);
                    }

                    // hickory rewrites txids for multiplexing; restore the client's.
                    let mut msg: Message = response.into();
                    msg.metadata.id = client_id;
                    // Read AD before tailoring strips it for non-DO clients.
                    let upstream_authenticated = msg.metadata.authentic_data;
                    let msg = prepare_response_for_client(msg, &client_request_msg);

                    match msg.to_bytes() {
                        Ok(bytes) => {
                            return Ok((bytes, entry.label.clone(), upstream_authenticated));
                        }
                        Err(e) => {
                            warn!(
                                event = "upstream.reencode_failed",
                                upstream = %entry.label,
                                error = %e,
                                "failed to re-encode upstream response"
                            );
                        }
                    }
                }
                Err(e) => {
                    // hickory surfaces NXDOMAIN/NODATA as an error; it is a valid
                    // answer, so rebuild and return it rather than failing over.
                    if let NetError::Dns(DnsError::NoRecordsFound(no_records)) = &e {
                        let ms = start.elapsed().as_secs_f64() * 1000.0;
                        if let Some(cell) = up.latencies.get(idx) {
                            update_latency_cell(cell, ms);
                        }
                        let response =
                            build_negative_response(client_id, no_records, &client_request_msg);
                        if let Ok(bytes) = response.to_bytes() {
                            // `NoRecords` has no AD field: logged as unauthenticated.
                            return Ok((bytes, entry.label.clone(), false));
                        }
                    }
                    warn!(
                        event = "upstream.forward_failed",
                        upstream = %entry.label,
                        error = %e,
                        "upstream forward failed"
                    );
                }
            }
        }

        Err(ForwardError::AllFailed)
    }

    /// Health check every configured upstream: `(server, ok, latency_ms)`.
    pub async fn health_check(&self) -> Vec<(String, bool, u64)> {
        let up = self.upstreams.load_full();
        let mut results = Vec::with_capacity(up.config.servers.len());
        for (idx, server) in up.config.servers.iter().enumerate() {
            let Some(entry) = up.entries[idx].as_ref() else {
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

    /// Probe all servers and update EMA latencies (background task).
    pub async fn probe_all(&self) {
        let up = self.upstreams.load_full();
        for (idx, entry) in up.entries.iter().enumerate() {
            let Some(entry) = entry else { continue };
            let start = std::time::Instant::now();
            if self.probe(entry).await.is_ok() {
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                if let Some(cell) = up.latencies.get(idx) {
                    update_latency_cell(cell, ms);
                }
            }
        }
    }

    /// Send a root `.` NS query to one upstream.
    ///
    /// NS, not A: the root has no A record, and hickory turns that empty
    /// NOERROR into `NoRecordsFound`, failing every probe.
    ///
    /// Retried once: the first send on a DoT/DoH connection that went stale
    /// (idle timeout, anycast reroute) fails before the pool reconnects, and
    /// unlike the forward path a probe has no other upstream to fail over to.
    async fn probe(&self, entry: &UpstreamEntry) -> Result<(), ()> {
        const PROBE_ATTEMPTS: usize = 2;
        for attempt in 0..PROBE_ATTEMPTS {
            // A fresh random id per attempt, so a late reply to the first
            // attempt is not matched against the second.
            let mut msg = Message::query();
            msg.metadata.recursion_desired = true;
            msg.add_query(Query::query(Name::root(), RecordType::NS));

            let request = DnsRequest::new(msg, DnsRequestOptions::default());
            match entry.pool.send(request).first_answer().await {
                Ok(_) => return Ok(()),
                // Only a failed final attempt marks the upstream down.
                Err(e) => warn!(
                    event = "upstream.probe_attempt_failed",
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
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::Record;

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

    fn response_with_dnssec_records() -> Message {
        let name = Name::from_ascii("api.example.com.").unwrap();
        let mut response = Message::response(0x1234, OpCode::Query);
        response.metadata.authentic_data = true;
        response.add_query(Query::query(name.clone(), RecordType::A));
        response.add_answer(Record::update0(name, 300, RecordType::RRSIG));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.set_max_payload(4096);
        response.set_edns(edns);
        response
    }

    fn client_request(edns: Option<bool>) -> Message {
        let mut request = Message::query();
        request.add_query(Query::query(
            Name::from_ascii("api.example.com.").unwrap(),
            RecordType::A,
        ));
        if let Some(dnssec_ok) = edns {
            let mut client_edns = Edns::new();
            client_edns.set_max_payload(4096);
            client_edns.set_dnssec_ok(dnssec_ok);
            request.set_edns(client_edns);
        }
        request
    }

    #[test]
    fn response_for_plain_client_omits_opt_and_dnssec_records() {
        let response =
            prepare_response_for_client(response_with_dnssec_records(), &client_request(None));

        assert!(response.edns.is_none());
        assert!(response.answers.is_empty());
        assert!(!response.metadata.authentic_data);
    }

    #[test]
    fn response_for_edns_client_without_do_has_opt_but_no_dnssec_records() {
        let response = prepare_response_for_client(
            response_with_dnssec_records(),
            &client_request(Some(false)),
        );

        let edns = response.edns.as_ref().expect("client sent OPT");
        assert!(!edns.flags().dnssec_ok);
        assert_eq!(edns.max_payload(), DNSSEC_UDP_PAYLOAD);
        assert!(response.answers.is_empty());
        assert!(!response.metadata.authentic_data);
    }

    #[test]
    fn response_for_do_client_keeps_opt_and_dnssec_records() {
        let response = prepare_response_for_client(
            response_with_dnssec_records(),
            &client_request(Some(true)),
        );

        assert!(response.edns.as_ref().unwrap().flags().dnssec_ok);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].record_type(), RecordType::RRSIG);
        assert!(response.metadata.authentic_data);
    }

    fn example_soa() -> Record<hickory_proto::rr::rdata::SOA> {
        use hickory_proto::rr::rdata::SOA;
        let soa = SOA::new(
            Name::from_ascii("ns1.example.com.").unwrap(),
            Name::from_ascii("hostmaster.example.com.").unwrap(),
            2_026_042_954,
            1200,
            144,
            1_814_400,
            7200,
        );
        Record::from_rdata(Name::from_ascii("example.com.").unwrap(), 7200, soa)
    }

    #[test]
    fn negative_response_preserves_soa_in_authority() {
        let name = Name::from_ascii("api.example.com.").unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(name.clone(), RecordType::AAAA));

        let mut no_records =
            NoRecords::new(Query::query(name, RecordType::AAAA), ResponseCode::NoError);
        no_records.soa = Some(Box::new(example_soa()));

        let response = build_negative_response(0x1234, &no_records, &request);

        assert_eq!(response.metadata.id, 0x1234);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            response.authorities.len(),
            1,
            "the SOA must be carried in the authority section so clients can negative-cache"
        );
        assert_eq!(response.authorities[0].record_type(), RecordType::SOA);
    }

    #[test]
    fn negative_response_echoes_query_rd() {
        let name = Name::from_ascii("api.example.com.").unwrap();
        for rd in [true, false] {
            let mut request = Message::query();
            request.metadata.recursion_desired = rd;
            request.add_query(Query::query(name.clone(), RecordType::AAAA));
            let no_records = NoRecords::new(
                Query::query(name.clone(), RecordType::AAAA),
                ResponseCode::NoError,
            );
            let response = build_negative_response(0x1234, &no_records, &request);
            assert_eq!(
                response.metadata.recursion_desired, rd,
                "RD must be copied from the client request"
            );
        }
    }

    #[test]
    fn negative_response_uses_full_authority_section_without_duplicating_soa() {
        let name = Name::from_ascii("api.example.com.").unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(name.clone(), RecordType::AAAA));

        // hickory fills both fields from the same section.
        let soa = example_soa();
        let mut no_records =
            NoRecords::new(Query::query(name, RecordType::AAAA), ResponseCode::NoError);
        no_records.soa = Some(Box::new(soa.clone()));
        no_records.authorities = Some(vec![soa.into_record_of_rdata()].into());

        let response = build_negative_response(0x1234, &no_records, &request);

        assert_eq!(
            response.authorities.len(),
            1,
            "SOA present in both fields must appear exactly once"
        );
        assert_eq!(response.authorities[0].record_type(), RecordType::SOA);
    }

    #[test]
    fn negative_response_echoes_opt_when_client_used_edns() {
        let name = Name::from_ascii("api.example.com.").unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(name.clone(), RecordType::HTTPS));
        let mut client_edns = Edns::new();
        client_edns.set_version(0);
        client_edns.set_max_payload(1232);
        request.set_edns(client_edns);

        let no_records =
            NoRecords::new(Query::query(name, RecordType::HTTPS), ResponseCode::NoError);
        let response = build_negative_response(0x1234, &no_records, &request);

        assert!(
            response.edns.is_some(),
            "RFC 6891 §6.1.1: a response to an EDNS request must carry an OPT"
        );
    }

    #[test]
    fn negative_response_omits_opt_when_client_sent_none() {
        let name = Name::from_ascii("api.example.com.").unwrap();
        let mut request = Message::query();
        request.add_query(Query::query(name.clone(), RecordType::HTTPS));

        let no_records =
            NoRecords::new(Query::query(name, RecordType::HTTPS), ResponseCode::NoError);
        let response = build_negative_response(0x1234, &no_records, &request);

        assert!(
            response.edns.is_none(),
            "RFC 6891 §7: no OPT in the response when the client sent none"
        );
    }

    #[tokio::test]
    async fn dnssec_toggle_defaults_on_and_flips() {
        let f = make_forwarder(UpstreamStrategy::Sequential).await;
        assert!(f.dnssec_enabled());
        f.set_dnssec_enabled(false);
        assert!(!f.dnssec_enabled());
    }

    async fn make_forwarder(strategy: UpstreamStrategy) -> UpstreamForwarder {
        // IP literals need no lookup; these tests never send.
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
                "https://dns.quad9.net:443/dns-query".to_string(),
            ]
        );
    }

    #[test]
    fn parse_bare_ipv4_takes_port_53() {
        let s = UpstreamSpec::parse("1.1.1.1").unwrap();
        assert_eq!(s.host, "1.1.1.1");
        assert_eq!(s.port, 53);
        assert_eq!(s.kind, UpstreamKind::Udp);
    }

    /// A bare IPv6 literal has colons but no port.
    #[test]
    fn parse_bare_ipv6_takes_port_53() {
        let s = UpstreamSpec::parse("2606:4700:4700::1111").unwrap();
        assert_eq!(s.host, "2606:4700:4700::1111");
        assert_eq!(s.port, 53);
        assert_eq!(s.kind, UpstreamKind::Udp);
        assert_eq!(s.canonical(), "[2606:4700:4700::1111]:53");
    }

    /// Ambiguous `inet_aton` shorthand and octal forms stay errors.
    #[test]
    fn parse_bare_ip_rejects_inet_aton_shorthand() {
        assert!(UpstreamSpec::parse("1.1").is_err());
        assert!(UpstreamSpec::parse("010.1.1.1").is_err());
        assert!(UpstreamSpec::parse("0x01010101").is_err());
    }

    /// A bare hostname has no transport to infer; it needs a scheme.
    #[test]
    fn parse_bare_hostname_still_rejected() {
        assert!(UpstreamSpec::parse("dns.example.com").is_err());
        assert!(UpstreamSpec::parse("localhost:53").is_err());
    }

    #[test]
    fn parse_upstreams_canonicalizes_every_scheme() {
        let out =
            parse_upstreams("1.1.1.1\n::1\ntls://dns.mullvad.net\nhttps://dns.quad9.net").unwrap();
        assert_eq!(
            out,
            vec![
                "1.1.1.1:53".to_string(),
                "[::1]:53".to_string(),
                "tls://dns.mullvad.net:853".to_string(),
                "https://dns.quad9.net:443/dns-query".to_string(),
            ]
        );
    }

    /// Equivalent spellings must collapse to one upstream.
    #[test]
    fn parse_upstreams_dedupes_equivalent_spellings() {
        let out = parse_upstreams("1.1.1.1, 1.1.1.1:53, [::1]:53, ::1").unwrap();
        assert_eq!(out, vec!["1.1.1.1:53".to_string(), "[::1]:53".to_string()]);
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

    #[tokio::test]
    async fn latency_write_after_shrinking_reconfigure_does_not_panic() {
        // A stale `idx` must not panic after `reconfigure` shrinks the set.
        let f = make_forwarder(UpstreamStrategy::LowestLatency).await; // 3 servers
        f.reconfigure(vec!["10.0.9.9:53".into()]).await; // shrink to 1

        // idx 2 is now out of range: a no-op.
        f.update_latency(2, 5.0);

        let snap = f.latencies();
        assert!(
            !snap.contains_key("10.0.0.3:53"),
            "stale-generation label must not leak into snapshot"
        );

        // Writing to a valid index on the new set still works.
        f.update_latency(0, 7.0);
        assert!(f.latencies().contains_key("10.0.9.9:53"));
    }

    #[tokio::test]
    async fn reconfigure_swaps_server_set_and_preserves_modes() {
        let f = make_forwarder(UpstreamStrategy::RoundRobin).await; // 3x 10.0.0.x:53
        f.set_dnssec_enabled(false);
        assert_eq!(f.server_order().len(), 3);

        f.reconfigure(vec!["10.0.1.1:53".into(), "10.0.1.2:53".into()])
            .await;

        // new set is live: 2 servers, labels updated, latencies reset
        assert_eq!(f.server_order().len(), 2);
        let snap = f.latencies();
        assert!(snap.is_empty(), "latencies reset on reconfigure");
        f.update_latency(0, 5.0);
        assert!(f.latencies().contains_key("10.0.1.1:53"));
        // independent modes survive the swap
        assert_eq!(f.strategy(), UpstreamStrategy::RoundRobin);
        assert!(!f.dnssec_enabled());
    }
}
