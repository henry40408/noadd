use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    /// Upstream server addresses in "IP:port" format.
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
                "194.242.2.2:53".into(),
            ],
            timeout_ms: 5000,
        }
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

/// Forwards DNS queries to upstream servers with configurable strategy.
///
/// Transport (UDP retransmit, socket reuse, txid validation, automatic
/// TCP-on-error fallback) is delegated to hickory's `NameServer`. This
/// type owns the per-upstream selection strategy and latency tracking.
pub struct UpstreamForwarder {
    config: UpstreamConfig,
    /// Upstreams indexed by label, in the same order as `config.servers`.
    /// Servers whose address cannot be parsed are silently dropped.
    entries: HashMap<String, UpstreamEntry>,
    strategy: ArcSwap<UpstreamStrategy>,
    rr_counter: AtomicUsize,
    latencies: Mutex<HashMap<String, f64>>,
}

impl UpstreamForwarder {
    /// Create a new forwarder with the given configuration.
    pub fn new(config: UpstreamConfig) -> Self {
        let timeout = Duration::from_millis(config.timeout_ms.max(MIN_TIMEOUT_MS));

        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = UDP_ATTEMPTS;
        opts.try_tcp_on_error = true;
        opts.validate = false;
        opts.preserve_intermediates = false;

        let provider = TokioConnectionProvider::default();

        let mut entries = HashMap::new();
        for server in &config.servers {
            match server.parse::<SocketAddr>() {
                Ok(addr) => {
                    let ns_cfg = NameServerConfig::new(addr, Protocol::Udp);
                    let name_server = NameServer::new(ns_cfg, opts.clone(), provider.clone());
                    entries.insert(
                        server.clone(),
                        UpstreamEntry {
                            label: server.clone(),
                            name_server,
                        },
                    );
                }
                Err(e) => {
                    warn!(server = %server, error = %e, "skipping unparseable upstream address");
                }
            }
        }

        Self {
            config,
            entries,
            strategy: ArcSwap::from_pointee(UpstreamStrategy::default()),
            rr_counter: AtomicUsize::new(0),
            latencies: Mutex::new(HashMap::new()),
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

    /// Return the server try-order for the current strategy.
    pub fn server_order(&self) -> Vec<String> {
        let servers = &self.config.servers;
        let len = servers.len();
        if len == 0 {
            return vec![];
        }

        match self.strategy() {
            UpstreamStrategy::Sequential => servers.clone(),
            UpstreamStrategy::RoundRobin => {
                let idx = self.rr_counter.load(Ordering::Relaxed) % len;
                let mut order = Vec::with_capacity(len);
                for i in 0..len {
                    order.push(servers[(idx + i) % len].clone());
                }
                order
            }
            UpstreamStrategy::LowestLatency => {
                let lat = self.latencies.lock().unwrap();
                if lat.is_empty() {
                    return servers.clone();
                }
                let mut sorted: Vec<String> = servers.clone();
                sorted.sort_by(|a, b| {
                    let la = lat.get(a).copied().unwrap_or(f64::MAX);
                    let lb = lat.get(b).copied().unwrap_or(f64::MAX);
                    la.partial_cmp(&lb).unwrap_or(std::cmp::Ordering::Equal)
                });
                sorted
            }
        }
    }

    /// Update the EMA latency for a server.
    pub fn update_latency(&self, server: &str, ms: f64) {
        use std::collections::hash_map::Entry;
        let mut lat = self.latencies.lock().unwrap();
        match lat.entry(server.to_string()) {
            Entry::Vacant(e) => {
                e.insert(ms);
            }
            Entry::Occupied(mut e) => {
                let ema = e.get_mut();
                *ema = EMA_ALPHA * ms + (1.0 - EMA_ALPHA) * *ema;
            }
        }
    }

    /// Get a snapshot of current EMA latencies.
    pub fn latencies(&self) -> HashMap<String, f64> {
        self.latencies.lock().unwrap().clone()
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

        for label in &order {
            let Some(entry) = self.entries.get(label) else {
                continue;
            };

            let request = DnsRequest::new(request_msg.clone(), DnsRequestOptions::default());
            let start = std::time::Instant::now();

            match entry.name_server.send(request).first_answer().await {
                Ok(response) => {
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    self.update_latency(&entry.label, ms);

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
        let mut results = Vec::new();
        for server in &self.config.servers {
            let Some(entry) = self.entries.get(server) else {
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
        for server in &self.config.servers {
            let Some(entry) = self.entries.get(server) else {
                continue;
            };
            let start = std::time::Instant::now();
            if self.probe(entry).await.is_ok() {
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                self.update_latency(&entry.label, ms);
            }
        }
    }

    /// Send a root "." A query to a single upstream and return on success.
    /// The root query always gets a valid response from any recursive resolver,
    /// making it a reliable liveness check.
    async fn probe(&self, entry: &UpstreamEntry) -> Result<(), ()> {
        let name = Name::root();
        let mut msg = Message::new();
        msg.set_id(rand::random::<u16>());
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(name, RecordType::A));

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

    fn make_forwarder(strategy: UpstreamStrategy) -> UpstreamForwarder {
        // Use real-looking IP:port so NameServer construction succeeds; tests
        // here only exercise ordering and EMA, never actually send.
        let config = UpstreamConfig {
            servers: vec![
                "10.0.0.1:53".into(),
                "10.0.0.2:53".into(),
                "10.0.0.3:53".into(),
            ],
            timeout_ms: 1000,
        };
        let f = UpstreamForwarder::new(config);
        f.set_strategy(strategy);
        f
    }

    #[test]
    fn test_sequential_order() {
        let f = make_forwarder(UpstreamStrategy::Sequential);
        let order = f.server_order();
        assert_eq!(order, vec!["10.0.0.1:53", "10.0.0.2:53", "10.0.0.3:53"]);
    }

    #[test]
    fn test_round_robin_rotates() {
        let f = make_forwarder(UpstreamStrategy::RoundRobin);
        let order1 = f.server_order();
        assert_eq!(order1, vec!["10.0.0.1:53", "10.0.0.2:53", "10.0.0.3:53"]);

        f.rr_counter.fetch_add(1, Ordering::Relaxed);
        let order2 = f.server_order();
        assert_eq!(order2, vec!["10.0.0.2:53", "10.0.0.3:53", "10.0.0.1:53"]);

        f.rr_counter.fetch_add(1, Ordering::Relaxed);
        let order3 = f.server_order();
        assert_eq!(order3, vec!["10.0.0.3:53", "10.0.0.1:53", "10.0.0.2:53"]);
    }

    #[test]
    fn test_lowest_latency_order() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);

        {
            let mut lat = f.latencies.lock().unwrap();
            lat.insert("10.0.0.1:53".into(), 50.0);
            lat.insert("10.0.0.2:53".into(), 10.0);
            lat.insert("10.0.0.3:53".into(), 30.0);
        }

        let order = f.server_order();
        assert_eq!(order, vec!["10.0.0.2:53", "10.0.0.3:53", "10.0.0.1:53"]);
    }

    #[test]
    fn test_lowest_latency_no_data_uses_config_order() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);
        let order = f.server_order();
        assert_eq!(order, vec!["10.0.0.1:53", "10.0.0.2:53", "10.0.0.3:53"]);
    }

    #[test]
    fn test_ema_update() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);

        f.update_latency("10.0.0.1:53", 100.0);
        {
            let lat = f.latencies.lock().unwrap();
            assert!((lat["10.0.0.1:53"] - 100.0).abs() < 0.001);
        }

        // EMA = 0.3 * 40 + 0.7 * 100 = 82.0
        f.update_latency("10.0.0.1:53", 40.0);
        {
            let lat = f.latencies.lock().unwrap();
            assert!((lat["10.0.0.1:53"] - 82.0).abs() < 0.001);
        }
    }

    #[test]
    fn test_set_strategy() {
        let f = make_forwarder(UpstreamStrategy::Sequential);
        assert_eq!(f.strategy(), UpstreamStrategy::Sequential);

        f.set_strategy(UpstreamStrategy::RoundRobin);
        assert_eq!(f.strategy(), UpstreamStrategy::RoundRobin);

        f.set_strategy(UpstreamStrategy::LowestLatency);
        assert_eq!(f.strategy(), UpstreamStrategy::LowestLatency);
    }
}
