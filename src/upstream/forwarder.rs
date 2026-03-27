use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use thiserror::Error;
use tokio::net::UdpSocket;

use super::strategy::UpstreamStrategy;

/// EMA smoothing factor. 0.3 means 30% weight for new observations.
const EMA_ALPHA: f64 = 0.3;

/// Minimal DNS query for "." A record (root), used for health checks and probing.
const ROOT_QUERY: [u8; 17] = [
    0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
];

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
            timeout_ms: 2000,
        }
    }
}

/// Errors that can occur during DNS forwarding.
#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("all upstreams failed")]
    AllFailed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Forwards DNS queries to upstream servers with configurable strategy.
pub struct UpstreamForwarder {
    config: UpstreamConfig,
    strategy: ArcSwap<UpstreamStrategy>,
    rr_counter: AtomicUsize,
    latencies: Mutex<HashMap<String, f64>>,
}

impl UpstreamForwarder {
    /// Create a new forwarder with the given configuration.
    pub fn new(config: UpstreamConfig) -> Self {
        Self {
            config,
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
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let servers = self.server_order();

        // For round-robin, increment counter after determining order
        if self.strategy() == UpstreamStrategy::RoundRobin {
            self.rr_counter.fetch_add(1, Ordering::Relaxed);
        }

        for server in &servers {
            let start = std::time::Instant::now();
            match self.try_forward(server, query_bytes, timeout).await {
                Ok(response) => {
                    let ms = start.elapsed().as_secs_f64() * 1000.0;
                    self.update_latency(server, ms);
                    return Ok((response, server.clone()));
                }
                Err(_) => continue,
            }
        }

        Err(ForwardError::AllFailed)
    }

    /// Attempt to forward a query to a single upstream server.
    async fn try_forward(
        &self,
        server: &str,
        query_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, ForwardError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(server).await?;
        socket.send(query_bytes).await?;

        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| ForwardError::AllFailed)??;

        Ok(buf[..len].to_vec())
    }

    /// Health check all configured upstream servers.
    /// Returns a list of (server, status, latency_ms).
    pub async fn health_check(&self) -> Vec<(String, bool, u64)> {
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let mut results = Vec::new();

        for server in &self.config.servers {
            let start = std::time::Instant::now();
            let ok = self.try_forward(server, &ROOT_QUERY, timeout).await.is_ok();
            let ms = start.elapsed().as_millis() as u64;
            results.push((server.clone(), ok, ms));
        }

        results
    }

    /// Probe all servers and update EMA latencies. Used by background task.
    pub async fn probe_all(&self) {
        let timeout = Duration::from_millis(self.config.timeout_ms);

        for server in &self.config.servers {
            let start = std::time::Instant::now();
            if self.try_forward(server, &ROOT_QUERY, timeout).await.is_ok() {
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                self.update_latency(server, ms);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_forwarder(strategy: UpstreamStrategy) -> UpstreamForwarder {
        let config = UpstreamConfig {
            servers: vec!["a:53".into(), "b:53".into(), "c:53".into()],
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
        assert_eq!(order, vec!["a:53", "b:53", "c:53"]);
    }

    #[test]
    fn test_round_robin_rotates() {
        let f = make_forwarder(UpstreamStrategy::RoundRobin);
        let order1 = f.server_order();
        assert_eq!(order1, vec!["a:53", "b:53", "c:53"]);

        f.rr_counter.fetch_add(1, Ordering::Relaxed);
        let order2 = f.server_order();
        assert_eq!(order2, vec!["b:53", "c:53", "a:53"]);

        f.rr_counter.fetch_add(1, Ordering::Relaxed);
        let order3 = f.server_order();
        assert_eq!(order3, vec!["c:53", "a:53", "b:53"]);
    }

    #[test]
    fn test_lowest_latency_order() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);

        {
            let mut lat = f.latencies.lock().unwrap();
            lat.insert("a:53".into(), 50.0);
            lat.insert("b:53".into(), 10.0);
            lat.insert("c:53".into(), 30.0);
        }

        let order = f.server_order();
        assert_eq!(order, vec!["b:53", "c:53", "a:53"]);
    }

    #[test]
    fn test_lowest_latency_no_data_uses_config_order() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);
        let order = f.server_order();
        assert_eq!(order, vec!["a:53", "b:53", "c:53"]);
    }

    #[test]
    fn test_ema_update() {
        let f = make_forwarder(UpstreamStrategy::LowestLatency);

        f.update_latency("a:53", 100.0);
        {
            let lat = f.latencies.lock().unwrap();
            assert!((lat["a:53"] - 100.0).abs() < 0.001);
        }

        // EMA = 0.3 * 40 + 0.7 * 100 = 82.0
        f.update_latency("a:53", 40.0);
        {
            let lat = f.latencies.lock().unwrap();
            assert!((lat["a:53"] - 82.0).abs() < 0.001);
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
