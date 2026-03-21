use std::time::Duration;

use thiserror::Error;
use tokio::net::UdpSocket;

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

/// Forwards DNS queries to upstream servers with failover support.
///
/// Works with raw DNS wire-format bytes. The caller is responsible for
/// parsing and serializing DNS messages.
pub struct UpstreamForwarder {
    config: UpstreamConfig,
}

impl UpstreamForwarder {
    /// Create a new forwarder with the given configuration.
    pub fn new(config: UpstreamConfig) -> Self {
        Self { config }
    }

    /// Forward a DNS query, trying each upstream in order until one succeeds.
    ///
    /// Returns `(response_bytes, upstream_address)` on success. The upstream
    /// address string identifies which server responded, useful for logging.
    pub async fn forward(&self, query_bytes: &[u8]) -> Result<(Vec<u8>, String), ForwardError> {
        let timeout = Duration::from_millis(self.config.timeout_ms);

        for server in &self.config.servers {
            match self.try_forward(server, query_bytes, timeout).await {
                Ok(response) => return Ok((response, server.clone())),
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
        // Minimal DNS query for "." A record (root)
        let query: [u8; 17] = [
            0x00, 0x01, // ID
            0x01, 0x00, // Flags: standard query, recursion desired
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
            0x00,       // root domain (empty label)
            0x00, 0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN
        ];

        let timeout = Duration::from_millis(self.config.timeout_ms);
        let mut results = Vec::new();

        for server in &self.config.servers {
            let start = std::time::Instant::now();
            let ok = self.try_forward(server, &query, timeout).await.is_ok();
            let ms = start.elapsed().as_millis() as u64;
            results.push((server.clone(), ok, ms));
        }

        results
    }
}
