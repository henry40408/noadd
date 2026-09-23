use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{debug, info};

use super::handler::{DnsHandler, build_servfail, truncate_for_udp};

/// Receive buffer: 4096 for EDNS (RFC 6891), not the classic 512.
const MAX_UDP_SIZE: usize = 4096;

/// Run the UDP DNS listener, handling queries in spawned tasks.
pub async fn run_udp_listener(addr: SocketAddr, handler: Arc<DnsHandler>) -> std::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    info!(
        event = "dns.listener_started",
        transport = "udp",
        %addr,
        "DNS listener started"
    );

    loop {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(e) => {
                debug!(
                    event = "dns.recv_failed",
                    transport = "udp",
                    error = %e,
                    "failed to receive datagram"
                );
                continue;
            }
        };

        buf.truncate(len);
        let handler = Arc::clone(&handler);
        let socket = Arc::clone(&socket);

        tokio::spawn(async move {
            let response = match handler.handle(&buf, src.ip(), None).await {
                // Truncate (TC) to the client's advertised size, 512 without
                // EDNS, so it retries over TCP.
                Ok(outcome) => truncate_for_udp(&buf, outcome.bytes),
                Err(e) => {
                    debug!(
                        event = "dns.handler_failed",
                        transport = "udp",
                        client = %src,
                        error = %e,
                        "query handler failed; answering SERVFAIL"
                    );
                    build_servfail(&buf)
                }
            };
            if let Err(e) = socket.send_to(&response, src).await {
                debug!(
                    event = "dns.send_failed",
                    transport = "udp",
                    client = %src,
                    error = %e,
                    "failed to send response"
                );
            }
        });
    }
}
