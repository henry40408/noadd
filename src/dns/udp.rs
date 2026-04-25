use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{debug, info};

use super::handler::{DnsHandler, build_servfail};

/// Maximum UDP DNS message size (RFC 6891 recommends 4096 for EDNS, but
/// standard DNS caps at 512; we use 4096 to support EDNS).
const MAX_UDP_SIZE: usize = 4096;

/// Run the UDP DNS listener, handling queries in spawned tasks.
pub async fn run_udp_listener(addr: SocketAddr, handler: Arc<DnsHandler>) -> std::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    info!("UDP DNS listener started on {addr}");

    loop {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(e) => {
                debug!("UDP recv_from error: {e}");
                continue;
            }
        };

        buf.truncate(len);
        let handler = Arc::clone(&handler);
        let socket = Arc::clone(&socket);

        tokio::spawn(async move {
            let response = match handler.handle(&buf, src.ip(), None).await {
                Ok(outcome) => outcome.bytes,
                Err(e) => {
                    debug!("DNS handler error for UDP query from {src}: {e}");
                    build_servfail(&buf)
                }
            };
            if let Err(e) = socket.send_to(&response, src).await {
                debug!("UDP send_to error for {src}: {e}");
            }
        });
    }
}
