use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info};

use super::handler::DnsHandler;

/// Run the TCP DNS listener per RFC 1035 Section 4.2.2 (length-prefixed messages)
/// with connection reuse per RFC 7766.
pub async fn run_tcp_listener(addr: SocketAddr, handler: Arc<DnsHandler>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("TCP DNS listener started on {addr}");

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                debug!("TCP accept error: {e}");
                continue;
            }
        };

        let handler = Arc::clone(&handler);

        tokio::spawn(async move {
            let (mut reader, mut writer) = stream.into_split();
            let client_ip = peer_addr.ip();

            loop {
                // 1. Read 2-byte big-endian length prefix
                let len = match reader.read_u16().await {
                    Ok(len) => len as usize,
                    Err(_) => break, // EOF or error — close connection
                };

                if len == 0 {
                    break;
                }

                // 2. Read the DNS message
                let mut buf = vec![0u8; len];
                if let Err(e) = reader.read_exact(&mut buf).await {
                    debug!("TCP read error from {peer_addr}: {e}");
                    break;
                }

                // 3. Handle the query
                match handler.handle(&buf, client_ip, None).await {
                    Ok(response) => {
                        // 4. Write 2-byte length prefix + response
                        let resp_len = response.len() as u16;
                        if let Err(e) = writer.write_u16(resp_len).await {
                            debug!("TCP write length error for {peer_addr}: {e}");
                            break;
                        }
                        if let Err(e) = writer.write_all(&response).await {
                            debug!("TCP write response error for {peer_addr}: {e}");
                            break;
                        }
                        if let Err(e) = writer.flush().await {
                            debug!("TCP flush error for {peer_addr}: {e}");
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("DNS handler error for TCP query from {peer_addr}: {e}");
                        break;
                    }
                }
            }
        });
    }
}
