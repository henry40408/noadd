use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info};

use super::handler::{DnsHandler, build_servfail};

/// Run the TCP DNS listener per RFC 1035 Section 4.2.2 (length-prefixed messages)
/// with connection reuse per RFC 7766.
pub async fn run_tcp_listener(addr: SocketAddr, handler: Arc<DnsHandler>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(
        event = "dns.listener_started",
        transport = "tcp",
        %addr,
        "DNS listener started"
    );
    serve_tcp(listener, handler).await
}

/// Serve length-prefixed DNS over an already-bound listener.
///
/// Split out from [`run_tcp_listener`] so tests can bind an ephemeral port,
/// learn its actual address, and then drive the accept loop — avoiding the
/// bind-drop-rebind race a `SocketAddr`-only entry point would force.
pub async fn serve_tcp(listener: TcpListener, handler: Arc<DnsHandler>) -> std::io::Result<()> {
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                debug!(
                    event = "dns.accept_failed",
                    transport = "tcp",
                    error = %e,
                    "failed to accept connection"
                );
                continue;
            }
        };

        let handler = Arc::clone(&handler);

        tokio::spawn(async move {
            let (mut reader, mut writer) = stream.into_split();
            let client_ip = peer_addr.ip();

            while let Ok(len) = reader.read_u16().await {
                let len = len as usize;
                if len == 0 {
                    break;
                }

                // 2. Read the DNS message
                let mut buf = vec![0u8; len];
                if let Err(e) = reader.read_exact(&mut buf).await {
                    debug!(
                        event = "dns.recv_failed",
                        transport = "tcp",
                        client = %peer_addr,
                        error = %e,
                        "failed to read query body"
                    );
                    break;
                }

                // 3. Handle the query
                let response = match handler.handle(&buf, client_ip, None).await {
                    Ok(outcome) => outcome.bytes,
                    Err(e) => {
                        debug!(
                            event = "dns.handler_failed",
                            transport = "tcp",
                            client = %peer_addr,
                            error = %e,
                            "query handler failed; answering SERVFAIL"
                        );
                        build_servfail(&buf)
                    }
                };

                // 4. Write 2-byte length prefix + response
                let resp_len = response.len() as u16;
                if let Err(e) = writer.write_u16(resp_len).await {
                    debug!(
                        event = "dns.send_failed",
                        transport = "tcp",
                        stage = "length_prefix",
                        client = %peer_addr,
                        error = %e,
                        "failed to send response"
                    );
                    break;
                }
                if let Err(e) = writer.write_all(&response).await {
                    debug!(
                        event = "dns.send_failed",
                        transport = "tcp",
                        stage = "body",
                        client = %peer_addr,
                        error = %e,
                        "failed to send response"
                    );
                    break;
                }
                if let Err(e) = writer.flush().await {
                    debug!(
                        event = "dns.send_failed",
                        transport = "tcp",
                        stage = "flush",
                        client = %peer_addr,
                        error = %e,
                        "failed to send response"
                    );
                    break;
                }
            }
        });
    }
}
