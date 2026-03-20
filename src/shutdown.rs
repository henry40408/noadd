use tokio::sync::broadcast;

/// Create a shutdown signal handler.
///
/// Returns a broadcast sender and a future that completes when a shutdown
/// signal (SIGTERM/SIGINT on Unix, Ctrl+C on other platforms) is received.
/// When the signal fires, a message is sent on the broadcast channel so
/// that all receivers can initiate graceful shutdown.
pub fn shutdown_signal() -> (broadcast::Sender<()>, impl std::future::Future<Output = ()>) {
    let (tx, _rx) = broadcast::channel::<()>(1);
    let tx_clone = tx.clone();

    let future = async move {
        listen_for_signal().await;
        let _ = tx_clone.send(());
    };

    (tx, future)
}

#[cfg(unix)]
async fn listen_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm =
        signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint =
        signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM, initiating shutdown");
        }
        _ = sigint.recv() => {
            tracing::info!("received SIGINT, initiating shutdown");
        }
    }
}

#[cfg(not(unix))]
async fn listen_for_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl_c");
    tracing::info!("received Ctrl+C, initiating shutdown");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown_signal_returns_sender() {
        let (tx, _future) = shutdown_signal();
        // Verify we can subscribe to the sender
        let mut rx = tx.subscribe();
        // Manually send a shutdown signal
        tx.send(()).unwrap();
        let result = rx.recv().await;
        assert!(result.is_ok());
    }
}
