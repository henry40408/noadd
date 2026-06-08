use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::broadcast;

/// Supervise a DNS listener so a fatal failure brings the whole process down.
///
/// The UDP/TCP listeners run in their own tasks; without supervision a bind or
/// accept-loop failure would only end that task, leaving the HTTP/DoH server
/// happily serving with dead plain-DNS — and the container's health check still
/// green. On error this records the failure (so `main` can exit non-zero) and
/// broadcasts a shutdown so the HTTP server and background tasks wind down
/// gracefully. `name` labels the listener in the log.
pub async fn supervise_listener<F>(
    name: &'static str,
    listener: F,
    shutdown: broadcast::Sender<()>,
    failed: Arc<AtomicBool>,
) where
    F: Future<Output = std::io::Result<()>>,
{
    if let Err(e) = listener.await {
        tracing::error!(error = %e, "{name} DNS listener failed; shutting down");
        failed.store(true, Ordering::Relaxed);
        let _ = shutdown.send(());
    }
}

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

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

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

    #[tokio::test]
    async fn test_supervise_listener_broadcasts_and_flags_on_failure() {
        let (tx, mut rx) = broadcast::channel::<()>(1);
        let failed = Arc::new(AtomicBool::new(false));

        supervise_listener(
            "TEST",
            async {
                Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "address in use",
                ))
            },
            tx.clone(),
            failed.clone(),
        )
        .await;

        assert!(failed.load(Ordering::Relaxed), "failure flag should be set");
        assert!(rx.try_recv().is_ok(), "shutdown should be broadcast");
    }

    #[tokio::test]
    async fn test_supervise_listener_quiet_on_success() {
        let (tx, mut rx) = broadcast::channel::<()>(1);
        let failed = Arc::new(AtomicBool::new(false));

        supervise_listener("TEST", async { Ok(()) }, tx.clone(), failed.clone()).await;

        assert!(
            !failed.load(Ordering::Relaxed),
            "failure flag must stay clear on clean exit"
        );
        assert!(
            rx.try_recv().is_err(),
            "no shutdown should be broadcast on clean exit"
        );
    }
}
