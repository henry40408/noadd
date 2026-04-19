use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

pub struct RebuildCoordinator {
    lock: Mutex<()>,
    state: Arc<RebuildState>,
}

#[derive(Default)]
pub struct RebuildState {
    pub rebuilding: AtomicBool,
    pub started_at: AtomicI64,
    pub last_completed_at: AtomicI64,
    pub last_duration_ms: AtomicU64,
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl RebuildCoordinator {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            lock: Mutex::new(()),
            state: Arc::new(RebuildState::default()),
        })
    }

    pub fn state(&self) -> Arc<RebuildState> {
        self.state.clone()
    }

    /// Spawn a rebuild-like async task, serialised against any other in-flight
    /// spawn. The closure returns a `Result`; errors are logged but still
    /// reset the state flags.
    pub fn spawn_raw<F, Fut, E>(self: Arc<Self>, f: F) -> JoinHandle<()>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send,
        E: std::fmt::Display + Send + 'static,
    {
        tokio::spawn(async move {
            let _guard = self.lock.lock().await;
            self.state.started_at.store(now_unix(), Ordering::Relaxed);
            self.state.rebuilding.store(true, Ordering::Relaxed);
            let t = Instant::now();
            let result = f().await;
            let duration_ms = t.elapsed().as_millis() as u64;
            self.state
                .last_duration_ms
                .store(duration_ms, Ordering::Relaxed);
            self.state
                .last_completed_at
                .store(now_unix(), Ordering::Relaxed);
            self.state.rebuilding.store(false, Ordering::Relaxed);
            if let Err(e) = result {
                tracing::error!(error = %e, "rebuild task failed");
            }
        })
    }
}
