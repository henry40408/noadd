use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinHandle;

use crate::now_unix;

/// Status channel backlog: two messages per rebuild, so this covers several
/// rebuilds; a client further behind is answered with the live state.
const STATUS_CHANNEL_CAPACITY: usize = 16;

pub struct RebuildCoordinator {
    lock: Mutex<()>,
    /// A coalescable task is waiting for `lock` and has not read state yet.
    queued: AtomicBool,
    state: Arc<RebuildState>,
    status: broadcast::Sender<RebuildStatus>,
}

#[derive(Default)]
pub struct RebuildState {
    pub rebuilding: AtomicBool,
    pub started_at: AtomicI64,
    pub last_duration_ms: AtomicU64,
    /// The latest rebuild failed, so the live engine may be stale.
    pub last_failed: AtomicBool,
}

impl RebuildState {
    fn snapshot(&self) -> RebuildStatus {
        RebuildStatus {
            rebuilding: self.rebuilding.load(Ordering::Relaxed),
            started_at: self.started_at.load(Ordering::Relaxed),
            last_duration_ms: self.last_duration_ms.load(Ordering::Relaxed),
        }
    }
}

/// What a rebuild is doing at one instant, as pushed to `GET /api/events`.
///
/// The one shape the admin UI's banner reads; the atomics above are the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RebuildStatus {
    pub rebuilding: bool,
    pub started_at: i64,
    pub last_duration_ms: u64,
}

impl RebuildCoordinator {
    pub fn new() -> Arc<Self> {
        let (status, _rx) = broadcast::channel(STATUS_CHANNEL_CAPACITY);
        Arc::new(Self {
            lock: Mutex::new(()),
            queued: AtomicBool::new(false),
            state: Arc::new(RebuildState::default()),
            status,
        })
    }

    pub fn state(&self) -> Arc<RebuildState> {
        self.state.clone()
    }

    /// The current state, for a caller that just connected.
    pub fn status(&self) -> RebuildStatus {
        self.state.snapshot()
    }

    /// Both edges of every rebuild (start and end), not a timed reading, so a
    /// rebuild shorter than a tick is still seen.
    pub fn subscribe(&self) -> broadcast::Receiver<RebuildStatus> {
        self.status.subscribe()
    }

    /// No subscribers is normal (no admin page open), not an error.
    fn publish(&self) {
        let _ = self.status.send(self.state.snapshot());
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
        self.spawn_task(false, f)
    }

    /// Like [`Self::spawn_raw`], for a rebuild that reads the latest state when
    /// it runs: while one such task is still waiting for the lock, another
    /// request adds nothing, so it returns `None`.
    ///
    /// The waiting task clears the flag *before* it reads state, so a request
    /// made after that point queues a new task and is never lost.
    pub fn spawn_coalesced<F, Fut, E>(self: Arc<Self>, f: F) -> Option<JoinHandle<()>>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send,
        E: std::fmt::Display + Send + 'static,
    {
        if self.queued.swap(true, Ordering::AcqRel) {
            return None;
        }
        Some(self.spawn_task(true, f))
    }

    fn spawn_task<F, Fut, E>(self: Arc<Self>, coalesced: bool, f: F) -> JoinHandle<()>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send,
        E: std::fmt::Display + Send + 'static,
    {
        tokio::spawn(async move {
            let _guard = self.lock.lock().await;
            if coalesced {
                // An RMW, so it acquires from a dropped request's `swap` and the
                // state that request wrote is visible to the read below.
                self.queued.swap(false, Ordering::AcqRel);
            }
            self.state.started_at.store(now_unix(), Ordering::Relaxed);
            self.state.rebuilding.store(true, Ordering::Relaxed);
            self.publish();
            let t = Instant::now();
            let result = f().await;
            let duration_ms = t.elapsed().as_millis() as u64;
            self.state
                .last_duration_ms
                .store(duration_ms, Ordering::Relaxed);
            self.state.rebuilding.store(false, Ordering::Relaxed);
            // After the flag and duration update, so a completion never carries
            // the previous rebuild's numbers.
            self.state
                .last_failed
                .store(result.is_err(), Ordering::Relaxed);
            self.publish();
            if let Err(e) = result {
                tracing::warn!(
                    event = "filter.rebuild_failed",
                    error = %e,
                    "rebuild task failed; keeping previous filter"
                );
            }
        })
    }
}
