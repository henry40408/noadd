use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinHandle;

use crate::now_unix;

/// Rows of history behind the status channel.
///
/// A rebuild publishes two messages — one as it starts, one as it ends — and
/// nothing else uses the channel, so this only has to cover a client stalled
/// across several consecutive rebuilds. A client that falls further behind is
/// answered with the live state rather than the messages it missed.
const STATUS_CHANNEL_CAPACITY: usize = 16;

pub struct RebuildCoordinator {
    lock: Mutex<()>,
    state: Arc<RebuildState>,
    status: broadcast::Sender<RebuildStatus>,
}

#[derive(Default)]
pub struct RebuildState {
    pub rebuilding: AtomicBool,
    pub started_at: AtomicI64,
    pub last_duration_ms: AtomicU64,
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
/// The same shape the admin UI's banner reads, and the only one: the atomics
/// above are the fact, this is how it travels, and there is no third spelling
/// of it in the admin layer to drift from either.
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
            state: Arc::new(RebuildState::default()),
            status,
        })
    }

    pub fn state(&self) -> Arc<RebuildState> {
        self.state.clone()
    }

    /// The state right now, for a caller that has just connected and cannot
    /// wait for the next transition to learn what is happening.
    pub fn status(&self) -> RebuildStatus {
        self.state.snapshot()
    }

    /// Both edges of every rebuild: `rebuilding` true as one starts, false as
    /// it ends. Two messages per rebuild rather than a reading on a timer,
    /// because a rebuild that starts and finishes between two ticks of a clock
    /// is one the operator would never see.
    pub fn subscribe(&self) -> broadcast::Receiver<RebuildStatus> {
        self.status.subscribe()
    }

    /// A send with no subscribers is not an error: it means no admin page is
    /// open, which is the appliance's normal state.
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
        tokio::spawn(async move {
            let _guard = self.lock.lock().await;
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
            // Published after the flag clears and the duration lands, so a
            // subscriber never sees a completion whose numbers are still the
            // previous rebuild's.
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
