//! Single-flight coalescing of concurrent cache-miss queries.
//!
//! N concurrent misses on one cache key make one upstream query: the first
//! arrival fetches, the rest wait on a `Notify` and re-check the cache after
//! the fetcher stores its result.

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::Notify;

use crate::cache::CacheKey;

/// Cache keys currently being resolved upstream. Sharded (`DashMap`) so
/// different keys do not serialise on one lock.
#[derive(Default)]
pub struct InflightUpstream {
    pending: DashMap<CacheKey, Arc<Notify>>,
}

/// Outcome of registering interest in a key.
pub enum BeginResult {
    /// First caller for this key. Hold the guard until the response is in the
    /// cache; dropping it wakes the waiters.
    Fetcher(FetchGuard),
    /// Another task is fetching. Subscribe, then re-check the cache once it
    /// fires.
    Waiter(Arc<Notify>),
}

impl InflightUpstream {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register interest in `key`; at most one `FetchGuard` exists per key.
    pub fn begin(self: &Arc<Self>, key: &CacheKey) -> BeginResult {
        // `entry()` holds the shard lock, making vacant→insert atomic.
        match self.pending.entry(key.clone()) {
            dashmap::Entry::Occupied(o) => BeginResult::Waiter(o.get().clone()),
            dashmap::Entry::Vacant(v) => {
                let notify = Arc::new(Notify::new());
                v.insert(notify.clone());
                BeginResult::Fetcher(FetchGuard {
                    owner: self.clone(),
                    key: key.clone(),
                    notify,
                })
            }
        }
    }

    /// Remove a key and notify any waiters. Called by `FetchGuard::drop`.
    fn finish(&self, key: &CacheKey, notify: &Arc<Notify>) {
        self.pending.remove(key);
        // Notify after removing the entry, so waiters do not wake into shard
        // contention; the cache write already happened before the guard drop.
        notify.notify_waiters();
    }

    /// Number of in-flight fetches. Exposed for tests.
    #[cfg(test)]
    pub fn inflight_count(&self) -> usize {
        self.pending.len()
    }
}

/// Held by the fetcher. Drop removes the entry and wakes waiters even on panic
/// or early return, so one bad fetch cannot wedge the key.
pub struct FetchGuard {
    owner: Arc<InflightUpstream>,
    key: CacheKey,
    notify: Arc<Notify>,
}

impl Drop for FetchGuard {
    fn drop(&mut self) {
        self.owner.finish(&self.key, &self.notify);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::ClientResponseProfile;
    use std::time::Duration;

    fn key(s: &str) -> CacheKey {
        CacheKey::new(s.to_string(), 1, ClientResponseProfile::default())
    }

    #[tokio::test]
    async fn first_caller_becomes_fetcher() {
        let inflight = Arc::new(InflightUpstream::new());
        let _guard = match inflight.begin(&key("a.com")) {
            BeginResult::Fetcher(g) => g,
            BeginResult::Waiter(_) => panic!("first caller should be fetcher"),
        };
        assert_eq!(inflight.inflight_count(), 1);
    }

    #[tokio::test]
    async fn second_caller_becomes_waiter() {
        let inflight = Arc::new(InflightUpstream::new());
        let _g = match inflight.begin(&key("a.com")) {
            BeginResult::Fetcher(g) => g,
            BeginResult::Waiter(_) => panic!("first caller should be fetcher"),
        };
        match inflight.begin(&key("a.com")) {
            BeginResult::Waiter(_) => {}
            BeginResult::Fetcher(_) => panic!("second caller should be waiter"),
        }
    }

    #[tokio::test]
    async fn different_keys_are_independent() {
        let inflight = Arc::new(InflightUpstream::new());
        let _g1 = match inflight.begin(&key("a.com")) {
            BeginResult::Fetcher(g) => g,
            BeginResult::Waiter(_) => panic!("first caller should be fetcher"),
        };
        match inflight.begin(&key("b.com")) {
            BeginResult::Fetcher(_g) => {}
            BeginResult::Waiter(_) => panic!("different key should get its own fetcher slot"),
        }
    }

    #[tokio::test]
    async fn drop_notifies_and_clears() {
        let inflight = Arc::new(InflightUpstream::new());
        let g = match inflight.begin(&key("a.com")) {
            BeginResult::Fetcher(g) => g,
            BeginResult::Waiter(_) => panic!("first caller should be fetcher"),
        };
        let notify = match inflight.begin(&key("a.com")) {
            BeginResult::Waiter(n) => n,
            BeginResult::Fetcher(_) => panic!("second caller should be waiter"),
        };

        // `notify_waiters` only wakes current subscribers, so drop later.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(g);
        });

        let res = tokio::time::timeout(Duration::from_millis(500), notify.notified()).await;
        assert!(
            res.is_ok(),
            "waiter should have been notified on fetcher drop"
        );
        assert_eq!(inflight.inflight_count(), 0);
    }
}
