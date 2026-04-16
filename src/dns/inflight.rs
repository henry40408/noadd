//! Single-flight coalescing of concurrent cache-miss queries.
//!
//! When N clients simultaneously miss the cache for the same
//! `(domain, query_type)` pair, we want exactly one upstream query — not N
//! identical ones. This module tracks which keys have an in-flight upstream
//! fetch. The first arrival becomes the "fetcher"; subsequent arrivals
//! subscribe to a `Notify` and re-check the cache after the fetcher stores
//! its result.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use crate::cache::CacheKey;

/// Map of cache keys currently being resolved upstream.
#[derive(Default)]
pub struct InflightUpstream {
    pending: Mutex<HashMap<CacheKey, Arc<Notify>>>,
}

/// Outcome of registering interest in a key.
pub enum BeginResult {
    /// We are the first caller for this key. Hold the guard until the
    /// upstream response has been written to the cache; dropping the guard
    /// wakes everyone waiting.
    Fetcher(FetchGuard),
    /// Another task is already fetching this key. Subscribe to this notify
    /// and re-check the cache once it fires.
    Waiter(Arc<Notify>),
}

impl InflightUpstream {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register interest in `key`. At most one caller can hold a
    /// `FetchGuard` for a given key at a time.
    pub fn begin(self: &Arc<Self>, key: &CacheKey) -> BeginResult {
        let mut map = self.pending.lock().unwrap();
        if let Some(notify) = map.get(key) {
            BeginResult::Waiter(notify.clone())
        } else {
            let notify = Arc::new(Notify::new());
            map.insert(key.clone(), notify.clone());
            BeginResult::Fetcher(FetchGuard {
                owner: self.clone(),
                key: key.clone(),
                notify,
            })
        }
    }

    /// Remove a key and notify any waiters. Called by `FetchGuard::drop`.
    fn finish(&self, key: &CacheKey, notify: &Arc<Notify>) {
        {
            let mut map = self.pending.lock().unwrap();
            map.remove(key);
        }
        // Notify *after* dropping the lock so waiters don't wake into
        // contention and so the cache-write (performed before this drop)
        // is observable on their re-check.
        notify.notify_waiters();
    }

    /// Number of in-flight fetches. Exposed for tests.
    #[cfg(test)]
    pub fn inflight_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
}

/// RAII guard held by the caller that is actually doing the upstream
/// fetch. On drop, removes the map entry and notifies waiters — even on
/// panic or early return via `?`, preventing a single bad fetch from
/// permanently wedging coalescing for this key.
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
    use std::time::Duration;

    fn key(s: &str) -> CacheKey {
        (s.to_string(), 1)
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
            _ => panic!(),
        };
        match inflight.begin(&key("a.com")) {
            BeginResult::Waiter(_) => {}
            _ => panic!("second caller should be waiter"),
        }
    }

    #[tokio::test]
    async fn different_keys_are_independent() {
        let inflight = Arc::new(InflightUpstream::new());
        let _g1 = match inflight.begin(&key("a.com")) {
            BeginResult::Fetcher(g) => g,
            _ => panic!(),
        };
        match inflight.begin(&key("b.com")) {
            BeginResult::Fetcher(_g) => {}
            _ => panic!("different key should get its own fetcher slot"),
        }
    }

    #[tokio::test]
    async fn drop_notifies_and_clears() {
        let inflight = Arc::new(InflightUpstream::new());
        let g = match inflight.begin(&key("a.com")) {
            BeginResult::Fetcher(g) => g,
            _ => panic!(),
        };
        let notify = match inflight.begin(&key("a.com")) {
            BeginResult::Waiter(n) => n,
            _ => panic!(),
        };

        // `Notify::notify_waiters` only wakes currently-subscribed waiters,
        // so the test must subscribe before the drop fires. Spawning the
        // drop in a delayed task models the real-world case where the
        // waiter starts awaiting and the fetcher completes later.
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
