use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use moka::future::Cache;
use moka::policy::EvictionPolicy;

/// Cache key: (domain name, DNS record type as u16)
pub type CacheKey = (String, u16);

/// Cache value: raw DNS response bytes + TTL metadata for optimistic serving.
///
/// Backed by an `Arc<Inner>` so clones (one per `cache.get()`) share the
/// patched-bytes cache below — without sharing, every cache hit would
/// recompute the TTL-decremented response from scratch.
#[derive(Clone)]
pub struct CacheValue {
    inner: Arc<CacheValueInner>,
}

struct CacheValueInner {
    bytes: Vec<u8>,
    ttl: Duration,
    inserted_at: Instant,
    /// Snapshot of the TTL-decremented response, valid for one integer
    /// second. Within that second multiple cache hits share the result;
    /// when the second rolls over the next caller recomputes and replaces.
    /// Whole-domain TTLs are integer seconds, so within a second the
    /// decremented bytes are identical and reusing them is safe.
    patched: Mutex<Option<PatchSnapshot>>,
}

struct PatchSnapshot {
    elapsed_secs: u32,
    bytes: Vec<u8>,
}

impl CacheValue {
    /// Original (non-decremented) upstream response bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.inner.bytes
    }

    /// The original upstream TTL.
    pub fn ttl(&self) -> Duration {
        self.inner.ttl
    }

    /// Whether the entry's original TTL has elapsed (stale but still usable).
    pub fn is_stale(&self) -> bool {
        self.inner.inserted_at.elapsed() > self.inner.ttl
    }

    /// How long ago this entry was inserted.
    pub fn elapsed(&self) -> Duration {
        self.inner.inserted_at.elapsed()
    }

    /// Return cached patched bytes if a snapshot exists for this exact
    /// `elapsed_secs`. Caller falls back to recomputing + `store_patched_bytes`
    /// when this returns `None`.
    pub fn try_patched_bytes(&self, elapsed_secs: u32) -> Option<Vec<u8>> {
        let snap = self.inner.patched.lock().unwrap();
        snap.as_ref()
            .filter(|s| s.elapsed_secs == elapsed_secs)
            .map(|s| s.bytes.clone())
    }

    /// Replace the patched-bytes snapshot. Last writer wins; if two callers
    /// race they both produce identical bytes for the same `elapsed_secs`,
    /// so overwriting either is safe.
    pub fn store_patched_bytes(&self, elapsed_secs: u32, bytes: Vec<u8>) {
        let mut snap = self.inner.patched.lock().unwrap();
        *snap = Some(PatchSnapshot {
            elapsed_secs,
            bytes,
        });
    }
}

/// Optimistic DNS response cache backed by moka.
///
/// Entries are kept in moka for up to `ttl + stale_window` (default 5 minutes).
/// When an entry's TTL has expired but is still within the stale window, `get()`
/// returns it with `is_stale() == true`, signaling the caller to serve it
/// immediately while refreshing in the background.
#[derive(Clone)]
pub struct DnsCache {
    cache: Cache<CacheKey, CacheValue>,
    /// How long to keep stale entries beyond their TTL.
    stale_window: Duration,
}

impl DnsCache {
    /// Create a new cache with the given maximum entry capacity.
    pub fn new(max_capacity: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .eviction_policy(EvictionPolicy::lru())
            .build();

        Self {
            cache,
            stale_window: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Get cached DNS response for a given domain + record type.
    ///
    /// Returns the entry even if its TTL has expired (stale), as long as it
    /// is within the stale window. Caller should check `is_stale()` and
    /// trigger a background refresh if true.
    pub async fn get(&self, key: &CacheKey) -> Option<CacheValue> {
        let entry = self.cache.get(key).await?;
        // Evict if beyond stale window
        if entry.inner.inserted_at.elapsed() > entry.inner.ttl + self.stale_window {
            self.cache.invalidate(key).await;
            return None;
        }
        Some(entry)
    }

    /// Cache a DNS response with the given TTL.
    pub async fn insert(&self, key: CacheKey, bytes: Vec<u8>, ttl: Duration) {
        self.cache
            .insert(
                key,
                CacheValue {
                    inner: Arc::new(CacheValueInner {
                        bytes,
                        ttl,
                        inserted_at: Instant::now(),
                        patched: Mutex::new(None),
                    }),
                },
            )
            .await;
    }

    /// Invalidate all cached entries (called when filter rules change).
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_insert_and_get() {
        let cache = DnsCache::new(100);
        let key = ("example.com".to_string(), 1);
        let data = vec![1, 2, 3];

        cache
            .insert(key.clone(), data.clone(), Duration::from_secs(60))
            .await;

        let result = cache.get(&key).await.unwrap();
        assert_eq!(result.bytes(), data.as_slice());
        assert_eq!(result.ttl(), Duration::from_secs(60));
        assert!(!result.is_stale());
    }

    #[tokio::test]
    async fn test_stale_entry_still_returned() {
        let cache = DnsCache::new(100);
        let key = ("stale.test".to_string(), 1);

        cache
            .insert(key.clone(), vec![1, 2], Duration::from_millis(1))
            .await;

        // Wait for TTL to expire but within stale window
        tokio::time::sleep(Duration::from_millis(50)).await;

        let result = cache.get(&key).await;
        assert!(result.is_some(), "stale entry should still be returned");
        assert!(result.unwrap().is_stale(), "entry should be marked stale");
    }

    #[tokio::test]
    async fn test_beyond_stale_window_not_returned() {
        let mut cache = DnsCache::new(100);
        cache.stale_window = Duration::from_millis(10); // very short for testing
        let key = ("gone.test".to_string(), 1);

        cache
            .insert(key.clone(), vec![1], Duration::from_millis(1))
            .await;

        // Wait beyond TTL + stale window
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(
            cache.get(&key).await.is_none(),
            "entry beyond stale window should be gone"
        );
    }

    #[tokio::test]
    async fn test_invalidate_all() {
        let cache = DnsCache::new(100);
        let key = ("clear.test".to_string(), 1);

        cache
            .insert(key.clone(), vec![1], Duration::from_secs(300))
            .await;

        cache.invalidate_all();
        cache.cache.run_pending_tasks().await;

        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn test_different_ttls_per_entry() {
        let mut cache = DnsCache::new(100);
        cache.stale_window = Duration::from_millis(5);
        let key_short = ("short.test".to_string(), 1);
        let key_long = ("long.test".to_string(), 1);

        cache
            .insert(key_short.clone(), vec![1], Duration::from_millis(1))
            .await;
        cache
            .insert(key_long.clone(), vec![2], Duration::from_secs(300))
            .await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Short TTL entry should be gone (beyond stale window)
        assert!(cache.get(&key_short).await.is_none());
        // Long TTL entry should still exist and fresh
        let long = cache.get(&key_long).await.unwrap();
        assert!(!long.is_stale());
    }

    #[tokio::test]
    async fn test_patched_bytes_window_reuse() {
        let cache = DnsCache::new(100);
        let key = ("patched.test".to_string(), 1);
        cache
            .insert(key.clone(), vec![0xab, 0xcd, 0xef], Duration::from_secs(60))
            .await;

        let entry = cache.get(&key).await.unwrap();

        // No snapshot stored yet — first lookup misses.
        assert!(entry.try_patched_bytes(0).is_none());

        entry.store_patched_bytes(0, vec![1, 2, 3]);
        assert_eq!(
            entry.try_patched_bytes(0).as_deref(),
            Some([1, 2, 3].as_slice())
        );

        // Different elapsed_secs window: cache miss.
        assert!(entry.try_patched_bytes(1).is_none());

        // Replacing the snapshot for a new window evicts the old one.
        entry.store_patched_bytes(1, vec![4, 5, 6]);
        assert_eq!(
            entry.try_patched_bytes(1).as_deref(),
            Some([4, 5, 6].as_slice())
        );
        assert!(entry.try_patched_bytes(0).is_none());
    }

    #[tokio::test]
    async fn test_patched_bytes_shared_across_clones() {
        // CacheValue's Arc inner means a clone obtained from a separate
        // cache.get() call must observe the same patched snapshot.
        let cache = DnsCache::new(100);
        let key = ("shared.test".to_string(), 1);
        cache
            .insert(
                key.clone(),
                vec![0xde, 0xad, 0xbe, 0xef],
                Duration::from_secs(60),
            )
            .await;

        let a = cache.get(&key).await.unwrap();
        a.store_patched_bytes(0, vec![9, 9, 9]);

        let b = cache.get(&key).await.unwrap();
        assert_eq!(
            b.try_patched_bytes(0).as_deref(),
            Some([9, 9, 9].as_slice())
        );
    }
}
