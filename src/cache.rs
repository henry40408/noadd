use std::time::{Duration, Instant};

use moka::future::Cache;
use moka::policy::EvictionPolicy;

/// Cache key: (domain name, DNS record type as u16)
pub type CacheKey = (String, u16);

/// Cache value: raw DNS response bytes + TTL metadata for optimistic serving.
#[derive(Clone)]
pub struct CacheValue {
    pub bytes: Vec<u8>,
    /// The original upstream TTL.
    pub ttl: Duration,
    /// When this entry was inserted.
    inserted_at: Instant,
}

impl CacheValue {
    /// Whether the entry's original TTL has elapsed (stale but still usable).
    pub fn is_stale(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
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
        if entry.inserted_at.elapsed() > entry.ttl + self.stale_window {
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
                    bytes,
                    ttl,
                    inserted_at: Instant::now(),
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
        assert_eq!(result.bytes, data);
        assert_eq!(result.ttl, Duration::from_secs(60));
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
}
