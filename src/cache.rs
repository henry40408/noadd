use std::time::Duration;

use moka::Expiry;
use moka::future::Cache;
use moka::policy::EvictionPolicy;

/// Cache key: (domain name, DNS record type as u16)
pub type CacheKey = (String, u16);

/// Cache value: raw DNS response bytes + per-entry TTL.
#[derive(Clone)]
pub struct CacheValue {
    pub bytes: Vec<u8>,
    pub ttl: Duration,
}

/// Per-entry expiry that uses each entry's upstream DNS TTL.
struct DnsCacheExpiry;

impl Expiry<CacheKey, CacheValue> for DnsCacheExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CacheValue,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

/// Per-entry TTL DNS response cache backed by moka.
///
/// Stores raw DNS response bytes keyed by (domain, record_type).
/// Each entry expires according to the upstream DNS TTL.
#[derive(Clone)]
pub struct DnsCache {
    cache: Cache<CacheKey, CacheValue>,
}

impl DnsCache {
    /// Create a new cache with the given maximum entry capacity.
    ///
    /// Each entry uses its own TTL from the upstream DNS response.
    pub fn new(max_capacity: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .eviction_policy(EvictionPolicy::lru())
            .expire_after(DnsCacheExpiry)
            .build();

        Self { cache }
    }

    /// Get cached DNS response bytes for a given domain + record type.
    ///
    /// Returns `None` on cache miss or if the entry has expired.
    pub async fn get(&self, key: &CacheKey) -> Option<CacheValue> {
        self.cache.get(key).await
    }

    /// Cache a DNS response with the given TTL.
    pub async fn insert(&self, key: CacheKey, bytes: Vec<u8>, ttl: Duration) {
        self.cache.insert(key, CacheValue { bytes, ttl }).await;
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
    }

    #[tokio::test]
    async fn test_expired_entry_not_returned() {
        let cache = DnsCache::new(100);
        let key = ("expire.test".to_string(), 1);

        cache
            .insert(key.clone(), vec![1], Duration::from_millis(1))
            .await;

        // Wait for expiry + moka housekeeping
        tokio::time::sleep(Duration::from_millis(100)).await;
        cache.cache.run_pending_tasks().await;

        assert!(cache.get(&key).await.is_none());
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
        let cache = DnsCache::new(100);
        let key_short = ("short.test".to_string(), 1);
        let key_long = ("long.test".to_string(), 1);

        cache
            .insert(key_short.clone(), vec![1], Duration::from_millis(1))
            .await;
        cache
            .insert(key_long.clone(), vec![2], Duration::from_secs(300))
            .await;

        tokio::time::sleep(Duration::from_millis(100)).await;
        cache.cache.run_pending_tasks().await;

        // Short TTL entry should be gone
        assert!(cache.get(&key_short).await.is_none());
        // Long TTL entry should still exist
        assert!(cache.get(&key_long).await.is_some());
    }
}
