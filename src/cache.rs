use moka::future::Cache;

/// Cache key: (domain name, DNS record type as u16)
pub type CacheKey = (String, u16);

/// TTL-based DNS response cache backed by moka.
///
/// Stores raw DNS response bytes keyed by (domain, record_type).
/// Uses a global TTL of 300 seconds; entries are evicted automatically.
#[derive(Clone)]
pub struct DnsCache {
    cache: Cache<CacheKey, Vec<u8>>,
}

impl DnsCache {
    /// Create a new cache with the given maximum entry capacity.
    ///
    /// All entries share a global TTL of 300 seconds.
    pub fn new(max_capacity: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(std::time::Duration::from_secs(300))
            .build();

        Self { cache }
    }

    /// Get cached DNS response bytes for a given domain + record type.
    ///
    /// Returns `None` on cache miss or if the entry has expired.
    pub async fn get(&self, key: &CacheKey) -> Option<Vec<u8>> {
        self.cache.get(key).await
    }

    /// Cache a DNS response.
    pub async fn insert(&self, key: CacheKey, response: Vec<u8>) {
        self.cache.insert(key, response).await;
    }

    /// Invalidate all cached entries (called when filter rules change).
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }
}
