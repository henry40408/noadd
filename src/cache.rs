use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::future::Cache;
use moka::policy::EvictionPolicy;

/// Client capabilities that affect the DNS wire response.
///
/// noadd caches encoded responses, not semantic `RRsets`, so responses for
/// clients with different EDNS / DNSSEC profiles must never share an entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ClientResponseProfile {
    pub has_edns: bool,
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
    /// Upstream DO-forcing policy captured when handling the request. This
    /// prevents an in-flight request from the old policy generation from
    /// repopulating a cache entry used after a runtime toggle.
    pub upstream_dnssec_enabled: bool,
}

/// Cache key for a client-ready DNS wire response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub domain: String,
    pub query_type: u16,
    pub response_profile: ClientResponseProfile,
}

impl CacheKey {
    pub fn new(domain: String, query_type: u16, response_profile: ClientResponseProfile) -> Self {
        Self {
            domain,
            query_type,
            response_profile,
        }
    }
}

/// Cache value: raw DNS response bytes + TTL metadata for optimistic serving.
///
/// Backed by an `Arc<Inner>` so the clone `cache.get()` hands back is a
/// refcount bump rather than a copy of the response.
#[derive(Clone)]
pub struct CacheValue {
    inner: Arc<CacheValueInner>,
}

struct CacheValueInner {
    /// A `Box<[u8]>` rather than a `Vec<u8>`: a cached response never grows, so
    /// the capacity field buys nothing and the spare capacity costs real
    /// resident memory. `Message::to_vec` hands back a buffer reserved at 512
    /// bytes whatever the answer's size, and a typical A response is under 100
    /// — the shrink at insert is what stops the cache holding that difference
    /// for every entry.
    bytes: Box<[u8]>,
    ttl: Duration,
    inserted_at: Instant,
    /// Upstream resolver's Authenticated Data verdict for this answer, captured
    /// before the response was tailored to any client. Stored separately from
    /// `bytes` because a non-DO client's cached wire response has the AD bit
    /// stripped, yet the query log must still surface the upstream verdict.
    authenticated_data: bool,
    /// Where the decrementable TTL fields sit inside `bytes`, found once here
    /// so serving the entry never has to parse it again. A typical answer has
    /// one to three records, so this is a handful of bytes against the second
    /// full copy of the response it replaces.
    ttl_offsets: Box<[u32]>,
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

    /// Upstream resolver's AD verdict for this cached answer.
    pub fn authenticated_data(&self) -> bool {
        self.inner.authenticated_data
    }

    /// Offsets of the TTL fields inside [`bytes`](Self::bytes), for
    /// `dns::ttl::apply_elapsed` to rewrite on a copy of them.
    pub fn ttl_offsets(&self) -> &[u32] {
        &self.inner.ttl_offsets
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
        if entry.inner.inserted_at.elapsed() > entry.inner.ttl + self.stale_window {
            self.cache.invalidate(key).await;
            return None;
        }
        Some(entry)
    }

    /// Cache a DNS response with the given TTL and upstream AD verdict.
    pub async fn insert(
        &self,
        key: CacheKey,
        bytes: Vec<u8>,
        ttl: Duration,
        authenticated_data: bool,
    ) {
        let ttl_offsets = crate::dns::ttl::ttl_offsets(&bytes);
        self.cache
            .insert(
                key,
                CacheValue {
                    inner: Arc::new(CacheValueInner {
                        bytes: bytes.into_boxed_slice(),
                        ttl,
                        inserted_at: Instant::now(),
                        authenticated_data,
                        ttl_offsets,
                    }),
                },
            )
            .await;
    }

    /// Invalidate all cached entries (called when filter rules change).
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Drain moka's write buffer so the cache holds exactly the entries that
    /// have been inserted. Only measurement needs this: moka applies writes
    /// asynchronously, so a memory reading taken right after a batch of
    /// inserts would otherwise count the buffer rather than the entries.
    pub async fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(domain: &str, query_type: u16) -> CacheKey {
        CacheKey::new(
            domain.to_string(),
            query_type,
            ClientResponseProfile::default(),
        )
    }

    #[tokio::test]
    async fn test_insert_and_get() {
        let cache = DnsCache::new(100);
        let key = key("example.com", 1);
        let data = vec![1, 2, 3];

        cache
            .insert(key.clone(), data.clone(), Duration::from_secs(60), true)
            .await;

        let result = cache.get(&key).await.unwrap();
        assert_eq!(result.bytes(), data.as_slice());
        assert_eq!(result.ttl(), Duration::from_secs(60));
        assert!(!result.is_stale());
        assert!(
            result.authenticated_data(),
            "AD verdict must round-trip through the cache"
        );
    }

    #[tokio::test]
    async fn test_stale_entry_still_returned() {
        let cache = DnsCache::new(100);
        let key = key("stale.test", 1);

        cache
            .insert(key.clone(), vec![1, 2], Duration::from_millis(1), false)
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
        let key = key("gone.test", 1);

        cache
            .insert(key.clone(), vec![1], Duration::from_millis(1), false)
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
        let key = key("clear.test", 1);

        cache
            .insert(key.clone(), vec![1], Duration::from_secs(300), false)
            .await;

        cache.invalidate_all();
        cache.cache.run_pending_tasks().await;

        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn test_different_ttls_per_entry() {
        let mut cache = DnsCache::new(100);
        cache.stale_window = Duration::from_millis(5);
        let key_short = key("short.test", 1);
        let key_long = key("long.test", 1);

        cache
            .insert(key_short.clone(), vec![1], Duration::from_millis(1), false)
            .await;
        cache
            .insert(key_long.clone(), vec![2], Duration::from_secs(300), false)
            .await;

        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(cache.get(&key_short).await.is_none());
        let long = cache.get(&key_long).await.unwrap();
        assert!(!long.is_stale());
    }

    #[tokio::test]
    async fn ttl_offsets_are_found_when_the_entry_is_inserted() {
        use hickory_proto::op::{Message, MessageType, OpCode};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData, Record};
        use std::str::FromStr;

        let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
        msg.add_answer(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::A(A(std::net::Ipv4Addr::new(203, 0, 113, 1))),
        ));
        let bytes = msg.to_vec().unwrap();

        let cache = DnsCache::new(100);
        let key = key("example.com", 1);
        cache
            .insert(key.clone(), bytes, Duration::from_secs(60), false)
            .await;

        let entry = cache.get(&key).await.unwrap();
        let offsets = entry.ttl_offsets();
        assert_eq!(offsets.len(), 1, "one answer record means one TTL field");

        let at = offsets[0] as usize;
        let stored = u32::from_be_bytes(entry.bytes()[at..at + 4].try_into().unwrap());
        assert_eq!(
            stored, 300,
            "the offset must point at the record's TTL in the cached bytes"
        );
    }

    #[tokio::test]
    async fn a_response_that_is_not_a_dns_message_gets_no_offsets() {
        let cache = DnsCache::new(100);
        let key = key("garbage.test", 1);
        cache
            .insert(
                key.clone(),
                vec![0xab, 0xcd],
                Duration::from_secs(60),
                false,
            )
            .await;

        let entry = cache.get(&key).await.unwrap();
        assert!(
            entry.ttl_offsets().is_empty(),
            "an unwalkable response must serve with its TTLs untouched, not panic"
        );
    }
}
