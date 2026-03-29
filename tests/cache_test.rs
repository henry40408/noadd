use std::time::Duration;

use noadd::cache::{CacheKey, DnsCache};

#[tokio::test]
async fn test_cache_miss_returns_none() {
    let cache = DnsCache::new(100);
    let key: CacheKey = ("example.com".to_string(), 1); // A record
    assert!(cache.get(&key).await.is_none());
}

#[tokio::test]
async fn test_cache_insert_and_get() {
    let cache = DnsCache::new(100);
    let key: CacheKey = ("example.com".to_string(), 1);
    let response = vec![0xDE, 0xAD, 0xBE, 0xEF];

    cache
        .insert(key.clone(), response.clone(), Duration::from_secs(60))
        .await;

    let cached = cache.get(&key).await;
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().bytes, response);
}

#[tokio::test]
async fn test_cache_invalidate_all() {
    let cache = DnsCache::new(100);

    let key_a: CacheKey = ("example.com".to_string(), 1);
    let key_aaaa: CacheKey = ("example.com".to_string(), 28);

    cache
        .insert(key_a.clone(), vec![1, 2, 3], Duration::from_secs(60))
        .await;
    cache
        .insert(key_aaaa.clone(), vec![4, 5, 6], Duration::from_secs(60))
        .await;

    // Both entries should be present
    assert!(cache.get(&key_a).await.is_some());
    assert!(cache.get(&key_aaaa).await.is_some());

    cache.invalidate_all();

    // Both entries should be gone
    assert!(cache.get(&key_a).await.is_none());
    assert!(cache.get(&key_aaaa).await.is_none());
}
