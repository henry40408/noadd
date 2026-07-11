use std::time::Duration;

use noadd::cache::{CacheKey, ClientResponseProfile, DnsCache};

fn key(domain: &str, query_type: u16) -> CacheKey {
    CacheKey::new(
        domain.to_string(),
        query_type,
        ClientResponseProfile::default(),
    )
}

#[tokio::test]
async fn test_cache_miss_returns_none() {
    let cache = DnsCache::new(100);
    let key = key("example.com", 1); // A record
    assert!(cache.get(&key).await.is_none());
}

#[tokio::test]
async fn test_cache_insert_and_get() {
    let cache = DnsCache::new(100);
    let key = key("example.com", 1);
    let response = vec![0xDE, 0xAD, 0xBE, 0xEF];

    cache
        .insert(
            key.clone(),
            response.clone(),
            Duration::from_secs(60),
            false,
        )
        .await;

    let cached = cache.get(&key).await;
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().bytes(), response.as_slice());
}

#[tokio::test]
async fn test_cache_distinguishes_client_response_profiles() {
    let cache = DnsCache::new(100);
    let plain = key("example.com", 1);
    let edns = CacheKey::new(
        "example.com".to_string(),
        1,
        ClientResponseProfile {
            has_edns: true,
            dnssec_ok: false,
            checking_disabled: false,
            upstream_dnssec_enabled: false,
        },
    );
    let forced_dnssec = CacheKey::new(
        "example.com".to_string(),
        1,
        ClientResponseProfile {
            upstream_dnssec_enabled: true,
            ..ClientResponseProfile::default()
        },
    );

    cache
        .insert(plain.clone(), vec![0x01], Duration::from_secs(300), false)
        .await;
    cache
        .insert(edns.clone(), vec![0x02], Duration::from_secs(300), false)
        .await;
    cache
        .insert(
            forced_dnssec.clone(),
            vec![0x03],
            Duration::from_secs(300),
            false,
        )
        .await;

    assert_eq!(cache.get(&plain).await.unwrap().bytes(), &[0x01]);
    assert_eq!(cache.get(&edns).await.unwrap().bytes(), &[0x02]);
    assert_eq!(cache.get(&forced_dnssec).await.unwrap().bytes(), &[0x03]);
}

#[tokio::test]
async fn test_cache_invalidate_all() {
    let cache = DnsCache::new(100);

    let key_a = key("example.com", 1);
    let key_aaaa = key("example.com", 28);

    cache
        .insert(key_a.clone(), vec![1, 2, 3], Duration::from_secs(60), false)
        .await;
    cache
        .insert(
            key_aaaa.clone(),
            vec![4, 5, 6],
            Duration::from_secs(60),
            false,
        )
        .await;

    // Both entries should be present
    assert!(cache.get(&key_a).await.is_some());
    assert!(cache.get(&key_aaaa).await.is_some());

    cache.invalidate_all();

    // Both entries should be gone
    assert!(cache.get(&key_a).await.is_none());
    assert!(cache.get(&key_aaaa).await.is_none());
}
