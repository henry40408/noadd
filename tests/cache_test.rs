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
    let cache = DnsCache::with_capacity_bytes(64 * 1024 * 1024);
    let key = key("example.com", 1); // A record
    assert!(cache.get(&key).await.is_none());
}

#[tokio::test]
async fn test_cache_insert_and_get() {
    let cache = DnsCache::with_capacity_bytes(64 * 1024 * 1024);
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
    let cache = DnsCache::with_capacity_bytes(64 * 1024 * 1024);
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
    let cache = DnsCache::with_capacity_bytes(64 * 1024 * 1024);

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

    assert!(cache.get(&key_a).await.is_some());
    assert!(cache.get(&key_aaaa).await.is_some());

    cache.invalidate_all();

    assert!(cache.get(&key_a).await.is_none());
    assert!(cache.get(&key_aaaa).await.is_none());
}

/// How many of `n` entries survive when each response is `response_len` bytes
/// and the cache is capped at `cap_bytes`.
///
/// Synthetic response bodies rather than real DNS messages: what is under test
/// is the bound, and a fixed size per entry is what makes the two arms of a
/// comparison differ in exactly one way.
async fn survivors(cap_bytes: u64, n: usize, response_len: usize) -> usize {
    let cache = DnsCache::with_capacity_bytes(cap_bytes);
    let keys: Vec<CacheKey> = (0..n).map(|i| key(&format!("e{i}.test"), 1)).collect();
    for k in &keys {
        cache
            .insert(
                k.clone(),
                vec![0xAB; response_len],
                Duration::from_secs(300),
                false,
            )
            .await;
    }
    cache.run_pending_tasks().await;

    let mut alive = 0;
    for k in &keys {
        if cache.get(k).await.is_some() {
            alive += 1;
        }
    }
    alive
}

/// The cache is bounded by the bytes its entries occupy, not by how many there
/// are. Under an entry-count bound both arms below would hold all 60; under a
/// byte bound the large ones evict each other long before the count is reached.
#[tokio::test]
async fn capacity_is_measured_in_bytes_not_entries() {
    const CAP: u64 = 100_000;
    const N: usize = 60;

    let small = survivors(CAP, N, 20).await;
    assert_eq!(
        small, N,
        "60 tiny responses are nowhere near {CAP} bytes and must all be kept"
    );

    let large = survivors(CAP, N, 8_000).await;
    assert!(
        large < N / 2,
        "60 x 8000-byte responses are five times the {CAP}-byte cap, yet {large} \
         of {N} survived — the bound is not counting bytes"
    );
}

/// A large response costs proportionally more to keep, which is the property
/// that stops one pathological answer holding the space of dozens of ordinary
/// ones.
#[tokio::test]
async fn a_large_response_displaces_more_than_a_small_one() {
    const CAP: u64 = 100_000;

    let small = survivors(CAP, 400, 20).await;
    let large = survivors(CAP, 400, 2_000).await;

    assert!(
        small > large * 3,
        "a 20-byte response should be worth several 2000-byte ones, but {small} \
         small survived against {large} large"
    );
}
