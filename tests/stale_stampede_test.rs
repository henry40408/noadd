//! Tests for stale-while-revalidate background refresh deduplication.
//!
//! Verifies that concurrent queries for a stale cache entry produce only
//! a single background upstream refresh, not one per query.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use noadd::cache::{CacheKey, ClientResponseProfile, DnsCache};
use noadd::dns::handler::{DnsHandler, QueryContext};
use noadd::filter::engine::FilterEngine;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

fn make_query_bytes(domain: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new(0xABCD, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut q = Query::new();
    q.set_name(Name::from_str(domain).unwrap());
    q.set_query_type(qtype);
    msg.add_query(q);
    msg.to_vec().unwrap()
}

fn cache_key(domain: &str, qtype: RecordType) -> CacheKey {
    // Mirror the profile the handler derives for `make_query_bytes`: a bare
    // query carries no EDNS/DO/CD, and `UpstreamForwarder` defaults to DNSSEC
    // enabled, so `upstream_dnssec_enabled` is true. A `default()` profile here
    // would key a different entry than the handler looks up and the stale
    // entries these tests plant would never be found.
    CacheKey::new(
        domain.to_lowercase(),
        u16::from(qtype),
        ClientResponseProfile {
            upstream_dnssec_enabled: true,
            ..ClientResponseProfile::default()
        },
    )
}

fn build_mock_response(query_bytes: &[u8], authenticated: bool) -> Vec<u8> {
    let query = Message::from_bytes(query_bytes).unwrap();
    let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = true;
    resp.metadata.recursion_available = true;
    resp.metadata.authentic_data = authenticated;
    for q in &query.queries {
        resp.add_query(q.clone());
    }
    if let Some(q) = query.queries.first() {
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record};
        let record = Record::from_rdata(
            q.name().clone(),
            60,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        );
        resp.add_answer(record);
    }
    resp.to_vec().unwrap()
}

/// Spawn a mock UDP DNS server that counts requests concurrently.
async fn spawn_mock_upstream(delay: Duration) -> (SocketAddr, Arc<AtomicU64>) {
    spawn_mock_upstream_ad(delay, false).await
}

/// Like [`spawn_mock_upstream`] but the mock answers with the given upstream
/// Authenticated Data (AD) verdict, to exercise AD-transparency logging.
async fn spawn_mock_upstream_ad(
    delay: Duration,
    authenticated: bool,
) -> (SocketAddr, Arc<AtomicU64>) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let counter = Arc::new(AtomicU64::new(0));
    let counter_clone = counter.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                break;
            };
            counter_clone.fetch_add(1, Ordering::SeqCst);
            let response_data = build_mock_response(&buf[..len], authenticated);
            let sock = socket.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = sock.send_to(&response_data, src).await;
            });
        }
    });

    (addr, counter)
}

async fn make_test_handler(
    upstream_addr: SocketAddr,
) -> (Arc<DnsHandler>, DnsCache, mpsc::Receiver<QueryContext>) {
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(
        vec![],
        vec![],
        vec![],
    )));
    let cache = DnsCache::new(10_000);
    let config = UpstreamConfig {
        servers: vec![upstream_addr.to_string()],
        timeout_ms: 10_000,
    };
    let forwarder = Arc::new(UpstreamForwarder::new(config).await);
    let (log_tx, log_rx) = mpsc::channel::<QueryContext>(10_000);
    let handler = Arc::new(DnsHandler::new(filter, cache.clone(), forwarder, log_tx));
    (handler, cache, log_rx)
}

/// 50 concurrent queries on a stale entry should produce exactly 1 upstream
/// refresh request, not 50.
#[tokio::test]
async fn test_stale_refresh_is_deduplicated() {
    // The mock delay both holds the coalescing window open and stands in for an
    // upstream's response time. Keep it under hickory's ~333ms UDP retransmit
    // floor (proto's DEFAULT_RETRY_FLOOR): a slower mock makes the transport
    // retransmit a single logical query, inflating the datagram count we assert
    // on. Real upstreams answer in well under 333ms, so they never retransmit.
    let (upstream_addr, upstream_counter) = spawn_mock_upstream(Duration::from_millis(200)).await;

    let (handler, cache, _log_rx) = make_test_handler(upstream_addr).await;

    let domain = "stampede-test.example.com";
    let query_bytes = make_query_bytes(domain, RecordType::A);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // Prime the cache
    let prime_resp = handler.handle(&query_bytes, client_ip, None).await.unwrap();
    assert!(!prime_resp.bytes.is_empty());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(upstream_counter.load(Ordering::SeqCst), 1);

    // Replace with instantly-stale entry
    let cache_key = cache_key(domain, RecordType::A);
    cache
        .insert(cache_key, prime_resp.bytes, Duration::from_millis(1), false)
        .await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    upstream_counter.store(0, Ordering::SeqCst);

    // Fire 50 concurrent queries — all will see stale data
    let n: usize = 50;
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let h = handler.clone();
        let q = query_bytes.clone();
        handles.push(tokio::spawn(async move {
            h.handle(&q, IpAddr::V4(Ipv4Addr::LOCALHOST), None)
                .await
                .unwrap()
        }));
    }

    for handle in handles {
        let resp = handle.await.unwrap();
        assert!(!resp.bytes.is_empty());
    }

    // Wait for background tasks to reach upstream
    tokio::time::sleep(Duration::from_millis(500)).await;

    let refresh_count = upstream_counter.load(Ordering::SeqCst);

    println!("Concurrent queries: {n}, upstream requests: {refresh_count}");

    assert_eq!(
        refresh_count, 1,
        "Expected exactly 1 deduplicated upstream refresh, got {refresh_count}"
    );
}

/// After the in-flight refresh completes, a new stale request should be able
/// to trigger another refresh (the lock is released).
#[tokio::test]
async fn test_refresh_lock_released_after_completion() {
    let (upstream_addr, upstream_counter) = spawn_mock_upstream(Duration::from_millis(100)).await;

    let (handler, cache, _log_rx) = make_test_handler(upstream_addr).await;

    let domain = "relock-test.example.com";
    let query_bytes = make_query_bytes(domain, RecordType::A);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // Prime
    let prime_resp = handler.handle(&query_bytes, client_ip, None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(upstream_counter.load(Ordering::SeqCst), 1);

    // Round 1: make stale, query once → triggers refresh
    let cache_key = cache_key(domain, RecordType::A);
    cache
        .insert(
            cache_key.clone(),
            prime_resp.bytes.clone(),
            Duration::from_millis(1),
            false,
        )
        .await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    upstream_counter.store(0, Ordering::SeqCst);

    handler.handle(&query_bytes, client_ip, None).await.unwrap();

    // Wait for refresh to complete
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        upstream_counter.load(Ordering::SeqCst),
        1,
        "round 1 should produce 1 refresh"
    );

    // Round 2: make stale again, query once → should trigger a NEW refresh
    cache
        .insert(cache_key, prime_resp.bytes, Duration::from_millis(1), false)
        .await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    upstream_counter.store(0, Ordering::SeqCst);

    handler.handle(&query_bytes, client_ip, None).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        upstream_counter.load(Ordering::SeqCst),
        1,
        "round 2 should also trigger a refresh (lock was released)"
    );
}

/// Different domains should refresh independently (no cross-key blocking).
#[tokio::test]
async fn test_different_domains_refresh_independently() {
    let (upstream_addr, upstream_counter) = spawn_mock_upstream(Duration::from_secs(1)).await;

    let (handler, cache, _log_rx) = make_test_handler(upstream_addr).await;
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // Prime two different domains
    let domains = ["alpha.example.com", "beta.example.com"];
    let mut primed = Vec::new();
    for domain in &domains {
        let q = make_query_bytes(domain, RecordType::A);
        let resp = handler.handle(&q, client_ip, None).await.unwrap();
        primed.push((domain, q, resp));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    upstream_counter.store(0, Ordering::SeqCst);

    // Make both stale
    for (domain, _, resp) in &primed {
        let key = cache_key(domain, RecordType::A);
        cache
            .insert(key, resp.bytes.clone(), Duration::from_millis(1), false)
            .await;
    }
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Query both concurrently
    let mut handles = Vec::new();
    for (_, q, _) in &primed {
        let h = handler.clone();
        let q = q.clone();
        handles.push(tokio::spawn(async move {
            h.handle(&q, IpAddr::V4(Ipv4Addr::LOCALHOST), None)
                .await
                .unwrap()
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    let count = upstream_counter.load(Ordering::SeqCst);

    assert_eq!(
        count, 2,
        "Two different stale domains should each trigger 1 refresh (total 2), got {count}"
    );
}

/// A client that did not request DNSSEC must not receive the AD bit, yet the
/// query log must still surface the upstream resolver's AD verdict.
#[tokio::test]
async fn test_non_dnssec_client_gets_ad_stripped_but_log_keeps_verdict() {
    let (upstream_addr, _counter) = spawn_mock_upstream_ad(Duration::from_millis(1), true).await;
    let (handler, _cache, mut log_rx) = make_test_handler(upstream_addr).await;

    // Bare query: no EDNS, so the client never advertised DNSSEC (no DO bit).
    let query_bytes = make_query_bytes("ad-transparency.example.com", RecordType::A);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let outcome = handler.handle(&query_bytes, client_ip, None).await.unwrap();

    // The wire response to this plain client must have the AD bit cleared
    // (byte 3, bit 0x20) even though the upstream set it.
    assert_eq!(
        outcome.bytes[3] & 0x20,
        0,
        "non-DO client must not receive the AD bit"
    );

    // ...but the query log must record the upstream's true AD verdict.
    let ctx = log_rx.try_recv().expect("should receive a log event");
    assert!(
        ctx.authenticated_data,
        "query log must surface the upstream AD verdict for a non-DO client"
    );
}
