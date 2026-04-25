//! Throughput measurement for the cache-hit fast path. Not an assertion —
//! meant to be run manually to compare the prepare_cached_response cost
//! across implementations:
//!
//!   cargo nextest run --no-capture --release \
//!     --run-ignored only cache_hit_bench
//!
//! Pre-populates the cache with N (domain, qtype) entries via real upstream
//! lookups on a UDP mock, then issues M concurrent queries that all hit the
//! cache. Cold-miss + upstream cost is amortised in warmup so the timed phase
//! reflects only filter check + cache.get + prepare_cached_response + logger
//! send. Defaults: 64 workers × 2000 cache-hit queries each.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use noadd::cache::DnsCache;
use noadd::dns::handler::{DnsHandler, QueryContext};
use noadd::filter::engine::FilterEngine;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

fn make_query_bytes(domain: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0xBEEF);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_str(domain).unwrap());
    q.set_query_type(qtype);
    msg.add_query(q);
    msg.to_vec().unwrap()
}

fn build_mock_response(query_bytes: &[u8]) -> Vec<u8> {
    let query = Message::from_bytes(query_bytes).unwrap();
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_desired(true);
    resp.set_recursion_available(true);
    for q in query.queries() {
        resp.add_query(q.clone());
    }
    if let Some(q) = query.queries().first() {
        // Three answer records to make the parse + reencode in the legacy
        // decrement_ttl path non-trivial — single-record responses are too
        // small for the patched-bytes cache to show measurable effect.
        for octet in [10, 20, 30] {
            resp.add_answer(Record::from_rdata(
                q.name().clone(),
                300,
                RData::A(A(Ipv4Addr::new(203, 0, 113, octet))),
            ));
        }
    }
    resp.to_vec().unwrap()
}

async fn spawn_mock_upstream() -> SocketAddr {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => break,
            };
            let response_data = build_mock_response(&buf[..len]);
            let _ = socket.send_to(&response_data, src).await;
        }
    });
    addr
}

async fn make_test_handler(addr: SocketAddr) -> Arc<DnsHandler> {
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![])));
    let cache = DnsCache::new(100_000);
    let forwarder = Arc::new(
        UpstreamForwarder::new(UpstreamConfig {
            servers: vec![addr.to_string()],
            timeout_ms: 5_000,
        })
        .await,
    );
    let (tx, _rx) = mpsc::channel::<QueryContext>(100_000);
    Arc::new(DnsHandler::new(filter, cache, forwarder, tx))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn cache_hit_bench() {
    let n_keys: usize = std::env::var("BENCH_KEYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let n_workers: usize = std::env::var("BENCH_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let per_worker: usize = std::env::var("BENCH_PER_WORKER")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    let total = n_workers * per_worker;

    let upstream_addr = spawn_mock_upstream().await;
    let handler = make_test_handler(upstream_addr).await;
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // Warm cache by issuing one query per key. After this loop every
    // subsequent handle() for these keys is a pure cache hit.
    let domains: Vec<String> = (0..n_keys)
        .map(|i| format!("hit-{i}.bench.example.com"))
        .collect();
    for d in &domains {
        let q = make_query_bytes(d, RecordType::A);
        handler.handle(&q, client_ip, None).await.unwrap();
    }

    // Build the per-worker query lists so cycling cost doesn't pollute
    // the inner loop's timing.
    let queries: Vec<Vec<u8>> = domains
        .iter()
        .map(|d| make_query_bytes(d, RecordType::A))
        .collect();

    let started = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let start_gate = Arc::new(tokio::sync::Notify::new());
    let queries = Arc::new(queries);
    let mut handles = Vec::with_capacity(n_workers);
    for _ in 0..n_workers {
        let h = handler.clone();
        let qs = queries.clone();
        let started = started.clone();
        let gate = start_gate.clone();
        handles.push(tokio::spawn(async move {
            started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            gate.notified().await;
            for i in 0..per_worker {
                let q = &qs[i % qs.len()];
                h.handle(q, client_ip, None).await.unwrap();
            }
        }));
    }

    while started.load(std::sync::atomic::Ordering::SeqCst) < n_workers as u64 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let t0 = Instant::now();
    start_gate.notify_waiters();
    for h in handles {
        h.await.unwrap();
    }
    let elapsed = t0.elapsed();

    eprintln!(
        "cache_hit_bench: {n_workers} workers × {per_worker} hits = {total} total over {n_keys} keys"
    );
    eprintln!("  elapsed = {elapsed:?}");
    eprintln!(
        "  aggregate qps = {:.0}",
        total as f64 / elapsed.as_secs_f64()
    );
    eprintln!(
        "  per-hit (avg, n_workers parallel) = {:.2} us",
        elapsed.as_micros() as f64 / per_worker as f64
    );
}
