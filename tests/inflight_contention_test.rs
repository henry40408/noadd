//! Throughput measurement for the inflight-coalescing map under
//! cold-miss stampede. Not an assertion — meant to be run manually
//! against different implementations of `InflightUpstream::pending` to
//! compare contention behavior:
//!
//!   cargo nextest run --no-capture --release inflight_contention
//!
//! Each worker issues N distinct (uncached, unique) queries; the mock
//! upstream replies immediately so the bench is bounded by handler
//! work — primarily the inflight map's begin/end pair, the moka cache,
//! and the logger send.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
        resp.add_answer(Record::from_rdata(
            q.name().clone(),
            60,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 10))),
        ));
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
async fn inflight_contention_bench() {
    let n_workers: usize = std::env::var("BENCH_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let per_worker: usize = std::env::var("BENCH_PER_WORKER")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let total = n_workers * per_worker;

    let upstream_addr = spawn_mock_upstream().await;
    let handler = make_test_handler(upstream_addr).await;
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let started = Arc::new(AtomicU64::new(0));
    let start_gate = Arc::new(tokio::sync::Notify::new());
    let mut handles = Vec::with_capacity(n_workers);
    for w in 0..n_workers {
        let h = handler.clone();
        let started = started.clone();
        let gate = start_gate.clone();
        handles.push(tokio::spawn(async move {
            // Wait at the gate so all workers begin in lockstep — mimics
            // a real concurrency burst rather than a staggered ramp-up.
            started.fetch_add(1, Ordering::SeqCst);
            gate.notified().await;
            for q in 0..per_worker {
                let domain = format!("w{w}-q{q}.bench.example.com");
                let query = make_query_bytes(&domain, RecordType::A);
                h.handle(&query, client_ip, None).await.unwrap();
            }
        }));
    }

    // Wait for all workers to be parked at the gate, then release.
    while started.load(Ordering::SeqCst) < n_workers as u64 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let t0 = Instant::now();
    start_gate.notify_waiters();
    for h in handles {
        h.await.unwrap();
    }
    let elapsed = t0.elapsed();

    eprintln!(
        "inflight_contention_bench: {n_workers} workers × {per_worker} unique queries = {total} total"
    );
    eprintln!("  elapsed = {elapsed:?}");
    eprintln!(
        "  aggregate qps = {:.0}",
        total as f64 / elapsed.as_secs_f64()
    );
}
