//! Per-entry memory of the DNS response cache, run manually:
//!
//!   cargo nextest run --no-capture --release \
//!     --run-ignored only `cache_memory_bench`
//!
//! Fills the cache with a production record-type mix (56% A, 25% AAAA, 19% TXT)
//! and reports live heap bytes and allocations per entry, via a tracking
//! allocator (an integration test does not link `main.rs`'s mimalloc).
//!
//! ⚠️ **Bytes and allocations come from separate fills.** Bytes are measured
//! with responses built inside the window, since the encoder's reservation is
//! part of the entry and the builder's temporaries net out. Allocation counts
//! do not net out, so `allocations_per_entry` builds everything first.
//!
//! Entries are also served once: an entry that grows when read (it once held a
//! second copy of the response) costs that growth for as long as it is hot.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use noadd::cache::{CacheKey, CacheValue, ClientResponseProfile, DnsCache};
use noadd::dns::ttl;

struct TrackingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding an unmodified layout to the system allocator.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: `ptr` and `layout` come from the caller's matching
        // allocation, which is this trait's contract.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarding the caller's own pointer, layout and size.
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
            LIVE_BYTES.fetch_add(new_size, Ordering::Relaxed);
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        new_ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarding an unmodified layout to the system allocator.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }
}

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

#[derive(Clone, Copy)]
struct Counters {
    live_bytes: usize,
    allocs: usize,
}

fn counters() -> Counters {
    Counters {
        live_bytes: LIVE_BYTES.load(Ordering::Relaxed),
        allocs: ALLOC_COUNT.load(Ordering::Relaxed),
    }
}

/// Signed live-byte delta. A phase can free earlier allocations and net
/// negative, hence the wrapping subtract.
fn live_delta(before: Counters, after: Counters) -> isize {
    after.live_bytes.wrapping_sub(before.live_bytes) as isize
}

/// Record-type mix from Cloudflare's published 1.1.1.1 cache distribution.
fn record_type_for(index: usize) -> RecordType {
    match index % 100 {
        0..=55 => RecordType::A,
        56..=80 => RecordType::AAAA,
        _ => RecordType::TXT,
    }
}

/// A realistic upstream answer: the question plus two or three records of the
/// requested type, TXT carrying token-sized strings.
fn build_response(domain: &str, qtype: RecordType, id: u16) -> Vec<u8> {
    let name = Name::from_str(domain).unwrap();
    let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = true;
    resp.metadata.recursion_available = true;

    let mut q = Query::new();
    q.set_name(name.clone());
    q.set_query_type(qtype);
    resp.add_query(q);

    match qtype {
        RecordType::AAAA => {
            for tail in [0x10, 0x20] {
                resp.add_answer(Record::from_rdata(
                    name.clone(),
                    300,
                    RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, tail))),
                ));
            }
        }
        RecordType::TXT => {
            resp.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::TXT(TXT::new(vec![
                    "v=spf1 include:_spf.example.com ~all".to_string(),
                    format!("noadd-verification={id:016x}{id:016x}"),
                ])),
            ));
        }
        _ => {
            for octet in [10, 20, 30] {
                resp.add_answer(Record::from_rdata(
                    name.clone(),
                    300,
                    RData::A(A(Ipv4Addr::new(203, 0, 113, octet))),
                ));
            }
        }
    }
    resp.to_vec().unwrap()
}

fn bench_key(index: usize) -> CacheKey {
    CacheKey::new(
        format!("entry-{index}.bench.example.com"),
        u16::from(record_type_for(index)),
        ClientResponseProfile::default(),
    )
}

/// Small next to the reservation, as in production: `Message::to_vec` reserves
/// 512 bytes for an answer typically under 100.
const PAYLOAD: usize = 64;
/// Exaggerated well past the encoder's 512 so the two measurements cannot be
/// confused.
const SLACK: usize = 64 * 1024;

/// Live bytes retained after storing a `PAYLOAD`-byte response in a buffer
/// reserved at `capacity`, allocated inside the window so the reservation shows.
async fn retained_by_insert(cache: &DnsCache, key: CacheKey, capacity: usize) -> isize {
    let before = counters();
    let mut response = Vec::with_capacity(capacity);
    response.extend_from_slice(&[0xAB; PAYLOAD]);
    cache
        .insert(key, response, Duration::from_secs(300), false)
        .await;
    cache.run_pending_tasks().await;
    live_delta(before, counters())
}

/// A cache hit as the handler serves it, minus the transaction ID.
fn serve(entry: &CacheValue) -> Vec<u8> {
    let mut bytes = entry.bytes().to_vec();
    let elapsed = entry.elapsed().as_secs() as u32;
    ttl::apply_elapsed(&mut bytes, entry.ttl_offsets(), elapsed);
    bytes
}

/// An entry must not retain the slack capacity of the buffer it was handed.
///
/// Only the difference between a tight and an over-reserved buffer is asserted,
/// which cancels the entry's and moka's own bookkeeping. nextest runs each test
/// in its own process, so the counters see only this test.
#[tokio::test]
async fn an_entry_does_not_retain_its_caller_s_spare_capacity() {
    // Generous for allocator rounding, two orders of magnitude below `SLACK`.
    const BUDGET: isize = 1024;

    let cache = DnsCache::with_capacity_bytes(64 * 1024 * 1024);

    let slack_key = bench_key(2);
    let tight = retained_by_insert(&cache, bench_key(1), PAYLOAD).await;
    let slack = retained_by_insert(&cache, slack_key.clone(), SLACK).await;

    assert!(
        slack - tight < BUDGET,
        "a {SLACK}-byte buffer cost {slack} bytes to cache where a tight one \
         cost {tight}; the spare capacity is being retained"
    );

    let entry = cache.get(&slack_key).await.expect("entry must be cached");
    assert_eq!(
        entry.bytes(),
        [0xAB; PAYLOAD],
        "shrinking must not truncate"
    );
}

/// Serving an entry must not make it bigger (it once cached a TTL-decremented
/// second copy of its bytes).
#[tokio::test]
async fn serving_an_entry_retains_nothing() {
    // Room for allocator noise, well below what a second copy would add.
    const BUDGET: isize = 512;

    let cache = DnsCache::with_capacity_bytes(64 * 1024 * 1024);
    let key = bench_key(3);
    let response = build_response(&key.domain, record_type_for(3), 3);
    let response_len = response.len();
    cache
        .insert(key.clone(), response, Duration::from_secs(300), false)
        .await;
    cache.run_pending_tasks().await;

    let entry = cache.get(&key).await.expect("entry must be cached");
    assert!(
        !entry.ttl_offsets().is_empty(),
        "the fixture must be a response whose TTLs are actually found"
    );

    let before = counters();
    for _ in 0..8 {
        drop(serve(&entry));
    }
    let retained = live_delta(before, counters());

    assert!(
        retained < BUDGET,
        "serving retained {retained} bytes for a {response_len}-byte response; \
         the entry is growing when it is read"
    );
}

/// Allocations one entry costs, with its response and key built beforehand —
/// unlike live bytes, the builder's allocations would not net out of a count.
async fn allocations_per_entry(n_entries: usize) -> f64 {
    let cache = DnsCache::with_capacity_bytes(n_entries as u64 * 1024);
    let prepared: Vec<(CacheKey, Vec<u8>)> = (0..n_entries)
        .map(|i| {
            let key = bench_key(i);
            let bytes = build_response(&key.domain, record_type_for(i), i as u16);
            (key, bytes)
        })
        .collect();

    let before = counters();
    for (key, bytes) in prepared {
        cache
            .insert(key, bytes, Duration::from_secs(300), false)
            .await;
    }
    // moka applies writes asynchronously; the node allocation lands here.
    cache.run_pending_tasks().await;
    let allocs = counters().allocs - before.allocs;

    drop(cache);
    allocs as f64 / n_entries as f64
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark; run manually with --ignored"]
async fn cache_memory_bench() {
    let n_entries: usize = std::env::var("BENCH_ENTRIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);

    let cache = DnsCache::with_capacity_bytes(n_entries as u64 * 1024);

    // Built inside the window on purpose: the encoder's buffer is what the cache
    // holds, so its sizing is part of the per-entry cost.
    let mut wire_bytes = 0usize;
    let mut key_bytes = 0usize;

    let before_insert = counters();
    for i in 0..n_entries {
        let key = bench_key(i);
        let bytes = build_response(&key.domain, record_type_for(i), i as u16);
        wire_bytes += bytes.len();
        key_bytes += key.domain.len();
        cache
            .insert(key, bytes, Duration::from_secs(300), false)
            .await;
    }
    cache.run_pending_tasks().await;
    let after_insert = counters();

    // Serve every entry once — the state a cache under real traffic sits in.
    let before_serve = counters();
    for i in 0..n_entries {
        let key = bench_key(i);
        let entry = cache.get(&key).await.expect("entry must still be cached");
        drop(serve(&entry));
    }
    cache.run_pending_tasks().await;
    let after_serve = counters();

    let n = n_entries as f64;
    let cold = live_delta(before_insert, after_insert);
    let by_serving = live_delta(before_serve, after_serve);

    eprintln!("cache_memory_bench: {n_entries} entries (56% A, 25% AAAA, 19% TXT)");
    eprintln!(
        "  wire payload     = {:.1} bytes/entry ({wire_bytes} total)",
        wire_bytes as f64 / n
    );
    eprintln!(
        "  key domain       = {:.1} bytes/entry",
        key_bytes as f64 / n
    );
    eprintln!(
        "  cold entry       = {:.1} bytes/entry ({cold} total)",
        cold as f64 / n
    );
    eprintln!(
        "  allocations      = {:.2} allocs/entry",
        allocations_per_entry(n_entries).await
    );
    eprintln!(
        "  added by serving = {:.1} bytes/entry ({by_serving} total)",
        by_serving as f64 / n
    );
    eprintln!(
        "  served entry     = {:.1} bytes/entry   <- the number to compare",
        (cold + by_serving) as f64 / n
    );
    eprintln!(
        "  overhead vs wire = {:.2}x",
        (cold + by_serving) as f64 / wire_bytes as f64
    );
    // Everything beyond wire bytes and domain: the weigher's per-entry constant.
    eprintln!(
        "  fixed overhead   = {:.1} bytes/entry   <- ENTRY_OVERHEAD_BYTES",
        (cold + by_serving - wire_bytes as isize - key_bytes as isize) as f64 / n
    );

    // Keep the cache alive past the last counter read.
    drop(cache);
}
