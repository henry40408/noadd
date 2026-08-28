//! Per-entry memory measurement for the DNS response cache. Not an assertion —
//! meant to be run manually to compare the resident cost of a cache entry
//! across implementations:
//!
//!   cargo nextest run --no-capture --release \
//!     --run-ignored only `cache_memory_bench`
//!
//! Fills the cache with N entries whose record-type mix follows production
//! resolver traffic (56% A, 25% AAAA, 19% TXT) and reports the live heap bytes
//! and allocation count attributable to each entry. A tracking allocator wraps
//! the system allocator to get those numbers; `main.rs` installs mimalloc, but
//! an integration test is its own binary and does not link it, so this crate is
//! free to install its own.
//!
//! Two numbers are reported because an entry grows once it is served:
//! `prepare_cached_response` stores a TTL-decremented snapshot on the entry, so
//! an entry under real traffic holds a second copy of the response. The
//! snapshot here is produced by re-encoding through hickory exactly as
//! `decrement_ttl` does, because how the encoder sizes its buffer is part of
//! what this measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use noadd::cache::{CacheKey, CacheValue, ClientResponseProfile, DnsCache};

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

/// Live-byte delta between two reads, as a signed value. Allocations made
/// before `before` can be freed after it, so a phase that nets negative is a
/// legitimate outcome rather than an underflow — hence the wrapping subtract.
fn live_delta(before: Counters, after: Counters) -> isize {
    after.live_bytes.wrapping_sub(before.live_bytes) as isize
}

/// The record-type mix of production resolver traffic, from Cloudflare's
/// published 1.1.1.1 cache distribution: 56% A, 25% AAAA, 19% TXT.
fn record_type_for(index: usize) -> RecordType {
    match index % 100 {
        0..=55 => RecordType::A,
        56..=80 => RecordType::AAAA,
        _ => RecordType::TXT,
    }
}

/// A realistic upstream answer: the echoed question plus two or three records
/// of the requested type. The TXT answers carry token-sized strings, which is
/// what puts them at the large end of the distribution.
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

/// A response payload small enough that a caller's reservation dwarfs it,
/// which is the situation every real caller is in: `Message::to_vec` reserves
/// 512 bytes for an answer that is typically under 100.
const PAYLOAD: usize = 64;
/// The reservation a slack buffer carries. Exaggerated well past the 512 the
/// encoder actually uses so the two measurements cannot be confused.
const SLACK: usize = 64 * 1024;

/// Live bytes retained after storing a `PAYLOAD`-byte response handed over in a
/// buffer reserved at `capacity`.
///
/// The buffer is allocated *inside* the measured window: the reservation is the
/// thing under test, so a buffer built beforehand would be invisible here.
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

/// The same measurement for the TTL-decremented snapshot an entry holds once
/// it has been served.
///
/// The caller's buffer is dropped before the second reading, as the handler's
/// is once the response has been sent — what is being measured is what the
/// entry keeps, not what the caller was still holding.
fn retained_by_snapshot(entry: &CacheValue, capacity: usize) -> isize {
    let before = counters();
    let mut patched = Vec::with_capacity(capacity);
    patched.extend_from_slice(&[0xCD; PAYLOAD]);
    entry.store_patched_bytes(0, &patched);
    drop(patched);
    live_delta(before, counters())
}

/// An entry must not retain the slack capacity of the buffer it was handed.
///
/// Each path is measured twice — once with a buffer sized to the response, once
/// with a heavily over-reserved one — and only the difference is asserted on.
/// Comparing the two cancels the entry's own bookkeeping and moka's, so the
/// threshold does not encode anything about how either is implemented.
///
/// nextest gives each test its own process, so the counters see this test's
/// allocations and no other's.
#[tokio::test]
async fn an_entry_does_not_retain_its_caller_s_spare_capacity() {
    // Generous next to the allocator's rounding of a 64-byte request, and two
    // orders of magnitude below `SLACK`.
    const BUDGET: isize = 1024;

    let cache = DnsCache::new(16);

    let tight_key = bench_key(1);
    let slack_key = bench_key(2);
    let tight = retained_by_insert(&cache, tight_key, PAYLOAD).await;
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

    let tight = retained_by_snapshot(&entry, PAYLOAD);
    let slack = retained_by_snapshot(&entry, SLACK);

    assert!(
        slack - tight < BUDGET,
        "a {SLACK}-byte buffer cost {slack} bytes to snapshot where a tight one \
         cost {tight}; the spare capacity is being retained"
    );
    assert_eq!(
        entry.try_patched_bytes(0).as_deref(),
        Some(&[0xCD; PAYLOAD][..]),
        "shrinking must not truncate"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark; run manually with --ignored"]
async fn cache_memory_bench() {
    let n_entries: usize = std::env::var("BENCH_ENTRIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);

    let cache = DnsCache::new(n_entries as u64 * 2);

    // Keys and responses are built inside the measured window on purpose. The
    // buffer `Message::to_vec` allocates is the buffer the cache goes on to
    // hold, so how the encoder sized it is part of the per-entry cost; hoisting
    // construction out would hide exactly the thing being measured. Only live
    // bytes are compared, so the parse-side temporaries net out.
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

    // Serve every entry once so each materialises its TTL-decremented
    // snapshot — the state a cache under real traffic sits in.
    let before_serve = counters();
    for i in 0..n_entries {
        let key = bench_key(i);
        let entry = cache.get(&key).await.expect("entry must still be cached");
        let elapsed = entry.elapsed().as_secs() as u32;
        if entry.try_patched_bytes(elapsed).is_none() {
            let reencoded = Message::from_bytes(entry.bytes())
                .unwrap()
                .to_vec()
                .unwrap();
            entry.store_patched_bytes(elapsed, &reencoded);
        }
    }
    cache.run_pending_tasks().await;
    let after_serve = counters();

    let n = n_entries as f64;
    let cold = live_delta(before_insert, after_insert);
    let snapshot = live_delta(before_serve, after_serve);

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
        "  cold entry       = {:.1} bytes/entry ({cold} total), {:.2} allocs/entry",
        cold as f64 / n,
        (after_insert.allocs - before_insert.allocs) as f64 / n
    );
    eprintln!(
        "  patched snapshot = {:.1} bytes/entry ({snapshot} total), {:.2} allocs/entry",
        snapshot as f64 / n,
        (after_serve.allocs - before_serve.allocs) as f64 / n
    );
    eprintln!(
        "  served entry     = {:.1} bytes/entry   <- the number to compare",
        (cold + snapshot) as f64 / n
    );
    eprintln!(
        "  overhead vs wire = {:.2}x",
        (cold + snapshot) as f64 / wire_bytes as f64
    );

    // Hold the cache past the final counter read so nothing measured above is
    // dropped before it is reported.
    drop(cache);
}
