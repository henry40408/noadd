//! What the dashboard costs in **page misses**, the unit
//! `stats_page_miss_bench` explains. Manual-only, gated by `#[ignore]`.
//!
//!   BENCH_DB=/tmp/noadd-bench.db cargo nextest run --release \
//!     --no-capture --run-ignored only `dashboard_page_miss`
//!
//! Two costs, reported separately because they recur at different rates: the
//! first response is paid once per visit, the event stream's snapshot every
//! `TICK_INTERVAL_SECS` for as long as a dashboard stays open. The tick is the
//! number to watch.
//!
//! Each reading is taken with the read pool's page cache dropped first, so the
//! number is what a cold appliance pays. `BENCH_NOW` (unix seconds) pins the
//! clock: every dashboard reading ends at now, so on a copy older than a day
//! the 24-hour readings would otherwise measure an empty window.

use noadd::admin::events::compute_snapshot;
use noadd::admin::stats::{
    compute_summary, compute_timeline, compute_top_domains_and_clients, compute_top_upstreams,
};
use noadd::db::Database;
use noadd::now_unix;

/// The limit and window `dashboard_page` and `compute_snapshot` pass. Kept here
/// rather than exported, so the per-reading rows below ask for what the page
/// asks for; the tick total goes through `compute_snapshot` itself.
const TOP_N: i64 = 10;
const TIMELINE_HOURS: i64 = 24;

/// Run `f` with the pool's page cache dropped first, and report how many pages
/// it had to read.
async fn page_misses<F, Fut, T>(db: &Database, f: F) -> i64
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    db.reset_read_page_accounting().await.unwrap();
    let before = db.read_page_cache_stats().await.unwrap();
    f().await;
    let after = db.read_page_cache_stats().await.unwrap();
    after.misses - before.misses
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "benchmark; run manually with --ignored"]
async fn dashboard_page_miss_bench() {
    let db_path = std::env::var("BENCH_DB").unwrap_or_else(|_| "/tmp/noadd-bench.db".into());
    assert!(
        std::path::Path::new(&db_path).exists(),
        "BENCH_DB={db_path} not found — copy a production database to a scratch path before running"
    );
    let now = std::env::var("BENCH_NOW").ok().map_or_else(now_unix, |v| {
        v.parse::<i64>().expect("BENCH_NOW must be unix seconds")
    });

    let db = Database::open(&db_path).await.unwrap();
    let storage = db.db_storage_stats().await.unwrap();
    eprintln!("dashboard_page_miss_bench: db={db_path} now={now}");

    // What `dashboard_page` reads before it writes any HTML.
    let first: Vec<(&str, i64)> = vec![
        (
            "summary",
            page_misses(&db, || compute_summary(&db, now)).await,
        ),
        (
            "top domains + clients",
            page_misses(&db, || compute_top_domains_and_clients(&db, now, TOP_N)).await,
        ),
        (
            "top upstreams",
            page_misses(&db, || compute_top_upstreams(&db, now, TOP_N)).await,
        ),
    ];
    let first_total: i64 = first.iter().map(|(_, n)| *n).sum();

    // The tick adds the timeline to the same three readings and runs all four
    // concurrently, so its total is measured as one call rather than summed.
    let timeline = page_misses(&db, || compute_timeline(&db, now, TIMELINE_HOURS)).await;
    let tick = page_misses(&db, || compute_snapshot(&db, now)).await;

    let mib = |pages: i64| (pages * 4096) as f64 / (1024.0 * 1024.0);
    eprintln!();
    eprintln!("  {:<42} {:>9}  {:>9}", "reading", "pages", "MiB");
    for (label, n) in &first {
        eprintln!("  {label:<42} {n:>9}  {:>9.1}", mib(*n));
    }
    eprintln!(
        "  {:<42} {first_total:>9}  {:>9.1}",
        "FIRST RESPONSE TOTAL",
        mib(first_total)
    );
    eprintln!(
        "  {:<42} {timeline:>9}  {:>9.1}",
        "timeline (tick only)",
        mib(timeline)
    );
    eprintln!(
        "  {:<42} {tick:>9}  {:>9.1}",
        "TICK TOTAL (compute_snapshot)",
        mib(tick)
    );
    eprintln!(
        "  database is {:.1} MiB",
        storage.main_bytes as f64 / (1024.0 * 1024.0)
    );

    // A reading that costs nothing means the cache was not actually dropped, so
    // every later number would be meaningless.
    assert!(
        tick > 0,
        "no page misses recorded — is BENCH_DB an empty database?"
    );
}
