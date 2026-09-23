//! What the dashboard costs in **page misses** (see `stats_page_miss_bench`).
//! Manual-only.
//!
//!   BENCH_DB=/tmp/noadd-bench.db cargo nextest run --release \
//!     --no-capture --run-ignored only `dashboard_page_miss`
//!
//! The first response is paid once per visit; the stream's snapshot every
//! `TICK_INTERVAL_SECS` while a dashboard is open — the number to watch.
//!
//! Each reading starts with the pool's page cache dropped (a cold appliance).
//! `BENCH_NOW` (unix seconds) pins the clock, so a copy older than a day does
//! not measure empty 24-hour windows.

use noadd::admin::events::compute_snapshot;
use noadd::admin::stats::{
    compute_summary, compute_timeline, compute_top_domains_and_clients, compute_top_upstreams,
};
use noadd::db::Database;
use noadd::now_unix;

/// Mirrors what `dashboard_page` and `compute_snapshot` pass (not exported).
const TOP_N: i64 = 10;
const TIMELINE_HOURS: i64 = 24;

/// Pages `f` reads with the pool's page cache dropped first.
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

    // The tick runs the timeline and the three readings concurrently, so it is
    // measured as one call rather than summed.
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

    // Zero means the cache was not dropped and every number is meaningless.
    assert!(
        tick > 0,
        "no page misses recorded — is BENCH_DB an empty database?"
    );
}
