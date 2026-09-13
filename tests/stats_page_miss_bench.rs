//! What the Statistics page costs in **page misses** — the 4 KiB database pages
//! `SQLite` has to fetch from the file to answer it. Manual-only, gated by
//! `#[ignore]`.
//!
//!   BENCH_DB=/tmp/noadd-bench.db cargo nextest run --release \
//!     --no-capture --run-ignored only `stats_page_miss`
//!
//! Pages, not milliseconds, because development runs off an SSD and the
//! appliance runs off an SD card: the same query that reads 12 000 pages looks
//! free on one and takes seconds on the other, so a wall-clock number measured
//! here says nothing about a Raspberry Pi. A page count is the same on both.
//! `stats_parallel_bench` is the wall-clock companion, and is the one to
//! distrust when the two disagree.
//!
//! Each reading is taken with the read pool's page cache dropped first, so the
//! number is what a cold appliance pays. `BENCH_RANGE` picks the window
//! (`7d`, `30d`, `90d`; default `30d`).

use noadd::admin::stats::{
    self, StatsRange, compute_db_health, compute_heatmap, compute_range_stats,
    compute_stats_timeline, compute_top_clients_ranged,
};
use noadd::db::Database;
use noadd::now_unix;

const TOP_N: i64 = 15;

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
async fn stats_page_miss_bench() {
    let db_path = std::env::var("BENCH_DB").unwrap_or_else(|_| "/tmp/noadd-bench.db".into());
    let range = match std::env::var("BENCH_RANGE").ok().as_deref() {
        Some("7d") => StatsRange::Days7,
        Some("90d") => StatsRange::Days90,
        _ => StatsRange::Days30,
    };
    assert!(
        std::path::Path::new(&db_path).exists(),
        "BENCH_DB={db_path} not found — copy a production database to a scratch path before running"
    );

    let db = Database::open(&db_path).await.unwrap();
    let now = now_unix();
    let page_size = db.db_storage_stats().await.unwrap();
    eprintln!(
        "stats_page_miss_bench: db={db_path} range={} ",
        range.label()
    );

    // Exactly what `stats_page` reads, in the order the template consumes it.
    let mut rows: Vec<(&str, i64)> = Vec::new();
    rows.push((
        "range_stats (breakdowns+latency+charts+domains)",
        page_misses(&db, || compute_range_stats(&db, now, range, TOP_N)).await,
    ));
    rows.push((
        "top_clients",
        page_misses(&db, || compute_top_clients_ranged(&db, now, range, TOP_N)).await,
    ));
    rows.push((
        "db_health",
        page_misses(&db, || compute_db_health(&db, now)).await,
    ));

    let page_total: i64 = rows.iter().map(|(_, n)| *n).sum();

    // The API's chart endpoints. The page no longer calls them — its charts are
    // folded from `range_stats` in the browser — so these are what a visit used
    // to add on top, and what an API caller still pays.
    let charts: Vec<(&str, i64)> = vec![
        (
            "  timeline (API only)",
            page_misses(&db, || compute_stats_timeline(&db, now, range, 0)).await,
        ),
        (
            "  heatmap (API only)",
            page_misses(&db, || compute_heatmap(&db, now, 0)).await,
        ),
    ];

    // Per-reading detail, so a regression names the query that caused it.
    let individual: Vec<(&str, i64)> = vec![
        (
            "  breakdowns alone",
            page_misses(&db, || stats::compute_breakdowns(&db, now, range)).await,
        ),
        (
            "  highlights alone",
            page_misses(&db, || stats::compute_highlights(&db, now, range)).await,
        ),
        (
            "  top_domains alone",
            page_misses(&db, || {
                stats::compute_top_domains_ranged(&db, now, range, TOP_N)
            })
            .await,
        ),
    ];

    let mib = |pages: i64| (pages * 4096) as f64 / (1024.0 * 1024.0);
    eprintln!();
    eprintln!("  {:<42} {:>9}  {:>9}", "reading", "pages", "MiB");
    for (label, n) in rows.iter().chain(&charts).chain(&individual) {
        eprintln!("  {label:<42} {n:>9}  {:>9.1}", mib(*n));
    }
    eprintln!(
        "  {:<42} {page_total:>9}  {:>9.1}",
        "PAGE TOTAL (whole visit)",
        mib(page_total)
    );
    eprintln!(
        "  database is {:.1} MiB",
        page_size.main_bytes as f64 / (1024.0 * 1024.0)
    );

    // A reading that costs nothing means the cache was not actually dropped, so
    // every later number would be meaningless.
    assert!(
        page_total > 0,
        "no page misses recorded — is BENCH_DB an empty database?"
    );
}
