//! What the Statistics page costs in **page misses** — 4 KiB pages `SQLite`
//! fetches from the file. Manual-only.
//!
//!   BENCH_DB=/tmp/noadd-bench.db cargo nextest run --release \
//!     --no-capture --run-ignored only `stats_page_miss`
//!
//! Pages, not milliseconds: development runs off an SSD and the appliance off
//! an SD card, so wall time here says nothing about a Raspberry Pi, while a page
//! count is the same on both. Distrust the wall-clock `stats_parallel_bench`
//! when the two disagree.
//!
//! Each reading starts with the pool's page cache dropped (a cold appliance).
//! `BENCH_RANGE`: `7d`, `30d` (default), `90d`. `BENCH_NOW` (unix seconds) pins
//! the window's end, so an old copy still measures its traffic.

use noadd::admin::stats::{
    self, StatsRange, compute_db_health, compute_heatmap, compute_range_stats,
    compute_stats_timeline,
};
use noadd::db::Database;
use noadd::now_unix;

const TOP_N: i64 = 15;

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
    let now = std::env::var("BENCH_NOW").ok().map_or_else(now_unix, |v| {
        v.parse::<i64>().expect("BENCH_NOW must be unix seconds")
    });
    let page_size = db.db_storage_stats().await.unwrap();
    eprintln!(
        "stats_page_miss_bench: db={db_path} range={} ",
        range.label()
    );

    // Exactly what `stats_page` reads.
    let mut rows: Vec<(&str, i64)> = Vec::new();
    rows.push((
        "range_stats (all readings, charts, both lists)",
        page_misses(&db, || compute_range_stats(&db, now, range, TOP_N)).await,
    ));
    rows.push((
        "db_health",
        page_misses(&db, || compute_db_health(&db, now)).await,
    ));

    let page_total: i64 = rows.iter().map(|(_, n)| *n).sum();

    // The API's chart endpoints: not called by the page (the browser folds its
    // charts from `range_stats`), but still paid by API callers.
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
            "  top_domains alone (domain index)",
            page_misses(&db, || {
                stats::compute_top_domains_ranged(&db, now, range, TOP_N)
            })
            .await,
        ),
        (
            "  both lists alone",
            page_misses(&db, || {
                stats::compute_top_clients_ranged(&db, now, range, TOP_N)
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

    // Zero means the cache was not dropped and every number is meaningless.
    assert!(
        page_total > 0,
        "no page misses recorded — is BENCH_DB an empty database?"
    );
}
