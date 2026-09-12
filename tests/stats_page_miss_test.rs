//! The Statistics page's cost expressed in pages fetched from the database
//! file, which is the only unit that transfers from a developer's SSD to the SD
//! card an appliance runs from.
//!
//! `stats_page_miss_bench` reports these numbers against a real database;
//! these assert the two properties that produce them, so a planner change or a
//! re-split query cannot quietly give them back.

use noadd::admin::stats::{self, StatsRange};
use noadd::db::{Database, QueryLogEntry};
use tempfile::tempdir;

/// Fat enough that the table dwarfs the indexes over it, which is what makes a
/// stray rowid lookup per row visible in the page count.
const RESULT_PADDING: usize = 240;
const ROWS: i64 = 20_000;

async fn seeded_db() -> Database {
    let dir = tempdir().unwrap();
    let path = dir.keep().join("misses.db");
    let db = Database::open(path.to_str().unwrap()).await.unwrap();

    let mut entries = Vec::with_capacity(ROWS as usize);
    for i in 0..ROWS {
        entries.push(QueryLogEntry {
            timestamp: i * 1000,
            domain: format!("host{}.example.com", i % 500),
            query_type: if i % 3 == 0 { "AAAA" } else { "A" }.to_string(),
            client_ip: format!("10.0.0.{}", i % 20),
            blocked: i % 7 == 0,
            cached: i % 5 == 0,
            upstream: None,
            doh_token: None,
            result: if i % 11 == 0 {
                None
            } else {
                Some("x".repeat(RESULT_PADDING))
            },
            response_ms: i % 50,
            authenticated_data: false,
        });
    }
    for chunk in entries.chunks(2_000) {
        db.insert_query_logs(chunk).await.unwrap();
    }
    db
}

async fn page_misses<F, Fut, T>(db: &Database, f: F) -> i64
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    db.reset_read_page_accounting().await.unwrap();
    let before = db.read_page_cache_stats().await.unwrap();
    f().await;
    db.read_page_cache_stats().await.unwrap().misses - before.misses
}

/// Classifying an outcome needs to know whether `result` held an answer. Read
/// off the table that is a rowid lookup per row and so the whole file; read off
/// `idx_query_logs_ts_metrics`, which carries the answer as a generated column,
/// it is the index alone.
#[tokio::test]
async fn the_outcome_breakdown_never_reads_the_log_table() {
    let db = seeded_db().await;
    let storage = db.db_storage_stats().await.unwrap();
    let db_pages = storage.main_bytes / 4096;

    let misses = page_misses(&db, || db.outcome_breakdown_since(0)).await;

    assert!(
        misses > 0,
        "no pages were read at all — the measurement is not working"
    );
    assert!(
        misses * 4 < db_pages,
        "outcome breakdown read {misses} of the database's {db_pages} pages; \
         that is the table, not the metrics index — has the planner stopped \
         honouring INDEXED BY, or has has_result left the index?"
    );
}

/// The page's readings are foldings of two index scans. Asked one at a time
/// they re-walk indexes each other has just walked, and the read pool spreads
/// them over connections with separate caches, so nothing is warm for the next.
#[tokio::test]
async fn the_page_reads_less_than_its_readings_do_separately() {
    let db = seeded_db().await;
    let now = ROWS; // seconds; the seed runs from 0 to ROWS
    let range = StatsRange::Days7;

    let combined = page_misses(&db, || stats::compute_range_stats(&db, now, range, 15)).await;
    let separate = page_misses(&db, || stats::compute_breakdowns(&db, now, range)).await
        + page_misses(&db, || stats::compute_highlights(&db, now, range)).await
        + page_misses(&db, || {
            stats::compute_top_domains_ranged(&db, now, range, 15)
        })
        .await;

    assert!(
        combined < separate,
        "combined read {combined} pages, the same answers read separately {separate} — \
         the page is no longer sharing its scans"
    );
}

/// The saving has to be a saving in what is read, not in what is answered.
#[tokio::test]
async fn the_shared_scans_answer_what_the_separate_ones_did() {
    let db = seeded_db().await;
    let now = ROWS;
    let range = StatsRange::Days7;

    let combined = stats::compute_range_stats(&db, now, range, 15)
        .await
        .unwrap();
    let breakdowns = stats::compute_breakdowns(&db, now, range).await.unwrap();
    let highlights = stats::compute_highlights(&db, now, range).await.unwrap();
    let top = stats::compute_top_domains_ranged(&db, now, range, 15)
        .await
        .unwrap();

    let sort = |mut v: Vec<(String, i64)>| {
        v.sort();
        v
    };
    assert_eq!(
        sort(combined.metrics.query_types.clone()),
        sort(breakdowns.query_types)
    );
    assert_eq!(
        sort(combined.metrics.outcomes.clone()),
        sort(breakdowns.outcomes)
    );
    assert_eq!(combined.metrics.latency, highlights.latency);
    assert_eq!(combined.domains.unique, highlights.unique_domains);
    assert_eq!(combined.domains.top, top);
}

/// The outcome breakdown, the query-type breakdown and the latency percentiles
/// are three foldings of one statement. Asked together they must cost one scan
/// of `idx_query_logs_ts_metrics`, not one each — which is what a page whose
/// numbers were re-split across statements would pay.
#[tokio::test]
async fn the_window_readings_are_one_scan_between_them() {
    let db = seeded_db().await;

    let together = page_misses(&db, || db.window_metrics_since(0)).await;
    let separate = page_misses(&db, || db.outcome_breakdown_since(0)).await
        + page_misses(&db, || db.query_type_breakdown_since(0)).await
        + page_misses(&db, || db.latency_summary_since(0)).await;

    assert!(
        together > 0,
        "no pages were read at all — the measurement is not working"
    );
    assert!(
        together * 2 <= separate,
        "the three window readings cost {together} pages together and {separate} \
         apart; one scan answering all three should be about a third of that — \
         has the page gone back to a statement per reading?"
    );
}

/// The heatmap reads `timestamp` and nothing else, so it belongs on the
/// smallest index that carries it. `idx_query_logs_ts_metrics` also covers it
/// and the planner will take it unaided, paying for four columns the query
/// never looks at.
#[tokio::test]
async fn the_heatmap_reads_the_narrowest_index_that_covers_it() {
    let db = seeded_db().await;

    let heatmap = page_misses(&db, || db.hourly_heatmap_since(0, 0)).await;
    let metrics_scan = page_misses(&db, || db.timeline_multi_since(0, 3600, 0)).await;

    assert!(
        heatmap > 0,
        "no pages were read at all — the measurement is not working"
    );
    assert!(
        heatmap < metrics_scan,
        "the heatmap read {heatmap} pages and a metrics scan {metrics_scan} — \
         it is no longer on idx_query_logs_timestamp"
    );
}
