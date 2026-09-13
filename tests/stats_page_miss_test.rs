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
            // About half forwarded, as on a real resolver: blocked and cached
            // answers never reach an upstream.
            upstream: (i % 2 == 0).then(|| format!("tls://1.1.1.{}:853", i % 4)),
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
        .await
        + page_misses(&db, || {
            stats::compute_top_clients_ranged(&db, now, range, 15)
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

/// The charts ride the scan that answers the breakdowns. Before, the browser
/// fetched the timeline and the heatmap after the page landed, which walked
/// the metrics index a second time and the timestamp index on top — so the
/// page's readings and its charts together must cost what the readings alone
/// did, and less than the three statements they replaced.
#[tokio::test]
async fn the_page_and_its_charts_are_one_metrics_scan() {
    let db = seeded_db().await;

    let scan = page_misses(&db, || db.stats_scan_since(0, 0)).await;
    let window = page_misses(&db, || db.window_metrics_since(0)).await;
    let replaced = window
        + page_misses(&db, || db.timeline_multi_since(0, 3600, 0)).await
        + page_misses(&db, || db.hourly_heatmap_since(0, 0)).await;

    assert!(
        window > 0,
        "no pages were read at all — the measurement is not working"
    );
    assert!(
        scan <= window + window / 10,
        "the page's scan read {scan} pages against {window} for the window readings \
         alone — is it off idx_query_logs_ts_metrics, or reading the table?"
    );
    assert!(
        scan * 2 < replaced,
        "the page's scan read {scan} pages and the statements it replaced {replaced} — \
         are the charts back on a scan of their own?"
    );
}

/// The dashboard's summary asks every tick for totals, blocks, cache hits and
/// mean latency over three windows. Every one of those is a column of
/// `idx_query_logs_ts_metrics`, so together they cost one scan of it — not the
/// two that asking the blocked counts and the cache figures separately paid.
#[tokio::test]
async fn the_dashboard_summary_is_one_metrics_scan() {
    let db = seeded_db().await;
    let now = ROWS; // seconds; the seed runs from 0 to ROWS

    let summary = page_misses(&db, || stats::compute_summary(&db, now)).await;
    let one_scan = page_misses(&db, || db.window_metrics_since(0)).await;

    assert!(
        one_scan > 0,
        "no pages were read at all — the measurement is not working"
    );
    assert!(
        summary <= one_scan + one_scan / 10,
        "the summary read {summary} pages where one scan of the metrics index \
         reads {one_scan} — has it gone back to a statement per figure?"
    );
}

/// The top upstreams read `upstream` and `response_ms`, which no index carried,
/// so every forwarded query in the window was a rowid lookup into the table —
/// on every dashboard tick. A partial index over the forwarded rows answers it
/// alone.
#[tokio::test]
async fn the_top_upstreams_never_read_the_log_table() {
    let db = seeded_db().await;
    let storage = db.db_storage_stats().await.unwrap();
    let db_pages = storage.main_bytes / 4096;

    let misses = page_misses(&db, || db.top_upstreams_since(0, 10)).await;

    assert!(
        misses > 0,
        "no pages were read at all — the measurement is not working"
    );
    assert!(
        misses * 4 < db_pages,
        "top upstreams read {misses} of the database's {db_pages} pages; that \
         is the table, not an index — is idx_query_logs_ts_upstream missing?"
    );
}

/// The domain and client lists read an index that starts with `timestamp`, so a
/// short window — the dashboard's 24 hours against a week of retention — reads
/// a short stretch of it. The group-first indexes they replaced could not be
/// restricted by the window at all, and read most of themselves whatever it was.
#[tokio::test]
async fn a_short_window_reads_a_short_stretch_of_the_traffic_lists() {
    let db = seeded_db().await;

    let whole = page_misses(&db, || db.traffic_lists_since(0, 15)).await;
    // The last tenth of the seed.
    let tail = page_misses(&db, || db.traffic_lists_since(ROWS - ROWS / 10, 15)).await;

    assert!(
        tail > 0,
        "no pages were read at all — the measurement is not working"
    );
    assert!(
        tail * 4 < whole,
        "a tenth of the window read {tail} pages against {whole} for all of it — \
         is the index still timestamp-first, and still named by INDEXED BY?"
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

/// The Database Health card's row count is read from one row of `settings`,
/// not counted. `SELECT COUNT(*)` has no shortcut in SQLite: it walks the
/// smallest index end to end, for a number the page prints and two of its
/// estimates divide by.
#[tokio::test]
async fn the_total_log_count_is_read_rather_than_counted() {
    let db = seeded_db().await;

    let read = page_misses(&db, || db.total_log_count()).await;
    let counted = page_misses(&db, || db.count_logs(None, None, None, None)).await;

    assert!(
        counted > 0,
        "counting read no pages at all — the measurement is not working"
    );
    assert!(
        read * 4 < counted,
        "the total read {read} pages and counting the same rows read {counted} — \
         is total_log_count back on COUNT(*)?"
    );
}
