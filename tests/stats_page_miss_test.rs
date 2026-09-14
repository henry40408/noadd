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
/// off the table that is a rowid lookup per row and so the whole file;
/// `query_stats_metrics_hour` carries the answer, so it never has to be.
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
         that is the table — is the breakdown still folding query_stats_metrics_hour?"
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
/// are three foldings of one statement. Asked together they must cost one read
/// of `query_stats_metrics_hour`, not one each — which is what a page whose
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

/// Twenty thousand queries inside one hour, from fifty domains and twenty
/// clients: the rollups hold a few hundred rows for what the table holds in
/// twenty thousand, which is the shape a busy resolver's hour takes.
async fn dense_db() -> Database {
    let dir = tempdir().unwrap();
    let path = dir.keep().join("dense.db");
    let db = Database::open(path.to_str().unwrap()).await.unwrap();

    let entries: Vec<QueryLogEntry> = (0..ROWS)
        .map(|i| QueryLogEntry {
            timestamp: i * 150,
            domain: format!("host{}.example.com", i % 50),
            query_type: if i % 3 == 0 { "AAAA" } else { "A" }.to_string(),
            client_ip: format!("10.0.0.{}", i % 20),
            blocked: i % 7 == 0,
            cached: i % 5 == 0,
            upstream: (i % 2 == 0).then(|| format!("tls://1.1.1.{}:853", i % 4)),
            doh_token: None,
            result: Some("x".repeat(RESULT_PADDING)),
            response_ms: i % 50,
            authenticated_data: false,
        })
        .collect();
    for chunk in entries.chunks(2_000) {
        db.insert_query_logs(chunk).await.unwrap();
    }
    db
}

/// Every reading a dashboard tick makes folds the rollups, and reads the table
/// only for the part of a unit its window starts inside — none here, because
/// every window below starts on a unit boundary. Before the rollups each of
/// these was a scan of an index as long as the window, and the window is the
/// whole table under the default retention, every ten seconds.
#[tokio::test]
async fn the_dashboard_readings_fold_rollups_rather_than_the_table() {
    let db = dense_db().await;

    // For scale: counting with a search that matches every domain walks an
    // index over every row, which is what each reading used to cost.
    let scan = page_misses(&db, || db.count_logs(Some("*"), None, None, None)).await;
    let readings = [
        (
            "summary",
            page_misses(&db, || db.summary_multi_since(0, 0, 0)).await,
        ),
        (
            "timeline",
            page_misses(&db, || db.timeline_since(0, 1_800)).await,
        ),
        (
            "traffic lists",
            page_misses(&db, || db.traffic_lists_since(0, 10)).await,
        ),
        (
            "domain stats",
            page_misses(&db, || db.domain_stats_since(0, 20)).await,
        ),
        (
            "top upstreams",
            page_misses(&db, || db.top_upstreams_since(0, 10)).await,
        ),
    ];

    assert!(
        scan > 0,
        "the scan read no pages at all — the measurement is not working"
    );
    for (label, read) in readings {
        assert!(
            read * 10 < scan,
            "{label} read {read} pages where a scan over every row reads {scan} — \
             is it back on the table instead of the rollups?"
        );
    }
}

/// The Statistics page's scan and the API's timeline, heatmap and window
/// readings fold the rollups too. Before, the page's scan and each of these was
/// a walk of an index as long as the window — the whole table under the
/// default retention.
#[tokio::test]
async fn the_statistics_readings_fold_rollups_rather_than_the_table() {
    let db = dense_db().await;

    let scan = page_misses(&db, || db.count_logs(Some("*"), None, None, None)).await;
    let readings = [
        (
            "stats scan",
            page_misses(&db, || db.stats_scan_since(0, 0)).await,
        ),
        (
            "window metrics",
            page_misses(&db, || db.window_metrics_since(0)).await,
        ),
        (
            "timeline",
            page_misses(&db, || db.timeline_multi_since(0, 3_600, 8 * 3_600)).await,
        ),
        (
            "heatmap",
            page_misses(&db, || db.hourly_heatmap_since(0, 8 * 3_600)).await,
        ),
    ];

    assert!(
        scan > 0,
        "the scan read no pages at all — the measurement is not working"
    );
    for (label, read) in readings {
        assert!(
            read * 10 < scan,
            "{label} read {read} pages where a scan over every row reads {scan} — \
             is it back on the table instead of the rollups?"
        );
    }
}

/// The Database Health card's row count is read from one row of `settings`,
/// not counted. `SELECT COUNT(*)` has no shortcut in SQLite: it walks the
/// smallest index end to end, for a number the page prints and two of its
/// estimates divide by.
#[tokio::test]
async fn the_total_log_count_is_read_rather_than_counted() {
    let db = seeded_db().await;

    let read = page_misses(&db, || db.total_log_count()).await;
    // `*` matches every domain, so this is the same total arrived at by counting.
    let counted = page_misses(&db, || db.count_logs(Some("*"), None, None, None)).await;

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

/// The query log's pager asks for its total on every load, and with no filter
/// applied that total is the table's row count — the number the write paths
/// already maintain. Counting it walks the smallest index end to end, which on
/// an unfiltered first page is nearly the whole cost of the load.
#[tokio::test]
async fn the_unfiltered_query_log_count_is_read_rather_than_counted() {
    let db = seeded_db().await;

    let unfiltered = page_misses(&db, || db.count_logs(None, None, None, None)).await;
    // A blank search box is no filter at all, so it must take the same path.
    let blank = page_misses(&db, || db.count_logs(Some("  "), None, None, None)).await;
    let counted = page_misses(&db, || db.count_logs(Some("*"), None, None, None)).await;

    assert!(
        counted > 0,
        "counting read no pages at all — the measurement is not working"
    );
    for (label, read) in [("no filter", unfiltered), ("blank search", blank)] {
        assert!(
            read * 4 < counted,
            "{label} read {read} pages and counting the same rows read {counted} — \
             is count_logs counting when nothing narrows it?"
        );
    }
}
