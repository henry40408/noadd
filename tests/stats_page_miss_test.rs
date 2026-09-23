//! Admin page costs in pages fetched from the database file — the only unit
//! that transfers from a developer's SSD to an appliance's SD card.
//!
//! The `*_page_miss_bench` files report the numbers against a real database;
//! these assert the properties behind them, so a planner change or a re-split
//! query cannot quietly give them back.

use noadd::admin::stats::{self, StatsRange};
use noadd::db::{Database, QueryLogEntry};
use tempfile::tempdir;

/// Fat enough that the table dwarfs its indexes, so a stray rowid lookup per
/// row shows in the page count.
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
            // About half forwarded, as on a real resolver.
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

/// Classifying an outcome needs whether `result` held an answer; from the table
/// that is a rowid lookup per row, but `query_stats_metrics_hour` carries it.
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

/// Asked one at a time, the page's readings re-walk what each other walked, on
/// pool connections with separate caches.
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

/// The saving must be in what is read, not in what is answered.
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

/// Outcomes, query types and latency percentiles are three foldings of one
/// statement: together they cost one read of `query_stats_metrics_hour`.
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

/// Twenty thousand queries inside one hour from fifty domains and twenty
/// clients — a busy resolver's hour, a few hundred rollup rows.
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

/// Every dashboard-tick reading folds the rollups, reading the table only for
/// a partial unit at its window's start (none here: windows start on a unit
/// boundary). Otherwise each would walk an index the length of the window,
/// every tick.
#[tokio::test]
async fn the_dashboard_readings_fold_rollups_rather_than_the_table() {
    let db = dense_db().await;

    // For scale: a search matching every domain walks an index over every row.
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
/// readings fold the rollups too.
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

/// The Database Health card's row count is read from `settings`, not counted:
/// `SELECT COUNT(*)` walks the smallest index end to end.
#[tokio::test]
async fn the_total_log_count_is_read_rather_than_counted() {
    let db = seeded_db().await;

    let read = page_misses(&db, || db.total_log_count()).await;
    // `*` matches every domain: the same total, counted.
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

/// With no filter, the log pager's total is the maintained row count; counting
/// it would be nearly the whole cost of an unfiltered first page.
#[tokio::test]
async fn the_unfiltered_query_log_count_is_read_rather_than_counted() {
    let db = seeded_db().await;

    let unfiltered = page_misses(&db, || db.count_logs(None, None, None, None)).await;
    // A blank search box is no filter, so it takes the same path.
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

/// Twenty thousand queries, one in four hundred from a quiet `DoH` token and one
/// in four hundred of a quiet record type.
async fn quiet_filters_db() -> Database {
    let dir = tempdir().unwrap();
    let path = dir.keep().join("filters.db");
    let db = Database::open(path.to_str().unwrap()).await.unwrap();

    let entries: Vec<QueryLogEntry> = (0..ROWS)
        .map(|i| QueryLogEntry {
            timestamp: i * 1000,
            domain: format!("host{}.example.com", i % 500),
            query_type: if i % 400 == 7 { "TXT" } else { "A" }.to_string(),
            client_ip: format!("10.0.0.{}", i % 20),
            blocked: i % 7 == 0,
            cached: i % 5 == 0,
            upstream: None,
            doh_token: (i % 400 == 3).then(|| "quiet".to_string()),
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

/// Filtering the log by token, record type or verdict seeks an index. Without
/// one, a quiet token's page and count walk the whole table, and a deep page of
/// blocked queries looks up every row it skips to learn its verdict.
#[tokio::test]
async fn the_query_log_filters_seek_their_indexes() {
    let db = quiet_filters_db().await;
    let db_pages = db.db_storage_stats().await.unwrap().main_bytes / 4096;
    let readings = [
        (
            "token page",
            page_misses(&db, || {
                db.query_logs(50, 0, None, None, Some("quiet"), None)
            })
            .await,
        ),
        (
            "token count",
            page_misses(&db, || db.count_logs(None, None, Some("quiet"), None)).await,
        ),
        (
            "type page",
            page_misses(&db, || db.query_logs(50, 0, None, None, None, Some("TXT"))).await,
        ),
        (
            "type count",
            page_misses(&db, || db.count_logs(None, None, None, Some("TXT"))).await,
        ),
        (
            "blocked page 20",
            page_misses(&db, || db.query_logs(50, 950, None, Some(true), None, None)).await,
        ),
        (
            "type + blocked page",
            page_misses(&db, || {
                db.query_logs(50, 0, None, Some(false), None, Some("TXT"))
            })
            .await,
        ),
    ];

    for (label, read) in readings {
        assert!(
            read > 0,
            "{label} read no pages at all — the measurement is not working"
        );
        assert!(
            read * 10 < db_pages,
            "{label} read {read} of the database's {db_pages} pages — \
             is the filter back to walking the table?"
        );
    }
}
