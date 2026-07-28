use noadd::db::{Database, QueryLogEntry};
use tempfile::tempdir;

async fn test_db() -> Database {
    let dir = tempdir().unwrap();
    // Persist the tempdir (no Drop cleanup) so it lives for the test.
    let path = dir.keep().join("test.db");
    let path_str = path.to_str().unwrap().to_string();
    Database::open(&path_str).await.unwrap()
}

fn entry(
    ts_secs: i64,
    qtype: &str,
    blocked: bool,
    cached: bool,
    result: Option<&str>,
) -> QueryLogEntry {
    QueryLogEntry {
        timestamp: ts_secs * 1000, // column is in ms
        domain: "example.com".to_string(),
        query_type: qtype.to_string(),
        client_ip: "1.2.3.4".to_string(),
        blocked,
        cached,
        upstream: None,
        doh_token: None,
        result: result.map(std::string::ToString::to_string),
        response_ms: 5,
        authenticated_data: false,
    }
}

#[tokio::test]
async fn timeline_multi_buckets_total_blocked_cached() {
    let db = test_db().await;
    let entries = vec![
        entry(600, "A", false, false, Some("NOERROR")),
        entry(610, "A", true, false, Some("NXDOMAIN")),
        entry(620, "A", false, true, Some("NOERROR")),
        entry(700, "AAAA", false, false, Some("NOERROR")),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let points = db.timeline_multi_since(0, 60, 0).await.unwrap();
    assert_eq!(points.len(), 2);
    assert_eq!(points[0].total, 3);
    assert_eq!(points[0].blocked, 1);
    assert_eq!(points[0].cached, 1);
    assert_eq!(points[1].total, 1);
    assert_eq!(points[1].blocked, 0);
    assert_eq!(points[1].cached, 0);
}

#[tokio::test]
async fn timeline_multi_empty_db() {
    let db = test_db().await;
    let points = db.timeline_multi_since(0, 60, 0).await.unwrap();
    assert!(points.is_empty());
}

#[tokio::test]
async fn timeline_multi_offset_aligns_day_buckets_to_local_midnight() {
    let db = test_db().await;
    // UTC+8 viewer (offset 8h). A query at 2026-06-13 00:00 UTC is local 08:00,
    // so its day bucket starts at the prior local midnight = 2026-06-12 16:00
    // UTC (1_781_280_000). A query 9h later (local 17:00 same day) shares it; a
    // query at 2026-06-13 16:00 UTC (next local midnight) starts a new bucket.
    let utc_midnight = 1_781_280_000 + 8 * 3600; // 2026-06-13 00:00 UTC
    let entries = vec![
        entry(utc_midnight, "A", false, false, None),
        entry(utc_midnight + 9 * 3600, "A", true, false, None),
        entry(utc_midnight + 16 * 3600, "A", false, true, None), // next local day
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let offset = 8 * 3600;
    let points = db.timeline_multi_since(0, 86400, offset).await.unwrap();
    assert_eq!(points.len(), 2);
    assert_eq!(points[0].timestamp, 1_781_280_000); // local midnight 6/13
    assert_eq!(points[0].total, 2);
    assert_eq!(points[0].blocked, 1);
    assert_eq!(points[1].timestamp, 1_781_280_000 + 86400);
    assert_eq!(points[1].total, 1);
    assert_eq!(points[1].cached, 1);
}

#[tokio::test]
async fn heatmap_groups_by_weekday_and_hour() {
    let db = test_db().await;
    // 2024-01-01 00:00:00 UTC = Monday, hour 0; epoch = 1704067200
    let monday_midnight = 1_704_067_200;
    let entries = vec![
        entry(monday_midnight + 10, "A", false, false, None),
        entry(monday_midnight + 20, "A", false, false, None),
        entry(monday_midnight + 3600 + 5, "A", false, false, None),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let cells = db.hourly_heatmap_since(0, 0).await.unwrap();
    let mon_0 = cells
        .iter()
        .find(|c| c.weekday == 1 && c.hour == 0)
        .expect("mon 0");
    let mon_1 = cells
        .iter()
        .find(|c| c.weekday == 1 && c.hour == 1)
        .expect("mon 1");
    assert_eq!(mon_0.count, 2);
    assert_eq!(mon_1.count, 1);
}

#[tokio::test]
async fn heatmap_shifts_cells_by_tz_offset() {
    let db = test_db().await;
    // 2024-01-01 00:00:00 UTC = Monday, hour 0.
    let monday_midnight = 1_704_067_200;
    db.insert_query_logs(&[entry(monday_midnight + 10, "A", false, false, None)])
        .await
        .unwrap();

    // UTC+8 puts the same instant at Monday 08:00 local.
    let cells = db.hourly_heatmap_since(0, 8 * 3600).await.unwrap();
    assert_eq!(cells.len(), 1);
    assert_eq!(cells[0].weekday, 1);
    assert_eq!(cells[0].hour, 8);

    // UTC-5 rolls it back over midnight to Sunday 19:00 local.
    let cells = db.hourly_heatmap_since(0, -5 * 3600).await.unwrap();
    assert_eq!(cells.len(), 1);
    assert_eq!(cells[0].weekday, 0);
    assert_eq!(cells[0].hour, 19);
}

#[tokio::test]
async fn heatmap_empty_db() {
    let db = test_db().await;
    let cells = db.hourly_heatmap_since(0, 0).await.unwrap();
    assert!(cells.is_empty());
}

#[tokio::test]
async fn query_type_breakdown_sorts_desc() {
    let db = test_db().await;
    let entries = vec![
        entry(1000, "A", false, false, Some("NOERROR")),
        entry(1001, "A", false, false, Some("NOERROR")),
        entry(1002, "AAAA", false, false, Some("NOERROR")),
        entry(1003, "HTTPS", false, false, Some("NOERROR")),
        entry(1004, "A", false, false, Some("NOERROR")),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let rows = db.query_type_breakdown_since(0).await.unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0], ("A".to_string(), 3));
    assert!(rows[1].1 == 1 && rows[2].1 == 1);
}

#[tokio::test]
async fn outcome_breakdown_categorizes_by_action() {
    let db = test_db().await;
    let entries = vec![
        // Resolved: upstream returned an answer
        entry(1000, "A", false, false, Some("142.250.196.142")),
        entry(1001, "A", false, false, Some("8.8.8.8")),
        // Blocked: filter matched (result is ignored for this bucket)
        entry(1002, "A", true, false, None),
        // Cached: served from cache
        entry(1003, "A", false, true, Some("1.1.1.1")),
        // Empty: upstream answered with no records (NXDOMAIN/NODATA approx)
        entry(1004, "A", false, false, None),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let rows = db.outcome_breakdown_since(0).await.unwrap();
    let map: std::collections::HashMap<String, i64> = rows.into_iter().collect();
    assert_eq!(map.get("Resolved"), Some(&2));
    assert_eq!(map.get("Blocked"), Some(&1));
    assert_eq!(map.get("Cached"), Some(&1));
    assert_eq!(map.get("Empty"), Some(&1));
}

#[tokio::test]
async fn db_storage_stats_are_sane() {
    let db = test_db().await;
    let s = db.db_storage_stats().await.unwrap();
    assert!(s.main_bytes > 0);
    // Reclaimable (freelist) pages cannot exceed the whole file.
    assert!(s.reclaimable_bytes >= 0 && s.reclaimable_bytes <= s.main_bytes);
}

#[tokio::test]
async fn total_log_count_matches_inserts() {
    let db = test_db().await;
    assert_eq!(db.total_log_count().await.unwrap(), 0);
    db.insert_query_logs(&[entry(1000, "A", false, false, None)])
        .await
        .unwrap();
    assert_eq!(db.total_log_count().await.unwrap(), 1);
}

fn entry_with(ts_secs: i64, domain: &str, response_ms: i64) -> QueryLogEntry {
    QueryLogEntry {
        timestamp: ts_secs * 1000,
        domain: domain.to_string(),
        query_type: "A".to_string(),
        client_ip: "1.2.3.4".to_string(),
        blocked: false,
        cached: false,
        upstream: None,
        doh_token: None,
        result: None,
        response_ms,
        authenticated_data: false,
    }
}

#[tokio::test]
async fn unique_domains_counts_distinct() {
    let db = test_db().await;
    db.insert_query_logs(&[
        entry_with(1000, "a.com", 1),
        entry_with(1001, "a.com", 2),
        entry_with(1002, "b.com", 3),
        entry_with(1003, "c.com", 4),
    ])
    .await
    .unwrap();

    assert_eq!(db.unique_domains_since(0).await.unwrap(), 3);
    // since filter excludes earlier rows
    assert_eq!(db.unique_domains_since(1002).await.unwrap(), 2);
}

#[tokio::test]
async fn unique_domains_empty_db_is_zero() {
    let db = test_db().await;
    assert_eq!(db.unique_domains_since(0).await.unwrap(), 0);
}

#[tokio::test]
async fn latency_summary_computes_percentiles() {
    let db = test_db().await;
    let entries: Vec<_> = (1..=100)
        .map(|i| entry_with(1000 + i, "x.com", i))
        .collect();
    db.insert_query_logs(&entries).await.unwrap();

    let summary = db.latency_summary_since(0).await.unwrap();
    assert_eq!(summary.sample_count, 100);
    // p50 -> rn <= 50 -> max response_ms = 50
    assert_eq!(summary.p50_ms, 50);
    assert_eq!(summary.p95_ms, 95);
    assert_eq!(summary.p99_ms, 99);
}

#[tokio::test]
async fn latency_summary_empty_db_is_zero() {
    let db = test_db().await;
    let summary = db.latency_summary_since(0).await.unwrap();
    assert_eq!(summary.sample_count, 0);
    assert_eq!(summary.p50_ms, 0);
    assert_eq!(summary.p95_ms, 0);
    assert_eq!(summary.p99_ms, 0);
}

#[tokio::test]
async fn compute_summary_populates_7d_and_30d_rates() {
    use noadd::admin::stats::compute_summary;

    let db = test_db().await;
    // "now" is 40 days past the epoch so all windows have room.
    let now: i64 = 40 * 86400;
    let one_day: i64 = 86400;

    // Today window (now - 86400 .. now): 2 total, 1 blocked, 1 allowed+cached.
    // Allowed row in today: response_ms=5, cached=true.
    let today_blocked = entry(now - 100, "A", true, false, Some("NXDOMAIN"));
    let today_allowed_cached = entry(now - 200, "A", false, true, Some("NOERROR"));

    // 7d window adds one allowed+uncached entry 3 days ago (response_ms=5, cached=false).
    let three_days_ago = entry(now - 3 * one_day, "A", false, false, Some("NOERROR"));

    // 30d window adds one blocked entry 20 days ago.
    let twenty_days_ago = entry(now - 20 * one_day, "A", true, false, Some("NXDOMAIN"));

    db.insert_query_logs(&[
        today_blocked,
        today_allowed_cached,
        three_days_ago,
        twenty_days_ago,
    ])
    .await
    .unwrap();

    let s = compute_summary(&db, now).await.unwrap();

    // today: 2 total, 1 blocked -> 0.5
    assert!((s.block_ratio_today - 0.5).abs() < 1e-9);
    // 7d: 3 total, 1 blocked -> 1/3
    assert!((s.block_ratio_7d - (1.0 / 3.0)).abs() < 1e-9);
    // 30d: 4 total, 2 blocked -> 0.5
    assert!((s.block_ratio_30d - 0.5).abs() < 1e-9);

    // today cache_hit_rate: 1 allowed row, cached=true -> 1.0
    assert!((s.cache_hit_rate_today - 1.0).abs() < 1e-9);
    // 7d cache_hit_rate: 2 allowed rows (one cached, one not) -> 0.5
    assert!((s.cache_hit_rate_7d - 0.5).abs() < 1e-9);
    // 30d cache_hit_rate: 2 allowed rows (same as 7d; the 20d-old is blocked) -> 0.5
    assert!((s.cache_hit_rate_30d - 0.5).abs() < 1e-9);

    // avg_response_ms across allowed rows. entry() hardcodes response_ms=5.
    assert!((s.avg_response_ms_today - 5.0).abs() < 1e-9);
    assert!((s.avg_response_ms_7d - 5.0).abs() < 1e-9);
    assert!((s.avg_response_ms_30d - 5.0).abs() < 1e-9);
}

#[tokio::test]
async fn count_queries_multi_since_matches_single_window() {
    let db = test_db().await;
    let now: i64 = 40 * 86400;
    let one_day: i64 = 86400;

    let entries = vec![
        entry(now - 100, "A", true, false, Some("NXDOMAIN")),
        entry(now - 200, "A", false, true, Some("NOERROR")),
        entry(now - 3 * one_day, "A", false, false, Some("NOERROR")),
        entry(now - 20 * one_day, "A", true, false, Some("NXDOMAIN")),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let single_today = db.count_queries_since(now - one_day).await.unwrap();
    let single_7d = db.count_queries_since(now - 7 * one_day).await.unwrap();
    let single_30d = db.count_queries_since(now - 30 * one_day).await.unwrap();

    let (today, d7, d30) = db
        .count_queries_multi_since(now - one_day, now - 7 * one_day, now - 30 * one_day)
        .await
        .unwrap();

    // The single-window helper returns the total only, so the cross-check
    // covers totals; the blocked halves are pinned directly below.
    assert_eq!(today.0, single_today);
    assert_eq!(d7.0, single_7d);
    assert_eq!(d30.0, single_30d);

    // Sanity: today = (2, 1); 7d = (3, 1); 30d = (4, 2).
    assert_eq!(today, (2, 1));
    assert_eq!(d7, (3, 1));
    assert_eq!(d30, (4, 2));
}

#[tokio::test]
async fn cache_stats_multi_since_computes_each_window() {
    // Previously cross-checked against a single-window cache_stats_since, which
    // production never called and which has been removed. The expectations are
    // now stated directly so the multi-window query keeps its coverage.
    let db = test_db().await;
    let now: i64 = 40 * 86400;
    let one_day: i64 = 86400;

    let entries = vec![
        entry(now - 100, "A", true, false, Some("NXDOMAIN")),
        entry(now - 200, "A", false, true, Some("NOERROR")),
        entry(now - 3 * one_day, "A", false, false, Some("NOERROR")),
        entry(now - 20 * one_day, "A", true, false, Some("NXDOMAIN")),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let (today, d7, d30) = db
        .cache_stats_multi_since(now - one_day, now - 7 * one_day, now - 30 * one_day)
        .await
        .unwrap();

    // Blocked rows are excluded, so only the allowed ones count:
    // today  -> 1 allowed, cached;              7d -> +1 allowed, uncached;
    // 30d    -> the 20-day-old row is blocked, so identical to 7d.
    // Every seeded row has response_ms = 5.
    assert_eq!((today.0, today.1), (1, 1));
    assert!((today.2 - 5.0).abs() < 1e-9);

    assert_eq!((d7.0, d7.1), (1, 2));
    assert!((d7.2 - 5.0).abs() < 1e-9);

    assert_eq!((d30.0, d30.1), (1, 2));
    assert!((d30.2 - 5.0).abs() < 1e-9);
}

#[tokio::test]
async fn compute_summary_queries_1m_counts_only_the_last_60_seconds() {
    use noadd::admin::stats::compute_summary;

    // The dashboard's Throughput card divides this by 60 and presents it as the
    // current rate, so the window boundary is user-visible: anything older than
    // 60s leaking in would inflate the live reading with historical traffic.
    let db = test_db().await;
    let now: i64 = 40 * 86400;

    db.insert_query_logs(&[
        // Inside the 60s window.
        entry(now - 5, "A", false, false, Some("NOERROR")),
        entry(now - 59, "A", true, false, Some("NXDOMAIN")),
        // Outside it, but still inside the 24h window.
        entry(now - 61, "A", false, false, Some("NOERROR")),
        entry(now - 3600, "A", false, false, Some("NOERROR")),
    ])
    .await
    .unwrap();

    let s = compute_summary(&db, now).await.unwrap();

    assert_eq!(
        s.queries_1m, 2,
        "only the two rows inside the 60s window should count toward the live rate"
    );
    assert_eq!(
        s.total_today, 4,
        "the 24h window should still see every row, including those the 1m window excludes"
    );
}

#[tokio::test]
async fn both_timeline_types_report_bucket_starts_in_the_same_unit() {
    // The two sibling types are returned by adjacent endpoints, and
    // TimelinePoint used to emit milliseconds while TimelineMultiPoint emitted
    // seconds. Nothing broke at the time only because the admin UI funnelled
    // both through a helper that accepts either magnitude; any consumer that
    // did not would have been off by a factor of 1000, silently, landing dates
    // in 1970 or the far future rather than erroring.
    let db = test_db().await;
    let entries = vec![
        entry(600, "A", false, false, Some("NOERROR")),
        entry(610, "A", true, false, Some("NXDOMAIN")),
        entry(700, "AAAA", false, false, Some("NOERROR")),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let single = db.timeline_since(0, 60).await.unwrap();
    let multi = db.timeline_multi_since(0, 60, 0).await.unwrap();

    assert_eq!(single.len(), 2);
    assert_eq!(multi.len(), 2);

    // Bucket starts are the literal second values, not milliseconds.
    assert_eq!(single[0].timestamp, 600);
    assert_eq!(single[1].timestamp, 660);

    for (a, b) in single.iter().zip(multi.iter()) {
        assert_eq!(
            a.timestamp, b.timestamp,
            "TimelinePoint and TimelineMultiPoint must express bucket starts in the same unit"
        );
        assert_eq!(a.total, b.total);
        assert_eq!(a.blocked, b.blocked);
    }
}
