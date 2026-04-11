use noadd::db::{Database, QueryLogEntry};
use tempfile::tempdir;

async fn test_db() -> Database {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.db");
    let path_str = path.to_str().unwrap().to_string();
    std::mem::forget(dir); // keep tempdir alive for the test
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
        result: result.map(|s| s.to_string()),
        response_ms: 5,
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

    let points = db.timeline_multi_since(0, 60).await.unwrap();
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
    let points = db.timeline_multi_since(0, 60).await.unwrap();
    assert!(points.is_empty());
}

#[tokio::test]
async fn heatmap_groups_by_weekday_and_hour() {
    let db = test_db().await;
    // 2024-01-01 00:00:00 UTC = Monday, hour 0; epoch = 1704067200
    let monday_midnight = 1704067200;
    let entries = vec![
        entry(monday_midnight + 10, "A", false, false, None),
        entry(monday_midnight + 20, "A", false, false, None),
        entry(monday_midnight + 3600 + 5, "A", false, false, None),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let cells = db.hourly_heatmap_since(0).await.unwrap();
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
async fn heatmap_empty_db() {
    let db = test_db().await;
    let cells = db.hourly_heatmap_since(0).await.unwrap();
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
async fn result_breakdown_buckets_null_as_unknown() {
    let db = test_db().await;
    let entries = vec![
        entry(1000, "A", false, false, Some("NOERROR")),
        entry(1001, "A", true, false, Some("NXDOMAIN")),
        entry(1002, "A", false, false, None),
        entry(1003, "A", false, false, Some("NOERROR")),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let rows = db.result_breakdown_since(0).await.unwrap();
    let map: std::collections::HashMap<String, i64> = rows.into_iter().collect();
    assert_eq!(map.get("NOERROR"), Some(&2));
    assert_eq!(map.get("NXDOMAIN"), Some(&1));
    assert_eq!(map.get("unknown"), Some(&1));
}

#[tokio::test]
async fn db_file_size_is_positive() {
    let db = test_db().await;
    let size = db.db_file_size().await.unwrap();
    assert!(size > 0);
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
    assert_eq!(summary.max_ms, 100);
    // Avg of 1..=100 is 50.5
    assert!((summary.avg_ms - 50.5).abs() < 0.001);
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
    assert_eq!(summary.max_ms, 0);
}
