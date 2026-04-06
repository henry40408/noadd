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
