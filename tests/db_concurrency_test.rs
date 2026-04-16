use std::time::Duration;

use noadd::db::{Database, QueryLogEntry};
use tempfile::tempdir;
use tokio::time::timeout;

fn sample_entry(i: i64) -> QueryLogEntry {
    QueryLogEntry {
        timestamp: 1_700_000_000_000 + i,
        domain: format!("host-{}.example.com", i % 1024),
        query_type: "A".to_string(),
        client_ip: format!("10.0.{}.{}", (i / 256) % 256, i % 256),
        blocked: i % 7 == 0,
        cached: i % 3 == 0,
        response_ms: (i % 50) + 1,
        upstream: Some("1.1.1.1".to_string()),
        doh_token: None,
        result: None,
    }
}

async fn open_db() -> Database {
    let dir = tempdir().unwrap();
    let path = dir.path().join("concurrency.db");
    let path_str = path.to_str().unwrap().to_string();
    // Leak the dir so the file lives for the duration of the test.
    std::mem::forget(dir);
    Database::open(&path_str).await.unwrap()
}

/// Concurrently run a heavy reader (latency_summary_since, which uses
/// window functions and scans query_logs) alongside a streaming writer
/// (insert_query_logs). With the reader connection in place, WAL allows
/// both paths to proceed in parallel on their own worker threads. The
/// assertion is existence: both tasks must complete without error.
///
/// No timing assertion beyond a generous 5s ceiling — speedup vs. the
/// single-connection baseline is machine-dependent and would make the
/// test flaky.
#[tokio::test]
async fn reader_and_writer_run_concurrently_without_error() {
    let db = open_db().await;

    // Pre-populate ~10_000 rows so latency_summary_since does real work.
    let seed: Vec<QueryLogEntry> = (0..10_000).map(sample_entry).collect();
    db.insert_query_logs(&seed).await.unwrap();

    let writer_db = db.clone();
    let writer = tokio::spawn(async move {
        for round in 0..10 {
            let batch: Vec<QueryLogEntry> = (0..500)
                .map(|i| sample_entry(100_000 + round * 500 + i))
                .collect();
            writer_db.insert_query_logs(&batch).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let reader_db = db.clone();
    let reader = tokio::spawn(async move {
        let since_seconds = 1_000_000_000_i64; // epoch seconds; well before any row
        for _ in 0..10 {
            let summary = reader_db
                .latency_summary_since(since_seconds)
                .await
                .unwrap();
            assert!(summary.sample_count > 0);
        }
    });

    let joined = async {
        writer.await.unwrap();
        reader.await.unwrap();
    };
    timeout(Duration::from_secs(5), joined)
        .await
        .expect("writer + reader must both complete within 5s");

    // Sanity check: final row count matches pre-population + 10 * 500 writes.
    let total = db.total_log_count().await.unwrap();
    assert_eq!(total, 10_000 + 10 * 500);
}

/// Smoke check for the spec's "defence-in-depth" claim: the read
/// connection is opened with SQLITE_OPEN_READ_ONLY, so any write
/// attempt would be rejected by SQLite. We can only observe this
/// indirectly through the public API — `Database` routes all writes
/// to the writer connection by construction. This test asserts the
/// positive: a write followed by a read works, which means Database
/// correctly chose each connection for each operation.
#[tokio::test]
async fn read_only_routing_does_not_break_writes() {
    let db = open_db().await;
    db.insert_query_logs(&[sample_entry(1)]).await.unwrap();
    let rows = db.query_logs(10, 0, None, None, None, None).await.unwrap();
    assert_eq!(rows.len(), 1);
}
