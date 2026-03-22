use noadd::db::Database;
use noadd::dns::handler::QueryContext;
use noadd::logger::QueryLogger;

#[tokio::test]
async fn test_logger_flushes_on_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db = Database::open(db_path.to_str().unwrap()).await.unwrap();

    let threshold = 5;
    let (logger, tx) = QueryLogger::new(db.clone(), threshold, 300);

    // Spawn the logger
    let handle = tokio::spawn(logger.run());

    // Send exactly `threshold` entries
    for i in 0..threshold {
        let ctx = QueryContext {
            timestamp: 1000 + i as i64,
            client_ip: "127.0.0.1".to_string(),
            domain: format!("example{i}.com"),
            query_type: "A".to_string(),
            action: "allowed".to_string(),
            cached: false,
            upstream: Some("8.8.8.8:53".to_string()),
            doh_token: None,
            response_time_ms: 10,
            matched_rule: None,
            matched_list: None,
        };
        tx.send(ctx).await.unwrap();
    }

    // Give the logger time to flush
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Drop sender to shut down the logger
    drop(tx);
    handle.await.unwrap();

    // Verify entries were written to the database
    let logs = db.query_logs(100, 0, None, None).await.unwrap();
    assert_eq!(logs.len(), threshold);

    for log in &logs {
        assert!(!log.blocked);
        assert_eq!(log.query_type, "A");
        assert_eq!(log.client_ip, "127.0.0.1");
    }
}

#[tokio::test]
async fn test_logger_flushes_on_channel_close() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db = Database::open(db_path.to_str().unwrap()).await.unwrap();

    // Set a high threshold so it won't trigger threshold-based flush
    let (logger, tx) = QueryLogger::new(db.clone(), 1000, 300);

    let handle = tokio::spawn(logger.run());

    // Send fewer entries than the threshold
    for i in 0..3 {
        let ctx = QueryContext {
            timestamp: 2000 + i as i64,
            client_ip: "10.0.0.1".to_string(),
            domain: format!("test{i}.org"),
            query_type: "AAAA".to_string(),
            action: "blocked".to_string(),
            cached: false,
            upstream: None,
            doh_token: None,
            response_time_ms: 5,
            matched_rule: Some("||test.org^".to_string()),
            matched_list: Some("blocklist".to_string()),
        };
        tx.send(ctx).await.unwrap();
    }

    // Drop sender to close the channel
    drop(tx);
    handle.await.unwrap();

    // Verify all entries were flushed on shutdown
    let logs = db.query_logs(100, 0, None, None).await.unwrap();
    assert_eq!(logs.len(), 3);

    for log in &logs {
        assert!(log.blocked);
        assert_eq!(log.query_type, "AAAA");
    }
}

#[tokio::test]
async fn test_logger_flushes_on_interval() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let db = Database::open(db_path.to_str().unwrap()).await.unwrap();

    // High threshold, short interval (1 second)
    let (logger, tx) = QueryLogger::new(db.clone(), 10000, 1);

    let handle = tokio::spawn(logger.run());

    // Send a couple entries (below threshold)
    for i in 0..2 {
        let ctx = QueryContext {
            timestamp: 3000 + i as i64,
            client_ip: "192.168.1.1".to_string(),
            domain: format!("interval{i}.com"),
            query_type: "A".to_string(),
            action: "allowed".to_string(),
            cached: false,
            upstream: None,
            doh_token: None,
            response_time_ms: 1,
            matched_rule: None,
            matched_list: None,
        };
        tx.send(ctx).await.unwrap();
    }

    // Wait for the interval to trigger (slightly more than 1 second)
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    // Verify entries were flushed by the timer
    let logs = db.query_logs(100, 0, None, None).await.unwrap();
    assert_eq!(logs.len(), 2);

    // Clean up
    drop(tx);
    handle.await.unwrap();
}
