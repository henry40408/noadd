use noadd::db::{Database, QueryLogEntry};
use tempfile::tempdir;

async fn test_db() -> Database {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.db");
    // Leak the dir so it lives for the duration of the test
    let path_str = path.to_str().unwrap().to_string();
    std::mem::forget(dir);
    Database::open(&path_str).await.unwrap()
}

#[tokio::test]
async fn test_database_creates_tables() {
    let db = test_db().await;
    let tables = db.list_tables().await.unwrap();
    assert!(tables.contains(&"settings".to_string()), "missing settings");
    assert!(
        tables.contains(&"query_logs".to_string()),
        "missing query_logs"
    );
    assert!(
        tables.contains(&"filter_lists".to_string()),
        "missing filter_lists"
    );
    assert!(
        tables.contains(&"custom_rules".to_string()),
        "missing custom_rules"
    );
    assert!(
        tables.contains(&"filter_list_content".to_string()),
        "missing filter_list_content"
    );
}

#[tokio::test]
async fn test_settings_get_set() {
    let db = test_db().await;
    db.set_setting("dns_port", "5353").await.unwrap();
    let val = db.get_setting("dns_port").await.unwrap();
    assert_eq!(val, Some("5353".to_string()));

    // Update existing setting
    db.set_setting("dns_port", "1053").await.unwrap();
    let val = db.get_setting("dns_port").await.unwrap();
    assert_eq!(val, Some("1053".to_string()));
}

#[tokio::test]
async fn test_settings_get_missing_returns_none() {
    let db = test_db().await;
    let val = db.get_setting("nonexistent").await.unwrap();
    assert_eq!(val, None);
}

#[tokio::test]
async fn test_insert_and_query_logs() {
    let db = test_db().await;
    let entries = vec![
        QueryLogEntry {
            timestamp: 1000000,
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "192.168.1.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 5,
        },
        QueryLogEntry {
            timestamp: 2000000,
            domain: "ads.tracker.com".to_string(),
            query_type: "AAAA".to_string(),
            client_ip: "192.168.1.2".to_string(),
            blocked: true,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
        },
    ];
    db.insert_query_logs(&entries).await.unwrap();

    // Query all
    let logs = db.query_logs(100, 0, None, None, None).await.unwrap();
    assert_eq!(logs.len(), 2);
    // Should be ordered by timestamp desc
    assert_eq!(logs[0].domain, "ads.tracker.com");
    assert_eq!(logs[1].domain, "example.com");

    // Filter by blocked
    let blocked = db.query_logs(100, 0, None, Some(true), None).await.unwrap();
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].domain, "ads.tracker.com");

    // Filter by search
    let searched = db
        .query_logs(100, 0, Some("example"), None, None)
        .await
        .unwrap();
    assert_eq!(searched.len(), 1);
    assert_eq!(searched[0].domain, "example.com");
}

#[tokio::test]
async fn test_query_logs_pagination() {
    let db = test_db().await;
    let mut entries = Vec::new();
    for i in 0..25 {
        entries.push(QueryLogEntry {
            timestamp: 1000000 + i * 1000,
            domain: format!("domain{}.com", i),
            query_type: "A".to_string(),
            client_ip: "192.168.1.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
        });
    }
    db.insert_query_logs(&entries).await.unwrap();

    let page1 = db.query_logs(10, 0, None, None, None).await.unwrap();
    assert_eq!(page1.len(), 10);
    // Ordered desc: domain24, domain23, ...
    assert_eq!(page1[0].domain, "domain24.com");

    let page2 = db.query_logs(10, 10, None, None, None).await.unwrap();
    assert_eq!(page2.len(), 10);
    assert_eq!(page2[0].domain, "domain14.com");

    let page3 = db.query_logs(10, 20, None, None, None).await.unwrap();
    assert_eq!(page3.len(), 5);
}

#[tokio::test]
async fn test_filter_lists_crud() {
    let db = test_db().await;

    // Add
    let id = db
        .add_filter_list("EasyList", "https://easylist.example.com/list.txt", true)
        .await
        .unwrap();
    assert!(id > 0);

    // Get all
    let lists = db.get_filter_lists().await.unwrap();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].name, "EasyList");
    assert_eq!(lists[0].url, "https://easylist.example.com/list.txt");
    assert!(lists[0].enabled);
    assert_eq!(lists[0].rule_count, 0);

    // Update enabled
    db.update_filter_list_enabled(id, false).await.unwrap();
    let lists = db.get_filter_lists().await.unwrap();
    assert!(!lists[0].enabled);

    // Update stats
    db.update_filter_list_stats(id, 42000, 9001).await.unwrap();
    let lists = db.get_filter_lists().await.unwrap();
    assert_eq!(lists[0].rule_count, 9001);
    assert_eq!(lists[0].last_updated, 42000);

    // Delete
    db.delete_filter_list(id).await.unwrap();
    let lists = db.get_filter_lists().await.unwrap();
    assert_eq!(lists.len(), 0);
}

#[tokio::test]
async fn test_custom_rules_crud() {
    let db = test_db().await;

    // Add
    let id = db
        .add_custom_rule("||ads.example.com^", "block")
        .await
        .unwrap();
    assert!(id > 0);

    let _id2 = db
        .add_custom_rule("@@||allowed.example.com^", "allow")
        .await
        .unwrap();

    // Get by type
    let block_rules = db.get_custom_rules_by_type("block").await.unwrap();
    assert_eq!(block_rules.len(), 1);
    assert_eq!(block_rules[0].rule, "||ads.example.com^");

    let allow_rules = db.get_custom_rules_by_type("allow").await.unwrap();
    assert_eq!(allow_rules.len(), 1);
    assert_eq!(allow_rules[0].rule, "@@||allowed.example.com^");

    // Delete
    db.delete_custom_rule(id).await.unwrap();
    let block_rules = db.get_custom_rules_by_type("block").await.unwrap();
    assert_eq!(block_rules.len(), 0);

    // Other type still exists
    let allow_rules = db.get_custom_rules_by_type("allow").await.unwrap();
    assert_eq!(allow_rules.len(), 1);
}

#[tokio::test]
async fn test_filter_list_content() {
    let db = test_db().await;

    // Add a filter list first
    let id = db
        .add_filter_list("TestList", "https://example.com/list.txt", true)
        .await
        .unwrap();

    // No content initially
    let content = db.get_filter_list_content(id).await.unwrap();
    assert_eq!(content, None);

    // Set content
    db.set_filter_list_content(id, "||ads.example.com^\n||tracker.example.com^")
        .await
        .unwrap();

    let content = db.get_filter_list_content(id).await.unwrap();
    assert_eq!(
        content,
        Some("||ads.example.com^\n||tracker.example.com^".to_string())
    );

    // Update content
    db.set_filter_list_content(id, "||newrule.com^")
        .await
        .unwrap();
    let content = db.get_filter_list_content(id).await.unwrap();
    assert_eq!(content, Some("||newrule.com^".to_string()));
}

#[tokio::test]
async fn test_count_queries_since() {
    let db = test_db().await;
    let entries = vec![
        QueryLogEntry {
            timestamp: 1000000,
            domain: "old.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 5,
        },
        QueryLogEntry {
            timestamp: 2000000,
            domain: "recent.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 3,
        },
        QueryLogEntry {
            timestamp: 3000000,
            domain: "blocked.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.2".to_string(),
            blocked: true,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
        },
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let (total, blocked) = db.count_queries_since(1500).await.unwrap();
    assert_eq!(total, 2);
    assert_eq!(blocked, 1);

    let (total, blocked) = db.count_queries_since(0).await.unwrap();
    assert_eq!(total, 3);
    assert_eq!(blocked, 1);
}

#[tokio::test]
async fn test_top_domains_since() {
    let db = test_db().await;
    let entries = vec![
        QueryLogEntry {
            timestamp: 1000000,
            domain: "popular.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
        },
        QueryLogEntry {
            timestamp: 2000000,
            domain: "popular.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
        },
        QueryLogEntry {
            timestamp: 3000000,
            domain: "rare.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
        },
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let top = db.top_domains_since(0, 10).await.unwrap();
    assert_eq!(top.len(), 2);
    assert_eq!(top[0].domain, "popular.com");
    assert_eq!(top[0].count, 2);
    assert_eq!(top[1].domain, "rare.com");
    assert_eq!(top[1].count, 1);

    // With limit
    let top = db.top_domains_since(0, 1).await.unwrap();
    assert_eq!(top.len(), 1);
}
