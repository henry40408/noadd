use noadd::db::{Database, DeleteUserOutcome, QueryLogEntry};
use tempfile::tempdir;

async fn test_db() -> Database {
    let dir = tempdir().unwrap();
    // Persist the tempdir (no Drop cleanup) so it lives for the duration of the test.
    let path = dir.keep().join("test.db");
    let path_str = path.to_str().unwrap().to_string();
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
            timestamp: 1_000_000,
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "192.168.1.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 5,
            authenticated_data: false,
        },
        QueryLogEntry {
            timestamp: 2_000_000,
            domain: "ads.tracker.com".to_string(),
            query_type: "AAAA".to_string(),
            client_ip: "192.168.1.2".to_string(),
            blocked: true,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
            authenticated_data: false,
        },
    ];
    db.insert_query_logs(&entries).await.unwrap();

    // Query all
    let logs = db.query_logs(100, 0, None, None, None, None).await.unwrap();
    assert_eq!(logs.len(), 2);
    // Should be ordered by timestamp desc
    assert_eq!(logs[0].domain, "ads.tracker.com");
    assert_eq!(logs[1].domain, "example.com");

    // Filter by blocked
    let blocked = db
        .query_logs(100, 0, None, Some(true), None, None)
        .await
        .unwrap();
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].domain, "ads.tracker.com");

    // Filter by search
    let searched = db
        .query_logs(100, 0, Some("example"), None, None, None)
        .await
        .unwrap();
    assert_eq!(searched.len(), 1);
    assert_eq!(searched[0].domain, "example.com");
}

#[tokio::test]
async fn test_query_logs_search_prefix_fastpath() {
    let db = test_db().await;
    let entries = vec![
        QueryLogEntry {
            timestamp: 1_000_000,
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
            authenticated_data: false,
        },
        QueryLogEntry {
            timestamp: 1_000_001,
            domain: "api.example.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
            authenticated_data: false,
        },
        QueryLogEntry {
            timestamp: 1_000_002,
            domain: "subexample.net".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
            authenticated_data: false,
        },
        QueryLogEntry {
            timestamp: 1_000_003,
            domain: "tracker.io".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
            authenticated_data: false,
        },
    ];
    db.insert_query_logs(&entries).await.unwrap();

    // Plain term -> prefix match: "example" matches "example.com" but NOT
    // "api.example.com" (no longer a substring match) and NOT "subexample.net".
    let prefix = db
        .query_logs(100, 0, Some("example"), None, None, None)
        .await
        .unwrap();
    assert_eq!(prefix.len(), 1);
    assert_eq!(prefix[0].domain, "example.com");
    let prefix_total = db
        .count_logs(Some("example"), None, None, None)
        .await
        .unwrap();
    assert_eq!(prefix_total, 1);

    // Case-insensitive: search term is lowercased before matching.
    let mixed = db
        .query_logs(100, 0, Some("ExAmPlE"), None, None, None)
        .await
        .unwrap();
    assert_eq!(mixed.len(), 1);
    assert_eq!(mixed[0].domain, "example.com");

    // Wildcards -> substring LIKE fallback. "*example*" matches every domain
    // containing "example".
    let glob_substring = db
        .query_logs(100, 0, Some("*example*"), None, None, None)
        .await
        .unwrap();
    assert_eq!(glob_substring.len(), 3);
    let like_substring = db
        .query_logs(100, 0, Some("%example%"), None, None, None)
        .await
        .unwrap();
    assert_eq!(like_substring.len(), 3);

    // Empty / whitespace-only search behaves as "no filter".
    let blank = db
        .query_logs(100, 0, Some("   "), None, None, None)
        .await
        .unwrap();
    assert_eq!(blank.len(), entries.len());
}

#[tokio::test]
async fn test_query_logs_pagination() {
    let db = test_db().await;
    let mut entries = Vec::new();
    for i in 0..25 {
        entries.push(QueryLogEntry {
            timestamp: 1_000_000 + i * 1000,
            domain: format!("domain{i}.com"),
            query_type: "A".to_string(),
            client_ip: "192.168.1.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
            authenticated_data: false,
        });
    }
    db.insert_query_logs(&entries).await.unwrap();

    let page1 = db.query_logs(10, 0, None, None, None, None).await.unwrap();
    assert_eq!(page1.len(), 10);
    // Ordered desc: domain24, domain23, ...
    assert_eq!(page1[0].domain, "domain24.com");

    let page2 = db.query_logs(10, 10, None, None, None, None).await.unwrap();
    assert_eq!(page2.len(), 10);
    assert_eq!(page2[0].domain, "domain14.com");

    let page3 = db.query_logs(10, 20, None, None, None, None).await.unwrap();
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
            timestamp: 1_000_000,
            domain: "old.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 5,
            authenticated_data: false,
        },
        QueryLogEntry {
            timestamp: 2_000_000,
            domain: "recent.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 3,
            authenticated_data: false,
        },
        QueryLogEntry {
            timestamp: 3_000_000,
            domain: "blocked.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.2".to_string(),
            blocked: true,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
            authenticated_data: false,
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
            timestamp: 1_000_000,
            domain: "popular.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
            authenticated_data: false,
        },
        QueryLogEntry {
            timestamp: 2_000_000,
            domain: "popular.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
            authenticated_data: false,
        },
        QueryLogEntry {
            timestamp: 3_000_000,
            domain: "rare.com".to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            upstream: None,
            doh_token: None,
            result: None,
            response_ms: 1,
            authenticated_data: false,
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

#[tokio::test]
async fn test_read_conn_opens_and_basic_roundtrip_works() {
    // Verifies that Database::open successfully opens both connections
    // against the same file and that a write followed by a read still
    // works end-to-end after the read_conn infrastructure is wired.
    let db = test_db().await;
    let entry = QueryLogEntry {
        timestamp: 1_700_000_000_000,
        domain: "example.com".to_string(),
        query_type: "A".to_string(),
        client_ip: "127.0.0.1".to_string(),
        blocked: false,
        cached: false,
        response_ms: 1,
        upstream: None,
        doh_token: None,
        result: None,
        authenticated_data: false,
    };
    db.insert_query_logs(std::slice::from_ref(&entry))
        .await
        .unwrap();
    let rows = db.query_logs(10, 0, None, None, None, None).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].domain, "example.com");
}

#[tokio::test]
async fn test_users_crud() {
    let db = test_db().await;
    assert_eq!(db.count_users().await.unwrap(), 0);

    let id = db.create_user("alice", "hash-a", 1000).await.unwrap();
    assert_eq!(db.count_users().await.unwrap(), 1);

    let auth = db.get_user_auth("alice").await.unwrap().unwrap();
    assert_eq!(auth.id, id);
    assert_eq!(auth.password_hash.as_deref(), Some("hash-a"));
    assert!(db.get_user_auth("nobody").await.unwrap().is_none());

    assert_eq!(db.get_username(id).await.unwrap().as_deref(), Some("alice"));

    db.update_user_password(id, "hash-b").await.unwrap();
    assert_eq!(
        db.get_user_password_hash(id).await.unwrap().as_deref(),
        Some("hash-b")
    );

    let users = db.list_users().await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "alice");

    // The last remaining operator cannot be deleted.
    assert_eq!(
        db.delete_user(id).await.unwrap(),
        DeleteUserOutcome::LastOperator
    );
    assert_eq!(db.count_users().await.unwrap(), 1);

    // With a second operator present, a non-last operator can be deleted.
    let id2 = db.create_user("bob", "hash-b2", 2000).await.unwrap();
    assert_eq!(
        db.delete_user(id2).await.unwrap(),
        DeleteUserOutcome::Deleted
    );
    assert_eq!(db.count_users().await.unwrap(), 1);

    // A non-existent id (while more than one operator remains) reports NotFound.
    db.create_user("carol", "hash-c", 3000).await.unwrap();
    assert_eq!(
        db.delete_user(99999).await.unwrap(),
        DeleteUserOutcome::NotFound
    );
    assert_eq!(db.count_users().await.unwrap(), 2);
}

#[tokio::test]
async fn test_create_user_no_password() {
    let db = test_db().await;

    let id = db.create_user_no_password("dave", 1000).await.unwrap();

    let auth = db.get_user_auth("dave").await.unwrap().unwrap();
    assert_eq!(auth.id, id);
    assert!(
        auth.password_hash.is_none(),
        "forward-auth-provisioned account must have no password"
    );
    assert!(db.get_user_password_hash(id).await.unwrap().is_none());

    // The username UNIQUE constraint still applies to passwordless accounts.
    assert!(db.create_user_no_password("dave", 2000).await.is_err());
}

#[tokio::test]
async fn test_duplicate_username_rejected() {
    let db = test_db().await;
    db.create_user("bob", "h", 1).await.unwrap();
    assert!(db.create_user("bob", "h2", 2).await.is_err());
}

#[tokio::test]
async fn test_sessions_crud_and_cascade() {
    let db = test_db().await;
    let uid = db.create_user("carol", "h", 100).await.unwrap();

    let sid = db
        .insert_session("tok-1", uid, 100, 100, Some("1.2.3.4"), Some("UA"))
        .await
        .unwrap();

    let list = db.list_sessions().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].username, "carol");
    assert_eq!(list[0].token, "tok-1");
    assert_eq!(list[0].ip.as_deref(), Some("1.2.3.4"));

    // delete_session_by_id returns the token for in-memory eviction
    assert_eq!(
        db.delete_session_by_id(sid).await.unwrap().as_deref(),
        Some("tok-1")
    );
    assert!(db.list_sessions().await.unwrap().is_empty());
    assert!(db.delete_session_by_id(sid).await.unwrap().is_none());

    // Deleting the user cascades to their sessions. Add a second operator first
    // so carol is not the last one (which would be refused).
    db.insert_session("tok-2", uid, 100, 100, None, None)
        .await
        .unwrap();
    db.create_user("carol2", "h", 200).await.unwrap();
    assert_eq!(
        db.delete_user(uid).await.unwrap(),
        DeleteUserOutcome::Deleted
    );
    assert!(db.list_sessions().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_load_sessions_drops_expired() {
    let db = test_db().await;
    let uid = db.create_user("dave", "h", 0).await.unwrap();
    db.insert_session("fresh", uid, 1_000, 1_000, None, None)
        .await
        .unwrap();
    db.insert_session("stale", uid, 1, 1, None, None)
        .await
        .unwrap();

    // max_age 100, now 1100 → cutoff 1000; "stale" (created_at 1) is purged.
    let loaded = db.load_sessions(100, 1_100).await.unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].token, "fresh");
    assert!(
        db.list_sessions()
            .await
            .unwrap()
            .iter()
            .all(|s| s.token == "fresh")
    );
}

#[tokio::test]
async fn test_flush_last_seen() {
    let db = test_db().await;
    let uid = db.create_user("erin", "h", 0).await.unwrap();
    db.insert_session("tok", uid, 0, 0, None, None)
        .await
        .unwrap();
    db.flush_sessions_last_seen(&[("tok".to_string(), 555)])
        .await
        .unwrap();
    assert_eq!(db.list_sessions().await.unwrap()[0].last_seen, 555);
}
