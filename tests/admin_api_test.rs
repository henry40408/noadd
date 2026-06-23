use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use noadd::admin::api::{AppState, ServerInfo, admin_router};
use noadd::admin::auth::{
    RateLimiter, SessionInfo, generate_token, hash_password, new_session_store, store_session,
};
use noadd::cache::DnsCache;
use noadd::db::Database;
use noadd::dns::handler::DnsHandler;
use noadd::filter::engine::FilterEngine;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};
use tokio::sync::mpsc;

#[path = "common/mod.rs"]
mod common;

async fn setup() -> (axum::Router, String) {
    setup_inner("http://127.0.0.1:1/filters.json").await
}

#[allow(dead_code)]
async fn setup_with_registry_url(url: String) -> (axum::Router, String) {
    setup_inner(&url).await
}

async fn setup_inner(registry_url: &str) -> (axum::Router, String) {
    build_app(registry_url, true).await
}

/// Build a router whose admin password is NOT set, so `/api/auth/setup`
/// does not short-circuit with 409. Returns only the router (no session
/// token is meaningful before setup).
#[allow(dead_code)]
async fn unconfigured_app() -> axum::Router {
    build_app("http://127.0.0.1:1/filters.json", false).await.0
}

async fn build_app(registry_url: &str, set_password: bool) -> (axum::Router, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let path_str = path.to_str().unwrap().to_string();
    std::mem::forget(dir);

    let db = Database::open(&path_str).await.unwrap();
    let sessions = new_session_store();
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(
        vec![],
        vec![],
        vec![],
    )));
    let cache = DnsCache::new(100);
    let rate_limiter = Arc::new(RateLimiter::new(5, 60));
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);
    let (log_tx, _log_rx) = mpsc::channel(64);
    let handler = Arc::new(DnsHandler::new(
        filter.clone(),
        cache.clone(),
        forwarder.clone(),
        log_tx,
    ));

    let token = generate_token();
    // Create an operator user + bound session (skipped for unconfigured apps that test setup)
    if set_password {
        let hash = hash_password("admin").unwrap();
        let uid = db
            .create_user("admin", &hash, noadd::now_unix())
            .await
            .unwrap();
        let now = noadd::now_unix();
        let sid = db
            .insert_session(&token, uid, now, now, None, None)
            .await
            .unwrap();
        store_session(
            &sessions,
            &token,
            SessionInfo {
                session_id: sid,
                user_id: uid,
                created_at: now,
                last_seen: now,
            },
        );
    }

    let list_manager = Arc::new(noadd::filter::lists::ListManager::new(
        db.clone(),
        filter.clone(),
    ));
    let rebuild = noadd::filter::rebuild::RebuildCoordinator::new();
    let registry = noadd::registry::RegistryClient::new(
        registry_url.to_string(),
        std::time::Duration::from_secs(3600),
    );

    let router = admin_router(AppState {
        db,
        sessions,
        filter,
        cache,
        rate_limiter,
        forwarder,
        handler,
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        list_manager,
        rebuild,
        registry,
        trusted_proxies: std::sync::Arc::new(noadd::net::TrustedProxies::default()),
    });
    (router, token)
}

#[tokio::test]
async fn rebuild_status_unauthenticated_returns_401() {
    let (app, _token) = setup().await;
    let req = Request::builder()
        .uri("/api/filter/rebuild-status")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

async fn wait_for_rebuild(app: &axum::Router, token: &str, before: i64) {
    use std::time::Duration;
    for _ in 0..100 {
        let req = Request::builder()
            .uri("/api/filter/rebuild-status")
            .header("cookie", format!("session={}", token))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let rebuilding = body
            .get("rebuilding")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let last_completed_at = body
            .get("last_completed_at")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        if !rebuilding && last_completed_at >= before {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("rebuild did not complete within 2s");
}

#[tokio::test]
async fn batch_add_unauthenticated_returns_401() {
    let (app, _token) = setup().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/lists/batch")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"items":[]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn batch_add_rejects_empty() {
    let (app, token) = setup().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/lists/batch")
        .header("content-type", "application/json")
        .header("cookie", format!("session={}", token))
        .body(Body::from(r#"{"items":[]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn batch_add_rejects_oversized() {
    let (app, token) = setup().await;
    let items: Vec<serde_json::Value> = (0..51)
        .map(|i| serde_json::json!({"name": format!("n{i}"), "url": format!("http://x/{i}")}))
        .collect();
    let body = serde_json::json!({ "items": items });
    let req = Request::builder()
        .method("POST")
        .uri("/api/lists/batch")
        .header("content-type", "application/json")
        .header("cookie", format!("session={}", token))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn batch_add_all_success() {
    use noadd::now_unix;

    let base = common::spawn_fake_upstream(
        "/filter_a.txt",
        "||ads.example.com^\n".to_string(),
        "text/plain",
    )
    .await;

    let (app, token) = setup().await;
    let before = now_unix();
    let body = serde_json::json!({
        "items": [
            {"name": "A", "url": format!("{base}/filter_a.txt")}
        ]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/lists/batch")
        .header("content-type", "application/json")
        .header("cookie", format!("session={}", token))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["added"].as_array().unwrap().len(), 1);
    assert_eq!(v["failed"].as_array().unwrap().len(), 0);
    assert_eq!(v["added"][0]["name"], "A");
    assert!(v["added"][0]["rule_count"].as_i64().unwrap() >= 1);

    wait_for_rebuild(&app, &token, before).await;
}

#[tokio::test]
async fn batch_add_partial_failure() {
    let ok_base =
        common::spawn_fake_upstream("/ok.txt", "||ok.example.com^\n".to_string(), "text/plain")
            .await;
    let bad_base = common::spawn_fake_upstream_status("/bad.txt", 404).await;

    let (app, token) = setup().await;
    let body = serde_json::json!({
        "items": [
            {"name": "OK", "url": format!("{ok_base}/ok.txt")},
            {"name": "BAD", "url": format!("{bad_base}/bad.txt")}
        ]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/lists/batch")
        .header("content-type", "application/json")
        .header("cookie", format!("session={}", token))
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let added = v["added"].as_array().unwrap();
    let failed = v["failed"].as_array().unwrap();
    assert_eq!(added.len(), 1);
    assert_eq!(failed.len(), 1);
    assert_eq!(added[0]["name"], "OK");
    assert_eq!(failed[0]["name"], "BAD");

    // OK list exists; BAD list was rolled back and is absent.
    let lists_req = Request::builder()
        .uri("/api/lists")
        .header("cookie", format!("session={}", token))
        .body(Body::empty())
        .unwrap();
    let lists_resp = app.oneshot(lists_req).await.unwrap();
    let bytes = axum::body::to_bytes(lists_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let lists: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let arr = lists.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "OK");
}

#[tokio::test]
async fn registry_filters_unauthenticated_returns_401() {
    let (app, _token) = setup().await;
    let req = Request::builder()
        .uri("/api/registry/filters")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn registry_filters_returns_cached_data() {
    let base = common::spawn_fake_upstream(
        "/filters.json",
        r#"{"filters":[{"filterKey":"k","filterId":1,"groupId":1,"name":"N","description":"D","homepage":null,"downloadUrl":"http://example.com/f.txt","deprecated":false,"tags":[],"languages":[],"version":"1","expires":1,"displayNumber":1,"subscriptionUrl":"","timeAdded":"","timeUpdated":""}],"groups":[{"groupId":1,"groupName":"General"}],"tags":[]}"#.to_string(),
        "application/json",
    )
    .await;

    let (app, token) = setup_with_registry_url(format!("{base}/filters.json")).await;

    let req = Request::builder()
        .uri("/api/registry/filters")
        .header("cookie", format!("session={}", token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["filters"].as_array().unwrap().len(), 1);
    assert_eq!(body["groups"][0]["groupName"], "General");
}

#[tokio::test]
async fn rebuild_status_initial_is_idle() {
    let (app, token) = setup().await;
    let req = Request::builder()
        .uri("/api/filter/rebuild-status")
        .header("cookie", format!("session={}", token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body.get("rebuilding").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(body.get("started_at").and_then(|v| v.as_i64()), Some(0));
    assert_eq!(
        body.get("last_completed_at").and_then(|v| v.as_i64()),
        Some(0)
    );
    assert_eq!(
        body.get("last_duration_ms").and_then(|v| v.as_u64()),
        Some(0)
    );
}

#[tokio::test]
async fn test_health_endpoint_exposes_dropped_log_count() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let drops = body
        .get("dropped_log_count")
        .and_then(|v| v.as_u64())
        .expect("dropped_log_count should be present and a u64");
    assert_eq!(drops, 0, "fresh handler should have zero drops");
}

#[tokio::test]
async fn test_login_rate_limit_is_per_connect_info_ip() {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    let (app, _token) = setup().await;
    let addr1: SocketAddr = "203.0.113.5:40000".parse().unwrap();
    let addr2: SocketAddr = "203.0.113.6:40000".parse().unwrap();

    // Rate limiter is configured as (5, 60). Six failed logins from addr1
    // should exhaust the budget; a request from addr2 must still be served.
    let make_req = |addr: SocketAddr| {
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"username":"admin","password":"wrong"}"#))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        req
    };

    let mut last_status = StatusCode::OK;
    for _ in 0..6 {
        last_status = app.clone().oneshot(make_req(addr1)).await.unwrap().status();
    }
    assert_eq!(
        last_status,
        StatusCode::TOO_MANY_REQUESTS,
        "addr1 should be rate limited after 5 attempts"
    );

    let other = app.clone().oneshot(make_req(addr2)).await.unwrap();
    assert_eq!(
        other.status(),
        StatusCode::UNAUTHORIZED,
        "addr2 should hit auth failure, not rate limit — limits are per-IP"
    );
}

#[tokio::test]
async fn test_health_endpoint_no_auth() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_settings_requires_auth() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_settings_with_auth() {
    let (app, token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .header("cookie", format!("session={}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_login_success() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"admin","password":"admin"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Should have a Set-Cookie header
    let set_cookie = response.headers().get("set-cookie");
    assert!(set_cookie.is_some(), "Expected Set-Cookie header");
    let cookie_str = set_cookie.unwrap().to_str().unwrap();
    assert!(
        cookie_str.contains("session="),
        "Cookie should contain session token"
    );
    assert!(
        cookie_str.contains("Max-Age="),
        "Cookie should have Max-Age set for persistent sessions"
    );
}

#[tokio::test]
async fn test_login_wrong_password() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"admin","password":"wrong"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_lists_crud() {
    let (app, token) = setup().await;
    let cookie = format!("session={}", token);

    // Add a list
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/lists")
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .body(Body::from(
                    r#"{"name":"TestList","url":"https://example.com/list.txt"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Get lists
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/lists")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let lists: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0]["name"], "TestList");
}

#[tokio::test]
async fn test_rules_unified_api() {
    let (app, token) = setup().await;
    let cookie = format!("session={}", token);

    // Add allow rule (@@|| prefix → auto-detected as allow)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/rules")
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .body(Body::from(r#"{"rule":"@@||safe.example.com^"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Add block rule (|| prefix → auto-detected as block)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/rules")
                .header("content-type", "application/json")
                .header("cookie", &cookie)
                .body(Body::from(r#"{"rule":"||ads.example.com^"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Get all rules
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/rules")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let rules: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["rule"], "@@||safe.example.com^");
    assert_eq!(rules[0]["rule_type"], "allow");
    assert_eq!(rules[1]["rule"], "||ads.example.com^");
    assert_eq!(rules[1]["rule_type"], "block");

    // Delete first rule
    let id = rules[0]["id"].as_i64().unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/rules/{id}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_stats_requires_auth() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/stats/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_stats_summary_with_auth() {
    let (app, token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/stats/summary")
                .header("cookie", format!("session={}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let summary: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(summary["total_today"], 0);
    assert_eq!(summary["blocked_today"], 0);
}

#[tokio::test]
async fn test_logs_endpoint() {
    let (app, token) = setup().await;
    let cookie = format!("session={}", token);

    // Get logs (empty)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/logs")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 0);
    assert!(json["logs"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_setup_initial_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let path_str = path.to_str().unwrap().to_string();
    std::mem::forget(dir);

    let db = Database::open(&path_str).await.unwrap();
    let sessions = new_session_store();
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(
        vec![],
        vec![],
        vec![],
    )));
    let cache = DnsCache::new(100);
    let rate_limiter = Arc::new(RateLimiter::new(5, 60));
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);
    let (log_tx, _log_rx) = mpsc::channel(64);
    let handler = Arc::new(DnsHandler::new(
        filter.clone(),
        cache.clone(),
        forwarder.clone(),
        log_tx,
    ));

    let list_manager = Arc::new(noadd::filter::lists::ListManager::new(
        db.clone(),
        filter.clone(),
    ));
    let rebuild = noadd::filter::rebuild::RebuildCoordinator::new();
    let registry = noadd::registry::RegistryClient::new(
        "http://127.0.0.1:1/filters.json".to_string(),
        std::time::Duration::from_secs(3600),
    );

    // No user set initially
    let app = admin_router(AppState {
        db: db.clone(),
        sessions: sessions.clone(),
        filter: filter.clone(),
        cache: cache.clone(),
        rate_limiter: rate_limiter.clone(),
        forwarder: forwarder.clone(),
        handler: handler.clone(),
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        list_manager: list_manager.clone(),
        rebuild: rebuild.clone(),
        registry: registry.clone(),
        trusted_proxies: std::sync::Arc::new(noadd::net::TrustedProxies::default()),
    });

    // Setup should succeed
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"admin","password":"newpass1"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Setup again should fail (user already exists)
    let app2 = admin_router(AppState {
        db,
        sessions,
        filter,
        cache,
        rate_limiter,
        forwarder,
        handler,
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        list_manager,
        rebuild,
        registry,
        trusted_proxies: std::sync::Arc::new(noadd::net::TrustedProxies::default()),
    });
    let response = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"admin","password":"another12"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_upstream_strategy_setting() {
    let (app, token) = setup().await;

    // Set strategy to round-robin
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/settings")
                .header("content-type", "application/json")
                .header("cookie", format!("session={token}"))
                .body(Body::from(r#"{"upstream_strategy":"round-robin"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Read it back
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .header("cookie", format!("session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["upstream_strategy"], "round-robin");
}

#[tokio::test]
async fn test_filter_check_allowed() {
    let (app, token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/filter/check")
                .header("content-type", "application/json")
                .header("cookie", format!("session={token}"))
                .body(Body::from(r#"{"domain":"example.com"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["action"], "allowed");
}

#[tokio::test]
async fn test_filter_check_requires_auth() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/filter/check")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"example.com"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_upstream_latency_endpoint() {
    let (app, token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/upstream/latency")
                .header("cookie", format!("session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array());
}

#[tokio::test]
async fn test_missing_asset_returns_404_not_spa_fallback() {
    // Regression: /favicon.ico (and any other missing asset) used to be
    // swallowed by the SPA fallback and returned index.html with
    // content-type text/html, which broke the browser-auto favicon.
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/favicon.ico")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_existing_asset_served_with_correct_mime() {
    // /favicon.svg is bundled by PR #34 and must be served as image/svg+xml.
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/favicon.svg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let ctype = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ctype.starts_with("image/svg+xml"),
        "expected image/svg+xml, got {ctype}"
    );
}

#[tokio::test]
async fn test_spa_route_still_serves_index_html() {
    // Extension-less paths should still fall through to index.html so
    // client-side routing (e.g. /dashboard, /settings) keeps working.
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let ctype = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ctype.starts_with("text/html"),
        "expected text/html, got {ctype}"
    );
}

#[tokio::test]
async fn test_apple_touch_icon_served_as_png() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/apple-touch-icon.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let ctype = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ctype.starts_with("image/png"),
        "expected image/png, got {ctype}"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..8], b"\x89PNG\r\n\x1a\n", "missing PNG magic bytes");
    assert!(
        body.len() > 500,
        "PNG body suspiciously small: {} bytes",
        body.len()
    );
}

#[tokio::test]
async fn setup_rejects_short_password_with_400() {
    let app = unconfigured_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/setup")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"username":"admin","password":"1234567"}"#)) // 7 chars
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg.to_lowercase().contains("at least") || msg.contains("8"),
        "expected a too-short error message mentioning the minimum, got: {body}"
    );
}

#[tokio::test]
async fn setup_accepts_eight_char_password_with_200() {
    let app = unconfigured_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/setup")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"username":"admin","password":"12345678"}"#)) // 8 chars
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body.get("success").and_then(|v| v.as_bool()), Some(true));
}

#[tokio::test]
async fn setup_already_configured_returns_409() {
    let (app, _token) = setup().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/setup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"username":"admin","password":"another-long-pw"}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        body.get("error").and_then(|v| v.as_str()).is_some(),
        "expected a JSON error body for 409, got: {body}"
    );
}

#[tokio::test]
async fn test_index_served_with_etag_and_no_cache() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "etag not quoted: {etag}"
    );
    let cc = response
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(cc, "no-cache");
}

#[tokio::test]
async fn test_index_conditional_request_returns_304() {
    let (app, _token) = setup().await;

    let first = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let etag = first
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    let second = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("if-none-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
    let body = axum::body::to_bytes(second.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        body.is_empty(),
        "304 body should be empty, got {} bytes",
        body.len()
    );
}

#[tokio::test]
async fn test_favicon_svg_has_etag() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/favicon.svg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("etag").is_some(),
        "favicon.svg missing etag"
    );
}

#[tokio::test]
async fn test_apple_touch_icon_has_etag_and_no_cache() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/apple-touch-icon.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("etag").is_some(), "missing etag");
    let cc = response
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(cc, "no-cache");
}

#[tokio::test]
async fn test_apple_touch_icon_conditional_request_returns_304() {
    let (app, _token) = setup().await;

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/apple-touch-icon.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let etag = first
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    let second = app
        .oneshot(
            Request::builder()
                .uri("/apple-touch-icon.png")
                .header("if-none-match", &etag)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(second.status(), StatusCode::NOT_MODIFIED);
    let body = axum::body::to_bytes(second.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        body.is_empty(),
        "304 body should be empty, got {} bytes",
        body.len()
    );
}

#[tokio::test]
async fn login_with_wrong_username_is_unauthorized() {
    let (app, _token) = setup().await;
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"ghost","password":"admin"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

fn authed(method: &str, uri: &str, token: &str, body: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", format!("session={token}"));
    if body.is_some() {
        b = b.header("content-type", "application/json");
    }
    b.body(
        body.map(|s| Body::from(s.to_string()))
            .unwrap_or(Body::empty()),
    )
    .unwrap()
}

#[tokio::test]
async fn create_and_list_operators() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/users",
            &token,
            Some(r#"{"username":"bob","password":"longpass1"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // Duplicate → 409
    let res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/users",
            &token,
            Some(r#"{"username":"bob","password":"longpass1"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cannot_delete_last_operator() {
    let (app, token) = setup().await;
    // Only "admin" (id 1) exists.
    let res = app
        .oneshot(authed("DELETE", "/api/users/1", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn change_own_password_requires_correct_current() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed(
            "POST",
            "/api/users/me/password",
            &token,
            Some(r#"{"current_password":"wrong","new_password":"brandnewpass"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn setup_creates_first_operator_when_empty() {
    let app = unconfigured_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"root","password":"hunter2pass"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_sessions_marks_current_and_hides_token() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed("GET", "/api/sessions", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("\"is_current\":true"));
    assert!(
        !text.contains(&token),
        "raw token must never appear in the response"
    );
}

#[tokio::test]
async fn revoke_current_session_clears_cookie() {
    let (app, token) = setup().await;
    // The seeded session has id 1.
    let res = app
        .oneshot(authed("DELETE", "/api/sessions/1", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let set_cookie = res
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().to_string());
    assert!(set_cookie.unwrap_or_default().contains("session="));
}
