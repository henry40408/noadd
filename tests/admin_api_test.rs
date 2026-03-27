use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use noadd::admin::api::{ServerInfo, admin_router};
use noadd::admin::auth::{RateLimiter, create_session, hash_password, new_session_store};
use noadd::cache::DnsCache;
use noadd::db::Database;
use noadd::filter::engine::FilterEngine;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

async fn setup() -> (axum::Router, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let path_str = path.to_str().unwrap().to_string();
    std::mem::forget(dir);

    let db = Database::open(&path_str).await.unwrap();
    let sessions = new_session_store();
    let token = create_session(&sessions);
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![])));
    let cache = DnsCache::new(100);
    let rate_limiter = Arc::new(RateLimiter::new(5, 60));
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()));

    // Set admin password
    let hash = hash_password("admin").unwrap();
    db.set_setting("admin_password_hash", &hash).await.unwrap();

    let router = admin_router(
        db,
        sessions,
        filter,
        cache,
        rate_limiter,
        forwarder,
        ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
    );
    (router, token)
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
                .body(Body::from(r#"{"password":"admin"}"#))
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
                .body(Body::from(r#"{"password":"wrong"}"#))
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
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![])));
    let cache = DnsCache::new(100);
    let rate_limiter = Arc::new(RateLimiter::new(5, 60));
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()));

    // No password set initially
    let app = admin_router(
        db.clone(),
        sessions.clone(),
        filter.clone(),
        cache.clone(),
        rate_limiter.clone(),
        forwarder.clone(),
        ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
    );

    // Setup should succeed
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"newpass"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Setup again should fail (password already exists)
    let app2 = admin_router(
        db,
        sessions,
        filter,
        cache,
        rate_limiter,
        forwarder,
        ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
    );
    let response = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"another"}"#))
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
