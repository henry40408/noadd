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
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);

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
async fn stats_v2_timeline_unauthenticated_returns_401() {
    let (app, _token) = setup().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/stats/v2/timeline?range=7d")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stats_v2_timeline_invalid_range_returns_400() {
    let (app, token) = setup().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/stats/v2/timeline?range=bogus")
                .header("cookie", format!("session={}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn stats_v2_timeline_empty_db_returns_empty_array() {
    let (app, token) = setup().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/stats/v2/timeline?range=7d")
                .header("cookie", format!("session={}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn stats_v2_health_returns_expected_fields() {
    let (app, token) = setup().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/stats/v2/health")
                .header("cookie", format!("session={}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body.get("db_size_bytes").is_some());
    assert!(body.get("total_log_count").is_some());
    assert!(body.get("oldest_log_timestamp").is_some());
    assert!(body.get("log_retention_days").is_some());
    assert!(body.get("avg_new_rows_per_day").is_some());
}
