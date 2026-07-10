use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::mpsc;
use tower::ServiceExt; // oneshot

use noadd::admin::api::{AppState, ServerInfo, admin_router};
use noadd::admin::auth::{RateLimiter, generate_api_key, new_session_store};
use noadd::cache::DnsCache;
use noadd::db::Database;
use noadd::dns::handler::DnsHandler;
use noadd::filter::engine::FilterEngine;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

/// Build the admin router with a seeded operator (`user_id` 1) and return the
/// router plus the backing Database. Mirrors `build_app` in `admin_api_test.rs`.
async fn build_app() -> (axum::Router, Database) {
    let dir = tempfile::tempdir().unwrap();
    // Persist the tempdir (no Drop cleanup) so the DB file lives for the test.
    let path = dir.keep().join("test.db");
    let path_str = path.to_str().unwrap().to_string();

    let db = Database::open(&path_str).await.unwrap();
    let hash = noadd::admin::auth::hash_password("admin").unwrap();
    db.create_user("admin", &hash, noadd::now_unix())
        .await
        .unwrap(); // id 1

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

    let state = AppState {
        db: db.clone(),
        sessions,
        filter,
        cache,
        rate_limiter,
        forwarder,
        handler,
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:5353".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        list_manager,
        rebuild,
        registry,
        trusted_proxies: Arc::new(noadd::net::TrustedProxies::default()),
    };
    (admin_router(state), db)
}

#[tokio::test]
async fn bearer_api_key_authenticates_like_a_session() {
    let (app, db) = build_app().await;

    let (full, prefix, hash) = generate_api_key();
    db.insert_api_key(1, "test", &hash, &prefix, 0, None)
        .await
        .unwrap();

    // Valid bearer key -> 200.
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/rules")
                .header("authorization", format!("Bearer {full}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // No credentials -> 401.
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/rules")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Garbage bearer token -> 401.
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/rules")
                .header("authorization", "Bearer noadd_not_a_real_key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
