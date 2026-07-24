//! Integration coverage for the first-line CSRF origin guard layered on the
//! admin router (`src/admin/csrf.rs`). The guard runs before any handler or
//! `AuthedUser` extraction, so these assert on status alone — a provably
//! cross-site unsafe-method request is short-circuited with 403, while
//! same-origin and header-less (CLI/bearer) requests reach their handler.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::mpsc;

use noadd::admin::api::{AppState, ServerInfo, admin_router};
use noadd::admin::auth::{RateLimiter, new_session_store};
use noadd::cache::DnsCache;
use noadd::db::{Database, QueryLogEntry};
use noadd::dns::handler::DnsHandler;
use noadd::filter::engine::FilterEngine;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

/// Build a bare admin router. No operator is provisioned — the guard fires
/// ahead of auth, so an unauthenticated app is enough to exercise it.
async fn build_app() -> axum::Router {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep().join("test.db");
    let db = Database::open(path.to_str().unwrap()).await.unwrap();

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
    let log_events = tokio::sync::broadcast::channel::<Arc<QueryLogEntry>>(256).0;

    admin_router(AppState {
        db,
        sessions: new_session_store(),
        filter,
        cache,
        rate_limiter,
        forwarder,
        handler,
        log_events,
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        cookie_secure: false,
        list_manager,
        rebuild: noadd::filter::rebuild::RebuildCoordinator::new(),
        registry: noadd::registry::RegistryClient::new(
            "http://127.0.0.1:1/filters.json".to_string(),
            std::time::Duration::from_secs(3600),
        ),
        trusted_proxies: Arc::new(noadd::net::TrustedProxies::default()),
        forward_auth: None,
    })
}

use tower::ServiceExt;

#[tokio::test]
async fn sec_fetch_site_cross_site_is_rejected() {
    let app = build_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/logout")
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn origin_host_mismatch_is_rejected() {
    let app = build_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/logout")
        .header("origin", "https://evil.test")
        .header("host", "app.test")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn same_origin_request_reaches_handler() {
    let app = build_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"username":"x","password":"y"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // The guard passes same-origin through; the handler then answers on its own
    // merits (bad creds → 401). What matters is it is NOT the guard's 403.
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn header_less_client_reaches_handler() {
    let app = build_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/rules")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"pattern":"example.com","action":"block"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // No Origin / Sec-Fetch-Site → treated as a non-browser client and passed
    // through; unauthenticated, so the handler rejects with 401, not the
    // guard's 403.
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
