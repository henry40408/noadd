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
/// router, the backing Database, and the session store. Mirrors `build_app` in
/// `admin_api_test.rs`. The store is handed back so a test can seed a browser
/// session, which is now the only way to reach `POST /api/api-keys`.
async fn build_app() -> (axum::Router, Database, noadd::admin::auth::SessionStore) {
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
        sessions: sessions.clone(),
        filter,
        cache,
        rate_limiter,
        invalid_session_limiter: Arc::new(RateLimiter::new(
            noadd::admin::auth::INVALID_SESSION_MAX_ATTEMPTS,
            noadd::admin::auth::INVALID_SESSION_WINDOW_SECS,
        )),
        lockout: Arc::new(noadd::admin::auth::AccountLockout::new()),
        forwarder,
        handler,
        log_events: tokio::sync::broadcast::channel(256).0,
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:5353".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        cookie_secure: false,
        list_manager,
        rebuild,
        registry,
        trusted_proxies: Arc::new(noadd::net::TrustedProxies::default()),
        forward_auth: None,
    };
    (admin_router(state), db, sessions)
}

/// Seed a live browser session for operator 1 and return its raw token, for
/// the endpoints that no longer accept an API key.
fn seed_session(sessions: &noadd::admin::auth::SessionStore) -> String {
    use noadd::admin::auth::{SessionInfo, generate_token, hash_session_token, store_session};
    let token = generate_token();
    let now = noadd::now_unix();
    store_session(
        sessions,
        &hash_session_token(&token),
        SessionInfo {
            session_id: 1,
            user_id: 1,
            created_at: now,
            last_seen: now,
            last_reauth_at: now,
        },
    );
    token
}

#[tokio::test]
async fn bearer_api_key_authenticates_like_a_session() {
    let (app, db, _sessions) = build_app().await;

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

#[tokio::test]
async fn api_key_lifecycle_over_http() {
    use serde_json::json;
    let (app, db, sessions) = build_app().await;

    // Authenticate management calls with a bootstrap key for user 1.
    let (boot, prefix, hash) = generate_api_key();
    db.insert_api_key(1, "boot", &hash, &prefix, 0, None)
        .await
        .unwrap();
    let auth = format!("Bearer {boot}");

    // Create returns the full token exactly once. Minting a key is a
    // sensitive action, so it goes through a freshly-authenticated browser
    // session rather than the bootstrap key — see `key_cannot_mint_a_key`.
    let session = seed_session(&sessions);
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/api-keys")
                .header("cookie", format!("session={session}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"name": "ci"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let token = created["token"].as_str().unwrap();
    assert!(token.starts_with("noadd_"));
    let new_id = created["id"].as_i64().unwrap();

    // List never leaks a token/hash.
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/api-keys")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!body.contains("token_hash"));
    assert!(!body.contains(token));

    // Delete the created key.
    let res = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/api-keys/{new_id}"))
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// An API key can read and revoke keys, but it cannot mint one. A key holds
/// no password, so it can never satisfy the re-authentication requirement —
/// and allowing it would let a short-lived key quietly issue itself a
/// permanent successor.
#[tokio::test]
async fn an_api_key_cannot_mint_another_api_key() {
    use serde_json::json;
    let (app, db, _sessions) = build_app().await;
    let (boot, prefix, hash) = generate_api_key();
    db.insert_api_key(1, "boot", &hash, &prefix, 0, None)
        .await
        .unwrap();

    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/api-keys")
                .header("authorization", format!("Bearer {boot}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"name": "escalation"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // A distinct code from `reauth_required`: no password the caller could
    // type would help here, so a client must not prompt for one.
    assert_eq!(
        body.get("code").and_then(serde_json::Value::as_str),
        Some("password_required"),
        "got: {body}"
    );
}

#[tokio::test]
async fn docs_endpoints_require_auth() {
    let (app, db, _sessions) = build_app().await;

    let (full, prefix, hash) = generate_api_key();
    db.insert_api_key(1, "test", &hash, &prefix, 0, None)
        .await
        .unwrap();

    for uri in ["/api/openapi.json", "/api/docs"] {
        // No credentials -> 401.
        let res = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "{uri} should require auth"
        );

        // Valid bearer key -> 200.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("authorization", format!("Bearer {full}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "{uri} should be 200 with a valid key"
        );
    }
}
