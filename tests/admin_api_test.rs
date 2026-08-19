use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio_stream::StreamExt;
use tower::ServiceExt;

use noadd::admin::api::{AppState, ServerInfo, admin_router};
use noadd::admin::auth::{
    RateLimiter, SessionInfo, SessionStore, generate_token, hash_password, hash_session_token,
    new_session_store, store_session,
};
use noadd::cache::{CacheKey, ClientResponseProfile, DnsCache};
use noadd::db::{Database, QueryLogEntry};
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
    let (app, token, _cache, _events) = build_app(registry_url, true).await;
    (app, token)
}

/// Build a router whose admin password is NOT set, so `/api/auth/setup`
/// does not short-circuit with 409. Returns only the router (no session
/// token is meaningful before setup).
#[allow(dead_code)]
async fn unconfigured_app() -> axum::Router {
    build_app("http://127.0.0.1:1/filters.json", false).await.0
}

async fn build_app(
    registry_url: &str,
    set_password: bool,
) -> (
    axum::Router,
    String,
    DnsCache,
    tokio::sync::broadcast::Sender<Arc<QueryLogEntry>>,
) {
    let (router, token, cache, log_events, _db, _sessions, _invalid_session_limiter) =
        build_app_opts(registry_url, set_password, false).await;
    (router, token, cache, log_events)
}

/// `build_app` with control over `AppState::cookie_secure`, for the tests that
/// assert the `Secure` attribute on the session cookie. Also hands back the
/// `Database` and `SessionStore` backing the router, so tests can seed extra
/// sessions directly into the same state the app queries, plus the
/// `invalid_session_limiter` the router counts unknown session cookies into.
async fn build_app_opts(
    registry_url: &str,
    set_password: bool,
    cookie_secure: bool,
) -> (
    axum::Router,
    String,
    DnsCache,
    tokio::sync::broadcast::Sender<Arc<QueryLogEntry>>,
    Database,
    SessionStore,
    Arc<RateLimiter>,
) {
    let dir = tempfile::tempdir().unwrap();
    // Persist the tempdir (no Drop cleanup) so the DB file lives for the test.
    let path = dir.keep().join("test.db");
    let path_str = path.to_str().unwrap().to_string();

    let db = Database::open(&path_str).await.unwrap();
    let sessions = new_session_store();
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(
        vec![],
        vec![],
        vec![],
    )));
    let cache = DnsCache::new(100);
    let rate_limiter = Arc::new(RateLimiter::new(5, 60));
    let lockout = Arc::new(noadd::admin::auth::AccountLockout::new());
    let invalid_session_limiter = Arc::new(RateLimiter::new(
        noadd::admin::auth::INVALID_SESSION_MAX_ATTEMPTS,
        noadd::admin::auth::INVALID_SESSION_WINDOW_SECS,
    ));
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
            .insert_session(&hash_session_token(&token), uid, now, now, None, None)
            .await
            .unwrap();
        store_session(
            &sessions,
            &hash_session_token(&token),
            SessionInfo {
                session_id: sid,
                user_id: uid,
                created_at: now,
                last_seen: now,
                last_reauth_at: now,
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

    let log_events = tokio::sync::broadcast::channel(256).0;

    let router = admin_router(AppState {
        db: db.clone(),
        sessions: sessions.clone(),
        filter,
        cache: cache.clone(),
        rate_limiter,
        invalid_session_limiter: invalid_session_limiter.clone(),
        lockout: lockout.clone(),
        forwarder,
        handler,
        log_events: log_events.clone(),
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        cookie_secure,
        list_manager,
        rebuild,
        registry,
        trusted_proxies: std::sync::Arc::new(noadd::net::TrustedProxies::default()),
        forward_auth: None,
    });
    (
        router,
        token,
        cache,
        log_events,
        db,
        sessions,
        invalid_session_limiter,
    )
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
            .header("cookie", format!("session={token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let rebuilding = body
            .get("rebuilding")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        // started_at >= before proves *this* rebuild began, and !rebuilding
        // that it finished — the pair the endpoint still reports since
        // last_completed_at was dropped as unread by any consumer.
        let started_at = body
            .get("started_at")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        if !rebuilding && started_at >= before {
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
        .header("cookie", format!("session={token}"))
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
        .header("cookie", format!("session={token}"))
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
        .header("cookie", format!("session={token}"))
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
        .header("cookie", format!("session={token}"))
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
        .header("cookie", format!("session={token}"))
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
        .header("cookie", format!("session={token}"))
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
        .header("cookie", format!("session={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body.get("rebuilding").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        body.get("started_at").and_then(serde_json::Value::as_i64),
        Some(0)
    );
    assert!(
        body.get("last_completed_at").is_none(),
        "last_completed_at was dropped: no consumer read it"
    );
    assert_eq!(
        body.get("last_duration_ms")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
}

#[tokio::test]
async fn test_health_endpoint_reports_no_drop_counter() {
    // Dropped query-log events are reported by an error-level log line, not
    // by a counter on this endpoint: a cumulative per-process number carries
    // neither a time nor a denominator, so it cannot tell an operator whether
    // loss is happening now or mattered at all. Pinned so the field is not
    // reintroduced as an apparently-free addition.
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
    assert!(
        body.get("dropped_log_count").is_none(),
        "dropped_log_count should not be part of the health payload"
    );
    assert_eq!(body.get("status").and_then(|v| v.as_str()), Some("ok"));
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
                .header("cookie", format!("session={token}"))
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

/// Log in against `app` and return the raw `Set-Cookie` value.
async fn login_set_cookie(app: axum::Router) -> String {
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
    response
        .headers()
        .get("set-cookie")
        .expect("login must emit a Set-Cookie header")
        .to_str()
        .unwrap()
        .to_string()
}

/// The stored identifier must not *be* the credential. A copy of the database
/// — a backup, a stray WAL file, a discarded SD card — must not hand over a
/// live session the way it did while `sessions.token` held plaintext.
#[tokio::test]
async fn login_persists_a_hash_never_the_cookie_value() {
    let (app, _token, _cache, _events, db, sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    let set_cookie = login_set_cookie(app).await;
    let cookie_value = set_cookie
        .split_once("session=")
        .expect("login must set the session cookie")
        .1
        .split(';')
        .next()
        .unwrap()
        .to_string();

    let rows = db.list_sessions().await.unwrap();
    assert!(
        rows.iter()
            .all(|r| r.token_hash != cookie_value && !r.token_hash.is_empty()),
        "no row may hold the raw cookie value"
    );
    assert!(
        rows.iter()
            .any(|r| r.token_hash == hash_session_token(&cookie_value)),
        "the session must be persisted under the hash of the cookie value"
    );
    // The in-memory store is keyed the same way, which is what lets a row
    // deleted by id be evicted from memory by the value the DELETE returned.
    let live = sessions.lock();
    assert!(!live.contains_key(&cookie_value));
    assert!(live.contains_key(&hash_session_token(&cookie_value)));
}

#[tokio::test]
async fn test_login_cookie_secure_when_enabled() {
    let (app, _token, _cache, _events, _db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, true).await;
    let cookie = login_set_cookie(app).await;
    assert!(
        cookie.contains("Secure"),
        "cookie_secure must put Secure on the session cookie: {cookie}"
    );
    // The other attributes must survive alongside it.
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Lax"), "{cookie}");
    // `Secure` implies the `__Host-` prefix, which gets the browser to also
    // enforce `Path=/` and no `Domain` and blocks a subdomain override.
    assert!(
        cookie.starts_with("__Host-session="),
        "cookie_secure must emit the __Host- prefixed name: {cookie}"
    );
}

#[tokio::test]
async fn test_login_cookie_not_secure_when_disabled() {
    // TLS terminates upstream (or not at all): a Secure cookie would be
    // dropped by the browser over plain HTTP and lock the operator out.
    let (app, _token, _cache, _events, _db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    let cookie = login_set_cookie(app).await;
    assert!(
        !cookie.contains("Secure"),
        "session cookie must not be Secure when cookie_secure is off: {cookie}"
    );
    // A browser silently rejects `__Host-`-prefixed cookies that aren't
    // `Secure`, so the plain-HTTP name must stay unprefixed.
    assert!(
        cookie.starts_with("session=") && !cookie.contains("__Host-"),
        "cookie_secure=false must keep the plain session cookie name: {cookie}"
    );
}

#[tokio::test]
async fn host_prefixed_cookie_is_accepted_on_read() {
    let (app, token, _cache, _events, _db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, true).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/auth/me")
                .header("cookie", format!("__Host-session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn legacy_cookie_name_still_accepted_when_secure() {
    // A restart that flips `cookie_secure` on (new TLS cert, added
    // `--cookie-secure`) must not invalidate sessions issued under the old,
    // unprefixed name.
    let (app, token, _cache, _events, _db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, true).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/auth/me")
                .header("cookie", format!("session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn logout_clears_the_host_prefixed_cookie() {
    let (app, token, _cache, _events, _db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, true).await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/logout")
                .header("cookie", format!("__Host-session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .expect("logout must clear the session cookie")
        .to_str()
        .unwrap();
    assert!(
        set_cookie.starts_with("__Host-session="),
        "logout must clear the name actually present on the request: {set_cookie}"
    );
    assert!(
        set_cookie.contains("Max-Age=0"),
        "cleared cookie must expire immediately: {set_cookie}"
    );
    // RFC 6265bis §5.5: a browser ignores a `__Host-`-prefixed `Set-Cookie`
    // that isn't `Secure`, so without this the removal is silently dropped
    // and the browser keeps sending the "deleted" cookie forever.
    assert!(
        set_cookie.contains("Secure"),
        "the __Host- removal must carry Secure or browsers ignore it entirely: {set_cookie}"
    );
}

/// OWASP session-ID brute-force detection: a client presenting cookies that
/// name no live session must be counted per source IP, so a burst becomes
/// visible in the audit log instead of being silently 401'd forever.
///
/// Asserted through the limiter the router counts into rather than through the
/// log line, which is the only observable the router exposes: after
/// `MAX_ATTEMPTS - 1` rejected requests, the test's own attempt must be the one
/// that crosses the threshold — which it can only be if the router counted
/// every preceding request.
#[tokio::test]
async fn unknown_session_cookies_are_counted_per_source_ip() {
    let (app, _token, _cache, _events, _db, _sessions, limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    let attempts = noadd::admin::auth::INVALID_SESSION_MAX_ATTEMPTS;
    for i in 0..attempts - 1 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/auth/me")
                    .header("cookie", format!("session=not-a-real-token-{i}"))
                    .header("x-forwarded-for", "203.0.113.7")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        limiter.tracked_ips(),
        1,
        "the guessing client must be tracked under exactly one source IP"
    );
    assert!(
        limiter.record_crossing("203.0.113.7".parse().unwrap()),
        "the router must have counted the preceding {} rejections, making this one the threshold",
        attempts - 1
    );
}

/// The counter must fire only on a *presented* session cookie. An
/// unauthenticated request that carries none (a first page load, an API client
/// that forgot its bearer token) is not a guess and must leave no trace —
/// otherwise ordinary 401s would drown the signal the burst warning exists for.
#[tokio::test]
async fn requests_without_a_session_cookie_are_not_counted() {
    let (app, _token, _cache, _events, _db, _sessions, limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    for _ in 0..noadd::admin::auth::INVALID_SESSION_MAX_ATTEMPTS {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/auth/me")
                    .header("x-forwarded-for", "203.0.113.7")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        limiter.tracked_ips(),
        0,
        "a request with no session cookie must not be counted as a guess"
    );
}

#[tokio::test]
async fn stale_host_cookie_does_not_shadow_a_valid_legacy_cookie() {
    // Reproduces the lockout: an operator's browser holds a stale
    // `__Host-session` (e.g. from before TLS termination moved to a reverse
    // proxy) alongside a freshly-issued, valid `session` cookie. Auth must
    // fall through to the cookie that actually validates rather than getting
    // stuck on the positionally-preferred but dead `__Host-` one.
    let (app, token, _cache, _events, _db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/auth/me")
                .header(
                    "cookie",
                    format!("__Host-session=not-a-real-token; session={token}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a valid `session` cookie must authenticate even alongside an invalid __Host-session"
    );
}

#[tokio::test]
async fn stale_legacy_cookie_does_not_shadow_a_valid_host_cookie() {
    // Mirror case: a valid `__Host-session` alongside a stale unprefixed
    // `session` cookie must still authenticate via the valid one.
    let (app, token, _cache, _events, _db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/auth/me")
                .header(
                    "cookie",
                    format!("__Host-session={token}; session=not-a-real-token"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a valid __Host-session cookie must authenticate even alongside an invalid session"
    );
}

#[tokio::test]
async fn logout_revokes_the_session_that_authenticated_the_request() {
    // Reproduces the bug: a browser can hold a stale `__Host-session`
    // alongside a live `session` cookie (see `session_cookie_hashes`).
    // `AuthedUser` correctly authenticates via the live one, but `logout`
    // used to act on whichever cookie was positionally first — clearing only
    // the stale name and reporting success while the live token, the one
    // that actually authenticated this very request, stayed valid.
    let (app, token, _cache, _events, _db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/logout")
                .header(
                    "cookie",
                    format!("__Host-session=stalegarbage; session={token}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let set_cookies: Vec<String> = response
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert!(
        set_cookies.iter().any(|c| c.starts_with("__Host-session=")),
        "logout must clear the __Host-session cookie too: {set_cookies:?}"
    );
    assert!(
        set_cookies.iter().any(|c| c.starts_with("session=")),
        "logout must clear the plain session cookie: {set_cookies:?}"
    );

    let me = app
        .oneshot(
            Request::builder()
                .uri("/api/auth/me")
                .header("cookie", format!("session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        me.status(),
        StatusCode::UNAUTHORIZED,
        "logout must revoke the session that actually authenticated the logout request, \
         not merely the positionally-first cookie"
    );
}

#[tokio::test]
async fn logout_revokes_every_live_session_named_by_a_cookie() {
    // Both accepted cookie names can each name a *live* session at once (log
    // in over plain HTTP, then again once the operator turns on TLS /
    // --cookie-secure). `logout` used to resolve a single token and revoke
    // only that one, even though it clears both cookie names regardless —
    // leaving the other session live server-side, still listed in
    // `GET /api/sessions` and replayable by anyone holding its token, for up
    // to the idle/absolute window.
    let (app, token_a, _cache, _events, db, sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    let admin_id = db
        .list_users()
        .await
        .unwrap()
        .into_iter()
        .find(|u| u.username == "admin")
        .unwrap()
        .id;

    // Seed a second, independently-live session (token B) for the same operator.
    let token_b = generate_token();
    let now = noadd::now_unix();
    let sid = db
        .insert_session(
            &hash_session_token(&token_b),
            admin_id,
            now,
            now,
            None,
            None,
        )
        .await
        .unwrap();
    store_session(
        &sessions,
        &hash_session_token(&token_b),
        SessionInfo {
            session_id: sid,
            user_id: admin_id,
            created_at: now,
            last_seen: now,
            last_reauth_at: now,
        },
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/logout")
                .header(
                    "cookie",
                    format!("__Host-session={token_a}; session={token_b}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let me_a = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/auth/me")
                .header("cookie", format!("session={token_a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        me_a.status(),
        StatusCode::UNAUTHORIZED,
        "logout must revoke the __Host-session token"
    );

    let me_b = app
        .oneshot(
            Request::builder()
                .uri("/api/auth/me")
                .header("cookie", format!("session={token_b}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        me_b.status(),
        StatusCode::UNAUTHORIZED,
        "logout must revoke every live session named by a cookie, not just the one \
         that authenticated the request"
    );
}

#[tokio::test]
async fn revoke_others_keeps_the_authenticated_session() {
    // Same two-cookie shape as `logout_revokes_the_session_that_authenticated_the_request`:
    // `revoke_others` used to pass the positionally-first cookie (the stale
    // `__Host-session`) as `keep`, so `retain`/`DELETE ... WHERE token != stale`
    // matched nothing and the caller's own live session — the one this
    // request authenticated with — was revoked along with everyone else's,
    // even though the endpoint is documented as "stay signed in on this
    // device".
    let (app, token, _cache, _events, _db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/revoke-others")
                .header(
                    "cookie",
                    format!("__Host-session=stalegarbage; session={token}"),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let me = app
        .oneshot(
            Request::builder()
                .uri("/api/auth/me")
                .header("cookie", format!("session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        me.status(),
        StatusCode::OK,
        "revoke-others must keep the session that authenticated the request signed in"
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
    let cookie = format!("session={token}");

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
    let cookie = format!("session={token}");

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
    let summary: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(summary["total_today"], 0);
    assert_eq!(summary["blocked_today"], 0);
}

#[tokio::test]
async fn test_logs_endpoint() {
    let (app, token) = setup().await;
    let cookie = format!("session={token}");

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
    // Persist the tempdir (no Drop cleanup) so the DB file lives for the test.
    let path = dir.keep().join("test.db");
    let path_str = path.to_str().unwrap().to_string();

    let db = Database::open(&path_str).await.unwrap();
    let sessions = new_session_store();
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(
        vec![],
        vec![],
        vec![],
    )));
    let cache = DnsCache::new(100);
    let rate_limiter = Arc::new(RateLimiter::new(5, 60));
    let lockout = Arc::new(noadd::admin::auth::AccountLockout::new());
    let invalid_session_limiter = Arc::new(RateLimiter::new(
        noadd::admin::auth::INVALID_SESSION_MAX_ATTEMPTS,
        noadd::admin::auth::INVALID_SESSION_WINDOW_SECS,
    ));
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
        invalid_session_limiter: invalid_session_limiter.clone(),
        lockout: lockout.clone(),
        forwarder: forwarder.clone(),
        handler: handler.clone(),
        log_events: tokio::sync::broadcast::channel(256).0,
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        cookie_secure: false,
        list_manager: list_manager.clone(),
        rebuild: rebuild.clone(),
        registry: registry.clone(),
        trusted_proxies: std::sync::Arc::new(noadd::net::TrustedProxies::default()),
        forward_auth: None,
    });

    // Setup should succeed
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"admin","password":"newpassphrase1"}"#,
                ))
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
        invalid_session_limiter,
        lockout: lockout.clone(),
        forwarder,
        handler,
        log_events: tokio::sync::broadcast::channel(256).0,
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        cookie_secure: false,
        list_manager,
        rebuild,
        registry,
        trusted_proxies: std::sync::Arc::new(noadd::net::TrustedProxies::default()),
        forward_auth: None,
    });
    let response = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"admin","password":"another-passphrase"}"#,
                ))
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
async fn test_dnssec_disabled_setting_round_trip() {
    let (app, token) = setup().await;

    // Write dnssec_disabled = "true"
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/settings")
                .header("content-type", "application/json")
                .header("cookie", format!("session={token}"))
                .body(Body::from(r#"{"dnssec_disabled":"true"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Read it back — must appear in GET /api/settings
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
    assert_eq!(
        json["dnssec_disabled"], "true",
        "dnssec_disabled must be returned by GET /api/settings"
    );
}

#[tokio::test]
async fn test_invalid_block_mode_rejected_and_not_persisted() {
    let (app, token) = setup().await;

    let response = app
        .clone()
        .oneshot(authed(
            "PUT",
            "/api/settings",
            &token,
            Some(r#"{"block_mode":"bogus"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app
        .oneshot(authed("GET", "/api/settings", &token, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.get("block_mode").is_none(),
        "invalid block_mode must not be persisted, got: {json}"
    );
}

#[tokio::test]
async fn test_invalid_block_custom_ipv4_rejected() {
    let (app, token) = setup().await;

    let response = app
        .clone()
        .oneshot(authed(
            "PUT",
            "/api/settings",
            &token,
            Some(r#"{"block_mode":"custom_ip","block_custom_ipv4":"not-an-ip"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Verify no partial write: block_mode must not have been persisted even
    // though it was valid, since the request as a whole was rejected.
    let response = app
        .oneshot(authed("GET", "/api/settings", &token, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json.get("block_mode").is_none(),
        "block_mode must not be persisted when the request is rejected, got: {json}"
    );
}

#[tokio::test]
async fn test_block_mode_partial_update_preserves_custom_ips() {
    let (app, token) = setup().await;

    // Set block_mode + both custom IPs.
    let response = app
        .clone()
        .oneshot(authed(
            "PUT",
            "/api/settings",
            &token,
            Some(
                r#"{"block_mode":"custom_ip","block_custom_ipv4":"192.0.2.1","block_custom_ipv6":"100::1"}"#,
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Now send a partial update with only block_mode set again; the
    // previously stored custom IPs must be preserved (merge-on-apply),
    // not wiped out.
    let response = app
        .clone()
        .oneshot(authed(
            "PUT",
            "/api/settings",
            &token,
            Some(r#"{"block_mode":"custom_ip"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(authed("GET", "/api/settings", &token, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["block_mode"], "custom_ip");
    assert_eq!(
        json["block_custom_ipv4"], "192.0.2.1",
        "partial update must not wipe previously stored block_custom_ipv4, got: {json}"
    );
    assert_eq!(
        json["block_custom_ipv6"], "100::1",
        "partial update must not wipe previously stored block_custom_ipv6, got: {json}"
    );
}

#[tokio::test]
async fn test_block_mode_nxdomain_round_trip() {
    let (app, token) = setup().await;

    let response = app
        .clone()
        .oneshot(authed(
            "PUT",
            "/api/settings",
            &token,
            Some(r#"{"block_mode":"nxdomain"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(authed("GET", "/api/settings", &token, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["block_mode"], "nxdomain");
}

#[tokio::test]
async fn test_block_mode_custom_ip_with_valid_addresses_accepted() {
    let (app, token) = setup().await;

    let response = app
        .clone()
        .oneshot(authed(
            "PUT",
            "/api/settings",
            &token,
            Some(
                r#"{"block_mode":"custom_ip","block_custom_ipv4":"192.0.2.1","block_custom_ipv6":"100::1"}"#,
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(authed("GET", "/api/settings", &token, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["block_mode"], "custom_ip");
    assert_eq!(json["block_custom_ipv4"], "192.0.2.1");
    assert_eq!(json["block_custom_ipv6"], "100::1");
}

#[tokio::test]
async fn test_dnssec_setting_change_invalidates_dns_cache() {
    let (app, token, cache, _events) = build_app("http://127.0.0.1:1/filters.json", true).await;
    let key = CacheKey::new(
        "example.com".to_string(),
        1,
        ClientResponseProfile::default(),
    );
    cache
        .insert(
            key.clone(),
            vec![0xde, 0xad, 0xbe, 0xef],
            std::time::Duration::from_secs(300),
            false,
        )
        .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/settings")
                .header("content-type", "application/json")
                .header("cookie", format!("session={token}"))
                .body(Body::from(r#"{"dnssec_disabled":"true"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        cache.get(&key).await.is_none(),
        "DNSSEC policy changes must not leave old wire responses cached"
    );
}

#[tokio::test]
async fn test_dnssec_setting_unchanged_keeps_dns_cache() {
    // The forwarder defaults to DNSSEC enabled (dnssec_disabled=false). Re-sending
    // that same value must not flush every client's cache.
    let (app, token, cache, _events) = build_app("http://127.0.0.1:1/filters.json", true).await;
    let key = CacheKey::new(
        "example.com".to_string(),
        1,
        ClientResponseProfile::default(),
    );
    cache
        .insert(
            key.clone(),
            vec![0xde, 0xad, 0xbe, 0xef],
            std::time::Duration::from_secs(300),
            false,
        )
        .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/settings")
                .header("content-type", "application/json")
                .header("cookie", format!("session={token}"))
                .body(Body::from(r#"{"dnssec_disabled":"false"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        cache.get(&key).await.is_some(),
        "an unchanged DNSSEC setting must not wipe the cache"
    );
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
async fn test_unknown_path_404s_rather_than_serving_a_shell() {
    // The SPA fallback is gone: it existed so a client-side route the server
    // knew nothing about still received the shell for the router to act on, and
    // every page path is a real route now. `/dashboard` was never one of them —
    // the dashboard is `/` — so it is exactly the stale link this must not
    // answer with a document.
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

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let ctype = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        !ctype.starts_with("text/html"),
        "a 404 must not look like a page, got {ctype}"
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

/// A `tracing` sink that keeps everything written to it, so a test can assert
/// on the audit events a handler emitted.
///
/// Under nextest each test is its own process, so installing a
/// thread-local default subscriber cannot leak into another test.
#[derive(Clone)]
struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

impl CapturedLogs {
    fn new() -> Self {
        Self(Arc::new(std::sync::Mutex::new(Vec::new())))
    }

    /// The captured output, one JSON object per line.
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }

    /// Install as the default subscriber for as long as the returned guard
    /// lives. JSON so a field can be matched as `"field":value` rather than
    /// by groping through prose.
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(self.clone())
            .with_max_level(tracing::Level::INFO)
            .finish();
        tracing::subscriber::set_default(subscriber)
    }
}

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Source string for the maximum-length boundary tests. It has to be long
/// enough to slice 128 characters out of *and* score well on zxcvbn, which
/// rules out the obvious `"a".repeat(128)` — a run of one character is scored
/// as a repeat and rejected for guessability, which would make the test pass
/// or fail for a reason that has nothing to do with the length boundary.
const STRONG_LONG_PASSPHRASE: &str = concat!(
    "vermilion-thicket-marlin-quartz-nimbus-cobalt-drift-walnut-orbit-",
    "vermilion-thicket-marlin-quartz-nimbus-cobalt-drift-walnut-orbit-",
);

/// Same idea for the characters-not-bytes test: 100 *distinct* CJK characters,
/// because `"密".repeat(100)` is a repeat and would be rejected on
/// guessability before the length check could be observed.
const STRONG_CJK_PASSPHRASE: &str = concat!(
    "山川河海風雲雷電花鳥魚蟲松竹梅蘭菊石泉澗谷嶺峰崖壁沙丘湖泊溪橋亭台樓閣舟車馬牛羊犬雞鴨鵝鶴鹿虎豹熊狼",
    "狐兔鼠蛇龜蛙蟬蝶蜂蟻蚊蠅蛛天地玄黃宇宙洪荒日月盈昃辰宿列張寒來暑往秋收冬藏閏餘成歲律呂調陽雲騰致雨",
);

#[tokio::test]
async fn setup_rejects_short_password_with_400() {
    let app = unconfigured_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/setup")
        .header("content-type", "application/json")
        // One character under the 12-character minimum: the boundary, not an
        // arbitrarily short string, so a minimum accidentally applied as `<=`
        // or read off by one still fails this.
        .body(Body::from(
            r#"{"username":"admin","password":"Yx7#qvLm2R!"}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg.to_lowercase().contains("at least"),
        "expected a too-short error message mentioning the minimum, got: {body}"
    );
}

#[tokio::test]
async fn setup_accepts_a_password_at_the_minimum_length_with_200() {
    let app = unconfigured_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/setup")
        .header("content-type", "application/json")
        // Exactly the 12-character minimum — the other side of the boundary
        // the test above guards.
        .body(Body::from(
            r#"{"username":"admin","password":"Yx7#qvLm2Rk!"}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body.get("success").and_then(serde_json::Value::as_bool),
        Some(true)
    );
}

/// A password past the 128-character maximum must be rejected outright rather
/// than truncated to fit: truncation would make every password sharing the
/// first 128 characters open the same account.
#[tokio::test]
async fn setup_rejects_an_over_long_password_with_400() {
    let app = unconfigured_app().await;
    let too_long = "a".repeat(129);
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/setup")
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"username":"admin","password":"{too_long}"}}"#
        )))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg.to_lowercase().contains("at most"),
        "expected a too-long error message mentioning the maximum, got: {body}"
    );
}

/// The maximum is a boundary, not a vibe: 128 characters exactly must still be
/// accepted.
#[tokio::test]
async fn setup_accepts_a_password_at_the_maximum_length_with_200() {
    let app = unconfigured_app().await;
    let at_max: String = STRONG_LONG_PASSPHRASE.chars().take(128).collect();
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/setup")
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"username":"admin","password":"{at_max}"}}"#
        )))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// The length band is counted in characters, not bytes. A 12-character CJK
/// passphrase is 36 bytes; a byte-counting minimum would accept it for the
/// wrong reason, and a byte-counting maximum would reject a perfectly ordinary
/// 50-character one.
#[tokio::test]
async fn password_length_is_counted_in_characters_not_bytes() {
    // 11 characters / 33 bytes — under the minimum however many bytes it is.
    let app = unconfigured_app().await;
    let eleven_chars: String = STRONG_CJK_PASSPHRASE.chars().take(11).collect();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"username":"admin","password":"{eleven_chars}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "11 characters is under the minimum even though it is 33 bytes"
    );

    // 100 characters / 300 bytes — comfortably inside a character-counted
    // maximum, well past a byte-counted one.
    let app = unconfigured_app().await;
    let hundred_chars: String = STRONG_CJK_PASSPHRASE.chars().take(100).collect();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"username":"admin","password":"{hundred_chars}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "100 characters is inside the maximum even though it is 300 bytes"
    );
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

/// Asks for `/app.css` rather than `/`: page routes resolve a session before
/// they answer now, so `/` redirects an unauthenticated request instead of
/// serving an embedded file. The revalidation contract being pinned here
/// belongs to the embedded assets, which `/app.css` is one of.
#[tokio::test]
async fn test_index_served_with_etag_and_no_cache() {
    let (app, _token) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/app.css")
                .body(Body::empty())
                .unwrap(),
        )
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
        .oneshot(
            Request::builder()
                .uri("/app.css")
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
                .uri("/app.css")
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

/// The session token a response's `Set-Cookie` hands back, if any. Used by the
/// rotation tests, where the token a request authenticated with is no longer
/// the token the next request must use.
fn rotated_session_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let set_cookie = headers.get("set-cookie")?.to_str().ok()?;
    Some(
        set_cookie
            .split_once("session=")?
            .1
            .split(';')
            .next()?
            .to_string(),
    )
}

fn authed(method: &str, uri: &str, token: &str, body: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", format!("session={token}"));
    if body.is_some() {
        b = b.header("content-type", "application/json");
    }
    b.body(body.map_or(Body::empty(), |s| Body::from(s.to_string())))
        .unwrap()
}

/// A login attempt that presents `ip` as its source address.
///
/// The tests below use a *different* address for every attempt, which is not a
/// trick to dodge the IP limiter but the attack the account lockout exists to
/// stop: OWASP's reason for keying the counter on the account is precisely
/// "to prevent an attacker from making login attempts from a large number of
/// different IP addresses". Each of these attempts is comfortably inside its
/// own IP budget; only the account budget sees all of them.
fn login_from(ip: &str, username: &str, password: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .header("x-forwarded-for", ip)
        .body(Body::from(format!(
            r#"{{"username":"{username}","password":"{password}"}}"#
        )))
        .unwrap()
}

/// Spend an account's free allowance, one attempt per source address, leaving
/// it locked. Returns the number of addresses used, so a caller can keep
/// picking fresh ones.
async fn lock_the_account(app: &axum::Router, username: &str) -> usize {
    let attempts = noadd::admin::auth::LOCKOUT_FREE_ATTEMPTS + 1;
    for i in 0..attempts {
        let res = app
            .clone()
            .oneshot(login_from(
                &format!("10.0.0.{i}"),
                username,
                "not-the-password",
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "attempt {i} must fail on the password, not the IP limiter"
        );
    }
    attempts as usize
}

/// The whole point: a thousand source addresses get a thousand IP budgets and
/// one account budget. Once that is spent, even the *correct* password is
/// refused.
#[tokio::test]
async fn a_distributed_guessing_run_locks_the_account() {
    let (app, _token) = setup().await;
    let used = lock_the_account(&app, "admin").await;

    let res = app
        .oneshot(login_from(&format!("10.0.0.{used}"), "admin", "admin"))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "the correct password must be refused while the account is locked"
    );
}

/// A lockout that announced itself would re-open the user-enumeration hole
/// the generic 401 exists to close: fail five times against a name and read
/// off whether it exists. A locked account must be indistinguishable from one
/// that was never there.
#[tokio::test]
async fn a_locked_account_is_indistinguishable_from_an_unknown_one() {
    let (app, _token) = setup().await;
    let used = lock_the_account(&app, "admin").await;

    let locked = app
        .clone()
        .oneshot(login_from(
            &format!("10.0.1.{used}"),
            "admin",
            "whatever-long",
        ))
        .await
        .unwrap();
    let unknown = app
        .oneshot(login_from(
            &format!("10.0.2.{used}"),
            "nobody",
            "whatever-long",
        ))
        .await
        .unwrap();

    assert_eq!(locked.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        locked.headers(),
        unknown.headers(),
        "a locked account must not be identifiable from the response headers"
    );
    let locked_body = axum::body::to_bytes(locked.into_body(), usize::MAX)
        .await
        .unwrap();
    let unknown_body = axum::body::to_bytes(unknown.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(locked_body, unknown_body);
}

/// Getting it right is the only evidence the failures were the real operator
/// fumbling, so it clears the history rather than leaving them one slip from a
/// lockout for the next hour.
#[tokio::test]
async fn a_successful_login_clears_the_account_budget() {
    let (app, _token) = setup().await;
    let free = noadd::admin::auth::LOCKOUT_FREE_ATTEMPTS;

    for i in 0..free {
        let res = app
            .clone()
            .oneshot(login_from(&format!("10.1.0.{i}"), "admin", "wrong-one"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    let res = app
        .clone()
        .oneshot(login_from("10.1.0.200", "admin", "admin"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // The allowance is whole again: the same number of failures as before
    // still does not lock, which it would if the counter had merely carried on.
    for i in 0..free {
        let res = app
            .clone()
            .oneshot(login_from(&format!("10.1.1.{i}"), "admin", "wrong-one"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    let res = app
        .oneshot(login_from("10.1.1.200", "admin", "admin"))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the counter must have restarted after the successful login"
    );
}

/// The other two endpoints that verify this same password draw on the same
/// account budget. Leaving either out would give an attacker who already holds
/// a session an unmetered place to grind the credential.
#[tokio::test]
async fn the_lockout_covers_every_endpoint_that_checks_the_password() {
    for (uri, body) in [
        ("/api/auth/reauth", r#"{"password":"admin"}"#),
        (
            "/api/users/me/password",
            r#"{"current_password":"admin","new_password":"vault-quartz-nimbus-84"}"#,
        ),
    ] {
        let (app, token) = setup().await;
        let used = lock_the_account(&app, "admin").await;

        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .header("cookie", format!("session={token}"))
                    .header("x-forwarded-for", format!("10.0.3.{used}"))
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "{uri} must honour the account lockout even with the right password"
        );
    }
}

/// Age a live session's password proof past the re-authentication window,
/// leaving everything else about it untouched — the session stays valid, only
/// the proof goes stale. Returns the number of sessions aged.
fn expire_reauth(sessions: &SessionStore, token: &str) -> usize {
    let hash = hash_session_token(token);
    let mut map = sessions.lock();
    let Some(info) = map.get_mut(&hash) else {
        return 0;
    };
    info.last_reauth_at = noadd::now_unix() - noadd::admin::auth::REAUTH_WINDOW_SECS - 1;
    1
}

/// The gap #208's own doc comment called out: an attacker holding a stolen
/// session cookie could mint a long-lived API key, and that key kept working
/// after the victim changed their password. Minting one now needs the
/// password again.
#[tokio::test]
async fn sensitive_actions_need_a_recent_password_proof() {
    // Each of these hands out durable access — a key that outlives the
    // session, or an operator account that is a second key to the whole box.
    let sensitive: &[(&str, &str, Option<&str>)] = &[
        ("POST", "/api/api-keys", Some(r#"{"name":"ci"}"#)),
        (
            "POST",
            "/api/users",
            Some(r#"{"username":"bob","password":"vault-quartz-nimbus-84"}"#),
        ),
        ("DELETE", "/api/users/2", None),
    ];

    for (method, uri, body) in sensitive {
        let (app, token, _cache, _events, _db, sessions, _isl) =
            build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;

        // Fresh out of login, the proof is current and the action goes
        // through — an operator must not be asked twice in a row.
        let res = app
            .clone()
            .oneshot(authed(method, uri, &token, *body))
            .await
            .unwrap();
        assert_ne!(
            res.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} must be allowed straight after login"
        );

        assert_eq!(expire_reauth(&sessions, &token), 1);

        let res = app
            .oneshot(authed(method, uri, &token, *body))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} must be refused once the proof is stale"
        );
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json.get("code").and_then(serde_json::Value::as_str),
            Some("reauth_required"),
            "the UI keys off this code — a bare 403 is indistinguishable from the CSRF guard's"
        );
    }
}

/// Re-authenticating restores the window, so the action that was just refused
/// succeeds on retry. This is the whole loop the admin UI drives.
#[tokio::test]
async fn reauth_reopens_the_window() {
    let (app, token, _cache, _events, _db, sessions, _isl) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    assert_eq!(expire_reauth(&sessions, &token), 1);

    let res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/api-keys",
            &token,
            Some(r#"{"name":"ci"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/auth/reauth",
            &token,
            Some(r#"{"password":"admin"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let res = app
        .oneshot(authed(
            "POST",
            "/api/api-keys",
            &token,
            Some(r#"{"name":"ci"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// A wrong password must not reopen the window, and must be audited — this is
/// the same guessing surface as `login`.
#[tokio::test]
async fn reauth_rejects_the_wrong_password_and_leaves_the_window_shut() {
    let (app, token, _cache, _events, _db, sessions, _isl) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    assert_eq!(expire_reauth(&sessions, &token), 1);

    let res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/auth/reauth",
            &token,
            Some(r#"{"password":"not-the-password"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let res = app
        .oneshot(authed(
            "POST",
            "/api/api-keys",
            &token,
            Some(r#"{"name":"ci"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a failed confirmation must not count as a proof"
    );
}

/// Verifying a password makes this a guessing surface, so it shares the login
/// budget for the same reason `change_own_password` does.
#[tokio::test]
async fn reauth_is_rate_limited() {
    let (app, token) = setup().await;
    let attempt = || {
        app.clone().oneshot(authed(
            "POST",
            "/api/auth/reauth",
            &token,
            Some(r#"{"password":"wrong"}"#),
        ))
    };
    for i in 0..5 {
        assert_eq!(
            attempt().await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "attempt {i} is inside the budget"
        );
    }
    assert_eq!(
        attempt().await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
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
            Some(r#"{"username":"bob","password":"long-enough-pass"}"#),
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
            Some(r#"{"username":"bob","password":"long-enough-pass"}"#),
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
            Some(r#"{"current_password":"wrong","new_password":"vault-quartz-nimbus-84"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// The length band applies wherever a password is *set*, not just at setup.
/// A minimum enforced only by the setup wizard would let an operator walk
/// their own password straight back under it.
#[tokio::test]
async fn change_own_password_enforces_the_length_band() {
    for (label, new_password) in [
        ("under the minimum", "Yx7#qvLm2R".to_string()),
        ("over the maximum", "a".repeat(129)),
    ] {
        let (app, token) = setup().await;
        let res = app
            .oneshot(authed(
                "POST",
                "/api/users/me/password",
                &token,
                Some(&format!(
                    r#"{{"current_password":"admin","new_password":"{new_password}"}}"#
                )),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "a new password {label} must be rejected"
        );
    }
}

/// The username is validated on the same endpoint and with the same shape of
/// rejection as the password, and had no coverage at all.
#[tokio::test]
async fn create_operator_rejects_an_invalid_username() {
    for (label, username) in [
        ("empty", String::new()),
        ("whitespace only", "   ".to_string()),
        ("past the 64-character limit", "u".repeat(65)),
    ] {
        let (app, token) = setup().await;
        let res = app
            .oneshot(authed(
                "POST",
                "/api/users",
                &token,
                Some(&format!(
                    r#"{{"username":"{username}","password":"vault-quartz-nimbus-84"}}"#
                )),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "a {label} username must be rejected"
        );
    }
}

#[tokio::test]
async fn create_operator_enforces_the_length_band() {
    for (label, password) in [
        ("under the minimum", "Yx7#qvLm2R".to_string()),
        ("over the maximum", "a".repeat(129)),
    ] {
        let (app, token) = setup().await;
        let res = app
            .oneshot(authed(
                "POST",
                "/api/users",
                &token,
                Some(&format!(r#"{{"username":"bob","password":"{password}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "an operator password {label} must be rejected"
        );
    }
}

/// Length alone is a weak policy: `password1234` and `noadd-noadd-noadd` both
/// clear a 12-character floor. Every endpoint that sets a password must run
/// the guessability check too, or an operator simply routes around the floor
/// at whichever endpoint forgot.
#[tokio::test]
async fn every_set_password_endpoint_rejects_a_guessable_password() {
    // Each is long enough to clear the length band and would have been
    // accepted before: a top-N password padded out, a keyboard run, dictionary
    // words, and one built from the account's own name.
    for weak in [
        "password1234",
        "qwertyuiopasdfgh",
        "letmeinletmein",
        "admin-admin-admin-1",
    ] {
        let app = unconfigured_app().await;
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/setup")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"username":"admin","password":"{weak}"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "setup must reject {weak:?}"
        );

        let (app, token) = setup().await;
        let res = app
            .oneshot(authed(
                "POST",
                "/api/users",
                &token,
                Some(&format!(r#"{{"username":"bob","password":"{weak}"}}"#)),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "operator creation must reject {weak:?}"
        );

        let (app, token) = setup().await;
        let res = app
            .oneshot(authed(
                "POST",
                "/api/users/me/password",
                &token,
                Some(&format!(
                    r#"{{"current_password":"admin","new_password":"{weak}"}}"#
                )),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::BAD_REQUEST,
            "password change must reject {weak:?}"
        );
    }
}

/// A rejection has to say what to change. Without a reason in the body the
/// admin UI can only show "400", and an operator has no way to tell a
/// too-short password from a too-guessable one.
#[tokio::test]
async fn a_rejected_password_explains_itself() {
    let app = unconfigured_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"admin","password":"password1234"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg.contains("passphrase"),
        "expected actionable guidance, got: {body}"
    );
    assert!(
        !msg.to_lowercase().contains("at least") && !msg.to_lowercase().contains("at most"),
        "a guessability rejection must not be reported as a length problem: {body}"
    );

    // The same endpoint's length rejection must remain distinguishable from it.
    let app = unconfigured_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"admin","password":"Yx7#qvLm2R"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg.to_lowercase().contains("at least"),
        "a short password must still be reported as too short: {body}"
    );
}

/// A password containing the account's own username is the first thing anyone
/// guessing at this particular box tries, and it sails past both a length
/// floor and a breach blocklist. zxcvbn only catches it if the username is
/// actually passed in as a user input.
#[tokio::test]
async fn the_username_is_fed_to_the_guessability_check() {
    // `zephyrqualm-8412` is weak *only* relative to that username: zxcvbn
    // scores it 2 when `zephyrqualm` is a user input and 4 when it is not.
    // The second half of this test is what makes the first half mean
    // something — without it, a password that is simply weak would pass just
    // as well and prove nothing about the username reaching the checker.
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed(
            "POST",
            "/api/users",
            &token,
            Some(r#"{"username":"zephyrqualm","password":"zephyrqualm-8412"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "a password built from the account's own username must be rejected"
    );

    let (app, token) = setup().await;
    let res = app
        .oneshot(authed(
            "POST",
            "/api/users",
            &token,
            Some(r#"{"username":"unrelated","password":"zephyrqualm-8412"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "the very same password is fine under a username it does not contain"
    );
}

/// Provisioning an operator hands out a second key to the whole appliance, so
/// it has to leave a trace naming who did it and who was created. Deleting one
/// is the same event in reverse; together they answer "who can administer this
/// box, and when did that change" from one event name.
#[tokio::test]
async fn operator_lifecycle_is_audited() {
    let logs = CapturedLogs::new();
    let guard = logs.install();

    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/users",
            &token,
            Some(r#"{"username":"bob","password":"vault-quartz-nimbus-84"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let res = app
        .oneshot(authed("DELETE", "/api/users/2", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    drop(guard);
    let text = logs.text();

    for (event, what) in [
        ("user.created", "provisioning an operator"),
        ("user.deleted", "removing an operator"),
    ] {
        assert!(
            text.contains(&format!(r#""event":"{event}""#)),
            "{what} must emit {event}; captured logs were:\n{text}"
        );
    }
    // The acting operator (admin, id 1) and the target (bob, id 2) must both
    // be recorded — an event naming only one of them cannot answer either
    // half of "who did what to whom".
    assert!(
        text.contains(r#""user_id":1"#) && text.contains(r#""target_user_id":2"#),
        "both the acting and the target operator must be named:\n{text}"
    );
    assert!(
        text.contains(r#""target_username":"bob""#),
        "an audit of who was provisioned is unreadable without the name:\n{text}"
    );
}

/// Changing a password verifies one, so it is a password-guessing surface and
/// must be throttled like the login endpoint. Without this an attacker sitting
/// at a signed-in terminal can grind the current-password field indefinitely
/// and take the account over permanently.
#[tokio::test]
async fn change_own_password_is_rate_limited() {
    let (app, token) = setup().await;
    // The router is built with the same 5-attempts-per-60s limiter `main`
    // uses, and every request here shares the fallback client IP.
    let attempt = || {
        app.clone().oneshot(authed(
            "POST",
            "/api/users/me/password",
            &token,
            Some(r#"{"current_password":"wrong","new_password":"a-long-enough-one"}"#),
        ))
    };
    for i in 0..5 {
        let res = attempt().await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "attempt {i} is inside the budget and must fail on the password, not the limiter"
        );
    }
    let res = attempt().await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the 6th attempt within the window must be throttled"
    );
}

/// The throttle counts against the same budget `login` uses, deliberately:
/// both are the same credential being guessed from the same address. This
/// pins that down so nobody "fixes" it into a separate limiter without
/// meaning to.
#[tokio::test]
async fn change_own_password_shares_the_login_budget() {
    let (app, token) = setup().await;
    for _ in 0..5 {
        let res = app
            .clone()
            .oneshot(authed(
                "POST",
                "/api/users/me/password",
                &token,
                Some(r#"{"current_password":"wrong","new_password":"a-long-enough-one"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    let res = app
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
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// An unknown username and a known username with the wrong password must be
/// indistinguishable in the response itself — the timing side of the same
/// property is pinned in `tests/admin_auth_test.rs`.
#[tokio::test]
async fn unknown_user_and_wrong_password_return_identical_401s() {
    let (app, _token) = setup().await;
    let login = |payload: &'static str| {
        app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
    };

    let unknown = login(r#"{"username":"nobody","password":"whatever-long"}"#)
        .await
        .unwrap();
    let wrong = login(r#"{"username":"admin","password":"whatever-long"}"#)
        .await
        .unwrap();

    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unknown.headers(),
        wrong.headers(),
        "response headers must not reveal whether the account exists"
    );

    let unknown_body = axum::body::to_bytes(unknown.into_body(), usize::MAX)
        .await
        .unwrap();
    let wrong_body = axum::body::to_bytes(wrong.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(unknown_body, wrong_body);
}

/// A password longer than any human types is refused before it ever reaches
/// Argon2. The cap is far above `MAX_PASSWORD_LENGTH` on purpose so an
/// operator whose password predates that limit is not locked out — this only
/// bounds the work an unauthenticated caller can demand.
#[tokio::test]
async fn login_rejects_an_absurdly_long_password() {
    let (app, _token) = setup().await;
    let absurd = "a".repeat(2000);
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"username":"admin","password":"{absurd}"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn change_password_revokes_other_sessions_of_same_user() {
    let (app, token_a, _cache, _events, db, sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    let admin_id = db
        .list_users()
        .await
        .unwrap()
        .into_iter()
        .find(|u| u.username == "admin")
        .unwrap()
        .id;

    // Seed a second session (token B) for the same user, bypassing login.
    let token_b = generate_token();
    let now = noadd::now_unix();
    let sid = db
        .insert_session(
            &hash_session_token(&token_b),
            admin_id,
            now,
            now,
            None,
            None,
        )
        .await
        .unwrap();
    store_session(
        &sessions,
        &hash_session_token(&token_b),
        SessionInfo {
            session_id: sid,
            user_id: admin_id,
            created_at: now,
            last_seen: now,
            last_reauth_at: now,
        },
    );

    let res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/users/me/password",
            &token_a,
            Some(r#"{"current_password":"admin","new_password":"vault-quartz-nimbus-84"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    // Token B was revoked by the password change.
    let res_b = app
        .clone()
        .oneshot(authed("GET", "/api/auth/me", &token_b, None))
        .await
        .unwrap();
    assert_eq!(res_b.status(), StatusCode::UNAUTHORIZED);

    // Token A (the device that made the change) stays signed in — but under
    // the rotated token, not the one it arrived with.
    let rotated = rotated_session_token(res.headers()).expect("rotation must set a cookie");
    let res_a = app
        .clone()
        .oneshot(authed("GET", "/api/auth/me", &token_a, None))
        .await
        .unwrap();
    assert_eq!(
        res_a.status(),
        StatusCode::UNAUTHORIZED,
        "the superseded token must stop working"
    );
    let res_rotated = app
        .oneshot(authed("GET", "/api/auth/me", &rotated, None))
        .await
        .unwrap();
    assert_eq!(res_rotated.status(), StatusCode::OK);
}

/// OWASP: renew the session ID after a privilege level change. Revoking the
/// *other* sessions is not enough on its own — it does nothing about a token
/// that leaked through a channel needing no ongoing browser access (a proxy
/// log, a shared terminal's history), which is exactly what rotation covers.
#[tokio::test]
async fn change_password_rotates_the_callers_own_token() {
    let (app, token_a, _cache, _events, db, sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;

    let res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/users/me/password",
            &token_a,
            Some(r#"{"current_password":"admin","new_password":"vault-quartz-nimbus-84"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let set_cookie = res
        .headers()
        .get("set-cookie")
        .expect("rotation must emit a Set-Cookie")
        .to_str()
        .unwrap()
        .to_string();
    let rotated = rotated_session_token(res.headers()).unwrap();
    assert_ne!(rotated, token_a, "the token must actually change");

    // The replacement must carry the same protections as the one login
    // issues; a rotation that silently dropped one would downgrade the very
    // session it was issued to protect.
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
    assert!(set_cookie.contains("SameSite=Lax"), "{set_cookie}");
    assert!(set_cookie.contains("Path=/"), "{set_cookie}");

    // Old token dead, new token live.
    let old = app
        .clone()
        .oneshot(authed("GET", "/api/auth/me", &token_a, None))
        .await
        .unwrap();
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
    let new = app
        .oneshot(authed("GET", "/api/auth/me", &rotated, None))
        .await
        .unwrap();
    assert_eq!(new.status(), StatusCode::OK);

    // Exactly one session survives, stored as a hash and reachable from both
    // views — the superseded row must not linger, or a restart would restore
    // it as a live session.
    let rows = db.list_sessions().await.unwrap();
    assert_eq!(rows.len(), 1, "the superseded row must be deleted");
    assert_eq!(rows[0].token_hash, hash_session_token(&rotated));
    let live = sessions.lock();
    assert_eq!(live.len(), 1);
    assert!(live.contains_key(&hash_session_token(&rotated)));
}

/// Regression guard: `change_own_password` must revoke only the caller's own
/// sessions via `revoke_user_sessions_except`, never the global
/// `revoke_other_sessions` (which would log out every operator).
#[tokio::test]
async fn change_password_keeps_other_operators_signed_in() {
    let (app, token_a, _cache, _events, db, sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;

    // A second, unrelated operator with their own session (token C).
    let hash = hash_password("bobpass1").unwrap();
    let bob_id = db
        .create_user("bob", &hash, noadd::now_unix())
        .await
        .unwrap();
    let token_c = generate_token();
    let now = noadd::now_unix();
    let sid = db
        .insert_session(&hash_session_token(&token_c), bob_id, now, now, None, None)
        .await
        .unwrap();
    store_session(
        &sessions,
        &hash_session_token(&token_c),
        SessionInfo {
            session_id: sid,
            user_id: bob_id,
            created_at: now,
            last_seen: now,
            last_reauth_at: now,
        },
    );

    let res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/users/me/password",
            &token_a,
            Some(r#"{"current_password":"admin","new_password":"vault-quartz-nimbus-84"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let res_c = app
        .oneshot(authed("GET", "/api/auth/me", &token_c, None))
        .await
        .unwrap();
    assert_eq!(res_c.status(), StatusCode::OK);
}

#[tokio::test]
async fn change_password_deletes_revoked_rows_from_db() {
    let (app, token_a, _cache, _events, db, sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    let admin_id = db
        .list_users()
        .await
        .unwrap()
        .into_iter()
        .find(|u| u.username == "admin")
        .unwrap()
        .id;

    let token_b = generate_token();
    let now = noadd::now_unix();
    let sid = db
        .insert_session(
            &hash_session_token(&token_b),
            admin_id,
            now,
            now,
            None,
            None,
        )
        .await
        .unwrap();
    store_session(
        &sessions,
        &hash_session_token(&token_b),
        SessionInfo {
            session_id: sid,
            user_id: admin_id,
            created_at: now,
            last_seen: now,
            last_reauth_at: now,
        },
    );

    let res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/users/me/password",
            &token_a,
            Some(r#"{"current_password":"admin","new_password":"vault-quartz-nimbus-84"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let rotated = rotated_session_token(res.headers()).expect("rotation must set a cookie");

    let res = app
        .oneshot(authed("GET", "/api/sessions", &rotated, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let rows: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the revoked session row must be deleted from the DB, not just memory"
    );
    assert_eq!(rows[0]["is_current"], true);
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
                    r#"{"username":"root","password":"hunter2passphrase"}"#,
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

#[tokio::test]
async fn list_operators_excludes_password_hash() {
    let (app, token) = setup().await;
    app.clone()
        .oneshot(authed(
            "POST",
            "/api/users",
            &token,
            Some(r#"{"username":"bob","password":"long-enough-pass"}"#),
        ))
        .await
        .unwrap();
    let res = app
        .oneshot(authed("GET", "/api/users", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("admin") && text.contains("bob"));
    assert!(
        !text.contains("password_hash"),
        "operator list must never expose password hashes"
    );
}

#[tokio::test]
async fn me_returns_current_operator_without_hash() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed("GET", "/api/auth/me", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("\"username\":\"admin\""));
    assert!(!text.contains("password_hash"));
}

#[tokio::test]
async fn create_operator_rejects_short_password() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed(
            "POST",
            "/api/users",
            &token,
            Some(r#"{"username":"shorty","password":"x"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_upstream_servers_round_trip_and_validation() {
    let (app, token) = setup().await;

    // valid → 200 and GET returns it
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/settings")
                .header("content-type", "application/json")
                .header("cookie", format!("session={token}"))
                .body(Body::from(
                    r#"{"upstream_servers":"1.1.1.1:53\ntls://dns.mullvad.net:853"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .header("cookie", format!("session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(get.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["upstream_servers"]
            .as_str()
            .unwrap()
            .contains("1.1.1.1:53")
    );

    // invalid → 400 and the setting is unchanged
    let bad = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/settings")
                .header("content-type", "application/json")
                .header("cookie", format!("session={token}"))
                .body(Body::from(r#"{"upstream_servers":"not an address"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_operator_succeeds_and_missing_returns_404() {
    let (app, token) = setup().await;
    // admin is id 1; add two more so the last-operator guard does not fire.
    for u in ["bob", "carol"] {
        app.clone()
            .oneshot(authed(
                "POST",
                "/api/users",
                &token,
                Some(&format!(
                    r#"{{"username":"{u}","password":"long-enough-pass"}}"#
                )),
            ))
            .await
            .unwrap();
    }
    // Delete bob (id 2) → 204.
    let res = app
        .clone()
        .oneshot(authed("DELETE", "/api/users/2", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    // A non-existent id while more than one operator remains → 404.
    let res = app
        .oneshot(authed("DELETE", "/api/users/999", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_logs_stream_sse_delivers_published_entry() {
    let (app, token, _cache, events) = build_app("http://127.0.0.1:1/filters.json", true).await;

    // Open the authenticated SSE stream. The handler subscribes to the
    // broadcast channel while producing the response, so a publish after
    // oneshot() returns is guaranteed to be delivered to this subscriber.
    let req = Request::builder()
        .uri("/api/logs/stream")
        .header("cookie", format!("session={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        ctype.starts_with("text/event-stream"),
        "unexpected content-type: {ctype}"
    );

    // Publish one entry through the broadcast sender the handler is now
    // subscribed to.
    let entry = QueryLogEntry {
        timestamp: 1234,
        domain: "live.example.com".to_string(),
        query_type: "A".to_string(),
        client_ip: "10.0.0.9".to_string(),
        blocked: false,
        cached: false,
        response_ms: 5,
        upstream: Some("1.1.1.1:53".to_string()),
        doh_token: None,
        result: None,
        authenticated_data: false,
    };
    events.send(Arc::new(entry)).unwrap();

    // Read SSE frames until the JSON data line for our entry arrives
    // (keep-alive comments may interleave). Bound with a timeout so a
    // regression can't hang the suite.
    let mut stream = resp.into_body().into_data_stream();
    let mut seen = String::new();
    let found = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.unwrap();
            seen.push_str(&String::from_utf8_lossy(&bytes));
            if seen.contains("live.example.com") {
                return true;
            }
        }
        false
    })
    .await
    .expect("timed out waiting for SSE data");
    assert!(
        found,
        "SSE stream did not deliver the published entry; got: {seen}"
    );
}

#[tokio::test]
async fn logout_cookie_session_revokes_and_clears_cookie() {
    let (app, token) = setup().await;

    let res = app
        .clone()
        .oneshot(authed("POST", "/api/auth/logout", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let set_cookie = res
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    assert!(
        set_cookie.contains("session="),
        "logout must clear the session cookie: {set_cookie}"
    );
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["via_forward_auth"], false);
    assert!(body["redirect_to"].is_null());

    // The session was revoked, so a follow-up authenticated call 401s.
    let res = app
        .oneshot(authed("GET", "/api/settings", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// Logout must ask the browser to drop cookies/cache/storage for this
/// origin, so "log out, then press Back" cannot show the admin screen
/// again. `executionContexts` is deliberately excluded (it would reload the
/// SPA before it can read `redirect_to` and hand off to forward-auth logout).
#[tokio::test]
async fn logout_sends_clear_site_data() {
    let (app, token) = setup().await;

    let res = app
        .oneshot(authed("POST", "/api/auth/logout", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let header = res
        .headers()
        .get("clear-site-data")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    assert_eq!(header, r#""cache", "cookies", "storage""#);
    assert!(
        !header.contains("executionContexts"),
        "Clear-Site-Data must not include executionContexts, it would kill the SPA before it reads redirect_to: {header}"
    );
}

#[tokio::test]
async fn logout_without_any_auth_returns_401() {
    let (app, _token) = setup().await;
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// Every authenticated admin JSON response carries a caching policy that
/// forbids storage — nothing in `/api/*` sets its own `Cache-Control`, so the
/// `no_store` layer must be the one stamping it (see `src/headers.rs`).
#[tokio::test]
async fn api_responses_are_not_stored() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed("GET", "/api/auth/me", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let cache_control = res
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cache_control.contains("no-store"),
        "expected no-store, got: {cache_control}"
    );
    assert_eq!(
        res.headers().get("pragma").and_then(|v| v.to_str().ok()),
        Some("no-cache")
    );
}

/// The `no_store` layer sits outside the `AuthedUser` extractor, so even a
/// bare 401 rejection (no handler ever ran) carries the no-store headers.
#[tokio::test]
async fn unauthenticated_rejections_are_not_stored() {
    let (app, _token) = setup().await;
    let req = Request::builder()
        .uri("/api/settings")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let cache_control = res
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cache_control.contains("no-store"),
        "expected no-store, got: {cache_control}"
    );
}

/// Regression guard: the `no_store` layer keys on "response already declares
/// a `Cache-Control`" and must not clobber the embedded assets' existing
/// `no-cache` + `ETag` revalidation headers.
///
/// `/app.css` rather than `/` — see `test_index_served_with_etag_and_no_cache`.
/// The distinction matters more now than it reads: a server-rendered page gets
/// `no-store` from that same layer, which is what keeps operator data out of
/// the browser cache, and only the static assets are meant to escape it.
#[tokio::test]
async fn static_assets_keep_no_cache_and_etag() {
    let (app, _token) = setup().await;
    let req = Request::builder()
        .uri("/app.css")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-cache")
    );
    assert!(res.headers().contains_key("etag"));
}

/// `Strict-Transport-Security` is layered onto the *merged* app in
/// `src/main.rs`, not inside `admin_router` — a `DoH`-only deployment must
/// get the header too, so it cannot live on the admin router alone. Pin that
/// by asserting `admin_router` in isolation never emits it.
#[tokio::test]
async fn hsts_header_is_not_sent_by_the_admin_router_alone() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed("GET", "/api/auth/me", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(!res.headers().contains_key("strict-transport-security"));
}

/// The mirror of the HSTS test above: clickjacking defence *does* belong on
/// the admin router, since the admin UI is the only browser-rendered surface
/// here, so a dropped `.layer(...)` must fail the suite. The unit test in
/// `src/headers.rs` only proves the middleware works when attached.
#[tokio::test]
async fn security_headers_are_sent_by_the_admin_router() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed("GET", "/api/auth/me", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        res.headers().get("content-security-policy").unwrap(),
        "frame-ancestors 'none'"
    );
    assert_eq!(
        res.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
}

/// The mobileconfig download carries authenticated DNS-over-HTTPS config
/// (the token in the URL is itself the credential), so it must not be stored.
#[tokio::test]
async fn mobileconfig_is_not_stored() {
    let (app, token, _cache, _log_events, db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;

    db.set_setting("public_url", "https://dns.example.com")
        .await
        .unwrap();

    let add_res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/doh-tokens",
            &token,
            Some(r#"{"token":"mobiletoken"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(add_res.status(), StatusCode::OK);

    let req = Request::builder()
        .uri("/api/mobileconfig/mobiletoken")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let cache_control = res
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cache_control.contains("no-store"),
        "expected no-store, got: {cache_control}"
    );
}

/// macOS 26.1 (Tahoe) rejects a DNS Settings profile that omits the top-level
/// `PayloadScope`, reporting "The 'VPN Service' payload could not be
/// installed". The key is what keeps the profile installable there.
#[tokio::test]
async fn mobileconfig_declares_system_payload_scope() {
    let (app, token, _cache, _log_events, db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;

    db.set_setting("public_url", "https://dns.example.com")
        .await
        .unwrap();

    let add_res = app
        .clone()
        .oneshot(authed(
            "POST",
            "/api/doh-tokens",
            &token,
            Some(r#"{"token":"mobiletoken"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(add_res.status(), StatusCode::OK);

    let req = Request::builder()
        .uri("/api/mobileconfig/mobiletoken")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8(body.to_vec()).unwrap();

    assert!(
        xml.contains("<key>PayloadScope</key>") && xml.contains("<string>System</string>"),
        "profile must declare a System PayloadScope, got: {xml}"
    );
    assert!(
        xml.contains("com.apple.dnsSettings.managed"),
        "profile must carry the DNS Settings payload, got: {xml}"
    );
    assert!(
        xml.contains("https://dns.example.com/dns-query/mobiletoken"),
        "profile must point at the token's DoH URL, got: {xml}"
    );
}

#[tokio::test]
async fn check_list_url_unknown_id_returns_404() {
    // Covers the DB-lookup branch without reaching the network: with no URL in
    // the body the handler resolves the list's own URL by id, and an id that
    // matches no row must 404 rather than fall through to another list's URL.
    let (app, token) = setup().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/lists/999999/check")
        .header("cookie", format!("session={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// --- Server-rendered pages ---

/// A browser asking for a page it has no session for is redirected to the
/// sign-in form, carrying where it was trying to go. The API answers the same
/// situation with a 401; the two are halves of one guard, and they share the
/// extractor underneath precisely so they cannot disagree about who is signed
/// in.
#[tokio::test]
async fn a_page_request_without_a_session_is_redirected_to_sign_in() {
    let (app, _token) = setup().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/login?next=/settings")
    );
}

/// Before any operator exists every page routes to the wizard, not to a sign-in
/// form nobody could satisfy.
#[tokio::test]
async fn a_page_request_before_setup_is_redirected_to_the_wizard() {
    let app = unconfigured_app().await;
    let res = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/setup")
    );
}

/// An off-origin `next` is dropped rather than honoured.
///
/// The sign-in page is exactly what a phishing link points at, and a redirect
/// it performs *after* authentication wears noadd's own URL as the bait. All
/// three spellings are covered because a browser honours all three: the
/// absolute URL, the protocol-relative form, and the backslash variant that
/// several browsers normalise into it.
#[tokio::test]
async fn sign_in_refuses_to_carry_an_off_origin_destination() {
    let (app, _token) = setup().await;
    for target in ["https://evil.example", "//evil.example", "/\\evil.example"] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/login?next={target}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{target}: expected the form");
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&bytes);
        assert!(
            !html.contains("evil.example"),
            "{target} survived into the rendered form"
        );
    }
}

/// A form sign-in mints the session and sends the browser where it was headed,
/// rather than answering with a body the way the JSON endpoint does.
#[tokio::test]
async fn a_form_sign_in_mints_a_session_and_redirects() {
    let (app, _token) = setup().await;
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("username=admin&password=admin&next=/settings"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/settings")
    );
    assert!(
        res.headers().get("set-cookie").is_some(),
        "no session cookie was issued"
    );
}

/// A refused sign-in re-renders the form so the typed username survives, but
/// still answers 401. A form that returns 200 on a rejected credential is lying
/// to everything except the eye.
#[tokio::test]
async fn a_refused_form_sign_in_answers_401_and_keeps_the_username() {
    let (app, _token) = setup().await;
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("username=admin&password=wrong-password"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("data-testid=\"login-error\""));
    assert!(
        html.contains("value=\"admin\""),
        "the typed username was discarded"
    );
}

/// A server-rendered page must never reach the browser's disk cache: an
/// operator's dashboard is not a cacheable representation, and the appliance is
/// commonly reached from a shared machine. The `no_store` layer gives it that
/// by keying on responses that declare no policy of their own — this pins that
/// a page is one of them, where the static assets deliberately are not.
#[tokio::test]
async fn a_server_rendered_page_is_never_stored() {
    let (app, token) = setup().await;
    let res = app.oneshot(authed("GET", "/", &token, None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let cc = res
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(cc.contains("no-store"), "page cache-control was {cc:?}");
}

/// Every signed-in page path answers with the shell. Asserted as a set rather
/// than one representative path: they are registered individually, so a route
/// dropped from the table is exactly the kind of mistake a single-path test
/// sails past.
#[tokio::test]
async fn every_page_path_is_served_to_an_authenticated_browser() {
    let (app, token) = setup().await;
    for path in ["/", "/stats", "/logs", "/filters", "/settings", "/account"] {
        let res = app
            .clone()
            .oneshot(authed("GET", path, &token, None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{path} was not served");
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8_lossy(&bytes);
        assert!(
            html.contains("id=\"app\"") && html.contains("/app.js"),
            "{path} did not render the shell"
        );
    }
}

/// The sign-in form renders for a browser with no session.
#[tokio::test]
async fn the_sign_in_page_renders_for_an_anonymous_browser() {
    let (app, _token) = setup().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("data-testid=\"login-submit\""));
    assert!(
        html.contains("action=\"/login\""),
        "the form must post back to /login"
    );
}

/// An already-authenticated browser asking for the sign-in page is sent onward
/// rather than shown a second form to fill in.
#[tokio::test]
async fn the_sign_in_page_sends_an_authenticated_browser_onward() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed("GET", "/login", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/")
    );
}

/// The wizard renders while no operator exists.
#[tokio::test]
async fn the_wizard_renders_before_the_first_operator_exists() {
    let app = unconfigured_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/setup")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("data-testid=\"setup-submit\""));
}

/// Once an operator exists the wizard is a dead end, so it redirects to sign-in
/// instead of offering to create a second first account.
#[tokio::test]
async fn the_wizard_sends_an_already_configured_appliance_to_sign_in() {
    let (app, _token) = setup().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/setup")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/login")
    );
}

/// A form post carrying a session cookie, for the pages behind authentication.
fn authed_form(uri: &str, token: &str, body: &'static str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", format!("session={token}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

fn form_post(uri: &str, body: &'static str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

/// Completing the wizard creates the operator and signs them in on the spot —
/// asking them to retype the password they just chose would be pure ceremony.
///
/// The welcome strip rides a flash cookie rather than the redirect target. A
/// `?welcome=1` would survive a refresh, a bookmark and a shared link, greeting
/// the operator again each time; the flash is read and cleared by the response
/// that renders it.
#[tokio::test]
async fn the_wizard_creates_the_first_operator_and_signs_them_in() {
    let app = unconfigured_app().await;
    let res = app
        .oneshot(form_post(
            "/setup",
            "username=admin&password=correct-horse-battery&confirm=correct-horse-battery",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/")
    );
    let cookies: Vec<&str> = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("session=")),
        "the new operator was not signed in: {cookies:?}"
    );
    assert!(
        cookies.iter().any(|c| c.contains("noadd_flash=welcome")),
        "no welcome notice was left for the shell: {cookies:?}"
    );
}

/// The confirmation field exists only in the form, so it is checked in the page
/// handler and nowhere else — `create_first_operator`, which the JSON endpoint
/// shares, has no business knowing about it.
#[tokio::test]
async fn the_wizard_re_renders_when_the_confirmation_does_not_match() {
    let app = unconfigured_app().await;
    let res = app
        .oneshot(form_post(
            "/setup",
            "username=admin&password=correct-horse-battery&confirm=something-else",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("do not match"));
    assert!(
        html.contains("value=\"admin\""),
        "the typed username was discarded"
    );
}

/// The shell is rendered by the server, active navigation item and all.
///
/// The active class is asserted on the path being served *and* its absence on
/// another: a template that marked every item active, or none, would satisfy
/// half of this and look fine in a screenshot.
#[tokio::test]
async fn the_shell_marks_the_navigation_item_for_the_path_it_serves() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed("GET", "/settings", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(
        html.contains(r#"class="nav-item active" href="/settings""#),
        "the settings item was not marked active"
    );
    assert!(
        !html.contains(r#"class="nav-item active" href="/logs""#),
        "an item for another path was marked active"
    );
    // The shell, not a client-side stand-in for it.
    assert!(html.contains(r#"action="/logout""#));
    assert!(html.contains("statusbar"));
}

/// The account page names who is signed in without the client asking.
#[tokio::test]
async fn the_account_page_renders_who_is_signed_in() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed("GET", "/account", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("Signed in as"));
    assert!(html.contains("admin"));
    assert!(html.contains(r#"action="/account/password""#));
}

/// The confirmation field is the form's own, so it is checked in the page
/// handler and never reaches the shared password path.
#[tokio::test]
async fn a_mismatched_confirmation_never_reaches_the_password_change() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed_form(
            "/account/password",
            &token,
            "current_password=admin&new_password=a-good-long-passphrase&confirm_password=different",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("do not match"));
}

/// A wrong current password is refused with 401 and says so — distinct from a
/// rejected *new* password, which would send the operator fixing the wrong
/// field.
#[tokio::test]
async fn a_wrong_current_password_is_reported_as_such() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed_form(
            "/account/password",
            &token,
            "current_password=nope&new_password=a-good-long-passphrase\
             &confirm_password=a-good-long-passphrase",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("Current password is incorrect"),
        "the operator was not told which field was wrong"
    );
}

/// A successful change redirects and issues a fresh session cookie — the shared
/// path rotates it, and re-rendering would leave the form holding the password
/// that was just replaced.
#[tokio::test]
async fn a_password_change_redirects_and_rotates_the_session() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed_form(
            "/account/password",
            &token,
            "current_password=admin&new_password=a-good-long-passphrase\
             &confirm_password=a-good-long-passphrase",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/account")
    );
    let cookies: Vec<&str> = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("session=")),
        "the session was not rotated: {cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.contains("noadd_flash=password_changed")),
        "no confirmation was left for the page: {cookies:?}"
    );
}

/// The settings page renders every scalar setting at its current value, so the
/// form is usable without a round trip to fill it in.
#[tokio::test]
async fn the_settings_page_renders_current_values() {
    let (app, token) = setup().await;
    app.clone()
        .oneshot(authed(
            "PUT",
            "/api/settings",
            &token,
            Some(r#"{"log_retention_days":"21","block_mode":"nxdomain"}"#),
        ))
        .await
        .unwrap();

    let res = app
        .oneshot(authed("GET", "/settings", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains(r#"value="21""#), "retention was not rendered");
    assert!(
        html.contains(r#"<option value="nxdomain" selected>"#),
        "the stored block mode was not selected"
    );
}

/// A settings save redirects rather than rendering: a POST left in the
/// browser's history is one refresh away from being submitted again.
#[tokio::test]
async fn a_settings_save_redirects_and_persists() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed_form(
            "/settings",
            &token,
            "upstream_servers=1.1.1.1:53&upstream_strategy=round-robin&dnssec=off\
             &block_mode=nxdomain&block_custom_ipv4=&block_custom_ipv6=\
             &log_retention_days=14&public_url=&doh_access_policy=deny",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/settings")
    );

    let page = app
        .oneshot(authed("GET", "/settings", &token, None))
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(page.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains(r#"<option value="round-robin" selected>"#));
    assert!(html.contains(r#"value="14""#));
}

/// A rejected value re-renders the form with everything the operator typed —
/// including the seven fields that were fine — and writes nothing.
///
/// The no-partial-write half is the one worth pinning: validation runs before
/// any `set_setting`, so a bad IP must not leave the retention change applied.
#[tokio::test]
async fn a_rejected_setting_keeps_the_whole_form_and_writes_nothing() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed_form(
            "/settings",
            &token,
            "upstream_servers=9.9.9.9:53&upstream_strategy=sequential&dnssec=on\
             &block_mode=custom_ip&block_custom_ipv4=not-an-ip&block_custom_ipv6=\
             &log_retention_days=30&public_url=&doh_access_policy=allow",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(
        html.contains("Not a valid IPv4 address"),
        "the reason did not reach the form"
    );
    assert!(
        html.contains(r#"value="not-an-ip""#) && html.contains(r#"value="30""#),
        "the operator's input was discarded"
    );

    // Nothing was written: the retention change rode along with the bad IP.
    let page = app
        .oneshot(authed("GET", "/settings", &token, None))
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(page.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&bytes).contains(r#"value="30""#),
        "a rejected save wrote part of itself"
    );
}

/// Signing out through the form revokes the session and sends the browser to
/// the sign-in page. The revocation is the part that matters: clearing the
/// cookie alone would leave a live session server-side that a copy of the
/// cookie could still present.
#[tokio::test]
async fn the_logout_form_revokes_the_session_and_redirects() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed("POST", "/logout", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/login")
    );

    // The same cookie must no longer authenticate anything.
    let after = app
        .oneshot(authed("GET", "/settings", &token, None))
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::SEE_OTHER,
        "the revoked session still resolved"
    );
}

/// A flash is shown once and then gone. It is cleared by the very response that
/// renders it, so the second request must not repeat it — the failure this
/// mechanism exists to prevent is a notice that reappears on every page.
#[tokio::test]
async fn a_flash_notice_is_shown_once_and_cleared() {
    let app = unconfigured_app().await;
    let created = app
        .clone()
        .oneshot(form_post(
            "/setup",
            "username=admin&password=correct-horse-battery&confirm=correct-horse-battery",
        ))
        .await
        .unwrap();
    // Carry every cookie the wizard set — the session and the flash both.
    let cookie_header = created
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|c| c.split(';').next())
        .collect::<Vec<_>>()
        .join("; ");

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header("cookie", &cookie_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(first.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&bytes).contains("setup-welcome"),
        "the welcome notice was not rendered"
    );

    // Second request, same session cookie, flash cleared by the first response.
    let session_only = cookie_header
        .split("; ")
        .find(|c| c.starts_with("session="))
        .unwrap()
        .to_string();
    let second = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("cookie", session_only)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(second.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&bytes).contains("setup-welcome"),
        "the welcome notice came back on the next page"
    );
}

/// A password the shared validator rejects comes back verbatim in the form. The
/// operator has to be told *which* rule they missed; a generic failure would
/// leave them guessing at a length they cannot see.
#[tokio::test]
async fn the_wizard_reports_why_a_password_was_rejected() {
    let app = unconfigured_app().await;
    let res = app
        .oneshot(form_post(
            "/setup",
            "username=admin&password=short&confirm=short",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(
        html.contains("at least 12 characters"),
        "the rejection reason did not reach the form"
    );
}

// --- Filters page (server-rendered) ---

/// A form post to a path built at runtime, which `authed_form`'s `&'static str`
/// body cannot express.
fn authed_form_owned(uri: &str, token: &str, body: String) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", format!("session={token}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

async fn body_text(res: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

async fn filters_html(app: &axum::Router, token: &str, query: &str) -> String {
    let res = app
        .clone()
        .oneshot(authed("GET", &format!("/filters{query}"), token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    body_text(res).await
}

/// The id of the first list on the page, read out of the markup the page itself
/// rendered — the same value a browser would post back.
fn first_list_id(html: &str) -> i64 {
    // Off the row's own toggle rather than a form action: `/filters/lists/update`
    // and `/filters/lists/enable-recommended` are also list actions, and both
    // appear above the table.
    let marker = r#"data-testid="filter-list-toggle" data-id=""#;
    let start = html.find(marker).expect("no list row on the page") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("malformed toggle");
    rest[..end].parse().expect("list id was not a number")
}

/// The id of the row for `name`, read out of the markup the page rendered.
fn list_id_by_name(html: &str, name: &str) -> i64 {
    let start = html
        .find(&format!(r#"data-name="{name}""#))
        .unwrap_or_else(|| panic!("no row for {name}"));
    let marker = r#"data-testid="filter-list-toggle" data-id=""#;
    let rest = &html[start..];
    let at = rest.find(marker).expect("row without a toggle") + marker.len();
    let rest = &rest[at..];
    rest[..rest.find('"').expect("malformed toggle")]
        .parse()
        .expect("list id was not a number")
}

/// Add one list through the form, and hand back its id.
async fn add_list(app: &axum::Router, token: &str, name: &str, url: &str) -> i64 {
    let res = app
        .clone()
        .oneshot(authed_form_owned(
            "/filters/lists",
            token,
            format!("name={name}&url={url}"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "adding a list failed");
    first_list_id(&filters_html(app, token, "").await)
}

/// The page arrives with the lists and rules already in it — the whole point of
/// rendering it on the server is that nothing has to be fetched to see them.
#[tokio::test]
async fn the_filters_page_renders_lists_and_rules() {
    let (app, token) = setup().await;
    add_list(&app, &token, "E2E+List", "https://example.com/l.txt").await;
    app.clone()
        .oneshot(authed_form(
            "/filters/rules",
            &token,
            "rule=%7C%7Crendered.example.com%5E",
        ))
        .await
        .unwrap();

    let html = filters_html(&app, &token, "").await;
    assert!(
        html.contains(r#"data-name="E2E List""#),
        "the list was not rendered into the table"
    );
    assert!(
        html.contains("rendered.example.com") && html.contains(r#"data-type="block""#),
        "the rule was not rendered"
    );
    // The client mounts a page component only into an empty `#page-content`;
    // shipping the element is what makes it upgrade in place instead.
    assert!(html.contains("<filters-page>"), "the body was not wrapped");
}

/// The domain test is a GET, so its verdict is in the URL: refreshable, and
/// answerable without JavaScript.
#[tokio::test]
async fn a_domain_test_is_answered_in_the_page() {
    let (app, token) = setup().await;
    app.clone()
        .oneshot(authed_form(
            "/filters/rules",
            &token,
            "rule=%7C%7Ctested.example.com%5E",
        ))
        .await
        .unwrap();
    // The rule reaches the engine through a background rebuild.
    for _ in 0..50 {
        let html = filters_html(&app, &token, "?test=tested.example.com").await;
        if html.contains("badge-blocked") {
            assert!(
                html.contains(r#"value="tested.example.com""#),
                "the tested domain was not kept in the field"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the domain test never reported the rule");
}

/// An untested page renders no verdict at all — an empty box, not "allowed".
#[tokio::test]
async fn a_page_with_no_test_renders_no_verdict() {
    let (app, token) = setup().await;
    let html = filters_html(&app, &token, "").await;
    assert!(
        !html.contains("badge-allowed") && !html.contains("badge-blocked"),
        "a verdict was rendered for a domain nobody tested"
    );
}

/// Adding a list redirects rather than rendering, so a refresh cannot add it
/// twice.
#[tokio::test]
async fn adding_a_list_through_the_form_redirects_and_persists() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed_form(
            "/filters/lists",
            &token,
            "name=Added+By+Form&url=https://example.com/added.txt",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/filters")
    );

    let html = filters_html(&app, &token, "").await;
    assert!(html.contains(r#"data-name="Added By Form""#));
}

/// A rejected list re-renders with what was typed and writes nothing. Retyping
/// the field that was fine is the failure this avoids.
#[tokio::test]
async fn a_rejected_list_keeps_what_was_typed() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed_form(
            "/filters/lists",
            &token,
            "name=Bad+Scheme&url=ftp://example.com/l.txt",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let html = body_text(res).await;
    assert!(
        html.contains("must start with http"),
        "the reason did not reach the form"
    );
    assert!(
        html.contains(r#"value="Bad Scheme""#)
            && html.contains(r#"value="ftp://example.com/l.txt""#),
        "the operator's input was discarded"
    );
    // The rejected list must not be in the table it re-rendered.
    assert!(
        !html.contains(r#"data-name="Bad Scheme""#),
        "a rejected list was created anyway"
    );
}

/// The JSON endpoint shares that validation, so the two cannot drift into
/// disagreeing about what a usable list is.
#[tokio::test]
async fn the_json_endpoint_refuses_the_same_list_the_form_does() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed(
            "POST",
            "/api/lists",
            &token,
            Some(r#"{"name":"","url":"https://example.com/l.txt"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

/// A checkbox posts nothing when it is unticked, which is the only signal that
/// a list is being turned off — so both directions are pinned here.
#[tokio::test]
async fn toggling_a_list_through_the_form_persists_both_ways() {
    let (app, token) = setup().await;
    let id = add_list(&app, &token, "Toggled", "https://example.com/t.txt").await;

    let off = app
        .clone()
        .oneshot(authed_form_owned(
            &format!("/filters/lists/{id}/toggle"),
            &token,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(off.status(), StatusCode::SEE_OTHER);
    let html = filters_html(&app, &token, "").await;
    assert!(!html.contains("checked"), "the list stayed enabled");
    // Nothing is enabled now, which the page has to say out loud.
    assert!(
        !html.contains(r#"data-testid="filters-all-disabled-warning" style="display:none""#),
        "the all-disabled warning stayed hidden"
    );

    let on = app
        .clone()
        .oneshot(authed_form_owned(
            &format!("/filters/lists/{id}/toggle"),
            &token,
            "enabled=on".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(on.status(), StatusCode::SEE_OTHER);
    assert!(
        filters_html(&app, &token, "").await.contains("checked"),
        "the list did not come back on"
    );
}

/// The Impact column answers one question: what stops being blocked if this
/// list goes away. Two lists holding the same rule each answer "nothing",
/// because removing either one on its own changes nothing — which is exactly
/// why the page tells the operator to turn them off one at a time.
#[tokio::test]
async fn the_filters_page_says_what_each_list_uniquely_provides() {
    let (app, token, _cache, _events, db, _sessions, _limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;

    for (name, file) in [("Shared", "a"), ("Overlapping", "b"), ("Alone", "c")] {
        add_list(
            &app,
            &token,
            name,
            &format!("https://example.com/{file}.txt"),
        )
        .await;
    }
    // `add_list` hands back the id of the *first* row, which is the same list
    // every time once there is more than one — so each id is read off its own
    // row here instead.
    let page = filters_html(&app, &token, "").await;
    let id_of = |name: &str| list_id_by_name(&page, name);
    let (shared, overlapping, alone) = (id_of("Shared"), id_of("Overlapping"), id_of("Alone"));
    // The download could not have succeeded against 127.0.0.1:1, so the content
    // is seeded directly — this test is about the comparison, not the fetch.
    db.set_filter_list_content(shared, "||ads.example^\n")
        .await
        .unwrap();
    db.set_filter_list_content(overlapping, "||ads.example^\n")
        .await
        .unwrap();
    db.set_filter_list_content(alone, "||tracker.example^\n||beacon.example^\n")
        .await
        .unwrap();

    // Any list change rebuilds the engine, and the engine is where the counts
    // come from. Posting the state a list is already in is the smallest thing
    // that triggers one — turning it off and on again would leave a window
    // where the engine is a rebuild that excluded it.
    let before = noadd::now_unix();
    let res = app
        .clone()
        .oneshot(authed_form_owned(
            &format!("/filters/lists/{alone}/toggle"),
            &token,
            "enabled=on".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    wait_for_rebuild(&app, &token, before).await;

    let html = filters_html(&app, &token, "").await;
    let row = |name: &str| {
        let start = html
            .find(&format!(r#"data-name="{name}""#))
            .unwrap_or_else(|| panic!("no row for {name}"));
        let rest = &html[start..];
        let end = rest.find("</tr>").expect("unterminated row");
        rest[..end].to_string()
    };

    assert!(
        row("Shared").contains("No impact"),
        "a rule another list also holds is not this list's own contribution: {}",
        row("Shared")
    );
    assert!(
        row("Overlapping").contains("No impact"),
        "the comparison has to be symmetric — both rows say the same thing"
    );
    assert!(
        row("Alone").contains("2 rules"),
        "rules no other list holds are what removing this list would cost"
    );
}

/// The same numbers reach `/api/lists`, because `app.js` redraws these rows
/// from it and a redrawn row has to be the row the server would have sent.
#[tokio::test]
async fn the_lists_api_carries_what_each_list_uniquely_provides() {
    let (app, token, _cache, _events, db, _sessions, _limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;

    let id = add_list(&app, &token, "Solo", "https://example.com/a.txt").await;
    db.set_filter_list_content(id, "||ads.example^\n")
        .await
        .unwrap();

    let before = noadd::now_unix();
    app.clone()
        .oneshot(authed_form_owned(
            &format!("/filters/lists/{id}/toggle"),
            &token,
            "enabled=on".to_string(),
        ))
        .await
        .unwrap();
    wait_for_rebuild(&app, &token, before).await;

    let res = app
        .clone()
        .oneshot(authed("GET", "/api/lists", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_text(res).await).unwrap();
    let list = body
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["id"] == id)
        .expect("the list is missing from /api/lists");
    assert_eq!(list["unique_rules"], 1);
}

/// A list the engine never loaded has nothing to compare, and saying so beats
/// printing a zero that would read as "safe to remove". A failed download looks
/// identical to a healthy list in every other column on the row.
#[tokio::test]
async fn a_list_that_never_downloaded_reports_no_rules_rather_than_no_impact() {
    let (app, token) = setup().await;
    add_list(&app, &token, "Never fetched", "https://example.com/a.txt").await;

    let html = filters_html(&app, &token, "").await;
    // Scoped to the row: the sentence above the table explains what "No impact"
    // means, so the phrase is on the page whether or not any list carries it.
    let row = {
        let start = html
            .find(r#"data-name="Never fetched""#)
            .expect("no row for the list");
        let rest = &html[start..];
        &rest[..rest.find("</tr>").expect("unterminated row")]
    };
    assert!(row.contains("No rules"), "{row}");
    assert!(
        !row.contains("No impact"),
        "an empty list must not read as a redundant one"
    );
}

/// Turning everything off and asking for the recommendation back is the escape
/// hatch from a noadd that looks healthy and blocks nothing.
#[tokio::test]
async fn enable_recommended_turns_a_list_back_on() {
    let (app, token) = setup().await;
    let id = add_list(&app, &token, "Only+List", "https://example.com/o.txt").await;
    app.clone()
        .oneshot(authed_form_owned(
            &format!("/filters/lists/{id}/toggle"),
            &token,
            String::new(),
        ))
        .await
        .unwrap();

    let res = app
        .clone()
        .oneshot(authed_form("/filters/lists/enable-recommended", &token, ""))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(
        filters_html(&app, &token, "").await.contains("checked"),
        "nothing was enabled"
    );
}

/// `?edit=` expands a row into a form filled from storage — not from the URL,
/// which is what stops a link pre-filling the form with values it carried.
#[tokio::test]
async fn expanding_a_list_for_editing_fills_the_form_from_storage() {
    let (app, token) = setup().await;
    let id = add_list(&app, &token, "Editable", "https://example.com/e.txt").await;

    let html = filters_html(&app, &token, &format!("?edit={id}")).await;
    assert!(
        html.contains(r#"data-testid="filter-list-edit-row""#),
        "the row did not expand"
    );
    assert!(
        html.contains(r#"value="Editable""#)
            && html.contains(r#"value="https://example.com/e.txt""#),
        "the edit form was not filled from storage"
    );

    // A nonsense id expands nothing rather than failing the whole page.
    let html = filters_html(&app, &token, "?edit=not-a-number").await;
    assert_eq!(html.matches("filter-list-edit-row").count(), 0);
}

/// A rejected edit keeps the row expanded with the submitted values, which is
/// the only way the operator gets to correct the field that was wrong.
#[tokio::test]
async fn editing_a_list_persists_and_a_rejection_keeps_the_row_open() {
    let (app, token) = setup().await;
    let id = add_list(&app, &token, "Before", "https://example.com/b.txt").await;

    let ok = app
        .clone()
        .oneshot(authed_form_owned(
            &format!("/filters/lists/{id}/edit"),
            &token,
            "name=After&url=https://example.com/a.txt".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::SEE_OTHER);
    assert!(
        filters_html(&app, &token, "")
            .await
            .contains(r#"data-name="After""#),
        "the edit did not persist"
    );

    let bad = app
        .clone()
        .oneshot(authed_form_owned(
            &format!("/filters/lists/{id}/edit"),
            &token,
            "name=&url=https://example.com/a.txt".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let html = body_text(bad).await;
    assert!(
        html.contains(r#"data-testid="filter-list-edit-row""#) && html.contains("Name is required"),
        "the rejected edit did not re-render the open row"
    );
}

/// Deleting a list is a POST — a GET would be followed by any link prefetcher
/// that happened across it.
#[tokio::test]
async fn deleting_a_list_through_the_form_persists() {
    let (app, token) = setup().await;
    let id = add_list(&app, &token, "Doomed", "https://example.com/d.txt").await;

    let res = app
        .clone()
        .oneshot(authed_form_owned(
            &format!("/filters/lists/{id}/delete"),
            &token,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(
        !filters_html(&app, &token, "")
            .await
            .contains(r#"data-name="Doomed""#),
        "the list survived its deletion"
    );
}

/// Adding and removing a custom rule, both through the form.
#[tokio::test]
async fn rules_can_be_added_and_deleted_through_the_form() {
    let (app, token) = setup().await;
    let added = app
        .clone()
        .oneshot(authed_form(
            "/filters/rules",
            &token,
            "rule=%40%40%7C%7Cformrule.example.com%5E",
        ))
        .await
        .unwrap();
    assert_eq!(added.status(), StatusCode::SEE_OTHER);

    let html = filters_html(&app, &token, "").await;
    assert!(
        html.contains("formrule.example.com") && html.contains(r#"data-type="allow""#),
        "the allow rule was not stored"
    );

    let marker = r#"action="/filters/rules/"#;
    let start = html.find(marker).expect("no rule row") + marker.len();
    let rest = &html[start..];
    let id: i64 = rest[..rest.find('/').unwrap()].parse().unwrap();

    let deleted = app
        .clone()
        .oneshot(authed_form_owned(
            &format!("/filters/rules/{id}/delete"),
            &token,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    assert!(
        !filters_html(&app, &token, "")
            .await
            .contains("formrule.example.com"),
        "the rule survived its deletion"
    );
}

/// Text that is not a rule re-renders with it still in the field, and says so.
#[tokio::test]
async fn an_unparseable_rule_re_renders_with_what_was_typed() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed_form("/filters/rules", &token, "rule=%20%20"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let html = body_text(res).await;
    assert!(
        html.contains("Not a rule noadd understands"),
        "the reason did not reach the form"
    );
    // The navigation still knows which page this is, even though the POST
    // arrived on `/filters/rules`.
    assert!(
        html.contains(r#"class="nav-item active" href="/filters""#),
        "the rejected post rendered with no active nav item"
    );
}

/// Every filters form is behind the session, like the page itself.
#[tokio::test]
async fn the_filters_forms_refuse_an_anonymous_browser() {
    let (app, _token) = setup().await;
    for path in [
        "/filters/lists",
        "/filters/lists/update",
        "/filters/lists/enable-recommended",
        "/filters/lists/1/toggle",
        "/filters/lists/1/edit",
        "/filters/lists/1/delete",
        "/filters/rules",
        "/filters/rules/1/delete",
    ] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("name=x&url=https://example.com/x.txt&rule=x"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::SEE_OTHER,
            "{path} answered an anonymous browser"
        );
        assert!(
            res.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .starts_with("/login"),
            "{path} did not send the browser to sign in"
        );
    }
}

// --- Query log page (server-rendered) ---

async fn logs_html(app: &axum::Router, token: &str, query: &str) -> String {
    let res = app
        .clone()
        .oneshot(authed("GET", &format!("/logs{query}"), token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    body_text(res).await
}

/// Rows and the pager arrive rendered, and the filters come back showing what
/// is applied — the whole page's state is in the URL.
#[tokio::test]
async fn the_logs_page_renders_rows_and_keeps_its_filters() {
    let (app, token, db) = setup_with_db().await;
    seed_queries(&db, "ads.example.com", "10.0.0.5", 2, true).await;
    seed_queries(&db, "good.example.com", "10.0.0.6", 1, false).await;

    let html = logs_html(&app, &token, "").await;
    assert!(html.contains("ads.example.com") && html.contains("good.example.com"));
    assert!(html.contains("Page 1 / 1"), "the pager was not rendered");
    assert!(html.contains("<logs-page>"), "the body was not wrapped");

    // A filter narrows the rows and comes back selected in the form.
    let html = logs_html(&app, &token, "?action=blocked").await;
    assert!(html.contains("ads.example.com"));
    assert!(
        !html.contains("good.example.com"),
        "the allowed query survived a blocked-only filter"
    );
    assert!(
        html.contains(r#"<option value="blocked" selected>"#),
        "the applied filter was not reflected in the form"
    );

    // And the search box keeps what was typed.
    let html = logs_html(&app, &token, "?q=good").await;
    assert!(
        html.contains(r#"value="good""#),
        "the search term was discarded"
    );
    assert!(
        !html.contains("ads.example.com"),
        "the search did not filter"
    );
}

/// Paging carries every filter. Dropping them would look like the filter
/// stopped working rather than like the page changed.
#[tokio::test]
async fn paging_keeps_the_filters_in_the_link() {
    let (app, token, db) = setup_with_db().await;
    // Two pages' worth, all blocked, so a filtered view still pages.
    seed_queries(&db, "ads.example.com", "10.0.0.5", 60, true).await;

    let html = logs_html(&app, &token, "?action=blocked").await;
    assert!(
        html.contains("Page 1 / 2"),
        "the total did not account for the filter"
    );
    let hrefs: Vec<&str> = html
        .match_indices(r#"href="/logs"#)
        .map(|(i, _)| {
            let rest = &html[i + 6..];
            &rest[..rest.find('"').unwrap_or(0)]
        })
        .collect();
    assert!(
        hrefs
            .iter()
            .any(|h| h.contains("action=blocked") && h.contains("page=2")),
        "the next link dropped the filter; links were {hrefs:?}"
    );

    let page2 = logs_html(&app, &token, "?action=blocked&page=2").await;
    assert!(page2.contains("Page 2 / 2"));
    assert!(
        page2.contains(r#"href="/logs?action=blocked""#),
        "the prev link did not return to an unnumbered first page"
    );
}

/// An empty table means two different things, and says which.
#[tokio::test]
async fn an_empty_log_is_told_apart_from_an_empty_filter() {
    let (app, token, db) = setup_with_db().await;

    // Nothing logged at all: the guide.
    let html = logs_html(&app, &token, "").await;
    assert!(html.contains(r#"data-testid="logs-empty-state""#));

    // Something logged, but nothing matching: not the guide.
    seed_queries(&db, "good.example.com", "10.0.0.6", 1, false).await;
    let html = logs_html(&app, &token, "?q=nothing-matches").await;
    assert!(html.contains("No logs found"));
    assert!(
        !html.contains(r#"data-testid="logs-empty-state""#),
        "a filtered miss showed the empty-log guide"
    );
}

/// A row's one-click action goes through the same rule path the filters page
/// uses, and returns to the view it was invoked from.
#[tokio::test]
async fn a_row_action_adds_the_rule_and_returns_to_the_same_view() {
    let (app, token, db) = setup_with_db().await;
    seed_queries(&db, "tracker.example.com", "10.0.0.5", 1, false).await;

    let res = app
        .clone()
        .oneshot(authed_form(
            "/logs/rules",
            &token,
            "rule=%7C%7Ctracker.example.com%5E&next=/logs%3Faction%3Dblocked",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/logs?action=blocked"),
        "the operator was not returned to the view they acted from"
    );

    // The rule is a real rule, parsed by the shared path.
    let filters = app
        .oneshot(authed("GET", "/filters", &token, None))
        .await
        .unwrap();
    assert!(body_text(filters).await.contains("tracker.example.com"));
}

/// `next` is attacker-controlled, so it gets the same treatment as `?next=` on
/// the sign-in page: same-origin paths only.
#[tokio::test]
async fn a_row_action_refuses_an_off_origin_return() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed_form(
            "/logs/rules",
            &token,
            "rule=%7C%7Cevil.example.com%5E&next=https://evil.example",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/logs"),
        "an off-origin next was honoured"
    );
}

/// Clearing answers on an unfiltered first page, whatever view it came from:
/// every filter now matches nothing, and "No logs found" would read as the
/// filter breaking rather than the log being empty.
#[tokio::test]
async fn clearing_the_log_lands_on_an_unfiltered_first_page() {
    let (app, token, db) = setup_with_db().await;
    seed_queries(&db, "ads.example.com", "10.0.0.5", 3, true).await;

    let res = app
        .clone()
        .oneshot(authed_form("/logs/clear", &token, ""))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/logs")
    );

    let html = logs_html(&app, &token, "").await;
    assert!(!html.contains("ads.example.com"), "the log was not cleared");
    assert!(html.contains(r#"data-testid="logs-empty-state""#));
}

/// A hand-edited page number lands on page one rather than 400-ing a page that
/// would otherwise render.
#[tokio::test]
async fn a_nonsense_page_number_renders_page_one() {
    let (app, token, db) = setup_with_db().await;
    seed_queries(&db, "good.example.com", "10.0.0.6", 1, false).await;

    for query in ["?page=not-a-number", "?page=0", "?page=-3"] {
        let html = logs_html(&app, &token, query).await;
        assert!(
            html.contains("Page 1 / 1"),
            "{query} did not land on page one"
        );
    }
}

/// Both logs forms are behind the session, like the page itself.
#[tokio::test]
async fn the_logs_forms_refuse_an_anonymous_browser() {
    let (app, _token) = setup().await;
    for path in ["/logs/rules", "/logs/clear"] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("rule=x"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::SEE_OTHER,
            "{path} answered anonymously"
        );
        assert!(
            res.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .starts_with("/login"),
            "{path} did not send the browser to sign in"
        );
    }
}

// --- Dashboard page (server-rendered) ---

/// A router plus the database behind it, so a test can seed the query log the
/// dashboard reads.
async fn setup_with_db() -> (axum::Router, String, Database) {
    let (router, token, _cache, _events, db, _sessions, _limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    (router, token, db)
}

/// Seed `count` queries for one domain, timestamped now. `query_logs.timestamp`
/// is milliseconds, which is exactly the sort of thing a test gets wrong once
/// and then never again.
async fn seed_queries(db: &Database, domain: &str, client: &str, count: usize, blocked: bool) {
    let now_ms = noadd::now_unix_ms();
    let entries: Vec<QueryLogEntry> = (0..count)
        .map(|i| QueryLogEntry {
            timestamp: now_ms - i as i64,
            domain: domain.to_string(),
            query_type: "A".to_string(),
            client_ip: client.to_string(),
            blocked,
            cached: false,
            response_ms: 12,
            upstream: Some("1.1.1.1:53".to_string()),
            doh_token: None,
            result: None,
            authenticated_data: false,
        })
        .collect();
    db.insert_query_logs(&entries).await.unwrap();
}

/// The numbers are in the first response. That is the whole point of rendering
/// this page on the server: it used to arrive empty and fill in over five API
/// calls.
#[tokio::test]
async fn the_dashboard_renders_its_numbers_and_tables() {
    let (app, token, db) = setup_with_db().await;
    seed_queries(&db, "ads.example.com", "10.0.0.5", 3, true).await;
    seed_queries(&db, "good.example.com", "10.0.0.6", 1, false).await;

    let res = app.oneshot(authed("GET", "/", &token, None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;

    // Four queries, three of them blocked: 75.0%. Matched with the surrounding
    // markup so a stray "4" elsewhere on the page cannot pass for the count.
    assert!(
        html.contains(r#"title="4">4</div>"#),
        "the query count was not rendered"
    );
    assert!(
        html.contains(r#"<div class="stat-value red">75.0%</div>"#),
        "the block rate was not rendered"
    );
    // Both domains, and the client they came from.
    assert!(
        html.contains("ads.example.com") && html.contains("good.example.com"),
        "the top-domains table was not rendered"
    );
    assert!(
        html.contains("10.0.0.5"),
        "the top-sources table was not rendered"
    );
    assert!(
        html.contains("1.1.1.1:53"),
        "the upstreams table was not rendered"
    );
    // Shares are rendered next to the counts.
    assert!(html.contains("(75.0%)"), "a row's share was not rendered");
    // The element the client upgrades in place.
    assert!(
        html.contains("<dashboard-page>"),
        "the body was not wrapped"
    );
}

/// With no traffic at all the page explains what to do about it, and hides the
/// chart it would otherwise draw an empty axis for.
#[tokio::test]
async fn an_appliance_with_no_queries_is_told_how_to_start() {
    let (app, token) = setup().await;
    let res = app.oneshot(authed("GET", "/", &token, None)).await.unwrap();
    let html = body_text(res).await;

    assert!(
        html.contains("Point a device at noadd to get started"),
        "the onboarding notice was not rendered"
    );
    assert!(
        !html.contains(r#"data-testid="dashboard-empty-state" style="display:none""#),
        "the onboarding notice was rendered hidden"
    );
    // The chart card carries one `style`, animation delay and all — a second
    // attribute would be dropped by the parser and the card would stay visible.
    assert!(
        html.contains(r#"id="chart-card" style="animation-delay:0.1s;display:none""#),
        "the chart card was not hidden"
    );
    // Zeroes, not blanks: an appliance that has answered nothing has answered
    // nothing, and the cards say so.
    assert!(
        html.contains(">0.0%<"),
        "the rates were not rendered as zero"
    );
}

/// The controls that only work with a client ship hidden rather than sitting
/// there doing nothing.
#[tokio::test]
async fn the_live_toggle_and_chart_are_marked_client_only() {
    let (app, token) = setup().await;
    let res = app.oneshot(authed("GET", "/", &token, None)).await.unwrap();
    let html = body_text(res).await;

    assert!(
        html.contains(r#"id="live-btn""#) && html.contains("js-only"),
        "the live toggle was not marked client-only"
    );
    assert!(
        html.contains(r#"data-testid="chart-needs-js""#),
        "the chart card did not say what it needs"
    );
}

// --- Registry page ---

/// A registry with one entry per case the page has to render: a plain one, a
/// deprecated one, one in a second group, and one whose homepage is a
/// `javascript:` URL that must never become a link.
fn registry_json(download_base: &str) -> String {
    let entry = |id: i64, group: i64, name: &str, desc: &str, homepage: &str, deprecated: bool| {
        format!(
            r#"{{
              "filterKey": "k{id}", "filterId": {id}, "groupId": {group},
              "name": "{name}", "description": "{desc}",
              "homepage": "{homepage}", "deprecated": {deprecated},
              "tags": [], "languages": [], "version": "1", "expires": 345600,
              "displayNumber": {id},
              "downloadUrl": "{download_base}/list_{id}.txt",
              "subscriptionUrl": "https://example.com/sub_{id}",
              "timeAdded": "2021-01-01T00:00:00+0000",
              "timeUpdated": "2026-04-19T00:00:00+0000"
            }}"#
        )
    };
    format!(
        r#"{{
          "filters": [
            {},
            {},
            {},
            {}
          ],
          "groups": [
            {{ "groupId": 1, "groupName": "General" }},
            {{ "groupId": 2, "groupName": "Security" }}
          ],
          "tags": []
        }}"#,
        entry(
            1,
            1,
            "Alpha List",
            "blocks alpha things",
            "https://alpha.example",
            false
        ),
        entry(
            2,
            2,
            "Beta Security",
            "blocks beta things",
            "https://beta.example",
            false
        ),
        entry(
            3,
            1,
            "Gamma Retired",
            "no longer maintained",
            "https://gamma.example",
            true
        ),
        entry(
            4,
            1,
            "Delta Hostile",
            "has a nasty homepage",
            "javascript:alert(1)",
            false
        ),
    )
}

async fn registry_html(app: &axum::Router, token: &str, query: &str) -> String {
    let res = app
        .clone()
        .oneshot(authed(
            "GET",
            &format!("/filters/registry{query}"),
            token,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    body_text(res).await
}

/// The whole registry arrives rendered, with the filters in the URL — the modal
/// this replaced had none of it without JavaScript.
#[tokio::test]
async fn the_registry_page_renders_its_entries() {
    let base = common::spawn_fake_upstream(
        "/filters.json",
        registry_json("https://lists.example"),
        "application/json",
    )
    .await;
    let (app, token) = setup_with_registry_url(format!("{base}/filters.json")).await;

    let html = registry_html(&app, &token, "").await;
    assert!(html.contains("<registry-page"), "the body was not wrapped");
    // Deprecated is hidden by default, so three of the four show.
    assert!(
        html.contains("Showing 3 of 4"),
        "the counts did not account for the default filters"
    );
    assert!(html.contains("Alpha List") && html.contains("Beta Security"));
    assert!(
        !html.contains("Gamma Retired"),
        "a deprecated entry rendered without being asked for"
    );
    // The group pill takes its colour from the group's name.
    assert!(
        html.contains(r#"<span class="group-pill security">Security</span>"#),
        "the group pill was not rendered"
    );
    // Every row posts its own id.
    assert!(html.contains(r#"name="filter_id" value="1""#));
}

/// Escaping keeps a value in its attribute; it does not make it safe to
/// navigate to. A `javascript:` homepage renders no link at all.
#[tokio::test]
async fn a_hostile_homepage_never_becomes_a_link() {
    let base = common::spawn_fake_upstream(
        "/filters.json",
        registry_json("https://lists.example"),
        "application/json",
    )
    .await;
    let (app, token) = setup_with_registry_url(format!("{base}/filters.json")).await;

    let html = registry_html(&app, &token, "").await;
    assert!(html.contains("Delta Hostile"), "the row itself is missing");
    assert!(
        !html.contains("javascript:"),
        "a javascript: URL reached the markup"
    );
    // The safe ones are still links.
    assert!(html.contains(r#"href="https://alpha.example""#));
}

/// Search, group and the deprecated toggle all live in the URL and come back
/// showing what is applied.
#[tokio::test]
async fn the_registry_filters_live_in_the_url() {
    let base = common::spawn_fake_upstream(
        "/filters.json",
        registry_json("https://lists.example"),
        "application/json",
    )
    .await;
    let (app, token) = setup_with_registry_url(format!("{base}/filters.json")).await;

    // Search matches the description as well as the name.
    let html = registry_html(&app, &token, "?q=beta").await;
    assert!(html.contains("Showing 1 of 4") && html.contains("Beta Security"));
    assert!(
        html.contains(r#"value="beta""#),
        "the search box did not keep what was typed"
    );

    let html = registry_html(&app, &token, "?group=2").await;
    assert!(html.contains("Showing 1 of 4") && html.contains("Beta Security"));
    assert!(
        html.contains(r#"<option value="2" selected>Security</option>"#),
        "the group select did not come back selected"
    );

    let html = registry_html(&app, &token, "?deprecated=1").await;
    assert!(
        html.contains("Showing 4 of 4") && html.contains("Gamma Retired"),
        "the deprecated toggle did not let them through"
    );
    assert!(html.contains(r#"name="deprecated" value="1" checked"#));

    // A filter that matches nothing says so rather than rendering an empty card.
    let html = registry_html(&app, &token, "?q=nothingatall").await;
    assert!(html.contains("Showing 0 of 4"));
    assert!(
        !html.contains(r#"data-testid="registry-empty" hidden"#),
        "the empty notice was rendered hidden"
    );
}

/// The form carries the current view, so adding from a filtered page comes back
/// to that page rather than to all of it.
#[tokio::test]
async fn the_add_form_carries_the_current_view() {
    let base = common::spawn_fake_upstream(
        "/filters.json",
        registry_json("https://lists.example"),
        "application/json",
    )
    .await;
    let (app, token) = setup_with_registry_url(format!("{base}/filters.json")).await;

    let html = registry_html(&app, &token, "?q=beta&group=2&deprecated=1").await;
    // The separators are escaped, which is what an attribute value wants — a
    // browser reads them back as `&`.
    assert!(
        html.contains(r#"action="/filters/registry/add?q=beta&#38;group=2&#38;deprecated=1""#),
        "the form did not carry the view it was submitted from"
    );
}

/// The third party is unreachable. That is a state the page renders — with a
/// retry that is an ordinary link — not an error it fails on.
#[tokio::test]
async fn an_unreachable_registry_renders_a_retry() {
    // The default setup points at a port nothing listens on.
    let (app, token) = setup().await;
    let html = registry_html(&app, &token, "?q=beta").await;

    assert!(
        html.contains(r#"data-testid="registry-unavailable""#),
        "the page did not say the registry was unreachable"
    );
    assert!(
        html.contains(r#"href="/filters/registry?q=beta""#),
        "the retry link did not return to the same view"
    );
}

/// Ticking nothing and pressing Add says so where the boxes are, rather than
/// redirecting to a page that would look like it had done something.
#[tokio::test]
async fn adding_nothing_is_answered_on_the_page() {
    let base = common::spawn_fake_upstream(
        "/filters.json",
        registry_json("https://lists.example"),
        "application/json",
    )
    .await;
    let (app, token) = setup_with_registry_url(format!("{base}/filters.json")).await;

    let res = app
        .oneshot(authed_form("/filters/registry/add", &token, ""))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("No lists selected"));
    assert!(html.contains(r#"data-testid="registry-failures""#));
}

/// A successful add redirects, so a refresh cannot add the same lists twice,
/// and the lists are really there.
#[tokio::test]
async fn adding_a_selection_redirects_to_the_filters_page() {
    let lists = common::spawn_fake_upstream(
        "/list_1.txt",
        "||alpha.example.com^\n".to_string(),
        "text/plain",
    )
    .await;
    let base =
        common::spawn_fake_upstream("/filters.json", registry_json(&lists), "application/json")
            .await;
    let (app, token, db) = {
        let (router, token, _cache, _events, db, _sessions, _limiter) =
            build_app_opts(&format!("{base}/filters.json"), true, false).await;
        (router, token, db)
    };

    let res = app
        .clone()
        .oneshot(authed_form("/filters/registry/add", &token, "filter_id=1"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").unwrap().to_str().unwrap(),
        "/filters"
    );

    let stored = db.get_filter_lists().await.unwrap();
    assert!(
        stored.iter().any(|l| l.name == "Alpha List"),
        "the list was not added; stored: {:?}",
        stored.iter().map(|l| &l.name).collect::<Vec<_>>()
    );

    // And the page now says so rather than offering to add it again.
    let html = registry_html(&app, &token, "").await;
    assert!(html.contains(r#"<span class="added-pill">Added</span>"#));
}

/// A list that cannot be downloaded comes back named, on the page, with the
/// reason — the one thing a redirect would discard.
#[tokio::test]
async fn a_failed_download_is_reported_on_the_page() {
    // The registry points its downloads at a port nothing listens on.
    let base = common::spawn_fake_upstream(
        "/filters.json",
        registry_json("http://127.0.0.1:1"),
        "application/json",
    )
    .await;
    let (app, token) = setup_with_registry_url(format!("{base}/filters.json")).await;

    let res = app
        .oneshot(authed_form("/filters/registry/add", &token, "filter_id=1"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(
        html.contains(r#"data-testid="registry-failures""#) && html.contains("Alpha List"),
        "the failure was not reported by name"
    );
}

// --- Statistics page ---

async fn stats_html(app: &axum::Router, token: &str, query: &str) -> String {
    let res = app
        .clone()
        .oneshot(authed("GET", &format!("/stats{query}"), token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    body_text(res).await
}

/// Five of the page's seven readings arrive in the first response: the
/// highlights, both breakdowns, both ranged lists and the health grid. Only the
/// three calendar-aligned charts are left to the client.
#[tokio::test]
async fn the_stats_page_renders_its_readings() {
    let (app, token, db) = setup_with_db().await;
    seed_queries(&db, "ads.example.com", "10.0.0.5", 3, true).await;
    seed_queries(&db, "good.example.com", "10.0.0.6", 1, false).await;

    let html = stats_html(&app, &token, "").await;

    assert!(html.contains("<stats-page>"), "the body was not wrapped");
    // Two distinct domains were queried.
    assert!(
        html.contains(r#"<div class="stat-label">Unique Domains</div><div class="stat-value accent" title="2">2</div>"#),
        "the highlights grid was not rendered"
    );
    // Both breakdowns: every query was an A record, three of four blocked.
    assert!(
        html.contains(r#"title="A">A</div>"#),
        "the query-type breakdown was not rendered"
    );
    assert!(
        html.contains(r#"title="Blocked">Blocked</div>"#),
        "the outcome breakdown was not rendered"
    );
    // Both ranged lists, with the share of the visible total alongside.
    assert!(
        html.contains("ads.example.com") && html.contains("good.example.com"),
        "the top-domains list was not rendered"
    );
    assert!(
        html.contains("10.0.0.5"),
        "the top-sources list was not rendered"
    );
    assert!(
        html.contains(r#"<div class="bar-row-pct">75.0%</div>"#),
        "a row's share was not rendered"
    );
    // The bar is sized against the largest row, so the largest one is full width.
    assert!(html.contains("width:100.0%"), "the bars were not sized");
    // And the health grid, which needs no traffic to have something to say.
    assert!(
        html.contains(r#"data-testid="db-health-card""#)
            && html.contains(r#"<div class="stat-label">Database Size</div>"#),
        "the database-health grid was not rendered"
    );
}

/// The range is the server's window, so it is in the URL: the switcher is three
/// links, the titles say which one is showing, and the active one is marked.
#[tokio::test]
async fn the_range_switcher_selects_the_window() {
    let (app, token) = setup().await;

    let html = stats_html(&app, &token, "").await;
    assert!(
        html.contains(r#"<a href="/stats?range=7d" class="active" aria-current="page">7d</a>"#),
        "the default range was not marked active"
    );
    assert!(
        html.contains("Top Domains (last 7d)"),
        "the card titles did not name the range"
    );

    let html = stats_html(&app, &token, "?range=30d").await;
    assert!(
        html.contains(r#"<a href="/stats?range=30d" class="active" aria-current="page">30d</a>"#),
        "the selected range was not marked active"
    );
    assert!(
        !html.contains(r#"<a href="/stats?range=7d" class="active""#),
        "two ranges were marked active at once"
    );
    assert!(
        html.contains("Queries (last 30d)")
            && html.contains("Block &amp; Cache rate (last 30d)")
            && html.contains("Top Domains (last 30d)")
            && html.contains("Top Sources (last 30d)"),
        "a card title kept the default range"
    );
}

/// A range someone typed themselves renders the default window rather than
/// refusing the page. This one is a link, and every window it supports is
/// spelled out in the switcher directly above it.
#[tokio::test]
async fn a_nonsense_range_renders_the_default_window() {
    let (app, token) = setup().await;
    let html = stats_html(&app, &token, "?range=nonsense").await;
    assert!(
        html.contains("Top Domains (last 7d)"),
        "an unrecognised range did not fall back to the default"
    );
}

/// The three charts are the documented exception to this page working without
/// scripting, and they say so rather than sitting empty. They are also exactly
/// the three readings that take a `tz_offset`.
#[tokio::test]
async fn the_charts_say_they_are_drawn_in_the_browser() {
    let (app, token) = setup().await;
    let html = stats_html(&app, &token, "").await;

    for testid in [
        "timeline-needs-js",
        "rate-trend-needs-js",
        "heatmap-needs-js",
    ] {
        assert!(
            html.contains(&format!(r#"data-testid="{testid}""#)),
            "the {testid} card did not say what it needs"
        );
    }
}

/// An appliance that has answered nothing still renders every card, saying so,
/// rather than failing to load.
#[tokio::test]
async fn a_stats_page_with_no_traffic_renders_empty_lists() {
    let (app, token) = setup().await;
    let html = stats_html(&app, &token, "").await;

    assert!(
        html.matches(r#"<p class="text-dim">No data yet</p>"#)
            .count()
            == 4,
        "the four bar lists did not all report an empty window"
    );
    // No samples means no percentiles, and a zero would read as an impossibly
    // fast one.
    assert!(
        html.contains(
            r#"<div class="stat-label">Latency p50</div><div class="stat-value text-green">—</div>"#
        ),
        "a latency with no samples was rendered as a number"
    );
}

// --- Account page: tables and the password-proofed actions ---

/// The admin password `build_app` provisions. Every form below that needs a
/// password proof presents this one.
const ACCOUNT_PASSWORD: &str = "admin";

async fn account_html(app: &axum::Router, token: &str, query: &str) -> String {
    let res = app
        .clone()
        .oneshot(authed("GET", &format!("/account{query}"), token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    body_text(res).await
}

/// The id of the operator with this username, read out of the page's markup.
fn operator_id(html: &str, username: &str) -> i64 {
    let row = format!(r#"data-testid="operator-row" data-name="{username}""#);
    let start = html.find(&row).expect("no such operator row");
    // The row's delete control is the link that expands it, not a form action —
    // the form only exists once the row is expanded.
    let marker = "?confirm_delete=";
    let rest = &html[start..];
    let at = rest.find(marker).expect("no delete link on the row") + marker.len();
    let tail = &rest[at..];
    tail[..tail.find('"').unwrap()]
        .parse()
        .expect("operator id was not a number")
}

/// The tables are the page now: nothing is fetched to fill them in.
#[tokio::test]
async fn the_account_page_renders_its_three_tables() {
    let (app, token) = setup().await;
    let html = account_html(&app, &token, "").await;

    // The signed-in operator is listed, and marked.
    assert!(
        html.contains(r#"data-testid="operator-row""#) && html.contains(">you<"),
        "the operators table was not rendered"
    );
    // Their own session is listed, and marked as this device.
    assert!(
        html.contains(r#"data-testid="session-row""#) && html.contains("this device"),
        "the sessions table was not rendered"
    );
    assert!(
        html.contains("No API keys yet"),
        "the API keys table was not rendered"
    );
    // The element the client upgrades in place.
    assert!(html.contains("<account-page>"), "the body was not wrapped");
}

/// The last operator standing cannot be deleted, and neither can you delete
/// yourself — so no row offers a link that only exists to be refused.
#[tokio::test]
async fn the_only_operator_has_no_delete_link() {
    let (app, token) = setup().await;
    let html = account_html(&app, &token, "").await;
    assert!(
        !html.contains("/account/operators/"),
        "a delete link was offered for the last operator"
    );
    assert!(
        html.contains(r#"aria-disabled="true""#),
        "the disabled state was not rendered"
    );
}

/// Adding an operator needs the acting operator's own password, in the form.
#[tokio::test]
async fn adding_an_operator_needs_the_password_and_redirects() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed_form(
            "/account/operators",
            &token,
            "username=second&password=another-long-passphrase&confirm=another-long-passphrase\
             &your_password=admin",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/account")
    );

    let html = account_html(&app, &token, "").await;
    assert!(
        html.contains(r#"data-name="second""#),
        "the operator is not listed"
    );
}

/// A wrong proof creates nothing and keeps the username, so only the password
/// has to be retyped.
#[tokio::test]
async fn a_wrong_proof_refuses_to_add_an_operator() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed_form(
            "/account/operators",
            &token,
            "username=nope&password=another-long-passphrase&confirm=another-long-passphrase\
             &your_password=wrong",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let html = body_text(res).await;
    assert!(
        html.contains("password is incorrect"),
        "the reason did not reach the form"
    );
    assert!(
        html.contains(r#"value="nope""#),
        "the typed username was discarded"
    );
    // No password is echoed back into the markup, ever.
    assert!(
        !html.contains("another-long-passphrase") && !html.contains(">wrong<"),
        "a password was rendered into the page"
    );
    // The navigation still knows this is the account page, though the POST
    // arrived on /account/operators.
    assert!(html.contains(r#"class="nav-item active" href="/account""#));

    let html = account_html(&app, &token, "").await;
    assert!(
        !html.contains(r#"data-name="nope""#),
        "the operator was created anyway"
    );
}

/// The mismatch is caught before the password is even checked, so a typo in the
/// new password does not spend an attempt from the shared budget.
#[tokio::test]
async fn a_mismatched_new_password_is_refused_without_spending_an_attempt() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed_form(
            "/account/operators",
            &token,
            "username=third&password=another-long-passphrase&confirm=different-passphrase\
             &your_password=admin",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(res).await.contains("Passwords do not match"));
}

/// `?confirm_delete=` expands the row into a named confirmation with its own
/// password field — the whole of the delete prompt, on the server.
#[tokio::test]
async fn deleting_an_operator_confirms_by_name_then_goes_through() {
    let (app, token) = setup().await;
    app.clone()
        .oneshot(authed_form(
            "/account/operators",
            &token,
            "username=doomed&password=another-long-passphrase&confirm=another-long-passphrase\
             &your_password=admin",
        ))
        .await
        .unwrap();
    let id = operator_id(&account_html(&app, &token, "").await, "doomed");

    let expanded = account_html(&app, &token, &format!("?confirm_delete={id}")).await;
    assert!(
        expanded.contains(r#"data-testid="operator-confirm-row""#) && expanded.contains("doomed"),
        "the confirmation did not name the operator"
    );

    // An id naming nobody expands nothing rather than confirming a delete of
    // someone who is not there.
    let none = account_html(&app, &token, "?confirm_delete=999999").await;
    assert!(!none.contains(r#"data-testid="operator-confirm-row""#));

    let res = app
        .clone()
        .oneshot(authed_form_owned(
            &format!("/account/operators/{id}/delete"),
            &token,
            format!("your_password={ACCOUNT_PASSWORD}"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(
        !account_html(&app, &token, "")
            .await
            .contains(r#"data-name="doomed""#),
        "the operator survived"
    );
}

/// A wrong proof leaves the operator in place, with the row still expanded so
/// the password can simply be retyped.
#[tokio::test]
async fn a_wrong_proof_refuses_to_delete_an_operator() {
    let (app, token) = setup().await;
    app.clone()
        .oneshot(authed_form(
            "/account/operators",
            &token,
            "username=spared&password=another-long-passphrase&confirm=another-long-passphrase\
             &your_password=admin",
        ))
        .await
        .unwrap();
    let id = operator_id(&account_html(&app, &token, "").await, "spared");

    let res = app
        .clone()
        .oneshot(authed_form_owned(
            &format!("/account/operators/{id}/delete"),
            &token,
            "your_password=wrong".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let html = body_text(res).await;
    assert!(html.contains(r#"data-testid="operator-confirm-row""#));
    assert!(html.contains("password is incorrect"));

    assert!(
        account_html(&app, &token, "")
            .await
            .contains(r#"data-name="spared""#),
        "the operator was deleted despite the wrong password"
    );
}

/// The API key form is the one success that renders rather than redirecting:
/// the token exists in that response and nowhere else.
#[tokio::test]
async fn creating_an_api_key_shows_the_token_once() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed_form(
            "/account/api-keys",
            &token,
            "name=ci&expires=&your_password=admin",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "creating a key should render");
    let html = body_text(res).await;
    assert!(
        html.contains(r#"data-testid="api-key-token""#) && html.contains("noadd_"),
        "the token was not shown"
    );
    assert!(
        html.contains(r#"data-name="ci""#),
        "the key is not in the table"
    );

    // And it is gone from the next render — the secret is not stored, so the
    // page cannot show it again even if it wanted to.
    let later = account_html(&app, &token, "").await;
    assert!(later.contains(r#"data-name="ci""#));
    assert!(
        !later.contains(r#"data-testid="api-key-token""#),
        "the token came back on a later page load"
    );
}

/// A wrong proof mints nothing and keeps the name and the expiry date.
#[tokio::test]
async fn a_wrong_proof_refuses_to_mint_an_api_key() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed_form(
            "/account/api-keys",
            &token,
            "name=rejected&expires=2030-06-01&your_password=wrong",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let html = body_text(res).await;
    assert!(html.contains("password is incorrect"));
    assert!(
        html.contains(r#"value="rejected""#) && html.contains(r#"value="2030-06-01""#),
        "the submitted values were discarded"
    );
    assert!(!html.contains("noadd_"), "a key was minted anyway");
}

/// An unusable expiry is caught before the password is checked.
#[tokio::test]
async fn an_unparseable_expiry_is_refused() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed_form(
            "/account/api-keys",
            &token,
            "name=ci&expires=soon&your_password=admin",
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(body_text(res).await.contains("YYYY-MM-DD"));
}

/// Revoking a key needs no password: it only ever reduces access.
#[tokio::test]
async fn an_api_key_can_be_revoked_from_the_page() {
    let (app, token) = setup().await;
    let created = app
        .clone()
        .oneshot(authed_form(
            "/account/api-keys",
            &token,
            "name=doomed-key&expires=&your_password=admin",
        ))
        .await
        .unwrap();
    let html = body_text(created).await;
    let marker = r#"action="/account/api-keys/"#;
    let start = html.find(marker).expect("no delete form") + marker.len();
    let rest = &html[start..];
    let id: i64 = rest[..rest.find('/').unwrap()].parse().unwrap();

    let res = app
        .clone()
        .oneshot(authed_form_owned(
            &format!("/account/api-keys/{id}/delete"),
            &token,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(
        account_html(&app, &token, "")
            .await
            .contains("No API keys yet"),
        "the key survived"
    );
}

/// Revoking someone else's session leaves you signed in; revoking your own
/// signs you out, which is a redirect to the sign-in page rather than a notice
/// on a page you can no longer see.
#[tokio::test]
async fn revoking_your_own_session_signs_you_out() {
    let (app, token) = setup().await;
    let html = account_html(&app, &token, "").await;
    let marker = r#"data-testid="session-row" data-id=""#;
    let start = html.find(marker).expect("no session row") + marker.len();
    let rest = &html[start..];
    let id: i64 = rest[..rest.find('"').unwrap()].parse().unwrap();

    let res = app
        .clone()
        .oneshot(authed_form_owned(
            &format!("/account/sessions/{id}/revoke"),
            &token,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/login")
    );

    // The revoked cookie no longer authenticates anything.
    let after = app
        .oneshot(authed("GET", "/account", &token, None))
        .await
        .unwrap();
    assert_eq!(after.status(), StatusCode::SEE_OTHER);
}

/// Signing the other devices out keeps this one signed in — the point of the
/// button being separate from "log out".
#[tokio::test]
async fn revoking_other_sessions_keeps_this_one() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed_form("/account/sessions/revoke-others", &token, ""))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/account")
    );

    let after = app
        .oneshot(authed("GET", "/account", &token, None))
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "this session was signed out too"
    );
}

/// Every account form is behind the session, like the page itself.
#[tokio::test]
async fn the_account_forms_refuse_an_anonymous_browser() {
    let (app, _token) = setup().await;
    for path in [
        "/account/operators",
        "/account/operators/1/delete",
        "/account/sessions/revoke-others",
        "/account/sessions/1/revoke",
        "/account/api-keys",
        "/account/api-keys/1/delete",
    ] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("your_password=x&username=x&name=x"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::SEE_OTHER,
            "{path} answered an anonymous browser"
        );
        assert!(
            res.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .starts_with("/login"),
            "{path} did not send the browser to sign in"
        );
    }
}
