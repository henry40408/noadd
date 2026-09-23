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

/// A router with no operator, so `/api/auth/setup` does not answer 409.
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

/// `build_app` with control over `AppState::cookie_secure`, also handing back the
/// `Database`, `SessionStore` and `invalid_session_limiter` behind the router so
/// tests can seed sessions and inspect the limiter directly.
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
    let cache = DnsCache::with_capacity_bytes(64 * 1024 * 1024);
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
    // An operator and a bound session, unless testing setup.
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
        events: std::sync::Arc::new(noadd::admin::events::EventHub::new(8)),
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

/// The `value` of the `<input>` carrying `id`, if any. A bare
/// `html.contains(r#"value="30""#)` would also match the settings page's
/// datalist `<option>`s, so this anchors to the input's own tag.
fn input_value<'a>(html: &'a str, id: &str) -> Option<&'a str> {
    let id_at = html.find(&format!(r#"id="{id}""#))?;
    let tag_start = html[..id_at].rfind('<')?;
    let tag = &html[tag_start..tag_start + html[tag_start..].find('>')?];
    let value_at = tag.find(r#"value=""#)? + r#"value=""#.len();
    let rest = &tag[value_at..];
    Some(&rest[..rest.find('"')?])
}

/// Splits `buf` into whole SSE frames, leaving any partial one (split across
/// chunks) behind.
fn drain_sse_frames(buf: &mut String) -> Vec<String> {
    let mut frames = Vec::new();
    while let Some(end) = buf.find("\n\n") {
        frames.push(buf.drain(..end + 2).collect());
    }
    frames
}

/// The JSON of a frame carrying event `name`, if that is what this frame is.
fn sse_event_data(frame: &str, name: &str) -> Option<serde_json::Value> {
    let mut matched = false;
    let mut data = None;
    for line in frame.lines() {
        if let Some(event) = line.strip_prefix("event:") {
            matched = event.trim() == name;
        } else if let Some(payload) = line.strip_prefix("data:") {
            data = serde_json::from_str(payload.trim()).ok();
        }
    }
    matched.then_some(data).flatten()
}

/// Waits for the rebuild that began at or after `before` to finish, via the
/// event stream. Every connection opens with a `rebuild` event, so a rebuild
/// that already finished is reported as settled straight away.
async fn wait_for_rebuild(app: &axum::Router, token: &str, before: i64) {
    let req = Request::builder()
        .uri("/api/events")
        .header("cookie", format!("session={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut stream = resp.into_body().into_data_stream();
    let mut buf = String::new();
    let settled = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(chunk) = stream.next().await {
            buf.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
            for frame in drain_sse_frames(&mut buf) {
                let Some(body) = sse_event_data(&frame, "rebuild") else {
                    continue;
                };
                // started_at >= before proves *this* rebuild began, and
                // !rebuilding that it finished.
                let rebuilding = body["rebuilding"].as_bool().unwrap_or(false);
                let started_at = body["started_at"].as_i64().unwrap_or(0);
                if !rebuilding && started_at >= before {
                    return true;
                }
            }
        }
        false
    })
    .await
    .expect("timed out waiting for the rebuild to settle");
    assert!(
        settled,
        "the event stream closed before the rebuild settled"
    );
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

/// The stream is the only place rebuild state is published, so it must answer
/// "what is happening now", not only "what changed".
#[tokio::test]
async fn event_stream_opens_with_the_current_rebuild_state() {
    let (app, token) = setup().await;
    let req = Request::builder()
        .uri("/api/events")
        .header("cookie", format!("session={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut stream = resp.into_body().into_data_stream();
    let mut buf = String::new();
    let opening = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(chunk) = stream.next().await {
            buf.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
            for frame in drain_sse_frames(&mut buf) {
                if let Some(body) = sse_event_data(&frame, "rebuild") {
                    return Some(body);
                }
            }
        }
        None
    })
    .await
    .expect("timed out waiting for the opening rebuild event")
    .expect("the stream closed without an opening rebuild event");

    // An appliance that has never rebuilt still reports it.
    assert_eq!(opening["rebuilding"].as_bool(), Some(false));
    assert_eq!(opening["started_at"].as_i64(), Some(0));
    assert_eq!(opening["last_duration_ms"].as_u64(), Some(0));
    assert!(
        opening.get("last_completed_at").is_none(),
        "last_completed_at was dropped: no consumer read it"
    );
}

/// A rebuild can start and finish between two ticks, so both edges are published.
#[tokio::test]
async fn event_stream_reports_both_edges_of_a_rebuild() {
    let (app, token) = setup().await;
    let req = Request::builder()
        .uri("/api/events")
        .header("cookie", format!("session={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = resp.into_body().into_data_stream();

    // The handler subscribes while producing the response, so a rebuild
    // triggered after oneshot() returns cannot be missed.
    let resp = app
        .oneshot(authed(
            "POST",
            "/api/rules",
            &token,
            Some(r#"{"rule":"||edges.example.com^"}"#),
        ))
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let mut buf = String::new();
    let mut flags = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(chunk) = stream.next().await {
            buf.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
            for frame in drain_sse_frames(&mut buf) {
                if let Some(body) = sse_event_data(&frame, "rebuild") {
                    flags.push(body["rebuilding"].as_bool().unwrap_or(false));
                }
            }
            // The opening state, then the two edges.
            if flags.len() >= 3 {
                return;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out; rebuild events so far: {flags:?}"));

    assert_eq!(
        flags,
        vec![false, true, false],
        "expected the opening idle state, then a rebuild starting and finishing"
    );
}

#[tokio::test]
async fn test_health_endpoint_reports_no_drop_counter() {
    // Dropped query-log events are reported by an error-level log line, not a
    // counter here: a cumulative number has neither a time nor a denominator.
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

/// The stored identifier must not be the credential: a copy of the database
/// (backup, stray WAL, discarded SD card) must not hand over a live session.
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
    // The in-memory store is keyed the same way, so a row deleted by id can be
    // evicted from memory by the value the DELETE returned.
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
    // `Secure` implies `__Host-`: the browser enforces `Path=/` and no `Domain`,
    // blocking a subdomain override.
    assert!(
        cookie.starts_with("__Host-session="),
        "cookie_secure must emit the __Host- prefixed name: {cookie}"
    );
}

#[tokio::test]
async fn test_login_cookie_not_secure_when_disabled() {
    // Over plain HTTP a Secure cookie is dropped, locking the operator out.
    let (app, _token, _cache, _events, _db, _sessions, _invalid_session_limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    let cookie = login_set_cookie(app).await;
    assert!(
        !cookie.contains("Secure"),
        "session cookie must not be Secure when cookie_secure is off: {cookie}"
    );
    // Browsers reject a non-`Secure` `__Host-` cookie, so it stays unprefixed.
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
    // Turning `cookie_secure` on must not invalidate sessions issued under the
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
    // RFC 6265bis §5.5: a non-`Secure` `__Host-` `Set-Cookie` is ignored, so
    // the removal would silently not happen.
    assert!(
        set_cookie.contains("Secure"),
        "the __Host- removal must carry Secure or browsers ignore it entirely: {set_cookie}"
    );
}

/// OWASP session-ID brute-force detection: cookies naming no live session are
/// counted per source IP so a burst reaches the audit log. Asserted through the
/// limiter: after `INVALID_SESSION_MAX_ATTEMPTS - 1` rejections, the test's own
/// attempt must be the one that crosses the threshold.
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

/// Only a *presented* session cookie counts; ordinary cookie-less 401s would
/// drown the signal.
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
    // Regression: a stale `__Host-session` (e.g. from before TLS moved to a
    // reverse proxy) alongside a valid `session`. Auth must fall through to the
    // cookie that validates, not stick on the positionally-preferred dead one.
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
    // Mirror case: valid `__Host-session`, stale `session`.
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
    // Regression: with a stale `__Host-session` beside a live `session` (see
    // `session_cookie_hashes`), `logout` acted on the positionally-first cookie
    // and left the live token that authenticated the request valid.
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
    // Both cookie names can name a live session at once (sign in over HTTP,
    // then again after enabling --cookie-secure). `logout` clears both names,
    // so it must revoke both sessions, not just one.
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
    // `revoke_others` must keep the session that authenticated, not the stale
    // positionally-first cookie, or it signs the caller out too.
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
    let cache = DnsCache::with_capacity_bytes(64 * 1024 * 1024);
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
        events: std::sync::Arc::new(noadd::admin::events::EventHub::new(8)),
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
        events: std::sync::Arc::new(noadd::admin::events::EventHub::new(8)),
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

    // No partial write: the valid block_mode was not persisted either.
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

/// Every custom-IP address the settings form's `<datalist>` offers is one the
/// save accepts — a rejected suggestion reads as a bug, not a typo.
#[tokio::test]
async fn block_custom_ip_suggestions_are_all_accepted() {
    use noadd::admin::api::{BLOCK_CUSTOM_IPV4_SUGGESTIONS, BLOCK_CUSTOM_IPV6_SUGGESTIONS};

    let (app, token) = setup().await;

    assert!(!BLOCK_CUSTOM_IPV4_SUGGESTIONS.is_empty());
    assert_eq!(
        BLOCK_CUSTOM_IPV6_SUGGESTIONS.len(),
        BLOCK_CUSTOM_IPV4_SUGGESTIONS.len(),
        "the form shows the two lists side by side; keep them the same depth"
    );

    // Paired, as custom_ip mode is actually used.
    for (v4, v6) in BLOCK_CUSTOM_IPV4_SUGGESTIONS
        .iter()
        .zip(BLOCK_CUSTOM_IPV6_SUGGESTIONS)
    {
        let body = format!(
            r#"{{"block_mode":"custom_ip","block_custom_ipv4":"{v4}","block_custom_ipv6":"{v6}"}}"#
        );
        let response = app
            .clone()
            .oneshot(authed("PUT", "/api/settings", &token, Some(&body)))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "suggested pair {v4} / {v6} was rejected"
        );

        let response = app
            .clone()
            .oneshot(authed("GET", "/api/settings", &token, None))
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["block_custom_ipv4"], *v4);
        assert_eq!(json["block_custom_ipv6"], *v6);
    }
}

/// The same for retention, which `apply_settings` does not validate: every
/// suggestion must round-trip.
#[tokio::test]
async fn log_retention_suggestions_are_all_accepted() {
    use noadd::admin::stats::LOG_RETENTION_DAYS_SUGGESTIONS;

    let (app, token) = setup().await;

    for days in LOG_RETENTION_DAYS_SUGGESTIONS {
        let body = format!(r#"{{"log_retention_days":"{days}"}}"#);
        let response = app
            .clone()
            .oneshot(authed("PUT", "/api/settings", &token, Some(&body)))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "suggested retention {days} was rejected"
        );

        let response = app
            .clone()
            .oneshot(authed("GET", "/api/settings", &token, None))
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["log_retention_days"], days.to_string());
    }
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

    // A partial update with only block_mode must preserve the stored custom IPs.
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
    // Regression: a missing asset such as /favicon.ico must 404, not return HTML.
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
    // /favicon.svg must be served as image/svg+xml.
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
    // There is no SPA fallback: every page is a real route, and `/dashboard`
    // (the dashboard is `/`) is not one.
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

/// A `tracing` sink that keeps everything written to it. Under nextest each test
/// is its own process, so the thread-local default cannot leak between tests.
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

    /// Install as the default subscriber while the guard lives. JSON, so a field
    /// matches as `"field":value`.
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

/// Source for the maximum-length tests: long enough to slice 128 characters from
/// and strong on zxcvbn, which would reject `"a".repeat(128)` as a repeat.
const STRONG_LONG_PASSPHRASE: &str = concat!(
    "vermilion-thicket-marlin-quartz-nimbus-cobalt-drift-walnut-orbit-",
    "vermilion-thicket-marlin-quartz-nimbus-cobalt-drift-walnut-orbit-",
);

/// 100 *distinct* CJK characters, for the same reason.
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
        // One under the 12-character minimum, so an off-by-one still fails.
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
        // Exactly the 12-character minimum.
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

/// A password past the 128-character maximum is rejected, not truncated —
/// truncation would let every password sharing the first 128 characters in.
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

/// Exactly 128 characters is still accepted.
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

/// The length band counts characters, not bytes (a CJK character is 3 bytes).
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

    // 100 characters / 300 bytes — inside the maximum only if counted in characters.
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

/// Asks for `/app.css`, an embedded asset: `/` is a page and redirects an
/// unauthenticated request.
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

/// The session token a response's `Set-Cookie` hands back, if any (rotation tests).
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

/// A login attempt from source address `ip`. The tests below use a different
/// address per attempt — the distributed attack the account lockout exists for:
/// each stays inside its own IP budget, and only the account budget sees them all.
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

/// Spend an account's free allowance, one address per attempt, leaving it locked.
/// Returns the number of addresses used, so a caller can pick fresh ones.
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

/// Many source addresses share one account budget; once spent, even the correct
/// password is refused.
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

/// A lockout that announced itself would reopen user enumeration, so a locked
/// account must be indistinguishable from an unknown one.
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

/// A correct password clears the failure history rather than leaving the operator
/// one slip from a lockout.
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

    // The allowance is whole again: the same failures still do not lock.
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

/// The other two endpoints that verify the password share the account budget,
/// or a session holder could grind the credential there unmetered.
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

/// Age a session's password proof past the re-authentication window, leaving the
/// session itself valid. Returns the number of sessions aged.
fn expire_reauth(sessions: &SessionStore, token: &str) -> usize {
    let hash = hash_session_token(token);
    let mut map = sessions.lock();
    let Some(info) = map.get_mut(&hash) else {
        return 0;
    };
    info.last_reauth_at = noadd::now_unix() - noadd::admin::auth::REAUTH_WINDOW_SECS - 1;
    1
}

/// A stolen session cookie must not mint durable access (an API key outlives a
/// password change), so these actions need a recent password proof.
#[tokio::test]
async fn sensitive_actions_need_a_recent_password_proof() {
    // Each hands out durable access: an API key or an operator account.
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

        // Fresh out of login the proof is current.
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
            "API callers key off this code — a bare 403 is indistinguishable from the CSRF guard's"
        );
    }
}

/// Re-authenticating via `POST /api/auth/reauth` restores the window, so the
/// refused action succeeds on retry.
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

/// A wrong password must not reopen the window.
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

/// Verifying a password makes this a guessing surface, so it is rate limited
/// like `change_own_password`.
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

/// The length band applies wherever a password is set, not just at setup.
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

/// The username is validated with the same shape of rejection as the password.
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

/// Length alone is weak (`password1234` clears a 12-character floor), so every
/// endpoint that sets a password also runs the guessability check.
#[tokio::test]
async fn every_set_password_endpoint_rejects_a_guessable_password() {
    // Each clears the length band: a padded top-N password, a keyboard run,
    // dictionary words, and one built from the account's own name.
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

/// A rejection says what to change, so a too-short password is distinguishable
/// from a too-guessable one.
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

/// A password built from the username passes a length floor and a breach list;
/// zxcvbn only catches it if the username is passed in as a user input.
#[tokio::test]
async fn the_username_is_fed_to_the_guessability_check() {
    // `zephyrqualm-8412` is weak *only* relative to that username (zxcvbn scores
    // 2 with it as a user input, 4 without). The second half proves the password
    // is not simply weak.
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

/// Creating and deleting an operator are audited, naming who acted and on whom.
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
    // Both the acting operator (admin, id 1) and the target (bob, id 2).
    assert!(
        text.contains(r#""user_id":1"#) && text.contains(r#""target_user_id":2"#),
        "both the acting and the target operator must be named:\n{text}"
    );
    assert!(
        text.contains(r#""target_username":"bob""#),
        "an audit of who was provisioned is unreadable without the name:\n{text}"
    );
}

/// Changing a password verifies one, so it is throttled like login — or a
/// signed-in terminal could grind the current-password field.
#[tokio::test]
async fn change_own_password_is_rate_limited() {
    let (app, token) = setup().await;
    // Same 5-per-60s limiter as `main`; every request shares the fallback IP.
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

/// Deliberately the same budget as `login`: the same credential guessed from the
/// same address.
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

/// An absurdly long password is refused before Argon2. The cap
/// (`MAX_LOGIN_PASSWORD_LENGTH`) is far above `MAX_PASSWORD_LENGTH` so a password
/// predating that limit still works; it only bounds unauthenticated work.
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

    // Token A (the device that made the change) stays signed in, under the
    // rotated token.
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

/// OWASP: renew the session ID after a privilege change. Revoking other sessions
/// does nothing about a token leaked out-of-band (a proxy log); rotation does.
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

    // The replacement carries the same cookie protections login issues.
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

    // Exactly one session survives, stored as a hash, in memory and on disk — a
    // lingering superseded row would be restored live by a restart.
    let rows = db.list_sessions().await.unwrap();
    assert_eq!(rows.len(), 1, "the superseded row must be deleted");
    assert_eq!(rows[0].token_hash, hash_session_token(&rotated));
    let live = sessions.lock();
    assert_eq!(live.len(), 1);
    assert!(live.contains_key(&hash_session_token(&rotated)));
}

/// Changing a password revokes only the caller's own sessions
/// (`revoke_user_sessions_except`), never every operator's (`revoke_other_sessions`).
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

    // The tail is `?logs=1` on the shared stream. The handler subscribes while
    // producing the response, so a publish after oneshot() returns is delivered.
    let req = Request::builder()
        .uri("/api/events?logs=1")
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

    // Read frames until our entry arrives (keep-alives may interleave), bounded
    // so a regression cannot hang the suite.
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
    // Named: an unnamed event reaches `onmessage`, not the page's `log` listener.
    assert!(
        seen.contains("event: log"),
        "the entry did not arrive as a `log` event; got: {seen}"
    );
}

/// Every page holds this stream open, so without `?logs=1` it must not carry
/// every query answered.
#[tokio::test]
async fn event_stream_sends_no_logs_when_they_are_not_asked_for() {
    let (app, token, _cache, events) = build_app("http://127.0.0.1:1/filters.json", true).await;

    let req = Request::builder()
        .uri("/api/events")
        .header("cookie", format!("session={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let entry = QueryLogEntry {
        timestamp: 1234,
        domain: "unwanted.example.com".to_string(),
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
    let _ = events.send(Arc::new(entry));

    let mut stream = resp.into_body().into_data_stream();
    let mut seen = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(chunk) = stream.next().await {
            seen.push_str(&String::from_utf8_lossy(&chunk.unwrap()));
        }
    })
    .await;
    assert!(
        !seen.contains("unwanted.example.com"),
        "a stream that did not ask for logs received one: {seen}"
    );
}

/// An unauthenticated stream would be a pre-auth handle on the appliance.
#[tokio::test]
async fn event_stream_refuses_an_unauthenticated_client() {
    let (app, _token, _cache, _events) = build_app("http://127.0.0.1:1/filters.json", true).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A `stats=1` stream gets a snapshot as it opens, not a tick later.
#[tokio::test]
async fn event_stream_opens_with_a_snapshot_when_stats_are_asked_for() {
    let (app, token, _cache, _events) = build_app("http://127.0.0.1:1/filters.json", true).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/events?stats=1")
                .header("cookie", format!("session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
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

    let mut stream = resp.into_body().into_data_stream();
    let mut seen = String::new();
    let found = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.unwrap();
            seen.push_str(&String::from_utf8_lossy(&bytes));
            if seen.contains("event: stats") {
                return true;
            }
        }
        false
    })
    .await
    .expect("timed out waiting for the opening snapshot");
    assert!(found, "no stats event on connect; got: {seen}");

    // The five fields `app.js` renders; a rename here is a blank dashboard.
    for field in [
        "summary",
        "timeline",
        "top_domains",
        "top_clients",
        "top_upstreams",
    ] {
        assert!(
            seen.contains(&format!("\"{field}\"")),
            "snapshot is missing `{field}`; got: {seen}"
        );
    }
}

/// Without `?stats=1` no snapshot is sent, or an idle page would cost five
/// aggregate queries a tick.
#[tokio::test]
async fn event_stream_sends_no_snapshot_when_stats_are_not_asked_for() {
    let (app, token, _cache, _events) = build_app("http://127.0.0.1:1/filters.json", true).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .header("cookie", format!("session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Bounded negative: nothing arriving in the window may be a snapshot.
    let mut stream = resp.into_body().into_data_stream();
    let mut seen = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.unwrap();
            seen.push_str(&String::from_utf8_lossy(&bytes));
        }
    })
    .await;
    assert!(
        !seen.contains("event: stats"),
        "a stream that did not ask for stats received one: {seen}"
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

/// Logout asks the browser to drop cookies/cache/storage, so Back cannot show
/// the admin screen. `executionContexts` is excluded: it would tear down the
/// page before a JSON caller reads `redirect_to`.
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
        "Clear-Site-Data must not include executionContexts, it would kill a page before it reads redirect_to: {header}"
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

/// Admin JSON responses are not stored: nothing in `/api/*` sets its own
/// `Cache-Control`, so `no_store` (`src/headers.rs`) stamps it.
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

/// `no_store` wraps the `AuthedUser` extractor, so even a bare 401 carries it.
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

/// `no_store` skips responses that already declare a `Cache-Control`, so it must
/// not clobber the assets' `no-cache` + `ETag`. (Pages, which declare none, do
/// get `no-store`.)
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

/// HSTS is layered onto the merged app in `src/main.rs` so `DoH`-only
/// deployments get it too; `admin_router` alone must not emit it.
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

/// Conversely, `security_headers` belongs on the admin router (the only
/// browser-rendered surface), so a dropped `.layer(...)` must fail here.
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

/// The mobileconfig carries a `DoH` token (a credential), so it must not be stored.
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

/// macOS 26.1 (Tahoe) rejects a DNS Settings profile without a top-level
/// `PayloadScope` ("The 'VPN Service' payload could not be installed").
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
    // With no URL in the body the handler looks the list up by id; an unknown
    // id must 404 without touching the network.
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

/// A page request without a session redirects to sign-in carrying `next`; the
/// API answers 401 from the same extractor.
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

/// The rendered HTML of a page.
async fn page_body(app: &axum::Router, uri: &str, token: &str) -> String {
    let req = Request::builder()
        .uri(uri)
        .header("cookie", format!("session={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET {uri}");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The onboarding notice is rendered by the server.
#[tokio::test]
async fn the_onboarding_notice_is_rendered_on_a_fresh_appliance() {
    let (app, token) = setup().await;
    let body = page_body(&app, "/settings", &token).await;
    assert!(
        body.contains(r#"data-testid="next-step-banner""#),
        "a fresh appliance should be told how to point a device at it"
    );
    // Its one control is a real form.
    assert!(body.contains(r#"action="/onboarding/dismiss""#));
    assert!(body.contains(r#"name="next" value="/settings""#));
}

/// Not on the dashboard, whose empty state already makes the point.
#[tokio::test]
async fn the_onboarding_notice_stays_off_the_dashboard() {
    let (app, token) = setup().await;
    let body = page_body(&app, "/", &token).await;
    assert!(
        !body.contains(r#"data-testid="next-step-banner""#),
        "the dashboard's own empty state already says this"
    );
    assert!(
        body.contains(r#"data-testid="dashboard-empty-state""#),
        "and it should still be the one saying it"
    );
}

/// Once a query has been answered, the notice is not rendered again.
#[tokio::test]
async fn the_onboarding_notice_goes_away_once_a_query_has_been_answered() {
    let (app, token, _cache, _events, db, _sessions, _limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    db.insert_query_logs(&[QueryLogEntry {
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
    }])
    .await
    .unwrap();

    let body = page_body(&app, "/settings", &token).await;
    assert!(!body.contains(r#"data-testid="next-step-banner""#));
}

/// Dismissing is a form post, and it returns the operator to the page they
/// dismissed it from rather than to the dashboard.
#[tokio::test]
async fn dismissing_the_onboarding_notice_persists_and_returns_to_the_page() {
    let (app, token) = setup().await;

    let req = Request::builder()
        .method("POST")
        .uri("/onboarding/dismiss")
        .header("cookie", format!("session={token}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("next=/logs"))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/logs")
    );

    let body = page_body(&app, "/settings", &token).await;
    assert!(
        !body.contains(r#"data-testid="next-step-banner""#),
        "the dismissal did not stick"
    );
}

/// `next` goes through `safe_next` like every other form: off-origin is refused.
#[tokio::test]
async fn dismissing_the_onboarding_notice_refuses_an_off_origin_return() {
    let (app, token) = setup().await;
    let req = Request::builder()
        .method("POST")
        .uri("/onboarding/dismiss")
        .header("cookie", format!("session={token}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("next=https://evil.example/"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        resp.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/")
    );
}

/// Before any operator exists every page routes to the wizard, not sign-in.
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

/// An off-origin `next` is dropped: a post-sign-in redirect is prime phishing
/// bait. All three spellings a browser honours are covered: absolute,
/// protocol-relative, and the backslash variant browsers normalise into it.
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

/// A form sign-in mints the session and redirects to where it was headed.
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

/// A refused sign-in re-renders the form with the username, at 401 — not 200.
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

/// A server-rendered page must never reach the disk cache (shared machines).
/// `no_store` applies because a page declares no policy of its own.
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

/// Every signed-in page path answers with the shell — all of them, since each
/// route is registered individually.
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

/// An authenticated browser asking for sign-in is sent onward.
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

/// Once an operator exists the wizard redirects to sign-in.
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

/// Completing the wizard creates the operator and signs them in. The welcome
/// rides a flash cookie, not `?welcome=1`, which would survive refreshes and links.
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

/// The confirmation field is the form's own, so the page handler checks it —
/// not `create_first_operator`, which the JSON endpoint shares.
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

/// The server renders the shell and marks the active nav item — asserted present
/// on this path and absent on another, so "all" or "none" both fail.
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
    assert!(html.contains(r#"action="/logout""#));
    assert!(html.contains("statusbar"));
    // The status badge ships hidden: without a client nothing can sense
    // liveness, so it must not claim ONLINE.
    assert!(
        html.contains("<server-status"),
        "the status bar is missing its indicator element"
    );
    let badge = html
        .split("<server-status")
        .nth(1)
        .and_then(|rest| rest.split('>').next())
        .unwrap_or_default()
        .to_string();
    assert!(
        badge.contains("hidden"),
        "the status indicator must ship hidden, got: <server-status{badge}>"
    );
}

/// The page offers the `<datalist>` suggestions the API tests prove are accepted.
#[tokio::test]
async fn the_settings_page_offers_suggestions_for_its_free_text_fields() {
    use noadd::admin::api::{BLOCK_CUSTOM_IPV4_SUGGESTIONS, BLOCK_CUSTOM_IPV6_SUGGESTIONS};
    use noadd::admin::stats::LOG_RETENTION_DAYS_SUGGESTIONS;

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

    // Each input points at its list, and the list exists.
    for (input_id, list_id) in [
        ("s-block-ipv4", "block-ipv4-list"),
        ("s-block-ipv6", "block-ipv6-list"),
        ("s-retention", "retention-list"),
    ] {
        assert!(
            html.contains(&format!(r#"id="{input_id}""#)),
            "{input_id} input missing"
        );
        assert!(
            html.contains(&format!(r#"list="{list_id}""#)),
            "{input_id} does not reference {list_id}"
        );
        assert!(
            html.contains(&format!(r#"<datalist id="{list_id}">"#)),
            "{list_id} not rendered"
        );
    }

    for v in BLOCK_CUSTOM_IPV4_SUGGESTIONS
        .iter()
        .chain(BLOCK_CUSTOM_IPV6_SUGGESTIONS)
        .map(std::string::ToString::to_string)
        .chain(LOG_RETENTION_DAYS_SUGGESTIONS.iter().map(i64::to_string))
    {
        assert!(
            html.contains(&format!(r#"<option value="{v}">"#)),
            "suggestion {v} not offered"
        );
    }
}

/// The account page renders who is signed in.
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

/// The form's own confirmation field is checked in the page handler, before the
/// shared password path.
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

/// A wrong current password answers 401 and says so, distinct from a rejected
/// new password.
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

/// A successful change redirects and issues the rotated session cookie.
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

/// The settings page renders every scalar setting at its current value.
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
    assert_eq!(
        input_value(&html, "s-retention"),
        Some("21"),
        "retention was not rendered"
    );
    assert!(
        html.contains(r#"<option value="nxdomain" selected>"#),
        "the stored block mode was not selected"
    );
}

/// A settings save redirects (PRG), so a refresh cannot resubmit it.
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
    assert_eq!(input_value(&html, "s-retention"), Some("14"));
}

/// A rejected value re-renders the form with everything typed and writes
/// nothing: validation runs before any `set_setting`, so a bad IP must not leave
/// the retention change applied.
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
    assert_eq!(
        input_value(&html, "s-block-ipv4"),
        Some("not-an-ip"),
        "the operator's input was discarded"
    );
    assert_eq!(
        input_value(&html, "s-retention"),
        Some("30"),
        "the operator's input was discarded"
    );

    // Nothing was written, including the retention change.
    let page = app
        .oneshot(authed("GET", "/settings", &token, None))
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(page.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        input_value(&String::from_utf8_lossy(&bytes), "s-retention"),
        Some(""),
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

/// A flash is cleared by the response that renders it, so it is shown once.
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
    // Carry both cookies the wizard set: the session and the flash.
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

/// The shared validator's rejection reason reaches the form verbatim, so the
/// operator learns which rule they missed.
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

/// [`authed_form`] with an owned body.
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

/// The id of the first list on the page, read from the rendered markup.
fn first_list_id(html: &str) -> i64 {
    // Off the row's toggle: `/filters/lists/update` and
    // `/filters/lists/enable-recommended` are list actions above the table.
    let marker = r#"data-testid="filter-list-toggle" data-id=""#;
    let start = html.find(marker).expect("no list row on the page") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("malformed toggle");
    rest[..end].parse().expect("list id was not a number")
}

/// The id of the row for `name`, read from the rendered markup.
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

/// The page arrives with the lists and rules already in it.
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
    // The page's custom element ships in the markup and upgrades in place.
    assert!(html.contains("<filters-page>"), "the body was not wrapped");
}

/// The domain test is a GET, so its verdict is refreshable and needs no script.
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

/// Adding a list redirects, so a refresh cannot add it twice.
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

/// A rejected list re-renders with what was typed and writes nothing.
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

/// The JSON endpoint shares that validation.
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

/// An unticked checkbox posts nothing, which is the only "off" signal — so both
/// directions are pinned.
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
    // Nothing is enabled now, so the warning shows.
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

/// Impact is what stops being blocked if this list alone goes away, so two lists
/// holding the same rule each report "nothing".
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
    // `add_list` returns the *first* row's id, so read each off its own row.
    let page = filters_html(&app, &token, "").await;
    let id_of = |name: &str| list_id_by_name(&page, name);
    let (shared, overlapping, alone) = (id_of("Shared"), id_of("Overlapping"), id_of("Alone"));
    // Downloads fail against 127.0.0.1:1, so the content is seeded directly.
    db.set_filter_list_content(shared, "||ads.example^\n")
        .await
        .unwrap();
    db.set_filter_list_content(overlapping, "||ads.example^\n")
        .await
        .unwrap();
    db.set_filter_list_content(alone, "||tracker.example^\n||beacon.example^\n")
        .await
        .unwrap();

    // The counts come from the engine. Re-posting a list's current state is the
    // smallest change that triggers a rebuild, without a window that excludes it.
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

/// The same numbers reach `/api/lists`, which `app.js` redraws these rows from.
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

/// A list the engine never loaded says "No rules", not a zero that reads as
/// "safe to remove" — elsewhere on the row it looks healthy.
#[tokio::test]
async fn a_list_that_never_downloaded_reports_no_rules_rather_than_no_impact() {
    let (app, token) = setup().await;
    add_list(&app, &token, "Never fetched", "https://example.com/a.txt").await;

    let html = filters_html(&app, &token, "").await;
    // Scoped to the row: the text above the table also says "No impact".
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

/// The escape hatch from an appliance with every list turned off.
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

/// `?edit=` expands a row into a form filled from storage, never from the URL.
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

/// A rejected edit keeps the row expanded with the submitted values.
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

/// Deleting a list is a POST — a link prefetcher would follow a GET.
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
    // The navigation still marks Filters, though the POST hit `/filters/rules`.
    assert!(
        html.contains(r#"class="nav-item active" href="/filters""#),
        "the rejected post rendered with no active nav item"
    );
}

/// Every filters form is behind the session.
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

async fn logs_html(app: &axum::Router, token: &str, query: &str) -> String {
    let res = app
        .clone()
        .oneshot(authed("GET", &format!("/logs{query}"), token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    body_text(res).await
}

/// Just the log table's rows. The search box's `<datalist>` lists the past
/// week's domains whatever the filter, so the whole page is the wrong haystack.
fn log_rows(html: &str) -> &str {
    let start = html
        .find(r#"<tbody id="log-body">"#)
        .expect("the log table body was not rendered");
    let end = html[start..]
        .find("</tbody>")
        .expect("the log table body was not closed")
        + start;
    &html[start..end]
}

/// Rows and pager arrive rendered, and the filters show what the URL applied.
#[tokio::test]
async fn the_logs_page_renders_rows_and_keeps_its_filters() {
    let (app, token, db) = setup_with_db().await;
    seed_queries(&db, "ads.example.com", "10.0.0.5", 2, true).await;
    seed_queries(&db, "good.example.com", "10.0.0.6", 1, false).await;

    let html = logs_html(&app, &token, "").await;
    let rows = log_rows(&html);
    assert!(rows.contains("ads.example.com") && rows.contains("good.example.com"));
    assert!(html.contains("Page 1 / 1"), "the pager was not rendered");
    assert!(html.contains("<logs-page>"), "the body was not wrapped");

    // A filter narrows the rows and comes back selected in the form.
    let html = logs_html(&app, &token, "?action=blocked").await;
    let rows = log_rows(&html);
    assert!(rows.contains("ads.example.com"));
    assert!(
        !rows.contains("good.example.com"),
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
        !log_rows(&html).contains("ads.example.com"),
        "the search did not filter"
    );
}

/// Both domain boxes (filters tester, logs search) suggest recently queried
/// domains, most-queried first.
#[tokio::test]
async fn the_domain_boxes_suggest_recently_queried_domains() {
    let (app, token, db) = setup_with_db().await;
    seed_queries(&db, "rare.example.com", "10.0.0.5", 1, false).await;
    seed_queries(&db, "common.example.com", "10.0.0.6", 5, true).await;

    for (path, list_id) in [("/logs", "log-domain-list"), ("/filters", "domain-list")] {
        let res = app
            .clone()
            .oneshot(authed("GET", path, &token, None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let html = body_text(res).await;

        assert!(
            html.contains(&format!(r#"<datalist id="{list_id}">"#)),
            "{path}: {list_id} not rendered"
        );
        assert!(
            html.contains(&format!(r#"list="{list_id}""#)),
            "{path}: the input does not reference {list_id}"
        );

        let common_at = html
            .find(r#"<option value="common.example.com">"#)
            .unwrap_or_else(|| panic!("{path}: common.example.com not offered"));
        let rare_at = html
            .find(r#"<option value="rare.example.com">"#)
            .unwrap_or_else(|| panic!("{path}: rare.example.com not offered"));
        assert!(
            common_at < rare_at,
            "{path}: the more-queried domain should be offered first"
        );
    }
}

/// A fresh install gets no `<datalist>` rather than an empty dropdown.
#[tokio::test]
async fn the_domain_boxes_offer_no_list_before_anything_is_queried() {
    let (app, token) = setup().await;

    for (path, list_id) in [("/logs", "log-domain-list"), ("/filters", "domain-list")] {
        let res = app
            .clone()
            .oneshot(authed("GET", path, &token, None))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let html = body_text(res).await;

        assert!(
            !html.contains(&format!(r#"<datalist id="{list_id}">"#)),
            "{path}: an empty datalist was rendered"
        );
        assert!(
            !html.contains(&format!(r#"list="{list_id}""#)),
            "{path}: the input points at a datalist that is not there"
        );
    }
}

/// Paging carries every filter; dropping them would look like a broken filter.
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

/// A row action uses the filters page's rule path and returns to its view.
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

/// `next` is attacker-controlled: same-origin paths only, as on sign-in.
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

/// Clearing lands on an unfiltered first page: a filtered "No logs found" would
/// read as a broken filter.
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

/// A nonsense page number renders page one rather than 400.
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

/// Both logs forms are behind the session.
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

/// A router plus its database, for seeding the query log.
async fn setup_with_db() -> (axum::Router, String, Database) {
    let (router, token, _cache, _events, db, _sessions, _limiter) =
        build_app_opts("http://127.0.0.1:1/filters.json", true, false).await;
    (router, token, db)
}

/// Seed `count` queries for one domain, timestamped now (`query_logs.timestamp`
/// is milliseconds).
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

/// The dashboard's numbers are in the first response.
#[tokio::test]
async fn the_dashboard_renders_its_numbers_and_tables() {
    let (app, token, db) = setup_with_db().await;
    seed_queries(&db, "ads.example.com", "10.0.0.5", 3, true).await;
    seed_queries(&db, "good.example.com", "10.0.0.6", 1, false).await;

    let res = app.oneshot(authed("GET", "/", &token, None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;

    // Four queries, three blocked: 75.0%. Matched with surrounding markup so a
    // stray "4" cannot pass.
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

/// With no traffic the page shows its empty-state guide and hides the chart.
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
    // One merged `style`: a second attribute would be dropped, leaving it visible.
    assert!(
        html.contains(r#"id="chart-card" style="animation-delay:0.1s;display:none""#),
        "the chart card was not hidden"
    );
    // Zeroes, not blanks.
    assert!(
        html.contains(">0.0%<"),
        "the rates were not rendered as zero"
    );
}

/// Client-only controls ship hidden.
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

/// A registry covering each case the page renders: plain, deprecated, a second
/// group, and a `javascript:` homepage that must never become a link.
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

/// The whole registry arrives rendered.
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

/// Escaping does not make a value safe to navigate to: a `javascript:` homepage
/// renders no link at all.
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

/// Search, group and the deprecated toggle live in the URL and show what is applied.
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

    // A filter matching nothing says so.
    let html = registry_html(&app, &token, "?q=nothingatall").await;
    assert!(html.contains("Showing 0 of 4"));
    assert!(
        !html.contains(r#"data-testid="registry-empty" hidden"#),
        "the empty notice was rendered hidden"
    );
}

/// The form carries the current view, so adding from a filtered page returns to it.
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
    // Separators are escaped in the attribute; a browser reads them as `&`.
    assert!(
        html.contains(r#"action="/filters/registry/add?q=beta&#38;group=2&#38;deprecated=1""#),
        "the form did not carry the view it was submitted from"
    );
}

/// An unreachable registry is a state the page renders, with a retry link.
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

/// Adding with nothing ticked is answered on the page, not with a redirect.
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

/// A successful add redirects (no double add on refresh) and persists the lists.
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

    // And the page no longer offers to add it.
    let html = registry_html(&app, &token, "").await;
    assert!(html.contains(r#"<span class="added-pill">Added</span>"#));
}

/// A failed download is reported on the page with its reason, which a redirect
/// would discard.
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

async fn stats_html(app: &axum::Router, token: &str, query: &str) -> String {
    let res = app
        .clone()
        .oneshot(authed("GET", &format!("/stats{query}"), token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    body_text(res).await
}

/// The highlights, both breakdowns, both ranged lists and the health grid arrive
/// rendered; the charts' series rides along for the client to fold.
#[tokio::test]
async fn the_stats_page_renders_its_readings() {
    let (app, token, db) = setup_with_db().await;
    seed_queries(&db, "ads.example.com", "10.0.0.5", 3, true).await;
    seed_queries(&db, "good.example.com", "10.0.0.6", 1, false).await;

    let html = stats_html(&app, &token, "").await;

    assert!(html.contains("<stats-page "), "the body was not wrapped");
    // Every query counted once for the timeline and once for the heatmap.
    let series: serde_json::Value = {
        let start = html.find(r#"data-series=""#).expect("no data-series") + 13;
        let end = start + html[start..].find('"').unwrap();
        serde_json::from_str(&html[start..end].replace("&#34;", "\"")).unwrap()
    };
    let sum = |key: &str| {
        series[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_i64().unwrap())
            .sum::<i64>()
    };
    assert_eq!((sum("total"), sum("blocked"), sum("heatmap")), (4, 3, 4));
    assert!(
        html.contains(r#"data-bucket-secs="3600""#),
        "the 7d range's bucket was not handed to the browser"
    );
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
    // Bars are sized against the largest row.
    assert!(html.contains("width:100.0%"), "the bars were not sized");
    // And the health grid.
    assert!(
        html.contains(r#"data-testid="db-health-card""#)
            && html.contains(r#"<div class="stat-label">Database Size</div>"#),
        "the database-health grid was not rendered"
    );
}

/// The range is in the URL: three links, the active one marked, the titles
/// naming it.
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

/// An unrecognised range renders the default window rather than an error.
#[tokio::test]
async fn a_nonsense_range_renders_the_default_window() {
    let (app, token) = setup().await;
    let html = stats_html(&app, &token, "?range=nonsense").await;
    assert!(
        html.contains("Top Domains (last 7d)"),
        "an unrecognised range did not fall back to the default"
    );
}

/// The three charts need scripting, and say so rather than sitting empty.
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

/// With no traffic every card still renders, saying so.
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
    // No samples, no percentile: a zero would read as impossibly fast.
    assert!(
        html.contains(
            r#"<div class="stat-label">Latency p50</div><div class="stat-value text-green">—</div>"#
        ),
        "a latency with no samples was rendered as a number"
    );
}

/// The admin password `build_app` provisions, for the forms needing a proof.
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

/// The id of the operator with this username, read from the page's markup.
fn operator_id(html: &str, username: &str) -> i64 {
    let row = format!(r#"data-testid="operator-row" data-name="{username}""#);
    let start = html.find(&row).expect("no such operator row");
    // The delete control is the link that expands the row; the form exists only
    // once expanded.
    let marker = "?confirm_delete=";
    let rest = &html[start..];
    let at = rest.find(marker).expect("no delete link on the row") + marker.len();
    let tail = &rest[at..];
    tail[..tail.find('"').unwrap()]
        .parse()
        .expect("operator id was not a number")
}

/// The account page's tables arrive rendered.
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

/// Neither the last operator nor yourself can be deleted, so no row offers a
/// link that would only be refused.
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

/// A wrong proof creates nothing and keeps the username.
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
    // No password is ever echoed back.
    assert!(
        !html.contains("another-long-passphrase") && !html.contains(">wrong<"),
        "a password was rendered into the page"
    );
    // The navigation still marks Account, though the POST hit /account/operators.
    assert!(html.contains(r#"class="nav-item active" href="/account""#));

    let html = account_html(&app, &token, "").await;
    assert!(
        !html.contains(r#"data-name="nope""#),
        "the operator was created anyway"
    );
}

/// A mismatch is caught before the password check, spending no attempt.
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

/// `?confirm_delete=` expands the row into a named confirmation with a password
/// field.
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

    // An id naming nobody expands nothing.
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

/// A wrong proof leaves the operator in place and the row expanded.
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

/// Minting an API key renders rather than redirecting: the token exists in that
/// response only.
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

    // Gone from the next render: the secret is not stored.
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

/// Revoking your own session signs you out, redirecting to sign-in.
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

/// Signing the other devices out keeps this one signed in.
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

/// Every account form is behind the session.
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
