//! Integration coverage for the first-line CSRF origin guard layered on the
//! admin router (`src/admin/csrf.rs`). The guard runs before any handler or
//! `AuthedUser` extraction, so most of these assert on status alone — a
//! provably cross-site unsafe-method request is short-circuited with 403,
//! while same-origin and header-less (CLI/bearer) requests reach their
//! handler.
//!
//! The last two assert on the `csrf.rejected` audit event instead: a bodyless
//! 403 that leaves no trace is indistinguishable from every other 403 this
//! appliance can return, which is the whole reason the event exists.

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
        invalid_session_limiter: Arc::new(RateLimiter::new(
            noadd::admin::auth::INVALID_SESSION_MAX_ATTEMPTS,
            noadd::admin::auth::INVALID_SESSION_WINDOW_SECS,
        )),
        lockout: Arc::new(noadd::admin::auth::AccountLockout::new()),
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

/// The `no_store` layer (`src/headers.rs`) is registered outside the CSRF
/// guard, so even the guard's own 403 — which never reaches a handler — must
/// carry the no-store headers.
#[tokio::test]
async fn csrf_rejection_is_not_stored() {
    let app = build_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/logout")
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let cache_control = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cache_control.contains("no-store"),
        "expected no-store, got: {cache_control}"
    );
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

/// A `tracing` sink that keeps everything written to it, so a test can assert
/// on the audit events the guard emitted.
///
/// Under nextest each test is its own process, so installing a thread-local
/// default subscriber cannot leak into another test.
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

/// The rejection is auditable, and carries all three classification inputs —
/// telling a real cross-site POST apart from a proxy that rewrote `Host`
/// needs every one of them.
#[tokio::test]
async fn rejection_records_the_classification_inputs() {
    let app = build_app().await;
    let logs = CapturedLogs::new();
    let guard = logs.install();

    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/logout")
        .header("origin", "https://evil.test")
        .header("host", "app.test")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    drop(guard);

    let text = logs.text();
    assert!(
        text.contains(r#""event":"csrf.rejected""#),
        "expected a csrf.rejected event, got: {text}"
    );
    for field in [
        r#""reason":"cross_site""#,
        r#""method":"POST""#,
        r#""path":"/api/auth/logout""#,
        r#""origin":"https://evil.test""#,
        r#""host":"app.test""#,
        // Absent here, and recorded as such rather than silently omitted:
        // "the browser did not send it" and "it said same-origin" are
        // different stories and must not render identically.
        r#""sec_fetch_site":"<none>""#,
    ] {
        assert!(text.contains(field), "missing {field} in: {text}");
    }
}

/// The anti-spam lock. `csrf_origin_guard` sits on every unsafe-method admin
/// request, so anything it logs on the *pass-through* path is written once
/// per state-changing call for the life of the deployment. A request it
/// allows must leave it silent.
#[tokio::test]
async fn a_request_the_guard_allows_logs_nothing() {
    let app = build_app().await;
    let logs = CapturedLogs::new();
    let guard = logs.install();

    // Header-less, i.e. the non-browser client path — the one a scanner or a
    // CLI takes, and the highest-volume way through this layer.
    let req = Request::builder()
        .method("POST")
        .uri("/api/rules")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"pattern":"example.com","action":"block"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    drop(guard);

    assert!(
        !logs.text().contains("csrf.rejected"),
        "the guard logged on a request it passed through: {}",
        logs.text()
    );
}
