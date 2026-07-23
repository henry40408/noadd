use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use noadd::admin::api::{AppState, ServerInfo, admin_router};
use noadd::admin::auth::{
    RateLimiter, SessionInfo, generate_token, hash_password, new_session_store, store_session,
};
use noadd::admin::forward_auth::ForwardAuthConfig;
use noadd::cache::DnsCache;
use noadd::db::Database;
use noadd::dns::handler::DnsHandler;
use noadd::filter::engine::FilterEngine;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};
use tokio::sync::mpsc;

/// CIDR trusted by every test's `forward_auth` config; `TRUSTED_PEER` is
/// inside it, `UNTRUSTED_PEER` is outside it.
const TRUSTED_CIDR: &str = "203.0.113.0/24";
const TRUSTED_PEER: &str = "203.0.113.10:9000";
const UNTRUSTED_PEER: &str = "198.51.100.10:9000";
const HEADER: &str = "Remote-User";

/// Build a router plus its backing `Database`. When `seed_operator` is true,
/// creates an operator ("admin" / "adminpass") with a valid session token.
/// When false, the database is empty.
async fn build(
    forward_auth: Option<Arc<ForwardAuthConfig>>,
    seed_operator: bool,
) -> (axum::Router, Database, Option<String>) {
    let dir = tempfile::tempdir().unwrap();
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
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);
    let (log_tx, _log_rx) = mpsc::channel(64);
    let handler = Arc::new(DnsHandler::new(
        filter.clone(),
        cache.clone(),
        forwarder.clone(),
        log_tx,
    ));

    let token = if seed_operator {
        let hash = hash_password("adminpass").unwrap();
        let uid = db
            .create_user("admin", &hash, noadd::now_unix())
            .await
            .unwrap();
        let token = generate_token();
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
        Some(token)
    } else {
        None
    };

    let list_manager = Arc::new(noadd::filter::lists::ListManager::new(
        db.clone(),
        filter.clone(),
    ));
    let rebuild = noadd::filter::rebuild::RebuildCoordinator::new();
    let registry = noadd::registry::RegistryClient::new(
        "http://127.0.0.1:1/filters.json".to_string(),
        std::time::Duration::from_secs(3600),
    );

    let router = admin_router(AppState {
        db: db.clone(),
        sessions,
        filter,
        cache,
        rate_limiter,
        forwarder,
        handler,
        log_events: tokio::sync::broadcast::channel(256).0,
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:53".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        list_manager,
        rebuild,
        registry,
        trusted_proxies: Arc::new(noadd::net::TrustedProxies::default()),
        forward_auth,
    });

    (router, db, token)
}

/// Build a router plus its backing `Database`, with an operator ("admin" /
/// "adminpass") already seeded and holding a valid session token — mirrors
/// `build_app` in `admin_api_test.rs`, parameterised on `forward_auth` so
/// tests can turn the feature on or off.
async fn build_app(
    forward_auth: Option<Arc<ForwardAuthConfig>>,
) -> (axum::Router, Database, String) {
    let (router, db, token) = build(forward_auth, true).await;
    (router, db, token.unwrap())
}

/// Build a router plus its backing `Database` with no seeded operator — the
/// database is empty and ready for tests that check initial setup behavior.
async fn build_app_without_operator(
    forward_auth: Option<Arc<ForwardAuthConfig>>,
) -> (axum::Router, Database) {
    let (router, db, _token) = build(forward_auth, false).await;
    (router, db)
}

fn forward_auth_cfg() -> Arc<ForwardAuthConfig> {
    Arc::new(
        ForwardAuthConfig::from_args(HEADER, TRUSTED_CIDR)
            .unwrap()
            .unwrap(),
    )
}

/// `GET /api/settings` with an optional `ConnectInfo` peer and an optional
/// forward-auth header value.
fn settings_request(peer: Option<&str>, username: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri("/api/settings");
    if let Some(u) = username {
        builder = builder.header(HEADER, u);
    }
    let mut req = builder.body(Body::empty()).unwrap();
    if let Some(p) = peer {
        let addr: SocketAddr = p.parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
    }
    req
}

#[tokio::test]
async fn trusted_peer_with_header_provisions_and_authenticates() {
    let (app, db, _token) = build_app(Some(forward_auth_cfg())).await;
    assert_eq!(db.count_users().await.unwrap(), 1); // just the seeded "admin"

    let resp = app
        .clone()
        .oneshot(settings_request(Some(TRUSTED_PEER), Some("alice")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(db.count_users().await.unwrap(), 2, "alice was provisioned");

    // A second identical request must not provision a duplicate.
    let resp = app
        .clone()
        .oneshot(settings_request(Some(TRUSTED_PEER), Some("alice")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        db.count_users().await.unwrap(),
        2,
        "still exactly one alice"
    );
}

#[tokio::test]
async fn peer_outside_trusted_cidr_is_rejected() {
    let (app, db, _token) = build_app(Some(forward_auth_cfg())).await;
    let resp = app
        .oneshot(settings_request(Some(UNTRUSTED_PEER), Some("alice")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(db.count_users().await.unwrap(), 1, "no user provisioned");
}

#[tokio::test]
async fn missing_connect_info_is_rejected() {
    let (app, db, _token) = build_app(Some(forward_auth_cfg())).await;
    let resp = app
        .oneshot(settings_request(None, Some("alice")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(db.count_users().await.unwrap(), 1);
}

#[tokio::test]
async fn trusted_peer_without_header_is_rejected() {
    let (app, db, _token) = build_app(Some(forward_auth_cfg())).await;
    let resp = app
        .oneshot(settings_request(Some(TRUSTED_PEER), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(db.count_users().await.unwrap(), 1);
}

#[tokio::test]
async fn forward_auth_disabled_ignores_header_even_from_trusted_looking_peer() {
    let (app, db, _token) = build_app(None).await;
    let resp = app
        .oneshot(settings_request(Some(TRUSTED_PEER), Some("alice")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(db.count_users().await.unwrap(), 1);
}

#[tokio::test]
async fn empty_username_is_rejected() {
    let (app, db, _token) = build_app(Some(forward_auth_cfg())).await;
    let resp = app
        .oneshot(settings_request(Some(TRUSTED_PEER), Some("   ")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(db.count_users().await.unwrap(), 1);
}

#[tokio::test]
async fn oversized_username_is_rejected() {
    let (app, db, _token) = build_app(Some(forward_auth_cfg())).await;
    let long = "a".repeat(noadd::admin::forward_auth::MAX_USERNAME_LEN + 1);
    let resp = app
        .oneshot(settings_request(Some(TRUSTED_PEER), Some(&long)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(db.count_users().await.unwrap(), 1);
}

#[tokio::test]
async fn control_char_username_is_rejected() {
    let (app, db, _token) = build_app(Some(forward_auth_cfg())).await;
    let resp = app
        .oneshot(settings_request(Some(TRUSTED_PEER), Some("ali\tce")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(db.count_users().await.unwrap(), 1);
}

#[tokio::test]
async fn forward_auth_header_sent_twice_is_rejected() {
    let (app, db, _token) = build_app(Some(forward_auth_cfg())).await;
    let mut req = Request::builder()
        .uri("/api/settings")
        .header(HEADER, "alice")
        .header(HEADER, "bob")
        .body(Body::empty())
        .unwrap();
    let addr: SocketAddr = TRUSTED_PEER.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(db.count_users().await.unwrap(), 1);
}

/// A forward-auth-provisioned account stores a sentinel hash that cannot be
/// parsed as a PHC string, so `verify_password` would return `Err` for it.
/// This is the regression guard ensuring `login` checks `has_no_password`
/// before `verify_password` and returns the ordinary 401 rather than letting
/// that `Err` surface as a 500, which would also leak which accounts are
/// forward-auth-provisioned.
#[tokio::test]
async fn provisioned_operator_cannot_password_login() {
    let (app, db, _token) = build_app(Some(forward_auth_cfg())).await;

    let resp = app
        .clone()
        .oneshot(settings_request(Some(TRUSTED_PEER), Some("alice")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(db.count_users().await.unwrap(), 2);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"alice","password":"whatever"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_cookie_still_wins_without_forward_auth_header() {
    let (app, _db, token) = build_app(Some(forward_auth_cfg())).await;

    // No forward-auth header at all, peer not even attached — the existing
    // cookie-based path must be entirely unaffected by forward auth being
    // configured.
    let req = Request::builder()
        .uri("/api/settings")
        .header("cookie", format!("session={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// When forward auth is configured, the setup wizard must refuse all requests,
/// even on a fresh install with zero users. This prevents anyone who can reach
/// the HTTP listener directly (bypassing the proxy) from claiming the first
/// operator account before the proxy provisions one.
#[tokio::test]
async fn setup_is_refused_when_forward_auth_is_configured() {
    let (app, db) = build_app_without_operator(Some(forward_auth_cfg())).await;
    assert_eq!(db.count_users().await.unwrap(), 0);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"eve","password":"hunter2hunter2"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        db.count_users().await.unwrap(),
        0,
        "no operator was created"
    );
}

/// When forward auth is disabled, the setup wizard must work normally on a
/// fresh install. This is a regression guard to ensure that non-forward-auth
/// deployments are unaffected by the new guard.
#[tokio::test]
async fn setup_still_works_without_forward_auth() {
    let (app, db) = build_app_without_operator(None).await;
    assert_eq!(db.count_users().await.unwrap(), 0);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"eve","password":"hunter2hunter2"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(db.count_users().await.unwrap(), 1, "operator was created");
}
