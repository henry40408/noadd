use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

use arc_swap::ArcSwap;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::Cookie;
use include_dir::{Dir, File, include_dir};
use serde::{Deserialize, Serialize};

use crate::admin::auth::{
    RateLimiter, SessionInfo, SessionStore, generate_token, hash_password, store_session,
    validate_session, verify_password,
};
use crate::admin::stats;
use crate::cache::DnsCache;
use crate::db::Database;
use crate::dns::handler::DnsHandler;
use crate::filter::engine::FilterEngine;
use crate::filter::lists::ListManager;
use crate::filter::rebuild::RebuildCoordinator;
use crate::net::{TrustedProxies, extract_client_ip};
use crate::registry::RegistryClient;
use crate::upstream::forwarder::UpstreamForwarder;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub sessions: SessionStore,
    pub filter: Arc<ArcSwap<FilterEngine>>,
    pub cache: DnsCache,
    pub rate_limiter: Arc<RateLimiter>,
    pub forwarder: Arc<UpstreamForwarder>,
    pub handler: Arc<DnsHandler>,
    pub server_info: ServerInfo,
    pub list_manager: Arc<ListManager>,
    pub rebuild: Arc<RebuildCoordinator>,
    pub registry: Arc<RegistryClient>,
    pub trusted_proxies: Arc<TrustedProxies>,
}

impl AppState {
    /// Spawn a background filter-engine rebuild via the coordinator.
    /// Handlers that mutate rules or lists use this so the HTTP response
    /// returns immediately while rebuilds are serialized in the background.
    fn trigger_rebuild(&self) {
        let manager = self.list_manager.clone();
        self.rebuild
            .clone()
            .spawn_raw(move || async move { manager.rebuild_filter().await });
    }
}

#[derive(Clone, Serialize)]
pub struct ServerInfo {
    pub dns_addr: String,
    pub http_addr: String,
    pub tls_enabled: bool,
}

pub fn admin_router(state: AppState) -> Router {
    Router::new()
        // Auth (no auth required)
        .route("/api/auth/login", post(login))
        .route("/api/auth/setup", post(setup))
        .route("/api/auth/revoke-all", post(revoke_all))
        .route("/api/auth/logout", post(logout))
        // Health + server info (no auth required for health)
        .route("/api/health", get(health))
        .route("/api/server-info", get(get_server_info))
        // Settings
        .route("/api/settings", get(get_settings).put(put_settings))
        // Lists
        .route("/api/lists", get(get_lists).post(add_list))
        .route("/api/lists/batch", post(batch_add_lists))
        .route("/api/lists/{id}", put(update_list).delete(delete_list))
        .route("/api/lists/{id}/check", post(check_list_url))
        .route("/api/lists/update", post(trigger_list_update))
        // Rules
        .route("/api/rules", get(get_rules).post(add_rule))
        .route("/api/rules/{id}", delete(delete_rule))
        // Filter check
        .route("/api/filter/check", post(filter_check))
        .route("/api/filter/rebuild-status", get(get_rebuild_status))
        // Registry
        .route("/api/registry/filters", get(get_registry_filters))
        // Upstream health
        .route("/api/upstream/health", get(upstream_health))
        .route("/api/upstream/latency", get(upstream_latency))
        // Operator management
        .route("/api/auth/me", get(get_me))
        .route(
            "/api/users",
            get(list_users_handler).post(create_user_handler),
        )
        .route("/api/users/{id}", delete(delete_user_handler))
        .route("/api/users/me/password", post(change_own_password))
        // Session management
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{id}", delete(revoke_session_by_id))
        // DoH tokens
        .route("/api/doh-tokens", get(get_doh_tokens).post(add_doh_token))
        .route("/api/doh-tokens/{id}", delete(delete_doh_token_endpoint))
        // Stats
        .route("/api/stats/summary", get(get_stats_summary))
        .route("/api/stats/timeline", get(get_stats_timeline))
        .route("/api/stats/top-domains", get(get_stats_top_domains))
        .route("/api/stats/top-clients", get(get_stats_top_clients))
        .route("/api/stats/top-upstreams", get(get_stats_top_upstreams))
        .route("/api/stats/v2/timeline", get(get_stats_v2_timeline))
        .route("/api/stats/v2/heatmap", get(get_stats_v2_heatmap))
        .route("/api/stats/v2/breakdown", get(get_stats_v2_breakdown))
        .route("/api/stats/v2/health", get(get_stats_v2_health))
        .route("/api/stats/v2/highlights", get(get_stats_v2_highlights))
        .route("/api/stats/v2/top-domains", get(get_stats_v2_top_domains))
        .route("/api/stats/v2/top-clients", get(get_stats_v2_top_clients))
        // Logs
        .route("/api/logs", get(get_logs).delete(delete_logs))
        // Apple mobileconfig (no auth — token in URL is the credential)
        .route("/api/mobileconfig/{token}", get(get_mobileconfig))
        // Apple touch icon (rendered from favicon.svg at build time)
        .route("/apple-touch-icon.png", get(serve_apple_touch_icon))
        .fallback(serve_static)
        .with_state(state)
}

static ADMIN_UI: Dir = include_dir!("$CARGO_MANIFEST_DIR/admin-ui/dist");

/// Strong, quoted ETag derived from a content hash. `DefaultHasher` seeds with
/// fixed keys, so the digest is deterministic across process restarts of the
/// same binary — exactly what a content-addressed validator needs, and with no
/// extra dependency.
fn etag_for(bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("\"{:016x}\"", hasher.finish())
}

/// Per-path ETags for the embedded admin UI, computed once. Assets are fixed at
/// compile time, so the map never needs invalidation.
fn ui_etags() -> &'static HashMap<PathBuf, String> {
    static ETAGS: OnceLock<HashMap<PathBuf, String>> = OnceLock::new();
    ETAGS.get_or_init(|| {
        ADMIN_UI
            .files()
            .map(|f| (f.path().to_path_buf(), etag_for(f.contents())))
            .collect()
    })
}

/// True when `If-None-Match` lists the given ETag (browsers echo back exactly
/// what we sent; we also tolerate a comma-separated list).
fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|t| t.trim() == etag))
        .unwrap_or(false)
}

/// Build a `200` (with body) or `304` response for an embedded file, always
/// carrying an `ETag` and `Cache-Control: no-cache`.
fn static_response(file: &File<'_>, headers: &HeaderMap) -> Response {
    let etag = ui_etags()
        .get(file.path())
        .cloned()
        .unwrap_or_else(|| etag_for(file.contents()));

    if if_none_match_matches(headers, &etag) {
        return (
            StatusCode::NOT_MODIFIED,
            [("etag", etag), ("cache-control", "no-cache".to_string())],
        )
            .into_response();
    }

    let mime = mime_guess::from_path(file.path()).first_or_octet_stream();
    (
        StatusCode::OK,
        [
            ("content-type", mime.to_string()),
            ("etag", etag),
            ("cache-control", "no-cache".to_string()),
        ],
        file.contents().to_vec(),
    )
        .into_response()
}

static APPLE_TOUCH_ICON: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/apple-touch-icon.png"));

fn apple_touch_icon_etag() -> &'static str {
    static ETAG: OnceLock<String> = OnceLock::new();
    ETAG.get_or_init(|| etag_for(APPLE_TOUCH_ICON))
}

async fn serve_apple_touch_icon(headers: HeaderMap) -> impl IntoResponse {
    let etag = apple_touch_icon_etag();
    if if_none_match_matches(&headers, etag) {
        return (
            StatusCode::NOT_MODIFIED,
            [("etag", etag), ("cache-control", "no-cache")],
        )
            .into_response();
    }
    (
        StatusCode::OK,
        [
            ("content-type", "image/png"),
            ("etag", etag),
            ("cache-control", "no-cache"),
        ],
        APPLE_TOUCH_ICON,
    )
        .into_response()
}

async fn serve_static(uri: Uri, headers: HeaderMap) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match ADMIN_UI.get_file(path) {
        Some(file) => static_response(file, &headers),
        None => {
            // Only fall back to index.html for extension-less paths (SPA
            // client-side routes like /dashboard, /settings). Requests for
            // missing assets (favicon.ico, robots.txt, *.map, etc.) must
            // 404 so the browser doesn't try to parse HTML as the asset.
            if std::path::Path::new(path).extension().is_some() {
                return (StatusCode::NOT_FOUND, "not found").into_response();
            }
            match ADMIN_UI.get_file("index.html") {
                Some(file) => static_response(file, &headers),
                None => (StatusCode::NOT_FOUND, "not found").into_response(),
            }
        }
    }
}

// --- Client IP extraction ---

/// Resolve the client IP for rate-limiting and audit purposes via the shared
/// `extract_client_ip` helper. Headers (`X-Forwarded-For`, `X-Real-IP`) are
/// trusted only when the TCP peer is loopback or matches a configured CIDR
/// in [`TrustedProxies`]; otherwise headers are client-controlled and would
/// let a remote caller spoof source IPs to evade per-IP rate limits.
fn client_ip(
    state: &AppState,
    connect: Option<&ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
) -> std::net::IpAddr {
    extract_client_ip(connect, headers, &state.trusted_proxies)
}

// --- Auth helper ---

/// Returns `(user_id, token)` for the current authenticated session, or 401.
fn current_session(state: &AppState, jar: &CookieJar) -> Result<(i64, String), StatusCode> {
    let token = jar
        .get("session")
        .map(|c| c.value().to_string())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    match validate_session(&state.sessions, &token) {
        Some(user_id) => Ok((user_id, token)),
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

fn require_auth(state: &AppState, jar: &CookieJar) -> Result<(), StatusCode> {
    current_session(state, jar).map(|_| ())
}

// --- Auth endpoints ---

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
}

async fn login(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), StatusCode> {
    let ip = client_ip(&state, connect.as_deref(), &headers);
    if !state.rate_limiter.check(ip) {
        tracing::warn!(%ip, "login rate limited");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    state.rate_limiter.record(ip);

    // Generic 401 whether the username is unknown or the password is wrong.
    let auth = state
        .db
        .get_user_auth(body.username.trim())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let valid = verify_password(&body.password, &auth.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !valid {
        tracing::warn!("login failed: invalid credentials");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let now = crate::now_unix();
    let token = generate_token();
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let session_id = state
        .db
        .insert_session(&token, auth.id, now, now, Some(&ip.to_string()), user_agent)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    store_session(
        &state.sessions,
        &token,
        SessionInfo {
            session_id,
            user_id: auth.id,
            created_at: now,
            last_seen: now,
        },
    );
    tracing::info!(user_id = auth.id, "login successful");

    let cookie = Cookie::build(("session", token))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .max_age(time::Duration::seconds(
            crate::admin::auth::SESSION_MAX_AGE_SECS,
        ))
        .build();

    Ok((jar.add(cookie), Json(LoginResponse { success: true })))
}

#[derive(Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct SetupResponse {
    pub success: bool,
}

/// Minimum length for the admin password set via `POST /api/auth/setup`.
const MIN_PASSWORD_LENGTH: usize = 8;

#[derive(Serialize)]
struct SetupErrorResponse {
    error: String,
}

fn setup_ise() -> (StatusCode, Json<SetupErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(SetupErrorResponse {
            error: "internal error".to_string(),
        }),
    )
}

async fn setup(
    State(state): State<AppState>,
    Json(body): Json<SetupRequest>,
) -> Result<Json<SetupResponse>, (StatusCode, Json<SetupErrorResponse>)> {
    let count = state.db.count_users().await.map_err(|_| setup_ise())?;
    if count > 0 {
        return Err((
            StatusCode::CONFLICT,
            Json(SetupErrorResponse {
                error: "already configured".to_string(),
            }),
        ));
    }
    let username = body.username.trim();
    if username.is_empty() || username.chars().count() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(SetupErrorResponse {
                error: "invalid username".to_string(),
            }),
        ));
    }
    if body.password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(SetupErrorResponse {
                error: format!("password must be at least {MIN_PASSWORD_LENGTH} characters"),
            }),
        ));
    }
    let hash = hash_password(&body.password).map_err(|_| setup_ise())?;
    state
        .db
        .create_user(username, &hash, crate::now_unix())
        .await
        .map_err(|_| setup_ise())?;
    Ok(Json(SetupResponse { success: true }))
}

async fn revoke_all(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;
    crate::admin::auth::revoke_all_sessions(&state.sessions, &state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

/// Log out the current session only: revoke this token, delete from DB, and
/// expire the client's session cookie. Other devices' sessions are untouched.
async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), StatusCode> {
    require_auth(&state, &jar)?;
    if let Some(c) = jar.get("session") {
        let token = c.value().to_string();
        crate::admin::auth::revoke_session(&state.sessions, &token);
        let _ = state.db.delete_session_by_token(&token).await;
    }
    let removal = Cookie::build(("session", "")).path("/").build();
    Ok((jar.remove(removal), StatusCode::OK))
}

// --- Operator management ---

#[derive(Serialize)]
struct MeResponse {
    id: i64,
    username: String,
}

async fn get_me(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<MeResponse>, StatusCode> {
    let (user_id, _token) = current_session(&state, &jar)?;
    let username = state
        .db
        .get_username(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(MeResponse {
        id: user_id,
        username,
    }))
}

async fn list_users_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<crate::db::UserRow>>, StatusCode> {
    require_auth(&state, &jar)?;
    let users = state
        .db
        .list_users()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(users))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
}

async fn create_user_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<CreateUserRequest>,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;
    let username = body.username.trim();
    if username.is_empty() || username.chars().count() > 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if body.password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(StatusCode::BAD_REQUEST);
    }
    let hash = hash_password(&body.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match state
        .db
        .create_user(username, &hash, crate::now_unix())
        .await
    {
        Ok(_) => Ok(StatusCode::CREATED),
        // UNIQUE violation → duplicate username.
        Err(_) => Err(StatusCode::CONFLICT),
    }
}

async fn delete_user_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;
    let count = state
        .db
        .count_users()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if count <= 1 {
        return Err(StatusCode::CONFLICT);
    }
    // Evict the deleted operator's sessions from the in-memory store before the
    // DB cascade removes the rows.
    let tokens: Vec<String> = state
        .sessions
        .lock()
        .iter()
        .filter(|(_, info)| info.user_id == id)
        .map(|(t, _)| t.clone())
        .collect();
    for t in &tokens {
        crate::admin::auth::revoke_session(&state.sessions, t);
    }
    state
        .db
        .delete_user(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_own_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<StatusCode, StatusCode> {
    let (user_id, _token) = current_session(&state, &jar)?;
    if body.new_password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(StatusCode::BAD_REQUEST);
    }
    let hash = state
        .db
        .get_user_password_hash(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let ok = verify_password(&body.current_password, &hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !ok {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let new_hash =
        hash_password(&body.new_password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .db
        .update_user_password(user_id, &new_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct SessionResponse {
    id: i64,
    username: String,
    created_at: i64,
    last_seen: i64,
    ip: Option<String>,
    user_agent: Option<String>,
    is_current: bool,
}

async fn list_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<SessionResponse>>, StatusCode> {
    let (_user_id, token) = current_session(&state, &jar)?;
    let rows = state
        .db
        .list_sessions()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Prefer the fresher in-memory last_seen when present.
    let live = state.sessions.lock();
    let out = rows
        .into_iter()
        .map(|r| {
            let last_seen = live
                .get(&r.token)
                .map(|i| i.last_seen)
                .unwrap_or(r.last_seen);
            SessionResponse {
                id: r.id,
                username: r.username,
                created_at: r.created_at,
                last_seen,
                ip: r.ip,
                user_agent: r.user_agent,
                is_current: r.token == token,
            }
        })
        .collect();
    Ok(Json(out))
}

async fn revoke_session_by_id(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<(CookieJar, StatusCode), StatusCode> {
    let (_user_id, current_token) = current_session(&state, &jar)?;
    let removed = state
        .db
        .delete_session_by_id(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match removed {
        Some(token) => {
            crate::admin::auth::revoke_session(&state.sessions, &token);
            if token == current_token {
                let removal = Cookie::build(("session", "")).path("/").build();
                return Ok((jar.remove(removal), StatusCode::NO_CONTENT));
            }
            Ok((jar, StatusCode::NO_CONTENT))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

// --- Health ---

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub needs_setup: bool,
    pub version: &'static str,
    /// Number of query-log events dropped because the async logger channel
    /// was saturated. Non-zero means query logging is incomplete.
    pub dropped_log_count: u64,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let needs_setup = state
        .db
        .count_users()
        .await
        .map(|n| n == 0)
        .unwrap_or(false);
    Json(HealthResponse {
        status: "ok".to_string(),
        needs_setup,
        version: env!("GIT_VERSION"),
        dropped_log_count: state.handler.log_drop_count(),
    })
}

async fn get_server_info(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<ServerInfo>, StatusCode> {
    require_auth(&state, &jar)?;
    Ok(Json(state.server_info.clone()))
}

// --- Settings ---

#[derive(Serialize, Deserialize)]
pub struct SettingsMap {
    #[serde(flatten)]
    pub settings: std::collections::HashMap<String, String>,
}

async fn get_settings(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<SettingsMap>, StatusCode> {
    require_auth(&state, &jar)?;

    // Return known settings
    let keys = [
        "upstream_servers",
        "upstream_strategy",
        "log_retention_days",
        "doh_access_policy",
        "public_url",
        "onboarding_banner_dismissed",
    ];
    let mut settings = std::collections::HashMap::new();

    for key in &keys {
        if let Ok(Some(val)) = state.db.get_setting(key).await {
            settings.insert(key.to_string(), val);
        }
    }

    Ok(Json(SettingsMap { settings }))
}

#[derive(Deserialize)]
pub struct UpdateSettingsRequest {
    #[serde(flatten)]
    pub settings: std::collections::HashMap<String, String>,
}

async fn put_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<UpdateSettingsRequest>,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;

    for (key, value) in &body.settings {
        state
            .db
            .set_setting(key, value)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // Apply strategy change immediately if present
    if let Some(strategy_str) = body.settings.get("upstream_strategy")
        && let Ok(strategy) = strategy_str.parse::<crate::upstream::strategy::UpstreamStrategy>()
    {
        state.forwarder.set_strategy(strategy);
    }

    Ok(StatusCode::OK)
}

// --- Lists ---

async fn get_lists(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<crate::db::FilterListRow>>, StatusCode> {
    require_auth(&state, &jar)?;

    let lists = state
        .db
        .get_filter_lists()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(lists))
}

#[derive(Deserialize)]
pub struct AddListRequest {
    pub name: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct AddListResponse {
    pub id: i64,
}

async fn add_list(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<AddListRequest>,
) -> Result<(StatusCode, Json<AddListResponse>), StatusCode> {
    require_auth(&state, &jar)?;

    let id = state
        .db
        .add_filter_list(&body.name, &body.url, true)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(AddListResponse { id })))
}

#[derive(Deserialize)]
pub struct UpdateListRequest {
    pub enabled: Option<bool>,
    pub name: Option<String>,
    pub url: Option<String>,
}

async fn update_list(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
    Json(body): Json<UpdateListRequest>,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;

    if let Some(enabled) = body.enabled {
        state
            .db
            .update_filter_list_enabled(id, enabled)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    if let (Some(name), Some(url)) = (body.name.as_deref(), body.url.as_deref()) {
        state
            .db
            .update_filter_list(id, name, url)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    state.trigger_rebuild();

    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct CheckListUrlRequest {
    pub url: Option<String>,
}

async fn check_list_url(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
    body: Option<Json<CheckListUrlRequest>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_auth(&state, &jar)?;

    // Use provided URL or fetch from DB
    let url = if let Some(Json(b)) = body
        && let Some(u) = b.url
    {
        u
    } else {
        let lists = state
            .db
            .get_filter_lists()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        lists
            .into_iter()
            .find(|l| l.id == id)
            .map(|l| l.url)
            .ok_or(StatusCode::NOT_FOUND)?
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(crate::user_agent())
        .build()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let content_length = resp.content_length().unwrap_or(0);
            Ok(Json(serde_json::json!({
                "ok": resp.status().is_success(),
                "status": status,
                "content_length": content_length,
                "url": url,
            })))
        }
        Err(e) => Ok(Json(serde_json::json!({
            "ok": false,
            "error": e.to_string(),
            "url": url,
        }))),
    }
}

async fn delete_list(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;

    state
        .db
        .delete_filter_list(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state.trigger_rebuild();

    Ok(StatusCode::OK)
}

#[derive(Serialize)]
pub struct ListUpdateResponse {
    pub message: String,
}

async fn trigger_list_update(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<ListUpdateResponse>, StatusCode> {
    require_auth(&state, &jar)?;

    state
        .list_manager
        .update_all_lists_no_rebuild()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state.trigger_rebuild();

    Ok(Json(ListUpdateResponse {
        message: "All lists downloaded; rebuild in progress".to_string(),
    }))
}

#[derive(Serialize)]
struct RebuildStatusResponse {
    rebuilding: bool,
    started_at: i64,
    last_completed_at: i64,
    last_duration_ms: u64,
}

async fn get_rebuild_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<RebuildStatusResponse>, StatusCode> {
    require_auth(&state, &jar)?;
    let s = state.rebuild.state();
    Ok(Json(RebuildStatusResponse {
        rebuilding: s.rebuilding.load(std::sync::atomic::Ordering::Relaxed),
        started_at: s.started_at.load(std::sync::atomic::Ordering::Relaxed),
        last_completed_at: s
            .last_completed_at
            .load(std::sync::atomic::Ordering::Relaxed),
        last_duration_ms: s
            .last_duration_ms
            .load(std::sync::atomic::Ordering::Relaxed),
    }))
}

#[derive(Deserialize)]
pub struct BatchAddRequest {
    pub items: Vec<BatchAddItem>,
}

#[derive(Deserialize)]
pub struct BatchAddItem {
    pub name: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct BatchAddedEntry {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub rule_count: i64,
}

#[derive(Serialize)]
pub struct BatchFailedEntry {
    pub name: String,
    pub url: String,
    pub error: String,
}

#[derive(Serialize)]
pub struct BatchAddResponse {
    pub added: Vec<BatchAddedEntry>,
    pub failed: Vec<BatchFailedEntry>,
}

async fn batch_add_lists(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<BatchAddRequest>,
) -> Result<Json<BatchAddResponse>, StatusCode> {
    require_auth(&state, &jar)?;
    if body.items.is_empty() || body.items.len() > 50 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(crate::user_agent())
        .build()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let sem = Arc::new(tokio::sync::Semaphore::new(4));
    let mut set = tokio::task::JoinSet::new();
    for item in body.items {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let db = state.db.clone();
        let http = client.clone();
        set.spawn(async move {
            let _permit = permit;
            let name = item.name.trim().to_string();
            let url = item.url.trim().to_string();
            let id = match db.add_filter_list(&name, &url, true).await {
                Ok(id) => id,
                Err(e) => {
                    return Err(BatchFailedEntry {
                        name,
                        url,
                        error: format!("{e}"),
                    });
                }
            };
            let fetch = http
                .get(&url)
                .send()
                .await
                .and_then(|r| r.error_for_status());
            match fetch {
                Ok(resp) => {
                    let content = match resp.text().await {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = db.delete_filter_list(id).await;
                            return Err(BatchFailedEntry {
                                name,
                                url,
                                error: format!("{e}"),
                            });
                        }
                    };
                    let rule_count = crate::filter::parser::parse_list(&content).len() as i64;
                    if let Err(e) = db.set_filter_list_content(id, &content).await {
                        let _ = db.delete_filter_list(id).await;
                        return Err(BatchFailedEntry {
                            name,
                            url,
                            error: format!("{e}"),
                        });
                    }
                    let now = crate::now_unix();
                    let _ = db.update_filter_list_stats(id, now, rule_count).await;
                    Ok(BatchAddedEntry {
                        id,
                        name,
                        url,
                        rule_count,
                    })
                }
                Err(e) => {
                    let _ = db.delete_filter_list(id).await;
                    Err(BatchFailedEntry {
                        name,
                        url,
                        error: format!("{e}"),
                    })
                }
            }
        });
    }

    let mut added = Vec::new();
    let mut failed = Vec::new();
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(a)) => added.push(a),
            Ok(Err(f)) => failed.push(f),
            Err(e) => failed.push(BatchFailedEntry {
                name: String::new(),
                url: String::new(),
                error: format!("task join error: {e}"),
            }),
        }
    }

    state.trigger_rebuild();

    Ok(Json(BatchAddResponse { added, failed }))
}

async fn get_registry_filters(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<crate::registry::RegistryData>, StatusCode> {
    require_auth(&state, &jar)?;
    match state.registry.list().await {
        Ok(data) => Ok(Json(data)),
        Err(e) => {
            tracing::warn!(error = %e, "registry fetch failed");
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

// --- Rules ---

#[derive(Deserialize)]
pub struct AddRuleRequest {
    pub rule: String,
}

#[derive(Serialize)]
pub struct AddRuleResponse {
    pub id: i64,
}

async fn get_rules(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<crate::db::CustomRuleRow>>, StatusCode> {
    require_auth(&state, &jar)?;

    let rules = state
        .db
        .get_all_custom_rules()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(rules))
}

async fn add_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<AddRuleRequest>,
) -> Result<(StatusCode, Json<AddRuleResponse>), StatusCode> {
    require_auth(&state, &jar)?;

    let rule_type = match crate::filter::parser::parse_rule(&body.rule) {
        Some(parsed) => match parsed.action {
            crate::filter::parser::RuleAction::Allow => "allow",
            crate::filter::parser::RuleAction::Block => "block",
        },
        None => return Err(StatusCode::BAD_REQUEST),
    };

    // No-op if rule already exists
    if state
        .db
        .has_custom_rule(&body.rule)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Ok((StatusCode::OK, Json(AddRuleResponse { id: 0 })));
    }

    let id = state
        .db
        .add_custom_rule(&body.rule, rule_type)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state.trigger_rebuild();

    Ok((StatusCode::CREATED, Json(AddRuleResponse { id })))
}

async fn delete_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;

    state
        .db
        .delete_custom_rule(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state.trigger_rebuild();

    Ok(StatusCode::OK)
}

// --- DoH Tokens ---

async fn get_doh_tokens(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<crate::db::DohTokenRow>>, StatusCode> {
    require_auth(&state, &jar)?;
    let tokens = state
        .db
        .get_doh_tokens()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(tokens))
}

#[derive(Deserialize)]
pub struct AddDohTokenRequest {
    pub token: String,
}

async fn add_doh_token(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<AddDohTokenRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_auth(&state, &jar)?;
    let token = body.token.trim().to_string();
    if token.is_empty() || token.contains('/') {
        return Err(StatusCode::BAD_REQUEST);
    }
    let id = state
        .db
        .add_doh_token(&token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "id": id, "token": token })))
}

async fn delete_doh_token_endpoint(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;
    state
        .db
        .delete_doh_token(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

// --- Filter Check ---

#[derive(Deserialize)]
struct FilterCheckRequest {
    domain: String,
}

async fn filter_check(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<FilterCheckRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_auth(&state, &jar)?;
    let domain = body.domain.trim().trim_end_matches('.');
    let filter = state.filter.load();
    let result = filter.check(domain);
    match result {
        crate::filter::engine::FilterResult::Blocked { rule, list } => {
            Ok(Json(serde_json::json!({
                "action": "blocked",
                "rule": rule,
                "list": list,
            })))
        }
        crate::filter::engine::FilterResult::Allowed { rule } => {
            let mut json = serde_json::json!({ "action": "allowed" });
            if let Some(r) = rule {
                json["rule"] = serde_json::Value::String(r);
            }
            Ok(Json(json))
        }
    }
}

// --- Upstream Health ---

async fn upstream_health(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    require_auth(&state, &jar)?;
    let results = state.forwarder.health_check().await;
    let json: Vec<serde_json::Value> = results
        .into_iter()
        .map(|(server, ok, ms)| {
            serde_json::json!({
                "server": server,
                "ok": ok,
                "latency_ms": ms,
            })
        })
        .collect();
    Ok(Json(json))
}

// --- Upstream Latency ---

async fn upstream_latency(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    require_auth(&state, &jar)?;
    let latencies = state.forwarder.latencies();
    let strategy = state.forwarder.strategy();

    // Find the preferred server (lowest EMA)
    let preferred = if strategy == crate::upstream::strategy::UpstreamStrategy::LowestLatency {
        latencies
            .iter()
            .min_by(|a, b| a.1.total_cmp(b.1))
            .map(|(k, _)| k.clone())
    } else {
        None
    };

    let json: Vec<serde_json::Value> = latencies
        .iter()
        .map(|(server, ema)| {
            serde_json::json!({
                "server": server,
                "ema_ms": (*ema * 10.0).round() / 10.0,
                "preferred": preferred.as_ref() == Some(server),
            })
        })
        .collect();
    Ok(Json(json))
}

// --- Stats ---

async fn get_stats_summary(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<stats::Summary>, StatusCode> {
    require_auth(&state, &jar)?;

    let now = crate::now_unix();
    let summary = stats::compute_summary(&state.db, now)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(summary))
}

#[derive(Deserialize)]
pub struct TimelineQuery {
    pub hours: Option<i64>,
}

async fn get_stats_timeline(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<TimelineQuery>,
) -> Result<Json<Vec<crate::db::TimelinePoint>>, StatusCode> {
    require_auth(&state, &jar)?;

    let now = crate::now_unix();
    let hours = query.hours.unwrap_or(24);
    let timeline = stats::compute_timeline(&state.db, now, hours)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(timeline))
}

#[derive(Deserialize)]
pub struct TopQuery {
    pub limit: Option<i64>,
}

async fn get_stats_top_domains(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<TopQuery>,
) -> Result<Json<Vec<crate::db::TopDomain>>, StatusCode> {
    require_auth(&state, &jar)?;

    let now = crate::now_unix();
    let limit = query.limit.unwrap_or(20);
    let domains = stats::compute_top_domains(&state.db, now, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(domains))
}

async fn get_stats_top_clients(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<TopQuery>,
) -> Result<Json<Vec<crate::db::TopClient>>, StatusCode> {
    require_auth(&state, &jar)?;

    let now = crate::now_unix();
    let limit = query.limit.unwrap_or(20);
    let clients = stats::compute_top_clients(&state.db, now, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(clients))
}

async fn get_stats_top_upstreams(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<TopQuery>,
) -> Result<Json<Vec<crate::db::TopUpstream>>, StatusCode> {
    require_auth(&state, &jar)?;

    let now = crate::now_unix();
    let limit = query.limit.unwrap_or(10);
    let upstreams = stats::compute_top_upstreams(&state.db, now, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(upstreams))
}

// --- Stats v2 ---

#[derive(Deserialize)]
pub struct StatsRangeQuery {
    pub range: Option<String>,
    /// Viewer's east-positive UTC offset in minutes (e.g. 480 for UTC+8), used
    /// to align timeline buckets to their local calendar. Only the timeline
    /// endpoint reads it; other handlers sharing this struct ignore it. Clamped
    /// to ±14h; missing ⇒ 0 (UTC-aligned).
    pub tz_offset: Option<i64>,
}

fn parse_stats_range(q: &StatsRangeQuery) -> Result<stats::StatsRange, StatusCode> {
    let raw = q.range.as_deref().unwrap_or("7d");
    stats::StatsRange::parse(raw).ok_or(StatusCode::BAD_REQUEST)
}

/// Resolve the viewer's UTC offset to seconds, clamped to the real-world range
/// (±14h) so a malformed value can't shift buckets to nonsense.
fn resolve_tz_offset_secs(q: &StatsRangeQuery) -> i64 {
    q.tz_offset.unwrap_or(0).clamp(-14 * 60, 14 * 60) * 60
}

async fn get_stats_v2_timeline(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<StatsRangeQuery>,
) -> Result<Json<Vec<crate::db::TimelineMultiPoint>>, StatusCode> {
    require_auth(&state, &jar)?;
    let range = parse_stats_range(&query)?;
    let tz_offset = resolve_tz_offset_secs(&query);
    let now = crate::now_unix();
    let timeline = stats::compute_stats_timeline(&state.db, now, range, tz_offset)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(timeline))
}

async fn get_stats_v2_heatmap(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<crate::db::HeatmapCell>>, StatusCode> {
    require_auth(&state, &jar)?;
    let now = crate::now_unix();
    let cells = stats::compute_heatmap(&state.db, now)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(cells))
}

async fn get_stats_v2_breakdown(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<StatsRangeQuery>,
) -> Result<Json<stats::Breakdowns>, StatusCode> {
    require_auth(&state, &jar)?;
    let range = parse_stats_range(&query)?;
    let now = crate::now_unix();
    let b = stats::compute_breakdowns(&state.db, now, range)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(b))
}

async fn get_stats_v2_health(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<stats::DbHealth>, StatusCode> {
    require_auth(&state, &jar)?;
    let now = crate::now_unix();
    let h = stats::compute_db_health(&state.db, now)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(h))
}

async fn get_stats_v2_highlights(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<StatsRangeQuery>,
) -> Result<Json<stats::StatsHighlights>, StatusCode> {
    require_auth(&state, &jar)?;
    let range = parse_stats_range(&query)?;
    let now = crate::now_unix();
    let h = stats::compute_highlights(&state.db, now, range)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(h))
}

#[derive(Deserialize)]
pub struct RangedTopQuery {
    pub range: Option<String>,
    pub limit: Option<i64>,
}

async fn get_stats_v2_top_domains(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<RangedTopQuery>,
) -> Result<Json<Vec<crate::db::TopDomain>>, StatusCode> {
    require_auth(&state, &jar)?;
    let range = parse_stats_range(&StatsRangeQuery {
        range: query.range.clone(),
        tz_offset: None,
    })?;
    let limit = query.limit.unwrap_or(15);
    let now = crate::now_unix();
    let rows = stats::compute_top_domains_ranged(&state.db, now, range, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}

async fn get_stats_v2_top_clients(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<RangedTopQuery>,
) -> Result<Json<Vec<crate::db::TopClient>>, StatusCode> {
    require_auth(&state, &jar)?;
    let range = parse_stats_range(&StatsRangeQuery {
        range: query.range.clone(),
        tz_offset: None,
    })?;
    let limit = query.limit.unwrap_or(15);
    let now = crate::now_unix();
    let rows = stats::compute_top_clients_ranged(&state.db, now, range, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}

// --- Apple mobileconfig ---

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct MobileConfigProfile {
    payload_content: Vec<MobileConfigDnsPayload>,
    payload_display_name: String,
    payload_identifier: String,
    payload_type: String,
    #[serde(rename = "PayloadUUID")]
    payload_uuid: String,
    payload_version: u32,
    payload_description: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct MobileConfigDnsPayload {
    #[serde(rename = "DNSSettings")]
    dns_settings: DnsSettings,
    payload_display_name: String,
    payload_identifier: String,
    payload_type: String,
    #[serde(rename = "PayloadUUID")]
    payload_uuid: String,
    payload_version: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DnsSettings {
    #[serde(rename = "DNSProtocol")]
    dns_protocol: String,
    #[serde(rename = "ServerURL")]
    server_url: String,
}

async fn get_mobileconfig(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    state
        .db
        .validate_doh_token(&token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let public_url = state
        .db
        .get_setting("public_url")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;

    if public_url.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let base = public_url.trim_end_matches('/');
    let server_url = format!("{base}/dns-query/{token}");
    let profile_id = format!("com.noadd.dns.{token}");
    let payload_uuid = make_uuid(&format!("{token}-payload"));
    let profile_uuid = make_uuid(&format!("{token}-profile"));

    let profile = MobileConfigProfile {
        payload_content: vec![MobileConfigDnsPayload {
            dns_settings: DnsSettings {
                dns_protocol: "HTTPS".into(),
                server_url,
            },
            payload_display_name: format!("noadd DNS ({token})"),
            payload_identifier: format!("{profile_id}.dns"),
            payload_type: "com.apple.dnsSettings.managed".into(),
            payload_uuid,
            payload_version: 1,
        }],
        payload_display_name: format!("noadd DNS ({token})"),
        payload_identifier: profile_id,
        payload_type: "Configuration".into(),
        payload_uuid: profile_uuid,
        payload_version: 1,
        payload_description: "Configures DNS-over-HTTPS to use noadd ad-blocking DNS server."
            .into(),
    };

    let mut xml = Vec::new();
    plist::to_writer_xml(&mut xml, &profile).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "content-type",
        "application/x-apple-aspen-config; charset=utf-8"
            .parse()
            .unwrap(),
    );
    headers.insert(
        "content-disposition",
        format!("attachment; filename=\"noadd-{token}.mobileconfig\"")
            .parse()
            .unwrap(),
    );

    Ok((StatusCode::OK, headers, xml))
}

/// Generate a deterministic UUID v5 from a seed string.
///
/// Uses the URL namespace since these UUIDs identify DoH URL-based resources.
fn make_uuid(seed: &str) -> String {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, seed.as_bytes()).to_string()
}

// --- Logs ---

#[derive(Deserialize)]
pub struct LogsQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub search: Option<String>,
    pub blocked: Option<bool>,
    pub token: Option<String>,
    pub query_type: Option<String>,
}

async fn get_logs(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<LogsQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    require_auth(&state, &jar)?;

    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);
    let search = query.search.as_deref();
    let blocked = query.blocked;
    let token = query.token.as_deref();
    let query_type = query.query_type.as_deref();
    let (logs, total) = tokio::join!(
        state
            .db
            .query_logs(limit, offset, search, blocked, token, query_type),
        state.db.count_logs(search, blocked, token, query_type),
    );
    let logs = logs.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let total = total.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "logs": logs,
        "total": total,
    })))
}

async fn delete_logs(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;

    state
        .db
        .delete_all_logs()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}
