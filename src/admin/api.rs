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
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::Cookie;
use include_dir::{Dir, File, include_dir};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use utoipa::OpenApi as _;
use utoipa_scalar::Scalar;

use crate::admin::auth::{
    RateLimiter, SessionInfo, SessionStore, generate_token, hash_api_key, hash_password,
    store_session, validate_session, verify_password,
};
use crate::admin::stats;
use crate::cache::DnsCache;
use crate::db::{Database, QueryLogEntry};
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
    pub log_events: tokio::sync::broadcast::Sender<std::sync::Arc<QueryLogEntry>>,
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

#[derive(Clone, Serialize, utoipa::ToSchema)]
pub struct ServerInfo {
    /// Address the plain-DNS listener is bound to, e.g. `0.0.0.0:53`.
    pub dns_addr: String,
    /// Address the admin/DoH HTTP(S) listener is bound to.
    pub http_addr: String,
    /// Whether the HTTP listener is serving TLS (ACME or user-provided certs).
    pub tls_enabled: bool,
}

/// `OpenAPI` document for the core programmatic subset of the admin API. Only the
/// endpoints a script would drive (health, settings, lists, rules, filter check,
/// stats summary, API keys) are annotated — the browser-only endpoints are not.
#[derive(utoipa::OpenApi)]
#[openapi(
    info(title = "noadd API", description = "Programmatic access to noadd."),
    paths(
        health, get_server_info,
        get_settings, put_settings,
        get_lists, add_list, update_list, delete_list,
        get_rules, add_rule, delete_rule,
        filter_check, get_stats_summary,
        get_logs, delete_logs,
        list_api_keys, create_api_key, delete_api_key,
    ),
    components(schemas(
        ServerInfo, HealthResponse, SettingsMap,
        AddListRequest, AddListResponse, UpdateListRequest,
        AddRuleRequest, AddRuleResponse,
        FilterCheckRequest, CreateApiKeyRequest, CreateApiKeyResponse,
        crate::db::CustomRuleRow, crate::db::FilterListRow, crate::db::ApiKeyRow,
        crate::admin::stats::Summary,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "system"), (name = "settings"), (name = "lists"),
        (name = "rules"), (name = "filter"), (name = "stats"), (name = "api-keys"),
        (name = "logs"),
    )
)]
struct ApiDoc;

struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "api_key",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some("noadd API key: `Authorization: Bearer noadd_…`"))
                    .build(),
            ),
        );
    }
}

/// Serve the raw `OpenAPI` document.
///
/// Requires an operator (session or API key). It exposes only the schema
/// shape, never any data, but recon of the API surface itself is still
/// gated on this security appliance.
async fn openapi_json(_auth: AuthedUser) -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// Serve the interactive Scalar API reference.
///
/// Requires an operator (session or API key), for the same reason as
/// `GET /api/openapi.json`.
async fn scalar_docs(_auth: AuthedUser) -> axum::response::Html<String> {
    axum::response::Html(Scalar::new(ApiDoc::openapi()).to_html())
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
        // API keys
        .route("/api/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api/api-keys/{id}", delete(delete_api_key))
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
        .route("/api/logs/stream", get(stream_logs))
        // Apple mobileconfig (no auth — token in URL is the credential)
        .route("/api/mobileconfig/{token}", get(get_mobileconfig))
        // Apple touch icon (rendered from favicon.svg at build time)
        .route("/apple-touch-icon.png", get(serve_apple_touch_icon))
        // OpenAPI spec + Scalar docs UI (schema only, no data — but still
        // gated: this is a security appliance and we minimize pre-auth recon)
        .route("/api/openapi.json", get(openapi_json))
        .route("/api/docs", get(scalar_docs))
        .fallback(serve_static)
        .with_state(state)
}

static ADMIN_UI: Dir = include_dir!("$CARGO_MANIFEST_DIR/admin-ui/dist");

/// Strong, quoted `ETag` derived from a content hash. `DefaultHasher` seeds with
/// fixed keys, so the digest is deterministic across process restarts of the
/// same binary — exactly what a content-addressed validator needs, and with no
/// extra dependency.
fn etag_for(bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("\"{:016x}\"", hasher.finish())
}

/// Per-path `ETags` for the embedded admin UI, computed once. Assets are fixed at
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

/// True when `If-None-Match` lists the given `ETag` (browsers echo back exactly
/// what we sent; we also tolerate a comma-separated list).
fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag))
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

    if let Some(file) = ADMIN_UI.get_file(path) {
        static_response(file, &headers)
    } else {
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

/// Extract a bearer token from the `Authorization` header, if present.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let v = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    v.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

/// An authenticated operator, resolved from either the browser `session` cookie
/// or an `Authorization: Bearer <api key>` header. Downstream handlers depend
/// only on `user_id`, so cookie and API-key requests are indistinguishable.
pub struct AuthedUser {
    pub user_id: i64,
}

impl axum::extract::FromRequestParts<AppState> for AuthedUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. Session cookie (browser path).
        let jar = CookieJar::from_headers(&parts.headers);
        if let Some(cookie) = jar.get("session")
            && let Some(user_id) = validate_session(&state.sessions, cookie.value())
        {
            return Ok(AuthedUser { user_id });
        }
        // 2. Bearer API key (programmatic path).
        if let Some(token) = bearer_token(&parts.headers) {
            let hash = hash_api_key(&token);
            let now = crate::now_unix();
            if let Ok(Some(user_id)) = state.db.validate_api_key(&hash, now).await {
                return Ok(AuthedUser { user_id });
            }
        }
        Err(StatusCode::UNAUTHORIZED)
    }
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
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let valid = verify_password(&body.password, &auth.password_hash)
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
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
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    let count = state.db.count_users().await.map_err(|_err| setup_ise())?;
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
    let hash = hash_password(&body.password).map_err(|_err| setup_ise())?;
    state
        .db
        .create_user(username, &hash, crate::now_unix())
        .await
        .map_err(|_err| setup_ise())?;
    Ok(Json(SetupResponse { success: true }))
}

async fn revoke_all(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<StatusCode, StatusCode> {
    crate::admin::auth::revoke_all_sessions(&state.sessions, &state.db)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

/// Log out the current session only: revoke this token, delete from DB, and
/// expire the client's session cookie. Other devices' sessions are untouched.
async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), StatusCode> {
    current_session(&state, &jar)?;
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
    auth: AuthedUser,
) -> Result<Json<MeResponse>, StatusCode> {
    let username = state
        .db
        .get_username(auth.user_id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(MeResponse {
        id: auth.user_id,
        username,
    }))
}

async fn list_users_handler(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<Vec<crate::db::UserRow>>, StatusCode> {
    let users = state
        .db
        .list_users()
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(users))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
}

async fn create_user_handler(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Json(body): Json<CreateUserRequest>,
) -> Result<StatusCode, StatusCode> {
    let username = body.username.trim();
    if username.is_empty() || username.chars().count() > 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if body.password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(StatusCode::BAD_REQUEST);
    }
    let hash = hash_password(&body.password).map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    match state
        .db
        .create_user(username, &hash, crate::now_unix())
        .await
    {
        Ok(_) => Ok(StatusCode::CREATED),
        // A UNIQUE violation means the username is taken (409); any other
        // database error is a genuine failure (500).
        Err(e) if e.is_unique_violation() => Err(StatusCode::CONFLICT),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn delete_user_handler(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    // The last-operator guard and the delete run atomically inside the DB layer,
    // so two concurrent deletes can never drop the instance to zero operators.
    match state
        .db
        .delete_user(id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        crate::db::DeleteUserOutcome::LastOperator => Err(StatusCode::CONFLICT),
        crate::db::DeleteUserOutcome::NotFound => Err(StatusCode::NOT_FOUND),
        crate::db::DeleteUserOutcome::Deleted => {
            // The DB `ON DELETE CASCADE` removed this operator's session rows;
            // evict the matching in-memory entries now that the durable delete
            // has succeeded (so a failed delete never logs a live user out).
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
            Ok(StatusCode::NO_CONTENT)
        }
    }
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
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let ok = verify_password(&body.current_password, &hash)
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !ok {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let new_hash =
        hash_password(&body.new_password).map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .db
        .update_user_password(user_id, &new_hash)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
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
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Prefer the fresher in-memory last_seen when present.
    let live = state.sessions.lock();
    let out = rows
        .into_iter()
        .map(|r| {
            let last_seen = live.get(&r.token).map_or(r.last_seen, |i| i.last_seen);
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
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
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

#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    /// Always `"ok"` while the process is up and serving requests.
    pub status: String,
    /// True when no operator account exists yet and `POST /api/auth/setup`
    /// still needs to be called before the admin UI is usable.
    pub needs_setup: bool,
    /// Build version string (from `git describe`).
    pub version: &'static str,
    /// Number of query-log events dropped because the async logger channel
    /// was saturated. Non-zero means query logging is incomplete.
    pub dropped_log_count: u64,
}

/// Report basic service health.
///
/// Always unauthenticated so monitoring and the setup wizard can call it
/// before any operator exists. Includes whether initial setup is still
/// pending and how many query-log events the async logger has dropped.
#[utoipa::path(
    get, path = "/api/health", tag = "system",
    responses((status = 200, description = "Service health", body = HealthResponse))
)]
async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let needs_setup = state.db.count_users().await.is_ok_and(|n| n == 0);
    Json(HealthResponse {
        status: "ok".to_string(),
        needs_setup,
        version: env!("GIT_VERSION"),
        dropped_log_count: state.handler.log_drop_count(),
    })
}

/// Get the server's bound addresses and TLS status.
///
/// Requires an operator (session or API key).
#[utoipa::path(
    get, path = "/api/server-info", tag = "system",
    security(("api_key" = [])),
    responses((status = 200, description = "Server addresses and TLS status", body = ServerInfo))
)]
async fn get_server_info(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<ServerInfo>, StatusCode> {
    Ok(Json(state.server_info.clone()))
}

// --- Settings ---

#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct SettingsMap {
    /// Flattened key/value pairs, e.g. `upstream_servers`,
    /// `upstream_strategy`, `log_retention_days`, `doh_access_policy`,
    /// `public_url`, `dnssec_disabled`, `block_mode`, `block_custom_ipv4`,
    /// `block_custom_ipv6`.
    #[serde(flatten)]
    pub settings: std::collections::HashMap<String, String>,
}

/// Get the current runtime settings.
///
/// Requires an operator (session or API key). Only known setting keys
/// (upstream servers/strategy, log retention, `DoH` access policy, public
/// URL, DNSSEC toggle, etc.) are returned; unknown keys stored in the
/// database are omitted.
#[utoipa::path(
    get, path = "/api/settings", tag = "settings",
    security(("api_key" = [])),
    responses((status = 200, description = "Current settings", body = SettingsMap))
)]
async fn get_settings(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<SettingsMap>, StatusCode> {
    // Return known settings
    let keys = [
        "upstream_servers",
        "upstream_strategy",
        "log_retention_days",
        "doh_access_policy",
        "public_url",
        "onboarding_banner_dismissed",
        "dnssec_disabled",
        "block_mode",
        "block_custom_ipv4",
        "block_custom_ipv6",
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

/// Update one or more runtime settings.
///
/// Requires an operator (session or API key). Only the keys present in the
/// request body are changed; others are left untouched. `upstream_servers`
/// is validated before anything is persisted, so a malformed value rejects
/// the whole request with no partial write. Changes to `upstream_strategy`,
/// `dnssec_disabled`, `upstream_servers`, and `block_mode` (and its
/// `block_custom_ipv4`/`block_custom_ipv6` companions) take effect
/// immediately, with no restart required.
#[utoipa::path(
    put, path = "/api/settings", tag = "settings",
    security(("api_key" = [])),
    request_body = SettingsMap,
    responses(
        (status = 200, description = "Settings saved"),
        (status = 400, description = "Invalid setting value")
    )
)]
async fn put_settings(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Json(body): Json<UpdateSettingsRequest>,
) -> Result<StatusCode, StatusCode> {
    // Validate upstream_servers before persisting anything — reject the whole
    // save on a bad entry so a broken value is never stored.
    let upstream_servers = match body.settings.get("upstream_servers") {
        Some(v) => Some(
            crate::upstream::forwarder::parse_upstreams(v).map_err(|_e| StatusCode::BAD_REQUEST)?,
        ),
        None => None,
    };

    // Validate block-mode settings before persisting anything.
    if let Some(mode) = body.settings.get("block_mode")
        && mode.trim().parse::<crate::dns::block::BlockMode>().is_err()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    for key in ["block_custom_ipv4", "block_custom_ipv6"] {
        if let Some(v) = body.settings.get(key) {
            let v = v.trim();
            if !v.is_empty() {
                let ok = if key == "block_custom_ipv4" {
                    v.parse::<std::net::Ipv4Addr>().is_ok()
                } else {
                    v.parse::<std::net::Ipv6Addr>().is_ok()
                };
                if !ok {
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }
    }

    for (key, value) in &body.settings {
        state
            .db
            .set_setting(key, value)
            .await
            .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // Apply strategy change immediately if present
    if let Some(strategy_str) = body.settings.get("upstream_strategy")
        && let Ok(strategy) = strategy_str.parse::<crate::upstream::strategy::UpstreamStrategy>()
    {
        state.forwarder.set_strategy(strategy);
    }

    if let Some(v) = body.settings.get("dnssec_disabled") {
        let new_enabled = v.trim() != "true";
        // Only flush when the policy actually flips. Cached values are
        // client-ready wire responses that may have been produced while upstream
        // DO forcing had the opposite state, so a real toggle must not keep
        // serving stale AD/RRSIG/OPT data. A settings save that re-sends the
        // unchanged value must not needlessly wipe every client's cache.
        if state.forwarder.dnssec_enabled() != new_enabled {
            state.forwarder.set_dnssec_enabled(new_enabled);
            state.cache.invalidate_all();
        }
    }

    if let Some(servers) = upstream_servers {
        state.forwarder.reconfigure(servers).await;
    }

    if body.settings.keys().any(|k| k.starts_with("block_")) {
        // Merge: prefer the just-submitted value, else the persisted one.
        async fn merged(
            db: &crate::db::Database,
            body: &std::collections::HashMap<String, String>,
            key: &str,
        ) -> Option<String> {
            match body.get(key) {
                Some(v) => Some(v.clone()),
                None => db.get_setting(key).await.ok().flatten(),
            }
        }
        let mode = merged(&state.db, &body.settings, "block_mode").await;
        let v4 = merged(&state.db, &body.settings, "block_custom_ipv4").await;
        let v6 = merged(&state.db, &body.settings, "block_custom_ipv6").await;
        let cfg = crate::dns::block::from_settings(mode.as_deref(), v4.as_deref(), v6.as_deref());
        state.handler.set_block_config(cfg);
    }

    Ok(StatusCode::OK)
}

// --- Lists ---

/// List all configured filter lists.
///
/// Requires an operator (session or API key). Includes both built-in and
/// user-added lists, with their enabled state and last-updated rule count.
#[utoipa::path(
    get, path = "/api/lists", tag = "lists",
    security(("api_key" = [])),
    responses((status = 200, description = "All filter lists", body = [crate::db::FilterListRow]))
)]
async fn get_lists(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<Vec<crate::db::FilterListRow>>, StatusCode> {
    let lists = state
        .db
        .get_filter_lists()
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(lists))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AddListRequest {
    /// Display name for the list.
    pub name: String,
    /// URL the list's contents are fetched from.
    pub url: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AddListResponse {
    /// Id of the newly created filter list.
    pub id: i64,
}

/// Add a new filter list by URL.
///
/// Requires an operator (session or API key). The list is created enabled
/// but its content is not fetched synchronously; use `POST
/// /api/lists/update` (or wait for the periodic refresh) to download it and
/// rebuild the filter engine.
#[utoipa::path(
    post, path = "/api/lists", tag = "lists",
    security(("api_key" = [])),
    request_body = AddListRequest,
    responses((status = 201, description = "List created", body = AddListResponse))
)]
async fn add_list(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Json(body): Json<AddListRequest>,
) -> Result<(StatusCode, Json<AddListResponse>), StatusCode> {
    let id = state
        .db
        .add_filter_list(&body.name, &body.url, true)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(AddListResponse { id })))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct UpdateListRequest {
    /// If present, enables or disables the list.
    pub enabled: Option<bool>,
    /// New display name; only applied if `url` is also present.
    pub name: Option<String>,
    /// New source URL; only applied if `name` is also present.
    pub url: Option<String>,
}

/// Update a filter list's enabled state, name, and/or URL.
///
/// Requires an operator (session or API key). All fields are optional and
/// independent: `enabled` toggles the list without touching name/url, and
/// name/url are only changed if both are provided together. Triggers an
/// async filter-engine rebuild so an enable/disable takes effect shortly
/// after the response returns.
#[utoipa::path(
    put, path = "/api/lists/{id}", tag = "lists",
    security(("api_key" = [])),
    params(("id" = i64, Path, description = "List id")),
    request_body = UpdateListRequest,
    responses((status = 200, description = "List updated"))
)]
async fn update_list(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Path(id): Path<i64>,
    Json(body): Json<UpdateListRequest>,
) -> Result<StatusCode, StatusCode> {
    if let Some(enabled) = body.enabled {
        state
            .db
            .update_filter_list_enabled(id, enabled)
            .await
            .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    if let (Some(name), Some(url)) = (body.name.as_deref(), body.url.as_deref()) {
        state
            .db
            .update_filter_list(id, name, url)
            .await
            .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    _auth: AuthedUser,
    Path(id): Path<i64>,
    body: Option<Json<CheckListUrlRequest>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
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
            .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
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
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

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

/// Delete a filter list.
///
/// Requires an operator (session or API key). Triggers an async filter-engine
/// rebuild so the list's rules stop applying shortly after the response
/// returns.
#[utoipa::path(
    delete, path = "/api/lists/{id}", tag = "lists",
    security(("api_key" = [])),
    params(("id" = i64, Path, description = "List id")),
    responses((status = 200, description = "List deleted"))
)]
async fn delete_list(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    state
        .db
        .delete_filter_list(id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    state.trigger_rebuild();

    Ok(StatusCode::OK)
}

#[derive(Serialize)]
pub struct ListUpdateResponse {
    pub message: String,
}

async fn trigger_list_update(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<ListUpdateResponse>, StatusCode> {
    state
        .list_manager
        .update_all_lists_no_rebuild()
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

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
    _auth: AuthedUser,
) -> Result<Json<RebuildStatusResponse>, StatusCode> {
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
    _auth: AuthedUser,
    Json(body): Json<BatchAddRequest>,
) -> Result<Json<BatchAddResponse>, StatusCode> {
    if body.items.is_empty() || body.items.len() > 50 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(crate::user_agent())
        .build()
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

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
    _auth: AuthedUser,
) -> Result<Json<crate::registry::RegistryData>, StatusCode> {
    match state.registry.list().await {
        Ok(data) => Ok(Json(data)),
        Err(e) => {
            tracing::warn!(error = %e, "registry fetch failed");
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

// --- Rules ---

#[derive(Deserialize, utoipa::ToSchema)]
pub struct AddRuleRequest {
    /// Rule text in hosts-file or Adblock-style syntax, e.g.
    /// `ads.example.com` or `@@allow.example.com`.
    pub rule: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AddRuleResponse {
    /// Id of the created rule, or `0` if it already existed.
    pub id: i64,
}

/// List all custom allow/block rules.
///
/// Requires an operator (session or API key). Returned in the same syntax
/// used to add them (hosts-file / Adblock-style lines).
#[utoipa::path(
    get, path = "/api/rules", tag = "rules",
    security(("api_key" = [])),
    responses((status = 200, description = "All custom rules", body = [crate::db::CustomRuleRow]))
)]
async fn get_rules(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<Vec<crate::db::CustomRuleRow>>, StatusCode> {
    let rules = state
        .db
        .get_all_custom_rules()
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(rules))
}

/// Add a custom allow/block rule.
///
/// Requires an operator (session or API key). No-op (200, `id: 0`) if the
/// exact rule text already exists rather than erroring; a genuinely new rule
/// returns 201 with its id. Rejects text that doesn't parse as a rule (400).
/// Triggers an async filter-engine rebuild so the rule takes effect shortly
/// after the response returns.
#[utoipa::path(
    post, path = "/api/rules", tag = "rules",
    security(("api_key" = [])),
    request_body = AddRuleRequest,
    responses(
        (status = 201, description = "Rule created", body = AddRuleResponse),
        (status = 200, description = "Rule already existed", body = AddRuleResponse),
        (status = 400, description = "Unparseable rule")
    )
)]
async fn add_rule(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Json(body): Json<AddRuleRequest>,
) -> Result<(StatusCode, Json<AddRuleResponse>), StatusCode> {
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
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Ok((StatusCode::OK, Json(AddRuleResponse { id: 0 })));
    }

    let id = state
        .db
        .add_custom_rule(&body.rule, rule_type)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    state.trigger_rebuild();

    Ok((StatusCode::CREATED, Json(AddRuleResponse { id })))
}

/// Delete a custom allow/block rule.
///
/// Requires an operator (session or API key). Triggers an async
/// filter-engine rebuild so the removal takes effect shortly after the
/// response returns.
#[utoipa::path(
    delete, path = "/api/rules/{id}", tag = "rules",
    security(("api_key" = [])),
    params(("id" = i64, Path, description = "Rule id")),
    responses((status = 200, description = "Deleted"))
)]
async fn delete_rule(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    state
        .db
        .delete_custom_rule(id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    state.trigger_rebuild();

    Ok(StatusCode::OK)
}

// --- DoH Tokens ---

async fn get_doh_tokens(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<Vec<crate::db::DohTokenRow>>, StatusCode> {
    let tokens = state
        .db
        .get_doh_tokens()
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(tokens))
}

#[derive(Deserialize)]
pub struct AddDohTokenRequest {
    pub token: String,
}

async fn add_doh_token(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Json(body): Json<AddDohTokenRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = body.token.trim().to_string();
    if token.is_empty() || token.contains('/') {
        return Err(StatusCode::BAD_REQUEST);
    }
    let id = state
        .db
        .add_doh_token(&token)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "id": id, "token": token })))
}

async fn delete_doh_token_endpoint(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    state
        .db
        .delete_doh_token(id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

// --- API Keys ---

#[derive(Deserialize, utoipa::ToSchema)]
pub struct CreateApiKeyRequest {
    /// Human-readable label for the key (1-64 characters), e.g. `"ci"`.
    pub name: String,
    /// Optional Unix timestamp (seconds) after which the key stops working.
    /// Omit or `null` for a key that never expires.
    pub expires_at: Option<i64>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct CreateApiKeyResponse {
    /// Id of the newly created key.
    pub id: i64,
    /// The label given at creation time.
    pub name: String,
    /// Short, non-secret prefix used to identify the key afterwards.
    pub prefix: String,
    /// Full secret — shown only in this create response, never again.
    pub token: String,
}

/// List the caller's own API keys.
///
/// Requires an operator (session or API key). Scoped to the authenticated
/// caller — never returns another operator's keys. Only metadata is
/// returned; the secret token itself is never shown again after creation.
#[utoipa::path(
    get, path = "/api/api-keys", tag = "api-keys",
    security(("api_key" = [])),
    responses((status = 200, description = "API keys for the caller", body = [crate::db::ApiKeyRow]))
)]
async fn list_api_keys(
    State(state): State<AppState>,
    auth: AuthedUser,
) -> Result<Json<Vec<crate::db::ApiKeyRow>>, StatusCode> {
    let keys = state
        .db
        .list_api_keys_for_user(auth.user_id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(keys))
}

/// Create a new API key for the calling operator.
///
/// Requires an operator (session or API key). The full secret `token` is
/// returned only in this response — it is never shown or recoverable again,
/// only the `prefix` is retained for identification afterwards. The new key
/// inherits the caller's permissions.
#[utoipa::path(
    post, path = "/api/api-keys", tag = "api-keys",
    security(("api_key" = [])),
    request_body = CreateApiKeyRequest,
    responses(
        (status = 201, description = "API key created; token shown once", body = CreateApiKeyResponse),
        (status = 400, description = "Invalid name")
    )
)]
async fn create_api_key(
    State(state): State<AppState>,
    auth: AuthedUser,
    Json(body): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), StatusCode> {
    let name = body.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (full, prefix, hash) = crate::admin::auth::generate_api_key();
    let now = crate::now_unix();
    let id = state
        .db
        .insert_api_key(auth.user_id, &name, &hash, &prefix, now, body.expires_at)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            id,
            name,
            prefix,
            token: full,
        }),
    ))
}

/// Delete one of the caller's own API keys.
///
/// Requires an operator (session or API key). Scoped to the authenticated
/// caller — deleting an id owned by another operator returns 404 rather
/// than revealing it exists.
#[utoipa::path(
    delete, path = "/api/api-keys/{id}", tag = "api-keys",
    security(("api_key" = [])),
    params(("id" = i64, Path, description = "API key id")),
    responses(
        (status = 200, description = "Deleted"),
        (status = 404, description = "Not found or not owned by caller")
    )
)]
async fn delete_api_key(
    State(state): State<AppState>,
    auth: AuthedUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    let deleted = state
        .db
        .delete_api_key(id, auth.user_id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    if deleted {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// --- Filter Check ---

#[derive(Deserialize, utoipa::ToSchema)]
pub struct FilterCheckRequest {
    /// Domain to evaluate, e.g. `"ads.example.com"`. A trailing dot is
    /// stripped before matching.
    domain: String,
}

/// Check what the filter engine would decide for a domain, without querying DNS.
///
/// Requires an operator (session or API key). Evaluates against the live,
/// currently-loaded filter engine (custom rules + enabled lists). The
/// response is an untyped JSON verdict: `{"action": "blocked", "rule":
/// ..., "list": ...}` or `{"action": "allowed", "rule": ...}` (rule
/// omitted when no explicit allow rule matched).
#[utoipa::path(
    post, path = "/api/filter/check", tag = "filter",
    security(("api_key" = [])),
    request_body = FilterCheckRequest,
    responses((status = 200, description = "Filter decision for the domain", body = serde_json::Value))
)]
async fn filter_check(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Json(body): Json<FilterCheckRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
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
    _auth: AuthedUser,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
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
    _auth: AuthedUser,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
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

/// Get aggregate query statistics for today, the last 7 days, and the last 30 days.
///
/// Requires an operator (session or API key). Includes totals, block ratio,
/// cache hit rate, average response time per window, plus the query rate
/// over the last minute.
#[utoipa::path(
    get, path = "/api/stats/summary", tag = "stats",
    security(("api_key" = [])),
    responses((status = 200, description = "Aggregate query statistics", body = crate::admin::stats::Summary))
)]
async fn get_stats_summary(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<stats::Summary>, StatusCode> {
    let now = crate::now_unix();
    let summary = stats::compute_summary(&state.db, now)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(summary))
}

#[derive(Deserialize)]
pub struct TimelineQuery {
    pub hours: Option<i64>,
}

async fn get_stats_timeline(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<TimelineQuery>,
) -> Result<Json<Vec<crate::db::TimelinePoint>>, StatusCode> {
    let now = crate::now_unix();
    let hours = query.hours.unwrap_or(24);
    let timeline = stats::compute_timeline(&state.db, now, hours)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(timeline))
}

#[derive(Deserialize)]
pub struct TopQuery {
    pub limit: Option<i64>,
}

async fn get_stats_top_domains(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<TopQuery>,
) -> Result<Json<Vec<crate::db::TopDomain>>, StatusCode> {
    let now = crate::now_unix();
    let limit = query.limit.unwrap_or(20);
    let domains = stats::compute_top_domains(&state.db, now, limit)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(domains))
}

async fn get_stats_top_clients(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<TopQuery>,
) -> Result<Json<Vec<crate::db::TopClient>>, StatusCode> {
    let now = crate::now_unix();
    let limit = query.limit.unwrap_or(20);
    let clients = stats::compute_top_clients(&state.db, now, limit)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(clients))
}

async fn get_stats_top_upstreams(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<TopQuery>,
) -> Result<Json<Vec<crate::db::TopUpstream>>, StatusCode> {
    let now = crate::now_unix();
    let limit = query.limit.unwrap_or(10);
    let upstreams = stats::compute_top_upstreams(&state.db, now, limit)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

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
    _auth: AuthedUser,
    Query(query): Query<StatsRangeQuery>,
) -> Result<Json<Vec<crate::db::TimelineMultiPoint>>, StatusCode> {
    let range = parse_stats_range(&query)?;
    let tz_offset = resolve_tz_offset_secs(&query);
    let now = crate::now_unix();
    let timeline = stats::compute_stats_timeline(&state.db, now, range, tz_offset)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(timeline))
}

async fn get_stats_v2_heatmap(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<Vec<crate::db::HeatmapCell>>, StatusCode> {
    let now = crate::now_unix();
    let cells = stats::compute_heatmap(&state.db, now)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(cells))
}

async fn get_stats_v2_breakdown(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<StatsRangeQuery>,
) -> Result<Json<stats::Breakdowns>, StatusCode> {
    let range = parse_stats_range(&query)?;
    let now = crate::now_unix();
    let b = stats::compute_breakdowns(&state.db, now, range)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(b))
}

async fn get_stats_v2_health(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<stats::DbHealth>, StatusCode> {
    let now = crate::now_unix();
    let h = stats::compute_db_health(&state.db, now)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(h))
}

async fn get_stats_v2_highlights(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<StatsRangeQuery>,
) -> Result<Json<stats::StatsHighlights>, StatusCode> {
    let range = parse_stats_range(&query)?;
    let now = crate::now_unix();
    let h = stats::compute_highlights(&state.db, now, range)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(h))
}

#[derive(Deserialize)]
pub struct RangedTopQuery {
    pub range: Option<String>,
    pub limit: Option<i64>,
}

async fn get_stats_v2_top_domains(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<RangedTopQuery>,
) -> Result<Json<Vec<crate::db::TopDomain>>, StatusCode> {
    let range = parse_stats_range(&StatsRangeQuery {
        range: query.range.clone(),
        tz_offset: None,
    })?;
    let limit = query.limit.unwrap_or(15);
    let now = crate::now_unix();
    let rows = stats::compute_top_domains_ranged(&state.db, now, range, limit)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}

async fn get_stats_v2_top_clients(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<RangedTopQuery>,
) -> Result<Json<Vec<crate::db::TopClient>>, StatusCode> {
    let range = parse_stats_range(&StatsRangeQuery {
        range: query.range.clone(),
        tz_offset: None,
    })?;
    let limit = query.limit.unwrap_or(15);
    let now = crate::now_unix();
    let rows = stats::compute_top_clients_ranged(&state.db, now, range, limit)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
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
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let public_url = state
        .db
        .get_setting("public_url")
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?
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
    plist::to_writer_xml(&mut xml, &profile).map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

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
/// Uses the URL namespace since these UUIDs identify `DoH` URL-based resources.
fn make_uuid(seed: &str) -> String {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, seed.as_bytes()).to_string()
}

// --- Logs ---

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogsQuery {
    /// Maximum number of log entries to return (default 100).
    pub limit: Option<i64>,
    /// Number of entries to skip from the most recent, for pagination (default 0).
    pub offset: Option<i64>,
    /// Case-insensitive substring to match against the queried domain.
    pub search: Option<String>,
    /// Filter by outcome: `true` returns only blocked queries, `false` only allowed.
    pub blocked: Option<bool>,
    /// Restrict to queries served through a specific `DoH` URL token.
    pub token: Option<String>,
    /// Filter by DNS record type (e.g. `A`, `AAAA`, `HTTPS`).
    pub query_type: Option<String>,
}

/// List recent DNS query logs, most recent first.
///
/// Supports pagination (`limit`/`offset`) and filtering by domain substring,
/// block outcome, `DoH` token, and DNS record type. Returns the matching
/// `logs` array plus the `total` count for the applied filters.
#[utoipa::path(
    get, path = "/api/logs", tag = "logs",
    security(("api_key" = [])),
    params(LogsQuery),
    responses((status = 200, description = "Matching query logs and total count", body = serde_json::Value))
)]
async fn get_logs(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<LogsQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
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
    let logs = logs.map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    let total = total.map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "logs": logs,
        "total": total,
    })))
}

/// Live tail of DNS query logs via Server-Sent Events.
///
/// Each newly-logged query is pushed as a JSON `QueryLogEntry` (identical
/// shape to `GET /api/logs` rows). Auth is via the same `AuthedUser`
/// extractor as the rest of the API; browsers send the `session` cookie on
/// the `EventSource` connection automatically. Events are broadcast before the
/// logger's DB flush, so the tail is real-time. A slow client that lags past
/// the broadcast buffer simply skips the missed entries (the tail resumes).
async fn stream_logs(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = state.log_events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|res| match res {
        Ok(entry) => Event::default().json_data(&*entry).ok().map(Ok),
        // Lagged: client fell behind the buffer — skip missed entries.
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Delete all DNS query logs.
///
/// Permanently clears the entire query-log history. This cannot be undone.
#[utoipa::path(
    delete, path = "/api/logs", tag = "logs",
    security(("api_key" = [])),
    responses((status = 200, description = "All query logs were deleted"))
)]
async fn delete_logs(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<StatusCode, StatusCode> {
    state
        .db
        .delete_all_logs()
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod openapi_tests {
    use super::*;
    use utoipa::OpenApi;

    #[test]
    fn openapi_spec_covers_core_paths_and_bearer_scheme() {
        let doc = ApiDoc::openapi();
        let json = serde_json::to_value(&doc).unwrap();
        let paths = json["paths"].as_object().unwrap();
        for p in [
            "/api/health",
            "/api/rules",
            "/api/lists",
            "/api/filter/check",
            "/api/stats/summary",
            "/api/api-keys",
            "/api/logs",
        ] {
            assert!(paths.contains_key(p), "spec missing path {p}");
        }
        // Bearer security scheme registered.
        let schemes = &json["components"]["securitySchemes"];
        assert!(
            schemes.get("api_key").is_some(),
            "missing api_key security scheme"
        );
    }

    /// Every annotated operation must carry a human-readable summary and
    /// description, not just bare status-code/param docs — otherwise the
    /// rendered Scalar UI shows nothing but an endpoint title.
    #[test]
    fn openapi_operations_have_summary_and_description() {
        let doc = ApiDoc::openapi();
        let json = serde_json::to_value(&doc).unwrap();
        let paths = json["paths"].as_object().unwrap();

        let non_empty_str =
            |v: &serde_json::Value| v.as_str().is_some_and(|s| !s.trim().is_empty());

        for (path, methods) in paths {
            for (method, op) in methods.as_object().unwrap() {
                assert!(
                    non_empty_str(&op["summary"]),
                    "{method} {path} is missing a non-empty summary"
                );
                assert!(
                    non_empty_str(&op["description"]),
                    "{method} {path} is missing a non-empty description"
                );
            }
        }
    }

    #[test]
    fn schema_fields_have_descriptions() {
        let doc = ApiDoc::openapi();
        let json = serde_json::to_value(&doc).unwrap();
        let schemas = &json["components"]["schemas"];

        for (schema_name, fields) in [
            ("CreateApiKeyRequest", vec!["name", "expires_at"]),
            ("ApiKeyRow", vec!["id", "name", "prefix"]),
        ] {
            for field in fields {
                let desc = &schemas[schema_name]["properties"][field]["description"];
                assert!(
                    desc.as_str().is_some_and(|s| !s.trim().is_empty()),
                    "{schema_name}.{field} is missing a schema field description"
                );
            }
        }
    }
}
