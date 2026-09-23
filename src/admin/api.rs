use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

use arc_swap::ArcSwap;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::header::AsHeaderName;
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
use utoipa::OpenApi as _;
use utoipa_scalar::Scalar;

use crate::admin::auth::{
    RateLimiter, SessionInfo, SessionStore, generate_token, has_no_password, hash_api_key,
    hash_password, session_log_id, spend_verify_cost, store_session, validate_session,
    verify_password,
};
use crate::admin::events;
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
    /// Counts unknown session tokens per source IP (see [`note_invalid_session_cookie`]).
    /// Separate from `rate_limiter` so cookie guessing cannot burn the login budget of an
    /// operator behind the same NAT address.
    pub invalid_session_limiter: Arc<RateLimiter>,
    /// Per-account password-failure backoff: `rate_limiter` bounds one source address, this
    /// bounds one account across every address.
    pub lockout: Arc<crate::admin::auth::AccountLockout>,
    pub forwarder: Arc<UpstreamForwarder>,
    pub handler: Arc<DnsHandler>,
    pub log_events: tokio::sync::broadcast::Sender<std::sync::Arc<QueryLogEntry>>,
    /// Hub behind `GET /api/events`, the admin UI's one push stream.
    pub events: std::sync::Arc<crate::admin::events::EventHub>,
    pub server_info: ServerInfo,
    /// Whether to set `Secure` on the session cookie, from
    /// [`crate::config::resolve_cookie_secure`]. Not on [`ServerInfo`], which is serialized
    /// to `/api/server-info`.
    pub cookie_secure: bool,
    pub list_manager: Arc<ListManager>,
    pub rebuild: Arc<RebuildCoordinator>,
    pub registry: Arc<RegistryClient>,
    pub trusted_proxies: Arc<TrustedProxies>,
    pub forward_auth: Option<Arc<crate::admin::forward_auth::ForwardAuthConfig>>,
}

impl AppState {
    /// Spawn a serialized background filter-engine rebuild, so a handler that mutates rules
    /// or lists can respond immediately. Also used by [`crate::admin::pages`].
    pub(crate) fn trigger_rebuild(&self) {
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

/// `OpenAPI` document for the programmatic subset of the admin API; browser-only endpoints
/// are not annotated.
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
        crate::db::CustomRuleRow, FilterListResponse, crate::db::ApiKeyRow,
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

/// Serve the raw `OpenAPI` document. Operator-only: it holds no data, but pre-auth recon of
/// the API surface is still denied.
async fn openapi_json(_auth: AuthedUser) -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// Serve the interactive Scalar API reference. Operator-only, like [`openapi_json`].
async fn scalar_docs(_auth: AuthedUser) -> axum::response::Html<String> {
    axum::response::Html(Scalar::new(ApiDoc::openapi()).to_html())
}

pub fn admin_router(state: AppState) -> Router {
    Router::new()
        // Server-rendered pages (`crate::admin::pages`); each resolves the session before
        // writing HTML, redirecting an unauthenticated browser.
        .route("/", get(crate::admin::pages::dashboard_page))
        .route("/stats", get(crate::admin::pages::stats_page))
        .route("/logs", get(crate::admin::pages::logs_page))
        .route("/logs/rules", post(crate::admin::pages::logs_rule_submit))
        .route("/logs/clear", post(crate::admin::pages::logs_clear_submit))
        .route("/filters", get(crate::admin::pages::filters_page))
        // One POST route per filter change rather than one endpoint switching on an action.
        .route(
            "/filters/lists",
            post(crate::admin::pages::filters_list_add_submit),
        )
        .route(
            "/filters/lists/update",
            post(crate::admin::pages::filters_lists_update_submit),
        )
        .route(
            "/filters/lists/enable-recommended",
            post(crate::admin::pages::filters_enable_recommended_submit),
        )
        .route(
            "/filters/lists/{id}/toggle",
            post(crate::admin::pages::filters_list_toggle_submit),
        )
        .route(
            "/filters/lists/{id}/edit",
            post(crate::admin::pages::filters_list_edit_submit),
        )
        .route(
            "/filters/lists/{id}/delete",
            post(crate::admin::pages::filters_list_delete_submit),
        )
        .route(
            "/filters/rules",
            post(crate::admin::pages::filters_rule_add_submit),
        )
        .route(
            "/filters/rules/{id}/delete",
            post(crate::admin::pages::filters_rule_delete_submit),
        )
        .route(
            "/onboarding/dismiss",
            post(crate::admin::pages::onboarding_dismiss_submit),
        )
        .route("/filters/registry", get(crate::admin::pages::registry_page))
        .route(
            "/filters/registry/add",
            post(crate::admin::pages::registry_add_submit),
        )
        .route(
            "/settings",
            get(crate::admin::pages::settings_page).post(crate::admin::pages::settings_submit),
        )
        .route("/account", get(crate::admin::pages::account_page))
        .route(
            "/account/password",
            post(crate::admin::pages::account_password_submit),
        )
        .route(
            "/account/operators",
            post(crate::admin::pages::account_operator_add_submit),
        )
        .route(
            "/account/operators/{id}/delete",
            post(crate::admin::pages::account_operator_delete_submit),
        )
        .route(
            "/account/sessions/revoke-others",
            post(crate::admin::pages::account_sessions_revoke_others_submit),
        )
        .route(
            "/account/sessions/{id}/revoke",
            post(crate::admin::pages::account_session_revoke_submit),
        )
        .route(
            "/account/api-keys",
            post(crate::admin::pages::account_api_key_create_submit),
        )
        .route(
            "/account/api-keys/{id}/delete",
            post(crate::admin::pages::account_api_key_delete_submit),
        )
        .route(
            "/login",
            get(crate::admin::pages::login_page).post(crate::admin::pages::login_submit),
        )
        .route(
            "/setup",
            get(crate::admin::pages::setup_page).post(crate::admin::pages::setup_submit),
        )
        // POST, not GET: a link prefetcher would follow a `GET /logout`.
        .route("/logout", post(crate::admin::pages::logout_submit))
        // Sign-in and setup need no auth; the other three below do.
        .route("/api/auth/login", post(login))
        .route("/api/auth/setup", post(setup))
        .route("/api/auth/reauth", post(reauth))
        .route("/api/auth/revoke-others", post(revoke_others))
        .route("/api/auth/logout", post(logout))
        // `health` needs no auth.
        .route("/api/health", get(health))
        .route("/api/server-info", get(get_server_info))
        .route("/api/settings", get(get_settings).put(put_settings))
        .route("/api/lists", get(get_lists).post(add_list))
        .route("/api/lists/batch", post(batch_add_lists))
        .route("/api/lists/{id}", put(update_list).delete(delete_list))
        .route("/api/lists/{id}/check", post(check_list_url))
        .route("/api/lists/update", post(trigger_list_update))
        .route("/api/rules", get(get_rules).post(add_rule))
        .route("/api/rules/{id}", delete(delete_rule))
        .route("/api/filter/check", post(filter_check))
        .route("/api/registry/filters", get(get_registry_filters))
        .route("/api/upstream/health", get(upstream_health))
        .route("/api/upstream/latency", get(upstream_latency))
        .route("/api/auth/me", get(get_me))
        .route(
            "/api/users",
            get(list_users_handler).post(create_user_handler),
        )
        .route("/api/users/{id}", delete(delete_user_handler))
        .route("/api/users/me/password", post(change_own_password))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{id}", delete(revoke_session_by_id))
        .route("/api/doh-tokens", get(get_doh_tokens).post(add_doh_token))
        .route("/api/doh-tokens/{id}", delete(delete_doh_token_endpoint))
        .route("/api/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api/api-keys/{id}", delete(delete_api_key))
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
        .route("/api/logs", get(get_logs).delete(delete_logs))
        .route("/api/events", get(stream_events))
        // No auth: the token in the URL is the credential.
        .route("/api/mobileconfig/{token}", get(get_mobileconfig))
        // Rendered from favicon.svg at build time.
        .route("/apple-touch-icon.png", get(serve_apple_touch_icon))
        // OpenAPI spec + Scalar docs UI (operator-only, see `openapi_json`).
        .route("/api/openapi.json", get(openapi_json))
        .route("/api/docs", get(scalar_docs))
        .fallback(serve_static)
        .with_state(state)
        .layer(tower_http::csrf::CsrfLayer::new())
        // Directly outside the guard: it logs the `ProtectionError` the guard attaches to its
        // 403.
        .layer(axum::middleware::from_fn(crate::admin::csrf::log_rejection))
        .layer(axum::middleware::from_fn(crate::headers::no_store))
        .layer(axum::middleware::from_fn(crate::headers::security_headers))
}

static ADMIN_UI: Dir = include_dir!("$CARGO_MANIFEST_DIR/admin-ui/dist");

/// Strong, quoted `ETag` from a content hash. `DefaultHasher` uses fixed keys, so the digest
/// is stable across restarts of the same binary.
fn etag_for(bytes: &[u8]) -> String {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("\"{:016x}\"", hasher.finish())
}

/// Per-path `ETags` for the embedded admin UI, computed once (assets are compile-time).
fn ui_etags() -> &'static HashMap<PathBuf, String> {
    static ETAGS: OnceLock<HashMap<PathBuf, String>> = OnceLock::new();
    ETAGS.get_or_init(|| {
        ADMIN_UI
            .files()
            .map(|f| (f.path().to_path_buf(), etag_for(f.contents())))
            .collect()
    })
}

/// True when `If-None-Match` lists the given `ETag` (a comma-separated list is tolerated).
fn if_none_match_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag))
}

/// `200` or `304` for an embedded file, always with an `ETag` and `Cache-Control: no-cache`.
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

/// Serve an embedded asset, or 404. No SPA fallback: every page path is a real route, so an
/// unmatched path has no page.
async fn serve_static(uri: Uri, headers: HeaderMap) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    match ADMIN_UI.get_file(path) {
        Some(file) => static_response(file, &headers),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Client IP for rate limiting and audit. Forwarding headers are trusted only from loopback
/// or a [`TrustedProxies`] CIDR; otherwise a caller could spoof its IP past per-IP limits.
pub(crate) fn client_ip(
    state: &AppState,
    connect: Option<&ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
) -> std::net::IpAddr {
    extract_client_ip(connect, headers, &state.trusted_proxies)
}

/// Bound on client-controlled text (`User-Agent`, key prefix) written to a log line.
pub(crate) const LOG_SAFE_MAX: usize = 256;

/// Truncate a client-controlled string to at most `max` bytes, on a `char` boundary.
pub(crate) fn log_safe(value: &str, max: usize) -> &str {
    if value.len() <= max {
        return value;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// The value of header `name` to log, telling an absent header (`<none>`) from a
/// non-ASCII one (`<non-ascii>`). Still caller-controlled: pass it through [`log_safe`].
pub(crate) fn header_log_value(headers: &HeaderMap, name: impl AsHeaderName) -> &str {
    match headers.get(name) {
        None => "<none>",
        Some(v) => v.to_str().unwrap_or("<non-ascii>"),
    }
}

/// The `User-Agent` value to log. See [`header_log_value`].
fn user_agent_log_value(headers: &HeaderMap) -> &str {
    header_log_value(headers, axum::http::header::USER_AGENT)
}

/// The **token hashes** of this request's session cookies, `__Host-` name first. Both names
/// are accepted so a deployment that gains or loses `Secure` keeps working. A browser can
/// hold both (a `__Host-` cookie survives a move behind a TLS-terminating proxy), so callers
/// must keep the first that **validates**, not the first present, or a stale cookie shadows
/// the live one.
///
/// Hashing here confines the raw token to the cookie boundary: downstream ([`SessionStore`],
/// `sessions.token_hash`, `session_log_id`) sees only hashes. Do not read the session cookie
/// from the jar directly.
fn session_cookie_hashes(jar: &CookieJar) -> impl Iterator<Item = String> {
    [
        crate::admin::auth::SESSION_COOKIE_HOST,
        crate::admin::auth::SESSION_COOKIE,
    ]
    .into_iter()
    .filter_map(|name| {
        jar.get(name)
            .map(|c| crate::admin::auth::hash_session_token(c.value()))
    })
}

/// Expire **every** session cookie present in the jar, not just the first: a browser can
/// hold both names (see [`session_cookie_hashes`]).
///
/// The `__Host-` removal always carries `Secure`, because a browser ignores a `__Host-`
/// `Set-Cookie` without it (RFC 6265bis §5.5).
pub(crate) fn clear_session_cookies(jar: CookieJar) -> CookieJar {
    let present: Vec<&str> = [
        crate::admin::auth::SESSION_COOKIE_HOST,
        crate::admin::auth::SESSION_COOKIE,
    ]
    .into_iter()
    .filter(|name| jar.get(name).is_some())
    .collect();
    present
        .into_iter()
        .map(|name| {
            Cookie::build((name, ""))
                .path("/")
                .secure(name == crate::admin::auth::SESSION_COOKIE_HOST)
                .build()
        })
        .fold(jar, CookieJar::remove)
}

/// The token hash of the session that actually authenticated this request, not merely the
/// first cookie present (see [`session_cookie_hashes`]); otherwise logout could revoke
/// nothing, or revoke-others could treat the caller's session as someone else's.
///
/// Checks store membership rather than calling `validate_session`: `AuthedUser` already
/// validated, and a second call would refresh `last_seen` and evict entries.
fn live_session_token_hash(state: &AppState, jar: &CookieJar) -> Option<String> {
    let sessions = state.sessions.lock();
    session_cookie_hashes(jar).find(|hash| sessions.contains_key(hash))
}

/// `(user_id, token_hash)` of the first session cookie that validates (see
/// [`session_cookie_hashes`]), or 401. `connect`/`headers` only attribute a failure to a
/// source IP for [`note_invalid_session_cookie`].
fn current_session(
    state: &AppState,
    connect: Option<&ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    jar: &CookieJar,
) -> Result<(i64, String), StatusCode> {
    let mut candidates = session_cookie_hashes(jar).peekable();
    let presented_a_cookie = candidates.peek().is_some();
    let found = candidates
        .find_map(|hash| validate_session(&state.sessions, &hash).map(|user_id| (user_id, hash)));
    if found.is_none() && presented_a_cookie {
        note_invalid_session_cookie(state, connect, headers);
    }
    found.ok_or(StatusCode::UNAUTHORIZED)
}

/// Count a session cookie naming no live session, warning once when one source crosses
/// [`crate::admin::auth::INVALID_SESSION_MAX_ATTEMPTS`] within the window (OWASP session-ID
/// guessing detection).
///
/// **Detect-only**, no blocking: a tab left open past its session's expiry keeps
/// requesting with the stale cookie, and blocking would lock the operator out.
///
/// Logged as `auth.failed` with a `method` field, like the other authentication failures.
fn note_invalid_session_cookie(
    state: &AppState,
    connect: Option<&ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
) {
    let ip = client_ip(state, connect, headers);
    if state.invalid_session_limiter.record_crossing(ip) {
        tracing::warn!(
            event = "auth.failed",
            method = "session_cookie",
            reason = "unknown_token_burst",
            %ip,
            attempts = crate::admin::auth::INVALID_SESSION_MAX_ATTEMPTS,
            window_secs = crate::admin::auth::INVALID_SESSION_WINDOW_SECS,
            user_agent = %log_safe(user_agent_log_value(headers), LOG_SAFE_MAX),
            "repeated session cookies naming no live session"
        );
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

/// An authenticated operator, from a session cookie, an `Authorization: Bearer <api key>`
/// header, or a reverse-proxy forward-auth header.
pub struct AuthedUser {
    pub user_id: i64,
    /// True only when the forward-auth header (SSO) authenticated the request.
    pub via_forward_auth: bool,
    /// The token hash when a session cookie authenticated the request, else `None`. Carried
    /// so [`ReauthedUser`] reads the stamp off the session this extractor chose rather than
    /// re-walking two cookie names (see [`session_cookie_hashes`]).
    pub session_token_hash: Option<String>,
}

impl axum::extract::FromRequestParts<AppState> for AuthedUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. Session cookie: the first that validates (see `session_cookie_hashes`).
        let jar = CookieJar::from_headers(&parts.headers);
        let mut candidates = session_cookie_hashes(&jar).peekable();
        let presented_a_cookie = candidates.peek().is_some();
        if let Some((user_id, token_hash)) = candidates
            .find_map(|hash| validate_session(&state.sessions, &hash).map(|uid| (uid, hash)))
        {
            return Ok(AuthedUser {
                user_id,
                via_forward_auth: false,
                session_token_hash: Some(token_hash),
            });
        }
        // Counted now, not deferred like `failed_key_prefix`: an unknown session ID was
        // presented whether or not a later credential authenticates the request.
        if presented_a_cookie {
            note_invalid_session_cookie(
                state,
                parts.extensions.get::<ConnectInfo<SocketAddr>>(),
                &parts.headers,
            );
        }
        // 2. Bearer API key. Its `auth.failed` is deferred to the rejection below, since
        // step 3 may still authenticate the request. Only set for `noadd_`-prefixed tokens.
        let mut failed_key_prefix: Option<String> = None;
        if let Some(token) = bearer_token(&parts.headers) {
            let hash = hash_api_key(&token);
            let now = crate::now_unix();
            if let Ok(Some(user_id)) = state.db.validate_api_key(&hash, now).await {
                return Ok(AuthedUser {
                    user_id,
                    via_forward_auth: false,
                    session_token_hash: None,
                });
            }
            // Log the non-secret prefix shown at creation, not the hash (which could be
            // matched offline against a known key set).
            if token.starts_with("noadd_") {
                failed_key_prefix = Some(log_safe(&token, 10).to_string());
            }
        }
        // 3. Forward auth from a trusted proxy peer. Last, so a cookie or API key wins.
        if let Some(cfg) = &state.forward_auth {
            let peer = parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ci| ci.0.ip());
            if let Some(username) = cfg.resolve_username(peer, &parts.headers) {
                return match resolve_forward_auth_user(state, &username).await {
                    Ok(user_id) => Ok(AuthedUser {
                        user_id,
                        via_forward_auth: true,
                        session_token_hash: None,
                    }),
                    Err(err) => {
                        tracing::error!(
                            event = "forward_auth.lookup_failed",
                            error = %err,
                            "forward-auth operator lookup failed"
                        );
                        // This exit skips the tail below, so emit the pending key failure here.
                        emit_failed_key_warning(parts, state, failed_key_prefix.as_deref());
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                };
            }
        }
        emit_failed_key_warning(parts, state, failed_key_prefix.as_deref());
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Count a password failure against `user_id`, logging a lockout when one starts or extends.
/// The event carries `user_id`, never the username.
fn note_account_failure(state: &AppState, user_id: i64, ip: std::net::IpAddr, endpoint: &str) {
    if let Some(lock) = state.lockout.record_failure(user_id) {
        tracing::warn!(
            event = "auth.account_locked",
            user_id,
            %ip,
            endpoint,
            locked_secs = lock.as_secs(),
            "account locked after repeated password failures"
        );
    }
}

/// Error body for a sensitive action refused for want of a recent password proof. `code`
/// tells its two cases apart from each other and from the CSRF guard's bare 403.
#[derive(Serialize)]
struct ReauthErrorResponse {
    error: String,
    code: &'static str,
}

/// An operator who proved the password recently enough for an action that hands out durable
/// access (minting an API key, adding or removing an operator) — what a stolen cookie is
/// after.
///
/// - **Session cookie**: needs a password proof within
///   [`crate::admin::auth::REAUTH_WINDOW_SECS`]; login counts as one.
/// - **Forward auth (SSO)**: exempt. The proxy authenticated this very request, and these
///   accounts store [`crate::admin::auth::NO_PASSWORD_SENTINEL`], so there is no password
///   to prove.
/// - **API key**: refused. A key cannot present a password, and could otherwise mint
///   itself a permanent successor.
pub struct ReauthedUser(pub AuthedUser);

impl axum::extract::FromRequestParts<AppState> for ReauthedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = AuthedUser::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        if auth.via_forward_auth {
            return Ok(Self(auth));
        }
        let Some(token_hash) = auth.session_token_hash.as_deref() else {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ReauthErrorResponse {
                    error:
                        "this action requires a password and cannot be performed with an API key"
                            .to_string(),
                    code: "password_required",
                }),
            )
                .into_response());
        };
        if crate::admin::auth::has_fresh_reauth(&state.sessions, token_hash) {
            return Ok(Self(auth));
        }
        Err((
            StatusCode::FORBIDDEN,
            Json(ReauthErrorResponse {
                error: "confirm your password to continue".to_string(),
                code: "reauth_required",
            }),
        )
            .into_response())
    }
}

/// Emit the deferred `auth.failed` for a `noadd_` bearer token that did not validate; a
/// no-op when `prefix` is `None`. Called from every failing exit of `AuthedUser`'s extractor.
fn emit_failed_key_warning(
    parts: &axum::http::request::Parts,
    state: &AppState,
    prefix: Option<&str>,
) {
    let Some(prefix) = prefix else {
        return;
    };
    let ip = extract_client_ip(
        parts.extensions.get::<ConnectInfo<SocketAddr>>(),
        &parts.headers,
        &state.trusted_proxies,
    );
    tracing::warn!(
        event = "auth.failed",
        method = "api_key",
        %ip,
        %prefix,
        "api key authentication failed"
    );
}

/// Map a forward-auth username to an operator id, provisioning it on first sight. A UNIQUE
/// violation means a concurrent request won the insert, so re-read.
async fn resolve_forward_auth_user(
    state: &AppState,
    username: &str,
) -> Result<i64, crate::db::DbError> {
    if let Some(auth) = state.db.get_user_auth(username).await? {
        return Ok(auth.id);
    }
    match state
        .db
        .create_user_no_password(username, crate::now_unix())
        .await
    {
        Ok(id) => {
            tracing::info!(
                event = "forward_auth.provisioned",
                %username,
                "provisioned operator from forward-auth header"
            );
            Ok(id)
        }
        Err(e) if e.is_unique_violation() => match state.db.get_user_auth(username).await? {
            Some(auth) => Ok(auth.id),
            None => Err(e),
        },
        Err(e) => Err(e),
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
}

/// Why a password sign-in was refused; `POST /api/auth/login` and `POST /login` each phrase
/// it in their own idiom.
pub(crate) enum LoginError {
    RateLimited,
    /// Unknown username, wrong password, forward-auth account, or locked account. One
    /// variant so a caller cannot tell them apart.
    Invalid,
    Internal,
}

/// Verify a username and password and mint a session, returning the jar with its
/// `Set-Cookie`.
///
/// The only password sign-in path — rate limit, constant Argon2 cost, per-account lockout,
/// audit events — shared by the JSON endpoint and the HTML form. Do not add a second copy.
pub(crate) async fn start_password_session(
    state: &AppState,
    connect: Option<&ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    jar: CookieJar,
    username: &str,
    password: &str,
) -> Result<CookieJar, LoginError> {
    let ip = client_ip(state, connect, headers);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    if !state.rate_limiter.check(ip) {
        tracing::warn!(
            event = "auth.failed",
            method = "password",
            reason = "rate_limited",
            %ip,
            "login rate limited"
        );
        return Err(LoginError::RateLimited);
    }
    state.rate_limiter.record(ip);

    // Every `Invalid` is audited, unknown usernames included. No username in the event,
    // matching the undistinguished response.
    let log_failed = || {
        tracing::warn!(
            event = "auth.failed",
            method = "password",
            %ip,
            user_agent = %log_safe(user_agent_log_value(headers), LOG_SAFE_MAX),
            "login failed"
        );
    };

    // Bound Argon2's input before hashing (see `MAX_LOGIN_PASSWORD_LENGTH`). Leaks nothing:
    // the verdict does not depend on the username.
    if password.len() > MAX_LOGIN_PASSWORD_LENGTH {
        log_failed();
        return Err(LoginError::Invalid);
    }

    // Generic failure whether the username is unknown or the password is wrong.
    let Some(auth) = state
        .db
        .get_user_auth(username.trim())
        .await
        .map_err(|_err| LoginError::Internal)?
    else {
        // Same Argon2 cost as a real account, so timing does not reveal the username.
        spend_verify_cost(password);
        log_failed();
        return Err(LoginError::Invalid);
    };

    // Forward-auth accounts store a sentinel, not a hash, and can never sign in with a
    // password. Must precede `verify_password` (which would 500 on the sentinel), and pads
    // the Argon2 cost so neither status nor timing reveals a proxy-provisioned account.
    if has_no_password(&auth.password_hash) {
        spend_verify_cost(password);
        log_failed();
        return Err(LoginError::Invalid);
    }

    // Only for a resolved username: an unknown one is never counted, so it can never be
    // locked, and the lockout cannot become an enumeration oracle. Padded for timing too.
    if state.lockout.is_locked(auth.id) {
        spend_verify_cost(password);
        log_failed();
        return Err(LoginError::Invalid);
    }

    let valid =
        verify_password(password, &auth.password_hash).map_err(|_err| LoginError::Internal)?;
    if !valid {
        note_account_failure(state, auth.id, ip, "login");
        log_failed();
        return Err(LoginError::Invalid);
    }
    state.lockout.record_success(auth.id);

    let now = crate::now_unix();
    // The raw token goes only into the `Set-Cookie`; everything persisted, held in memory
    // or logged is its hash, so a database copy yields no usable credential.
    let token = generate_token();
    let token_hash = crate::admin::auth::hash_session_token(&token);
    let session_id = state
        .db
        .insert_session(
            &token_hash,
            auth.id,
            now,
            now,
            Some(&ip.to_string()),
            user_agent,
        )
        .await
        .map_err(|_err| LoginError::Internal)?;
    store_session(
        &state.sessions,
        &token_hash,
        SessionInfo {
            session_id,
            user_id: auth.id,
            created_at: now,
            last_seen: now,
            // Signing in is a password proof, so it satisfies `ReauthedUser`.
            last_reauth_at: now,
        },
    );
    tracing::info!(
        event = "session.created",
        user_id = auth.id,
        session_id,
        sid_hash = %session_log_id(&token_hash),
        %ip,
        user_agent = %log_safe(user_agent_log_value(headers), LOG_SAFE_MAX),
        "login successful"
    );

    Ok(jar.add(build_session_cookie(token, state.cookie_secure)))
}

/// `POST /api/auth/login`: [`start_password_session`] mapped to status codes.
async fn login(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), StatusCode> {
    let jar = start_password_session(
        &state,
        connect.as_deref(),
        &headers,
        jar,
        &body.username,
        &body.password,
    )
    .await
    .map_err(|err| match err {
        LoginError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        LoginError::Invalid => StatusCode::UNAUTHORIZED,
        LoginError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    })?;
    Ok((jar, Json(LoginResponse { success: true })))
}

/// The `Set-Cookie` for a freshly minted session token, shared by sign-in and password
/// rotation so both agree on every attribute (`HttpOnly`, `Secure`, ...).
fn build_session_cookie(token: String, cookie_secure: bool) -> Cookie<'static> {
    Cookie::build((
        crate::admin::auth::session_cookie_name(cookie_secure),
        token,
    ))
    .path("/")
    .http_only(true)
    .secure(cookie_secure)
    // Lax, not Strict: Lax already withholds the cookie from cross-site unsafe methods and
    // no GET writes, so Strict would only break deep links.
    .same_site(axum_extra::extract::cookie::SameSite::Lax)
    .max_age(time::Duration::seconds(
        crate::admin::auth::SESSION_MAX_AGE_SECS,
    ))
    .build()
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

#[derive(Serialize)]
pub struct LogoutResponse {
    /// Where to send the browser to end the upstream (proxy/SSO) session; `None` when no
    /// forward-auth logout URL is configured.
    pub redirect_to: Option<String>,
    /// Whether this request authenticated via the forward-auth proxy header.
    pub via_forward_auth: bool,
}

/// Minimum length for a password being *set*.
///
/// NIST SP 800-63B asks for 15 without a second factor, which noadd lacks; 12 is a
/// compromise for operators typing on a phone. Raise to 15 once a second factor exists.
/// Not checked at sign-in, so older, shorter passwords keep working until changed.
pub(crate) const MIN_PASSWORD_LENGTH: usize = 12;

/// Maximum length for a password being set, bounding Argon2's work. Rejected rather than
/// truncated, which would let two passwords open the same account.
const MAX_PASSWORD_LENGTH: usize = 128;

/// Upper bound on a password at *sign-in*. Far looser than [`MAX_PASSWORD_LENGTH`]: it only
/// bounds unauthenticated Argon2 work, and must admit passwords set before that limit
/// existed.
const MAX_LOGIN_PASSWORD_LENGTH: usize = 1024;

/// Weakest zxcvbn score a new password may have. Three ("moderate protection from an
/// offline slow-hash scenario", 10^10 guesses) rather than four, which demands a long
/// passphrase; online guessing is already throttled to 5 attempts a minute per IP.
const MIN_PASSWORD_SCORE: zxcvbn::Score = zxcvbn::Score::Three;

/// Check a to-be-set password, returning the rejection message. Shared by every path that
/// sets a password so the floor cannot drift between them.
///
/// Length is checked before guessability, as the more actionable message. `user_inputs`
/// carries the username so zxcvbn penalises passwords built from it.
fn validate_new_password(password: &str, user_inputs: &[&str]) -> Result<(), String> {
    let len = password.chars().count();
    if len < MIN_PASSWORD_LENGTH {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LENGTH} characters"
        ));
    }
    if len > MAX_PASSWORD_LENGTH {
        return Err(format!(
            "password must be at most {MAX_PASSWORD_LENGTH} characters"
        ));
    }

    let entropy = zxcvbn::zxcvbn(password, user_inputs);
    if entropy.score() >= MIN_PASSWORD_SCORE {
        return Ok(());
    }
    // zxcvbn's own diagnosis where it has one: a fixed phrase, not derived from the password.
    let reason = entropy
        .feedback()
        .and_then(zxcvbn::feedback::Feedback::warning)
        .map_or_else(
            || "it is too easy to guess".to_string(),
            |warning| warning.to_string().trim_end_matches('.').to_lowercase(),
        );
    Err(format!(
        "password rejected: {reason}. Use a longer passphrase of several unrelated words."
    ))
}

/// A reason on an error where the status alone leaves the caller unable to act (e.g. a
/// rejected password). Authentication failures stay bare so no body becomes a
/// user-enumeration oracle.
#[derive(Serialize)]
struct ApiErrorResponse {
    error: String,
}

/// A `400` carrying `message` as its reason.
fn bad_request(message: String) -> (StatusCode, Json<ApiErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiErrorResponse { error: message }),
    )
}

/// An opaque `500` that reveals nothing about the server's internals.
fn internal_error() -> (StatusCode, Json<ApiErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiErrorResponse {
            error: "internal error".to_string(),
        }),
    )
}

/// Why first-run setup was refused. Only [`SetupError::Invalid`] carries a message, the one
/// the operator can act on.
pub(crate) enum SetupError {
    /// Forward auth is configured, so the wizard does not apply.
    Disabled,
    AlreadyConfigured,
    Invalid(String),
    Internal,
}

/// Create the first operator account. The only setup path, shared by `POST /api/auth/setup`
/// and `POST /setup`: its guards are what stop a second account being claimed.
pub(crate) async fn create_first_operator(
    state: &AppState,
    username: &str,
    password: &str,
) -> Result<(), SetupError> {
    // Under forward auth the first proxied request provisions the operator (`health`
    // reports `needs_setup: false`); leaving setup open would let anyone bypassing the
    // proxy claim the first account before then.
    if state.forward_auth.is_some() {
        return Err(SetupError::Disabled);
    }

    let count = state
        .db
        .count_users()
        .await
        .map_err(|_err| SetupError::Internal)?;
    if count > 0 {
        return Err(SetupError::AlreadyConfigured);
    }
    let username = username.trim();
    if username.is_empty() || username.chars().count() > 64 {
        return Err(SetupError::Invalid("invalid username".to_string()));
    }
    validate_new_password(password, &[username]).map_err(SetupError::Invalid)?;
    let hash = hash_password(password).map_err(|_err| SetupError::Internal)?;
    state
        .db
        .create_user(username, &hash, crate::now_unix())
        .await
        .map_err(|_err| SetupError::Internal)?;
    Ok(())
}

async fn setup(
    State(state): State<AppState>,
    Json(body): Json<SetupRequest>,
) -> Result<Json<SetupResponse>, (StatusCode, Json<ApiErrorResponse>)> {
    create_first_operator(&state, &body.username, &body.password)
        .await
        .map_err(|err| match err {
            SetupError::Disabled => (
                StatusCode::FORBIDDEN,
                Json(ApiErrorResponse {
                    error: "setup is disabled when forward auth is configured".to_string(),
                }),
            ),
            SetupError::AlreadyConfigured => (
                StatusCode::CONFLICT,
                Json(ApiErrorResponse {
                    error: "already configured".to_string(),
                }),
            ),
            SetupError::Invalid(error) => {
                (StatusCode::BAD_REQUEST, Json(ApiErrorResponse { error }))
            }
            SetupError::Internal => internal_error(),
        })?;
    Ok(Json(SetupResponse { success: true }))
}

#[derive(Deserialize)]
pub struct ReauthRequest {
    pub password: String,
}

/// `POST /api/auth/reauth`: prove the password again, opening this session's
/// [`crate::admin::auth::REAUTH_WINDOW_SECS`] window for sensitive actions. Cookie-only
/// (it stamps a session; [`ReauthedUser`] handles the other callers). Answers 204.
async fn reauth(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<ReauthRequest>,
) -> Result<StatusCode, StatusCode> {
    let (user_id, token_hash) = current_session(&state, connect.as_deref(), &headers, &jar)?;
    let ip = client_ip(&state, connect.as_deref(), &headers);

    match confirm_password(&state, user_id, &token_hash, ip, &body.password).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(ReauthError::RateLimited) => Err(StatusCode::TOO_MANY_REQUESTS),
        Err(ReauthError::Invalid) => Err(StatusCode::UNAUTHORIZED),
        Err(ReauthError::Internal) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Why a password confirmation was refused.
pub enum ReauthError {
    RateLimited,
    /// Wrong password, no password to check, or a session gone meanwhile; one variant so
    /// they cannot be told apart.
    Invalid,
    Internal,
}

/// Verify an operator's own password and stamp their session as re-authenticated.
///
/// The only password check for a *sensitive action*, shared by `POST /api/auth/reauth` and
/// the account page's forms: one rate limit, one lockout, one audit event. The form path
/// gets the stamp too, though it does not need it.
pub(crate) async fn confirm_password(
    state: &AppState,
    user_id: i64,
    token_hash: &str,
    ip: std::net::IpAddr,
    password: &str,
) -> Result<(), ReauthError> {
    if !state.rate_limiter.check(ip) {
        tracing::warn!(
            event = "auth.failed",
            method = "password",
            reason = "rate_limited",
            user_id,
            %ip,
            "reauthentication rate limited"
        );
        return Err(ReauthError::RateLimited);
    }
    state.rate_limiter.record(ip);

    // Same Argon2 input bound as sign-in.
    if password.len() > MAX_LOGIN_PASSWORD_LENGTH {
        return Err(ReauthError::Invalid);
    }

    let hash = state
        .db
        .get_user_password_hash(user_id)
        .await
        .map_err(|_err| ReauthError::Internal)?
        .ok_or(ReauthError::Invalid)?;
    // A forward-auth operator holds the sentinel, not a hash (and `ReauthedUser` exempts
    // them anyway): answer 401, not the 500 verifying the sentinel would produce.
    if has_no_password(&hash) {
        return Err(ReauthError::Invalid);
    }
    if state.lockout.is_locked(user_id) {
        spend_verify_cost(password);
        return Err(ReauthError::Invalid);
    }
    let ok = verify_password(password, &hash).map_err(|_err| ReauthError::Internal)?;
    if !ok {
        note_account_failure(state, user_id, ip, "reauth");
        tracing::warn!(
            event = "auth.failed",
            method = "password",
            reason = "reauth",
            user_id,
            %ip,
            "reauthentication rejected"
        );
        return Err(ReauthError::Invalid);
    }
    state.lockout.record_success(user_id);
    if !crate::admin::auth::mark_reauthenticated(&state.sessions, token_hash) {
        // The session expired or was revoked since it was validated; nothing was stamped.
        return Err(ReauthError::Invalid);
    }
    tracing::info!(
        event = "auth.reauthenticated",
        user_id,
        sid_hash = %session_log_id(token_hash),
        %ip,
        "password confirmed for a sensitive action"
    );
    Ok(())
}

/// Log out every *other* session, keeping the caller's current one signed in.
/// A forward-auth / API-key caller has no session cookie, so all sessions are
/// revoked (none is their own device).
async fn revoke_others(
    State(state): State<AppState>,
    auth: AuthedUser,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<StatusCode, StatusCode> {
    let ip = client_ip(&state, connect.as_deref(), &headers);
    let current_hash = live_session_token_hash(&state, &jar);
    revoke_every_other_session(&state, auth.user_id, ip, current_hash.as_deref())
        .await
        .map_err(|()| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

/// Revoke every session except `current_hash`. Shared by `POST /api/auth/revoke-others` and
/// the account page's form.
pub(crate) async fn revoke_every_other_session(
    state: &AppState,
    actor_user_id: i64,
    ip: std::net::IpAddr,
    current_hash: Option<&str>,
) -> Result<(), ()> {
    let revoked_rows =
        crate::admin::auth::revoke_other_sessions(&state.sessions, &state.db, current_hash)
            .await
            .map_err(|_err| ())?;
    // `scope` and `revoked_rows` are deliberate: the delete spans every operator, and the
    // count is DB rows, which can exceed live sessions (an evicted session keeps its row
    // until the periodic sweep).
    tracing::info!(
        event = "session.destroyed",
        reason = "revoked_others",
        scope = "all_operators",
        user_id = actor_user_id,
        %ip,
        revoked_rows,
        "revoked other sessions across all operators"
    );
    Ok(())
}

/// Ask the browser to drop this origin's cookies, cached responses and storage, beyond what
/// `Set-Cookie` expires.
///
/// Not `executionContexts`, which reloads the page: the JSON caller must still read
/// `redirect_to`, and the form caller is mid-redirect.
pub(crate) const CLEAR_SITE_DATA: (axum::http::HeaderName, &str) = (
    axum::http::HeaderName::from_static("clear-site-data"),
    r#""cache", "cookies", "storage""#,
);

/// Revoke every session this request's cookies name, clear the cookies, and return the
/// forward-auth logout URL, if any. Shared by `POST /api/auth/logout` and `POST /logout`.
pub(crate) async fn end_session(
    state: &AppState,
    auth: &AuthedUser,
    connect: Option<&ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    jar: CookieJar,
) -> (CookieJar, Option<String>) {
    let ip = client_ip(state, connect, headers);
    // Revoke every token a cookie names, not just the authenticating one: both cookies are
    // cleared below, and an unrevoked one would leave a live, replayable session behind.
    let candidates: Vec<String> = session_cookie_hashes(&jar).collect();
    for token_hash in &candidates {
        let revoked = crate::admin::auth::revoke_session(&state.sessions, token_hash);
        let _ = state.db.delete_session_by_token_hash(token_hash).await;
        // Log only a session that existed: the cookie is unvalidated input, and a fabricated
        // one must not inject a `session.destroyed` event.
        if let Some(info) = revoked {
            tracing::info!(
                event = "session.destroyed",
                reason = "logout",
                user_id = info.user_id,
                session_id = info.session_id,
                sid_hash = %session_log_id(token_hash),
                %ip,
                "logged out"
            );
        }
    }
    let jar = clear_session_cookies(jar);
    let redirect_to = if auth.via_forward_auth {
        state
            .forward_auth
            .as_ref()
            .and_then(|c| c.logout_url().map(str::to_string))
    } else {
        None
    };
    (jar, redirect_to)
}

/// `POST /api/auth/logout`: see [`end_session`]. A forward-auth caller has no session here,
/// so `redirect_to` (the proxy/SSO logout URL) is how it actually signs out.
async fn logout(
    State(state): State<AppState>,
    auth: AuthedUser,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<
    (
        CookieJar,
        [(axum::http::HeaderName, &'static str); 1],
        Json<LogoutResponse>,
    ),
    StatusCode,
> {
    let via_forward_auth = auth.via_forward_auth;
    let (jar, redirect_to) = end_session(&state, &auth, connect.as_deref(), &headers, jar).await;
    Ok((
        jar,
        [CLEAR_SITE_DATA],
        Json(LogoutResponse {
            redirect_to,
            via_forward_auth,
        }),
    ))
}

#[derive(Serialize)]
struct MeResponse {
    id: i64,
    username: String,
    /// True when the forward-auth header (SSO) authenticated this request.
    via_sso: bool,
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
        via_sso: auth.via_forward_auth,
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

/// `POST /api/users`: see [`create_operator`].
async fn create_user_handler(
    State(state): State<AppState>,
    ReauthedUser(auth): ReauthedUser,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiErrorResponse>)> {
    let ip = client_ip(&state, connect.as_deref(), &headers);
    match create_operator(&state, auth.user_id, ip, &body.username, &body.password).await {
        Ok(_id) => Ok(StatusCode::CREATED),
        Err(OperatorError::Invalid(message)) => Err(bad_request(message)),
        Err(OperatorError::Conflict) => Err((
            StatusCode::CONFLICT,
            Json(ApiErrorResponse {
                error: "username already exists".to_string(),
            }),
        )),
        // `LastOperator` and `NotFound` cannot come out of a create.
        Err(_) => Err(internal_error()),
    }
}

/// Why an operator could not be created or removed.
pub enum OperatorError {
    /// Carries the reason, which the operator can act on.
    Invalid(String),
    /// The username is taken.
    Conflict,
    /// Refusing to leave the appliance with no one who can administer it.
    LastOperator,
    NotFound,
    Internal,
}

/// Provision another operator, with full admin access. Shared by `POST /api/users` and the
/// account page's form; both prove a password first ([`ReauthedUser`] /
/// [`confirm_password`]).
pub(crate) async fn create_operator(
    state: &AppState,
    actor_user_id: i64,
    ip: std::net::IpAddr,
    username: &str,
    password: &str,
) -> Result<i64, OperatorError> {
    let username = username.trim();
    if username.is_empty() || username.chars().count() > 64 {
        return Err(OperatorError::Invalid("invalid username".to_string()));
    }
    if let Err(error) = validate_new_password(password, &[username]) {
        return Err(OperatorError::Invalid(error));
    }
    let hash = hash_password(password).map_err(|_err| OperatorError::Internal)?;
    match state
        .db
        .create_user(username, &hash, crate::now_unix())
        .await
    {
        Ok(id) => {
            // Pairs with `user.deleted`. `user_id` is the actor, `target_user_id` the new
            // account; the username is bounded, being caller-controlled.
            tracing::info!(
                event = "user.created",
                user_id = actor_user_id,
                target_user_id = id,
                target_username = %log_safe(username, LOG_SAFE_MAX),
                %ip,
                "operator created"
            );
            Ok(id)
        }
        // Naming a taken username is safe: the caller is an operator who can already
        // `GET /api/users`.
        Err(e) if e.is_unique_violation() => Err(OperatorError::Conflict),
        Err(_) => Err(OperatorError::Internal),
    }
}

async fn delete_user_handler(
    State(state): State<AppState>,
    ReauthedUser(auth): ReauthedUser,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    let ip = client_ip(&state, connect.as_deref(), &headers);
    match remove_operator(&state, auth.user_id, ip, id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(OperatorError::LastOperator) => Err(StatusCode::CONFLICT),
        Err(OperatorError::NotFound) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Delete an operator and their sessions. Shared by `DELETE /api/users/{id}` and the account
/// page's form.
pub(crate) async fn remove_operator(
    state: &AppState,
    actor_user_id: i64,
    ip: std::net::IpAddr,
    id: i64,
) -> Result<(), OperatorError> {
    // The last-operator guard and the delete are atomic in the DB layer, so concurrent
    // deletes cannot reach zero operators.
    match state
        .db
        .delete_user(id)
        .await
        .map_err(|_err| OperatorError::Internal)?
    {
        crate::db::DeleteUserOutcome::LastOperator => Err(OperatorError::LastOperator),
        crate::db::DeleteUserOutcome::NotFound => Err(OperatorError::NotFound),
        crate::db::DeleteUserOutcome::Deleted => {
            // `ON DELETE CASCADE` removed the session rows; evict the in-memory entries only
            // now, so a failed delete never logs anyone out.
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
            // `user_id` is the actor; the deleted operator is `target_user_id`.
            tracing::info!(
                event = "session.destroyed",
                reason = "user_deleted",
                user_id = actor_user_id,
                target_user_id = id,
                %ip,
                revoked = tokens.len(),
                "revoked sessions for deleted user"
            );
            // The account's own event, pairing with `user.created`.
            tracing::info!(
                event = "user.deleted",
                user_id = actor_user_id,
                target_user_id = id,
                %ip,
                "operator deleted"
            );
            Ok(())
        }
    }
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}
/// Why a password change was refused. `Rejected` carries the policy message verbatim.
pub(crate) enum PasswordChangeError {
    RateLimited,
    Rejected(String),
    /// The current password did not match (distinct from `Rejected`, so the operator fixes
    /// the right field).
    WrongPassword,
    Internal,
}

/// Change the signed-in operator's password, revoke their *other* sessions, and rotate the
/// caller's own token (OWASP). Revocation ejects a live stolen cookie elsewhere; rotation
/// covers a token leaked out of band (a proxy log, a screenshot). Shared by
/// `POST /api/users/me/password` and the account page's form; its rate limit, lockout and
/// `auth.failed` line are what stop a stolen session grinding the password.
///
/// The replacement session is stored *before* the old one is destroyed, so a failure
/// leaves a working session. Once the password write commits, a revocation or rotation
/// failure is only logged: the change cannot be undone, and a 500 would invite a retry.
///
/// API keys are **not** revoked: one minted with a stolen cookie survives a password
/// change and must be deleted separately.
///
/// Cookie-only, so `keep` is always `Some`. A future path for API-key / forward-auth
/// callers, or an admin reset of another account, must pass `None` to
/// [`crate::admin::auth::revoke_user_sessions_except`] — never use
/// `revoke_other_sessions`, which spans every operator.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn change_password_for_session(
    state: &AppState,
    headers: &HeaderMap,
    jar: CookieJar,
    user_id: i64,
    token_hash: &str,
    ip: std::net::IpAddr,
    current_password: &str,
    new_password: &str,
) -> Result<CookieJar, PasswordChangeError> {
    // Throttled on sign-in's budget: it guesses the same credential from the same IP.
    if !state.rate_limiter.check(ip) {
        tracing::warn!(
            event = "auth.failed",
            method = "password",
            reason = "rate_limited",
            user_id,
            %ip,
            "password change rate limited"
        );
        return Err(PasswordChangeError::RateLimited);
    }
    state.rate_limiter.record(ip);

    // The username feeds zxcvbn; failing to read it only weakens that check, not a 500.
    let username = state.db.get_username(user_id).await.ok().flatten();
    let user_inputs: Vec<&str> = username.as_deref().into_iter().collect();
    if let Err(error) = validate_new_password(new_password, &user_inputs) {
        return Err(PasswordChangeError::Rejected(error));
    }
    let hash = state
        .db
        .get_user_password_hash(user_id)
        .await
        .map_err(|_err| PasswordChangeError::Internal)?
        .ok_or(PasswordChangeError::Internal)?;
    // Unreachable (a passwordless account never holds a session), but keep the sentinel
    // away from `verify_password`, which would 500.
    if has_no_password(&hash) {
        return Err(PasswordChangeError::WrongPassword);
    }
    // Same account lockout as sign-in.
    if state.lockout.is_locked(user_id) {
        spend_verify_cost(current_password);
        return Err(PasswordChangeError::WrongPassword);
    }
    let ok =
        verify_password(current_password, &hash).map_err(|_err| PasswordChangeError::Internal)?;
    if !ok {
        note_account_failure(state, user_id, ip, "change_password");
        tracing::warn!(
            event = "auth.failed",
            method = "password",
            reason = "change_password",
            user_id,
            %ip,
            "current password rejected"
        );
        return Err(PasswordChangeError::WrongPassword);
    }
    state.lockout.record_success(user_id);
    let new_hash = hash_password(new_password).map_err(|_err| PasswordChangeError::Internal)?;
    state
        .db
        .update_user_password(user_id, &new_hash)
        .await
        .map_err(|_err| PasswordChangeError::Internal)?;
    match crate::admin::auth::revoke_user_sessions_except(
        &state.sessions,
        &state.db,
        user_id,
        Some(token_hash),
    )
    .await
    {
        Ok(revoked) => tracing::info!(
            event = "session.destroyed",
            reason = "password_change",
            user_id,
            revoked,
            "revoked other sessions after password change"
        ),
        Err(err) => tracing::error!(
            event = "session.revoke_failed",
            error = %err,
            user_id,
            "password changed but revoking other sessions failed"
        ),
    }

    Ok(rotate_own_session(state, headers, jar, user_id, token_hash, ip).await)
}

/// `POST /api/users/me/password`: [`change_password_for_session`] mapped to status codes.
async fn change_own_password(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<ChangePasswordRequest>,
) -> Response {
    let (user_id, token_hash) = match current_session(&state, connect.as_deref(), &headers, &jar) {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    };
    let ip = client_ip(&state, connect.as_deref(), &headers);
    match change_password_for_session(
        &state,
        &headers,
        jar,
        user_id,
        &token_hash,
        ip,
        &body.current_password,
        &body.new_password,
    )
    .await
    {
        Ok(jar) => (jar, StatusCode::NO_CONTENT).into_response(),
        Err(PasswordChangeError::RateLimited) => StatusCode::TOO_MANY_REQUESTS.into_response(),
        Err(PasswordChangeError::Rejected(message)) => bad_request(message).into_response(),
        Err(PasswordChangeError::WrongPassword) => StatusCode::UNAUTHORIZED.into_response(),
        Err(PasswordChangeError::Internal) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Replace the caller's session with a fresh one, returning the jar with its `Set-Cookie`.
/// On failure the original session and jar are kept (see [`change_password_for_session`]).
async fn rotate_own_session(
    state: &AppState,
    headers: &HeaderMap,
    jar: CookieJar,
    user_id: i64,
    old_token_hash: &str,
    ip: std::net::IpAddr,
) -> CookieJar {
    let now = crate::now_unix();
    let token = generate_token();
    let token_hash = crate::admin::auth::hash_session_token(&token);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    // Persisted before anything is destroyed.
    let session_id = match state
        .db
        .insert_session(
            &token_hash,
            user_id,
            now,
            now,
            Some(&ip.to_string()),
            user_agent,
        )
        .await
    {
        Ok(id) => id,
        Err(err) => {
            tracing::error!(
                event = "session.rotate_failed",
                error = %err,
                user_id,
                "password changed but minting the replacement session failed"
            );
            return jar;
        }
    };
    store_session(
        &state.sessions,
        &token_hash,
        SessionInfo {
            session_id,
            user_id,
            created_at: now,
            last_seen: now,
            // The current password was just verified.
            last_reauth_at: now,
        },
    );
    tracing::info!(
        event = "session.created",
        reason = "password_change",
        user_id,
        session_id,
        sid_hash = %session_log_id(&token_hash),
        %ip,
        user_agent = %log_safe(user_agent_log_value(headers), LOG_SAFE_MAX),
        "rotated session after password change"
    );

    // Evicting from memory is what stops the old token. A failed row delete is logged:
    // `load_sessions_from_db` would restore the row as live on restart.
    let revoked = crate::admin::auth::revoke_session(&state.sessions, old_token_hash);
    if let Err(err) = state.db.delete_session_by_token_hash(old_token_hash).await {
        tracing::error!(
            event = "session.revoke_failed",
            error = %err,
            user_id,
            "rotated session but deleting the superseded row failed"
        );
    }
    if let Some(info) = revoked {
        tracing::info!(
            event = "session.destroyed",
            reason = "rotated",
            user_id,
            session_id = info.session_id,
            sid_hash = %session_log_id(old_token_hash),
            %ip,
            "superseded by the rotated session"
        );
    }

    jar.add(build_session_cookie(token, state.cookie_secure))
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub id: i64,
    pub username: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub is_current: bool,
}

async fn list_sessions(
    State(state): State<AppState>,
    _auth: AuthedUser,
    jar: CookieJar,
) -> Result<Json<Vec<SessionResponse>>, StatusCode> {
    // The cookie only marks the caller's own row; API-key / forward-auth callers get none.
    let current_hash = live_session_token_hash(&state, &jar);
    sessions_snapshot(&state, current_hash.as_deref())
        .await
        .map(Json)
        .map_err(|()| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Every session, with the caller's own marked. Shared by `GET /api/sessions` and the
/// account page; "last seen" prefers the in-memory value, which is fresher than the row.
pub(crate) async fn sessions_snapshot(
    state: &AppState,
    current_hash: Option<&str>,
) -> Result<Vec<SessionResponse>, ()> {
    let rows = state.db.list_sessions().await.map_err(|_err| ())?;
    let live = state.sessions.lock();
    Ok(rows
        .into_iter()
        .map(|r| {
            let last_seen = live.get(&r.token_hash).map_or(r.last_seen, |i| i.last_seen);
            SessionResponse {
                id: r.id,
                username: r.username,
                created_at: r.created_at,
                last_seen,
                ip: r.ip,
                user_agent: r.user_agent,
                is_current: current_hash == Some(r.token_hash.as_str()),
            }
        })
        .collect())
}

async fn revoke_session_by_id(
    State(state): State<AppState>,
    auth: AuthedUser,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<(CookieJar, StatusCode), StatusCode> {
    let ip = client_ip(&state, connect.as_deref(), &headers);
    // Only used to clear the caller's cookie if its own session is revoked, so it must be
    // read before `revoke_session_row` evicts that session.
    let current_hash = live_session_token_hash(&state, &jar);
    match revoke_session_row(&state, auth.user_id, ip, id, current_hash.as_deref()).await {
        Ok(true) => Ok((clear_session_cookies(jar), StatusCode::NO_CONTENT)),
        Ok(false) => Ok((jar, StatusCode::NO_CONTENT)),
        Err(SessionRevokeError::NotFound) => Err(StatusCode::NOT_FOUND),
        Err(SessionRevokeError::Internal) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub enum SessionRevokeError {
    NotFound,
    Internal,
}

/// Revoke one session by row id, returning whether it was the caller's own (the caller
/// handles the cookie). Shared by `DELETE /api/sessions/{id}` and the account page's form.
pub(crate) async fn revoke_session_row(
    state: &AppState,
    actor_user_id: i64,
    ip: std::net::IpAddr,
    id: i64,
    current_hash: Option<&str>,
) -> Result<bool, SessionRevokeError> {
    let removed = state
        .db
        .delete_session_by_id(id)
        .await
        .map_err(|_err| SessionRevokeError::Internal)?;
    let Some(token_hash) = removed else {
        return Err(SessionRevokeError::NotFound);
    };
    crate::admin::auth::revoke_session(&state.sessions, &token_hash);
    tracing::info!(
        event = "session.destroyed",
        reason = "revoked_by_id",
        user_id = actor_user_id,
        session_id = id,
        sid_hash = %session_log_id(&token_hash),
        %ip,
        "revoked session by id"
    );
    Ok(current_hash == Some(token_hash.as_str()))
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    /// Always `"ok"` while the process is up and serving requests.
    pub status: String,
    /// True when no operator exists yet and `POST /api/auth/setup` must be called first.
    /// Always false under forward auth, where the first proxied request provisions one.
    pub needs_setup: bool,
    /// Build version string (from `git describe`).
    pub version: &'static str,
}

/// Whether there is no operator yet and setup is needed. Always `false` under forward auth.
/// Also decides whether the pages send a signed-out browser to `/setup` or `/login`.
pub(crate) async fn needs_setup(state: &AppState) -> bool {
    state.forward_auth.is_none() && state.db.count_users().await.is_ok_and(|n| n == 0)
}

/// Report basic service health.
///
/// Unauthenticated, so monitoring and setup can call it before any operator exists.
/// Reports whether initial setup is still pending.
#[utoipa::path(
    get, path = "/api/health", tag = "system",
    responses((status = 200, description = "Service health", body = HealthResponse))
)]
async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        needs_setup: needs_setup(&state).await,
        version: env!("GIT_VERSION"),
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

#[derive(Serialize, Deserialize, utoipa::ToSchema)]
pub struct SettingsMap {
    /// Flattened key/value pairs, e.g. `upstream_servers`, `upstream_strategy`,
    /// `log_retention_days`, `dnssec_disabled`, `block_mode`.
    #[serde(flatten)]
    pub settings: std::collections::HashMap<String, String>,
}

/// Get the current runtime settings.
///
/// Requires an operator (session or API key). Only known setting keys are returned.
#[utoipa::path(
    get, path = "/api/settings", tag = "settings",
    security(("api_key" = [])),
    responses((status = 200, description = "Current settings", body = SettingsMap))
)]
async fn get_settings(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<SettingsMap>, StatusCode> {
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

/// Addresses the settings form suggests for `block_custom_ipv4`, in order. `0.0.0.0` is
/// there because the two custom fields are set independently; `192.0.2.1` is TEST-NET-1
/// (RFC 5737). Every entry must pass [`apply_settings`]'s check
/// (`block_custom_ip_suggestions_are_all_accepted`).
pub const BLOCK_CUSTOM_IPV4_SUGGESTIONS: &[&str] = &["0.0.0.0", "127.0.0.1", "192.0.2.1"];

/// The IPv6 half of [`BLOCK_CUSTOM_IPV4_SUGGESTIONS`], same contract against
/// [`std::net::Ipv6Addr`]. `100::` is the discard-only prefix (RFC 6666).
pub const BLOCK_CUSTOM_IPV6_SUGGESTIONS: &[&str] = &["::", "::1", "100::"];

/// Why a settings save was refused. The API answers a bare 400; the page uses `field` to
/// place the message next to the input.
pub(crate) enum SettingsError {
    Invalid {
        field: &'static str,
        message: String,
    },
    Internal,
}

/// Validate, persist and apply runtime settings. Shared by `PUT /api/settings` and the
/// settings form. Everything is validated before anything is written (no partial save), and
/// runtime changes apply only after persisting.
pub(crate) async fn apply_settings(
    state: &AppState,
    settings: &std::collections::HashMap<String, String>,
) -> Result<(), SettingsError> {
    let upstream_servers = match settings.get("upstream_servers") {
        Some(v) => Some(
            crate::upstream::forwarder::parse_upstreams(v).map_err(|_e| {
                SettingsError::Invalid {
                    field: "upstream_servers",
                    message:
                        "Not a valid upstream — use ip:port, tls://host, or https://host/dns-query"
                            .to_string(),
                }
            })?,
        ),
        None => None,
    };

    if let Some(mode) = settings.get("block_mode")
        && mode.trim().parse::<crate::dns::block::BlockMode>().is_err()
    {
        return Err(SettingsError::Invalid {
            field: "block_mode",
            message: "Unknown block mode".to_string(),
        });
    }
    for key in ["block_custom_ipv4", "block_custom_ipv6"] {
        if let Some(v) = settings.get(key) {
            let v = v.trim();
            if !v.is_empty() {
                let ok = if key == "block_custom_ipv4" {
                    v.parse::<std::net::Ipv4Addr>().is_ok()
                } else {
                    v.parse::<std::net::Ipv6Addr>().is_ok()
                };
                if !ok {
                    return Err(SettingsError::Invalid {
                        field: key,
                        message: if key == "block_custom_ipv4" {
                            "Not a valid IPv4 address".to_string()
                        } else {
                            "Not a valid IPv6 address".to_string()
                        },
                    });
                }
            }
        }
    }

    for (key, value) in settings {
        state
            .db
            .set_setting(key, value)
            .await
            .map_err(|_err| SettingsError::Internal)?;
    }

    if let Some(strategy_str) = settings.get("upstream_strategy")
        && let Ok(strategy) = strategy_str.parse::<crate::upstream::strategy::UpstreamStrategy>()
    {
        state.forwarder.set_strategy(strategy);
    }

    if let Some(v) = settings.get("dnssec_disabled") {
        let new_enabled = v.trim() != "true";
        // Flush only on a real flip: cached wire responses carry the old AD/RRSIG/OPT
        // state, but re-saving the unchanged value must not wipe the cache.
        if state.forwarder.dnssec_enabled() != new_enabled {
            state.forwarder.set_dnssec_enabled(new_enabled);
            state.cache.invalidate_all();
        }
    }

    if let Some(servers) = upstream_servers {
        state.forwarder.reconfigure(servers).await;
    }

    if settings.keys().any(|k| k.starts_with("block_")) {
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
        let mode = merged(&state.db, settings, "block_mode").await;
        let v4 = merged(&state.db, settings, "block_custom_ipv4").await;
        let v6 = merged(&state.db, settings, "block_custom_ipv6").await;
        let cfg = crate::dns::block::from_settings(mode.as_deref(), v4.as_deref(), v6.as_deref());
        state.handler.set_block_config(cfg);
    }

    Ok(())
}

/// Update one or more runtime settings.
///
/// Requires an operator (session or API key). Only keys in the body change; everything is
/// validated before anything is written, so a bad value rejects the whole request.
/// Upstream, strategy, DNSSEC and block-mode changes apply without a restart.
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
    match apply_settings(&state, &body.settings).await {
        Ok(()) => Ok(StatusCode::OK),
        // Bare 400 is the published contract; the field detail is for the form.
        Err(SettingsError::Invalid { .. }) => Err(StatusCode::BAD_REQUEST),
        Err(SettingsError::Internal) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// List all configured filter lists.
///
/// Requires an operator (session or API key). Includes built-in and user-added lists.
#[utoipa::path(
    get, path = "/api/lists", tag = "lists",
    security(("api_key" = [])),
    responses((status = 200, description = "All filter lists", body = [FilterListResponse]))
)]
async fn get_lists(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<Vec<FilterListResponse>>, StatusCode> {
    let lists = state
        .db
        .get_filter_lists()
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    // From the live engine, not storage: uniqueness is a property of the loaded rule set.
    let unique = state.filter.load().unique_rules_by_list();

    Ok(Json(
        lists
            .into_iter()
            .map(|l| FilterListResponse {
                unique_rules: unique.get(&l.id).map(|n| i64::from(*n)),
                id: l.id,
                name: l.name,
                url: l.url,
                enabled: l.enabled,
                last_updated: l.last_updated,
                rule_count: l.rule_count,
            })
            .collect(),
    ))
}

/// A filter list, plus what removing it would cost. `FilterListRow`'s fields are spelled out
/// rather than flattened so the `OpenAPI` document shows one flat object.
#[derive(Serialize, utoipa::ToSchema)]
pub struct FilterListResponse {
    /// List id.
    pub id: i64,
    /// Display name.
    pub name: String,
    /// Source URL the list's contents are fetched from.
    pub url: String,
    /// Whether the list's rules are currently applied by the filter engine.
    pub enabled: bool,
    /// Unix timestamp (seconds) the list was last downloaded, or `0` if never.
    pub last_updated: i64,
    /// Number of rules parsed out of the list's content on last download.
    pub rule_count: i64,
    /// Rules no other loaded list provides: what removing this list would unblock. `null`
    /// when it contributes no rules (disabled, empty, or failed to download).
    pub unique_rules: Option<i64>,
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

/// Why a filter list could not be created or edited. `Invalid.field` places the form's
/// message; the JSON endpoint answers a bare 400.
pub enum ListError {
    Invalid {
        field: &'static str,
        message: String,
    },
    Internal,
}

/// Validate a filter list's name/URL, for both the form and the JSON endpoint. The URL check
/// is only the scheme; whether it *serves* a list is `POST /api/lists/{id}/check`'s job.
fn validate_list(name: &str, url: &str) -> Result<(), ListError> {
    if name.trim().is_empty() {
        return Err(ListError::Invalid {
            field: "name",
            message: "Name is required".to_string(),
        });
    }
    let url = url.trim();
    if url.is_empty() {
        return Err(ListError::Invalid {
            field: "url",
            message: "URL is required".to_string(),
        });
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(ListError::Invalid {
            field: "url",
            message: "URL must start with http:// or https://".to_string(),
        });
    }
    Ok(())
}

/// Create a filter list, enabled, without fetching it (left to `POST /api/lists/update` or
/// the periodic refresh, so a slow remote does not hold the request open).
pub async fn create_filter_list(state: &AppState, name: &str, url: &str) -> Result<i64, ListError> {
    validate_list(name, url)?;
    state
        .db
        .add_filter_list(name.trim(), url.trim(), true)
        .await
        .map_err(|_err| ListError::Internal)
}

/// Change a filter list's name and URL together, validated as a pair.
pub async fn modify_filter_list(
    state: &AppState,
    id: i64,
    name: &str,
    url: &str,
) -> Result<(), ListError> {
    validate_list(name, url)?;
    state
        .db
        .update_filter_list(id, name.trim(), url.trim())
        .await
        .map_err(|_err| ListError::Internal)
}

/// Add a new filter list by URL.
///
/// Requires an operator (session or API key). The list is created enabled but not fetched;
/// call `POST /api/lists/update` (or wait for the periodic refresh) to download it and
/// rebuild the filter engine.
#[utoipa::path(
    post, path = "/api/lists", tag = "lists",
    security(("api_key" = [])),
    request_body = AddListRequest,
    responses(
        (status = 201, description = "List created", body = AddListResponse),
        (status = 400, description = "Missing name, or a URL noadd cannot fetch")
    )
)]
async fn add_list(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Json(body): Json<AddListRequest>,
) -> Result<(StatusCode, Json<AddListResponse>), StatusCode> {
    let id = create_filter_list(&state, &body.name, &body.url)
        .await
        .map_err(list_error_status)?;

    Ok((StatusCode::CREATED, Json(AddListResponse { id })))
}

/// The status a [`ListError`] answers with over JSON (field detail is for the form).
fn list_error_status(err: ListError) -> StatusCode {
    match err {
        ListError::Invalid { .. } => StatusCode::BAD_REQUEST,
        ListError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
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
/// Requires an operator (session or API key). `enabled` applies on its own; name and URL
/// only when both are given. Triggers an async filter-engine rebuild.
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
        modify_filter_list(&state, id, name, url)
            .await
            .map_err(list_error_status)?;
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
    let url = if let Some(Json(b)) = body
        && let Some(u) = b.url
    {
        u
    } else {
        state
            .db
            .filter_list_url(id)
            .await
            .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?
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
/// Requires an operator (session or API key). Triggers an async filter-engine rebuild.
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

/// Most lists one batch may add, on both the registry page and the JSON endpoint.
pub const BATCH_ADD_LIMIT: usize = 50;

async fn batch_add_lists(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Json(body): Json<BatchAddRequest>,
) -> Result<Json<BatchAddResponse>, StatusCode> {
    Ok(Json(add_lists_batch(&state, body.items).await?))
}

/// Add a batch of lists, downloading each and rolling back the ones that fail, then rebuild
/// once. The only batch-add path, shared by `POST /api/lists/batch` and the registry form.
pub async fn add_lists_batch(
    state: &AppState,
    items: Vec<BatchAddItem>,
) -> Result<BatchAddResponse, StatusCode> {
    if items.is_empty() || items.len() > BATCH_ADD_LIMIT {
        return Err(StatusCode::BAD_REQUEST);
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent(crate::user_agent())
        .build()
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;

    let sem = Arc::new(tokio::sync::Semaphore::new(4));
    let mut set = tokio::task::JoinSet::new();
    for item in items {
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
                .and_then(reqwest::Response::error_for_status);
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

    Ok(BatchAddResponse { added, failed })
}

async fn get_registry_filters(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<crate::registry::RegistryData>, StatusCode> {
    match state.registry.list().await {
        Ok(data) => Ok(Json(data)),
        Err(e) => {
            tracing::warn!(
                event = "registry.fetch_failed",
                error = %e,
                "registry fetch failed"
            );
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

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
/// Requires an operator (session or API key). Returned in the syntax they were added in.
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
/// Requires an operator (session or API key). A new rule returns 201 with its id; an
/// existing one is a no-op 200 with `id: 0`; unparseable text is a 400. Triggers an async
/// filter-engine rebuild.
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
    match create_custom_rule(&state, &body.rule).await {
        Ok(Some(id)) => Ok((StatusCode::CREATED, Json(AddRuleResponse { id }))),
        // Already there: same end state, but not a creation.
        Ok(None) => Ok((StatusCode::OK, Json(AddRuleResponse { id: 0 }))),
        Err(RuleError::Unparseable) => Err(StatusCode::BAD_REQUEST),
        Err(RuleError::Internal) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Why a custom rule could not be added.
pub enum RuleError {
    /// The text does not parse as a rule in any supported syntax.
    Unparseable,
    Internal,
}

/// Add a custom rule; `Ok(None)` if the exact text already exists. The parse decides allow
/// vs block and is the validation, shared by the form and the API.
pub async fn create_custom_rule(state: &AppState, rule: &str) -> Result<Option<i64>, RuleError> {
    let rule = rule.trim();
    let rule_type = match crate::filter::parser::parse_rule(rule) {
        Some(parsed) => match parsed.action {
            crate::filter::parser::RuleAction::Allow => "allow",
            crate::filter::parser::RuleAction::Block => "block",
        },
        None => return Err(RuleError::Unparseable),
    };

    if state
        .db
        .has_custom_rule(rule)
        .await
        .map_err(|_err| RuleError::Internal)?
    {
        return Ok(None);
    }

    let id = state
        .db
        .add_custom_rule(rule, rule_type)
        .await
        .map_err(|_err| RuleError::Internal)?;

    state.trigger_rebuild();

    Ok(Some(id))
}

/// Delete a custom allow/block rule.
///
/// Requires an operator (session or API key). Triggers an async filter-engine rebuild.
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
/// Requires an operator (session or API key). Metadata only, never the secret.
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
/// Requires a session with a recent password proof (`POST /api/auth/reauth`, or sign-in);
/// an API key cannot mint another. The key inherits the caller's permissions. The secret
/// `token` is returned only here; afterwards only `prefix` identifies the key.
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
    ReauthedUser(auth): ReauthedUser,
    Json(body): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), StatusCode> {
    match issue_api_key(&state, auth.user_id, &body.name, body.expires_at).await {
        Ok(created) => Ok((StatusCode::CREATED, Json(created))),
        Err(ApiKeyError::Invalid(_)) => Err(StatusCode::BAD_REQUEST),
        Err(ApiKeyError::Internal) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Why an API key could not be minted.
pub enum ApiKeyError {
    Invalid(String),
    Internal,
}

/// Mint an API key, returning the only copy of its secret (only the hash is stored). Shared
/// by `POST /api/api-keys` and the account page's form.
pub(crate) async fn issue_api_key(
    state: &AppState,
    user_id: i64,
    name: &str,
    expires_at: Option<i64>,
) -> Result<CreateApiKeyResponse, ApiKeyError> {
    let name = name.trim().to_string();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(ApiKeyError::Invalid(
            "Name is required, and at most 64 characters".to_string(),
        ));
    }
    let (full, prefix, hash) = crate::admin::auth::generate_api_key();
    let now = crate::now_unix();
    let id = state
        .db
        .insert_api_key(user_id, &name, &hash, &prefix, now, expires_at)
        .await
        .map_err(|_err| ApiKeyError::Internal)?;
    tracing::info!(
        event = "apikey.created",
        user_id,
        key_id = id,
        %prefix,
        expires_at,
        "api key created"
    );
    Ok(CreateApiKeyResponse {
        id,
        name,
        prefix,
        token: full,
    })
}

/// Delete one of the caller's own API keys.
///
/// Requires an operator (session or API key). Another operator's key answers 404, not
/// revealing it exists.
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
    match revoke_api_key(&state, auth.user_id, id).await {
        Ok(true) => Ok(StatusCode::OK),
        Ok(false) => Err(StatusCode::NOT_FOUND),
        Err(()) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Revoke one of an operator's own API keys, reporting whether it existed. Scoped to
/// `user_id` in the query, so another operator's key looks absent.
pub(crate) async fn revoke_api_key(state: &AppState, user_id: i64, id: i64) -> Result<bool, ()> {
    let deleted = state
        .db
        .delete_api_key(id, user_id)
        .await
        .map_err(|_err| ())?;
    if deleted {
        tracing::info!(
            event = "apikey.destroyed",
            user_id,
            key_id = id,
            "api key deleted"
        );
    }
    Ok(deleted)
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct FilterCheckRequest {
    /// Domain to evaluate, e.g. `"ads.example.com"`; a trailing dot is stripped.
    domain: String,
}

/// Check what the filter engine would decide for a domain, without querying DNS.
///
/// Requires an operator (session or API key). Evaluates the live engine and answers
/// `{"action": "blocked", "rule": ..., "list": ...}` or `{"action": "allowed", "rule": ...}`
/// (`rule` omitted when no allow rule matched).
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

async fn upstream_latency(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let latencies = state.forwarder.latencies();
    let strategy = state.forwarder.strategy();

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

/// Get aggregate query statistics for today, the last 7 days, and the last 30 days.
///
/// Requires an operator (session or API key). Totals, block ratio, cache hit rate and
/// average response time per window, plus the last minute's query rate.
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

// Each stats/v2 endpoint declares exactly the parameters it honours, and
// `deny_unknown_fields` makes any other a 400 rather than silently ignored.

/// Query for `/api/stats/v2/timeline`, the one endpoint honouring both `range` and
/// `tz_offset`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineV2Query {
    pub range: Option<String>,
    /// Viewer's east-positive UTC offset in minutes (e.g. 480 for UTC+8), aligning buckets
    /// to the local calendar. Clamped to ±14h, rounded to 15 minutes; missing ⇒ 0 (UTC).
    pub tz_offset: Option<i64>,
}

/// Query for `/api/stats/v2/heatmap`. No `range`: its window is fixed (see
/// [`stats::compute_heatmap`]).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeatmapQuery {
    /// See [`TimelineV2Query::tz_offset`].
    pub tz_offset: Option<i64>,
}

/// Query for the stats/v2 endpoints whose window is not calendar-aligned (no `tz_offset`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeQuery {
    pub range: Option<String>,
}

/// Parse a `range` parameter, defaulting to 7 days when absent.
fn parse_stats_range(raw: Option<&str>) -> Result<stats::StatsRange, StatusCode> {
    stats::StatsRange::parse(raw.unwrap_or("7d")).ok_or(StatusCode::BAD_REQUEST)
}

/// Resolve the viewer's UTC offset to seconds, clamped to ±14h. Rounded to a quarter hour,
/// the grain of the `query_stats_quarter` rollup these charts fold; no zone in use is
/// affected.
fn resolve_tz_offset_secs(tz_offset: Option<i64>) -> i64 {
    let minutes = tz_offset.unwrap_or(0).clamp(-14 * 60, 14 * 60);
    (minutes + 7).div_euclid(15) * 15 * 60
}

async fn get_stats_v2_timeline(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<TimelineV2Query>,
) -> Result<Json<Vec<crate::db::TimelineMultiPoint>>, StatusCode> {
    let range = parse_stats_range(query.range.as_deref())?;
    let tz_offset = resolve_tz_offset_secs(query.tz_offset);
    let now = crate::now_unix();
    let timeline = stats::compute_stats_timeline(&state.db, now, range, tz_offset)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(timeline))
}

async fn get_stats_v2_heatmap(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<HeatmapQuery>,
) -> Result<Json<Vec<crate::db::HeatmapCell>>, StatusCode> {
    let tz_offset = resolve_tz_offset_secs(query.tz_offset);
    let now = crate::now_unix();
    let cells = stats::compute_heatmap(&state.db, now, tz_offset)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(cells))
}

async fn get_stats_v2_breakdown(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<RangeQuery>,
) -> Result<Json<stats::Breakdowns>, StatusCode> {
    let range = parse_stats_range(query.range.as_deref())?;
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
    Query(query): Query<RangeQuery>,
) -> Result<Json<stats::StatsHighlights>, StatusCode> {
    let range = parse_stats_range(query.range.as_deref())?;
    let now = crate::now_unix();
    let h = stats::compute_highlights(&state.db, now, range)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(h))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangedTopQuery {
    pub range: Option<String>,
    pub limit: Option<i64>,
}

async fn get_stats_v2_top_domains(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<RangedTopQuery>,
) -> Result<Json<Vec<crate::db::TopDomain>>, StatusCode> {
    let range = parse_stats_range(query.range.as_deref())?;
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
    let range = parse_stats_range(query.range.as_deref())?;
    let limit = query.limit.unwrap_or(15);
    let now = crate::now_unix();
    let rows = stats::compute_top_clients_ranged(&state.db, now, range, limit)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}

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
    /// Required by macOS 26.1+: without it a `com.apple.dnsSettings.managed` profile is
    /// treated as a user-scoped VPN service and fails ("The 'VPN Service' payload could not
    /// be installed"). iOS ignores it.
    payload_scope: String,
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
        payload_scope: "System".into(),
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

/// Deterministic UUID v5 from a seed, in the URL namespace (these identify `DoH` URLs).
fn make_uuid(seed: &str) -> String {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, seed.as_bytes()).to_string()
}

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
/// Supports pagination and filters; returns `logs` plus the `total` matching the filters.
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

/// Query for [`stream_events`].
#[derive(Deserialize)]
pub struct EventStreamQuery {
    /// Ask for `stats` events (only the dashboard does, so other pages cost no snapshot).
    pub stats: Option<String>,
    /// Ask for `log` events, one per answered query (only the query log's tail, while on).
    pub logs: Option<String>,
}

impl EventStreamQuery {
    fn wants_stats(&self) -> bool {
        flag(self.stats.as_deref())
    }

    fn wants_logs(&self) -> bool {
        flag(self.logs.as_deref())
    }
}

/// Accepts `1` as well as `true`: `serde_urlencoded` would 400 `?stats=1` for a `bool`.
fn flag(value: Option<&str>) -> bool {
    matches!(value, Some("1" | "true"))
}

/// One arm of the pump's `select!`: a receive that never completes when the source is absent
/// (never asked for, or closed and retired). Cancel-safe: the receiver lives in the
/// `Option`, not in the future `select!` drops.
async fn next_broadcast<T: Clone>(
    source: &mut Option<tokio::sync::broadcast::Receiver<T>>,
) -> Result<T, tokio::sync::broadcast::error::RecvError> {
    match source {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// `GET /api/events`: the admin UI's one push channel, one connection per tab.
///
/// - `ping` every tick: the status indicator's heartbeat, a real event because SSE
///   keep-alive comments never reach `EventSource`. Carries `traffic` (ever answered a
///   query), which retires the onboarding notice.
/// - `stats`: a [`events::DashboardSnapshot`], when `?stats=1`.
/// - `log`: a [`QueryLogEntry`] per answered query, published before the DB flush, when
///   `?logs=1`.
/// - `rebuild`: a [`crate::filter::rebuild::RebuildStatus`] on both edges of every filter
///   rebuild, unasked-for (the banner is in the shell).
///
/// On open, a stats client gets a snapshot at once (so the server-rendered numbers do not
/// lag the first tick), and every client gets the current `rebuild` state — this stream is
/// the only place it is published, so a rebuild that just finished must still be reported.
async fn stream_events(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Query(query): Query<EventStreamQuery>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let wants_stats = query.wants_stats();
    let hub = state.events.clone();
    let mut ticks = Some(hub.subscribe());
    // Only when asked for: even an unread receiver costs the sender every answered query.
    let mut logs = query.wants_logs().then(|| state.log_events.subscribe());
    // Unconditional: a rebuild publishes only twice per run.
    let mut rebuilds = Some(state.rebuild.subscribe());
    // For the pump, which answers a lagged subscriber with the live state.
    let rebuild = state.rebuild.clone();

    // Moved into the pump so it lives as long as the connection; dropping the last one
    // stops the ticker computing snapshots.
    let guard = wants_stats.then(|| hub.stats_guard());

    let mut initial = Vec::new();
    if let Ok(event) = Event::default()
        .event("rebuild")
        .json_data(rebuild.status())
    {
        initial.push(event);
    }
    if wants_stats {
        match events::compute_snapshot(&state.db, crate::now_unix()).await {
            Ok(snap) => {
                if let Ok(event) = Event::default().event("stats").json_data(&snap) {
                    initial.push(event);
                }
            }
            Err(e) => tracing::warn!(
                event = "events.snapshot_failed",
                stage = "initial",
                error = %e,
                "failed to compute the opening dashboard snapshot"
            ),
        }
    }

    // A tick becomes one or two events, so pump into a channel. When the client goes away
    // the next send fails and the task (and its guard) ends.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(8);
    tokio::spawn(async move {
        let _guard = guard;
        // Held so the tick source cannot close when the handler returns.
        let _hub = hub;

        for event in initial {
            if tx.send(Ok(event)).await.is_err() {
                return;
            }
        }

        // A closed source retires its own arm rather than ending the connection: the
        // heartbeat must outlive the tail.
        while ticks.is_some() || logs.is_some() || rebuilds.is_some() {
            tokio::select! {
                received = next_broadcast(&mut ticks) => {
                    let tick = match received {
                        Ok(tick) => tick,
                        // Lagged: the next tick carries the whole state.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            ticks = None;
                            continue;
                        }
                    };

                    if let Ok(event) = Event::default()
                        .event("ping")
                        .json_data(serde_json::json!({
                            "seq": tick.seq,
                            "at": tick.at,
                            "traffic": tick.traffic,
                        }))
                        && tx.send(Ok(event)).await.is_err()
                    {
                        break;
                    }

                    if let Some(snapshot) = tick.snapshot.as_ref()
                        && let Ok(event) = Event::default().event("stats").json_data(&**snapshot)
                        && tx.send(Ok(event)).await.is_err()
                    {
                        break;
                    }
                }

                received = next_broadcast(&mut logs) => {
                    let entry = match received {
                        Ok(entry) => entry,
                        // Lagged: skip what was missed rather than replay a burst.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            logs = None;
                            continue;
                        }
                    };

                    if let Ok(event) = Event::default().event("log").json_data(&*entry)
                        && tx.send(Ok(event)).await.is_err()
                    {
                        break;
                    }
                }

                received = next_broadcast(&mut rebuilds) => {
                    let status = match received {
                        Ok(status) => status,
                        // Lagged: a missed edge never recurs (a missed completion would
                        // leave the banner spinning), so send the live state.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            rebuild.status()
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            rebuilds = None;
                            continue;
                        }
                    };

                    if let Ok(event) = Event::default().event("rebuild").json_data(status)
                        && tx.send(Ok(event)).await.is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    Sse::new(tokio_stream::wrappers::ReceiverStream::new(rx)).keep_alive(KeepAlive::default())
}

/// Delete all DNS query logs.
///
/// Permanently clears the entire query-log history.
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

    /// Every annotated operation needs a summary (first doc paragraph) and a description
    /// (the rest), or Scalar shows only a title.
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

/// The helpers that make a caller-controlled string safe to log. Production callers sit in
/// `tracing` fields, evaluated only with a subscriber, so nothing else tests these.
#[cfg(test)]
mod log_value_tests {
    use super::*;

    /// An absent header must not be logged as a garbled one.
    #[test]
    fn header_log_value_separates_absent_from_unreadable() {
        let mut headers = HeaderMap::new();
        assert_eq!(header_log_value(&headers, "x-probe"), "<none>");
        assert_eq!(user_agent_log_value(&headers), "<none>");

        headers.insert("x-probe", axum::http::HeaderValue::from_static("plain"));
        assert_eq!(header_log_value(&headers, "x-probe"), "plain");

        // Latin-1 bytes: a legal header value, but not `to_str`-able.
        headers.insert(
            axum::http::header::USER_AGENT,
            axum::http::HeaderValue::from_bytes(b"caf\xe9").unwrap(),
        );
        assert_eq!(user_agent_log_value(&headers), "<non-ascii>");
    }

    /// `log_safe` never splits a multi-byte UTF-8 sequence.
    #[test]
    fn log_safe_truncates_on_a_char_boundary() {
        assert_eq!(log_safe("short", LOG_SAFE_MAX), "short");
        // Each of these is 3 bytes, so a limit of 4 lands mid-character.
        let cjk = "山川河海";
        let cut = log_safe(cjk, 4);
        assert_eq!(cut, "山");
        assert!(cjk.starts_with(cut));
    }
}
