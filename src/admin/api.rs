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
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use utoipa::OpenApi as _;
use utoipa_scalar::Scalar;

use crate::admin::auth::{
    RateLimiter, SessionInfo, SessionStore, generate_token, has_no_password, hash_api_key,
    hash_password, session_log_id, spend_verify_cost, store_session, validate_session,
    verify_password,
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
    /// Counts unknown session tokens per source IP, so a client guessing
    /// session IDs is reported (see [`note_invalid_session_cookie`]). A
    /// separate instance from `rate_limiter` on purpose: sharing one would let
    /// cookie guessing burn a legitimate operator's login budget from behind
    /// the same NAT address.
    pub invalid_session_limiter: Arc<RateLimiter>,
    /// Per-account password-failure backoff, the account-keyed counterpart to
    /// the IP-keyed `rate_limiter`. Both are needed: one bounds a single
    /// source address, the other a single account across every address an
    /// attacker can reach it from.
    pub lockout: Arc<crate::admin::auth::AccountLockout>,
    pub forwarder: Arc<UpstreamForwarder>,
    pub handler: Arc<DnsHandler>,
    pub log_events: tokio::sync::broadcast::Sender<std::sync::Arc<QueryLogEntry>>,
    pub server_info: ServerInfo,
    /// Whether to set `Secure` on the admin session cookie. Resolved once at
    /// startup by [`crate::config::resolve_cookie_secure`]. Kept off
    /// [`ServerInfo`] deliberately — that struct is serialized to
    /// `/api/server-info`, and this is a cookie-emission detail, not part of
    /// the public API surface.
    pub cookie_secure: bool,
    pub list_manager: Arc<ListManager>,
    pub rebuild: Arc<RebuildCoordinator>,
    pub registry: Arc<RegistryClient>,
    pub trusted_proxies: Arc<TrustedProxies>,
    pub forward_auth: Option<Arc<crate::admin::forward_auth::ForwardAuthConfig>>,
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
        // Server-rendered pages (see `crate::admin::pages`). Each signed-in
        // route resolves the session before any HTML is written, so an
        // unauthenticated browser is redirected rather than served a shell that
        // has to discover the same thing for itself.
        .route("/", get(crate::admin::pages::shell_page))
        .route("/stats", get(crate::admin::pages::shell_page))
        .route("/logs", get(crate::admin::pages::shell_page))
        .route("/filters", get(crate::admin::pages::shell_page))
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
            "/login",
            get(crate::admin::pages::login_page).post(crate::admin::pages::login_submit),
        )
        .route(
            "/setup",
            get(crate::admin::pages::setup_page).post(crate::admin::pages::setup_submit),
        )
        // POST, not GET: signing out changes state, and a `GET /logout` is
        // something a link prefetcher would happily follow on the operator's
        // behalf.
        .route("/logout", post(crate::admin::pages::logout_submit))
        // Auth (no auth required)
        .route("/api/auth/login", post(login))
        .route("/api/auth/setup", post(setup))
        .route("/api/auth/reauth", post(reauth))
        .route("/api/auth/revoke-others", post(revoke_others))
        .route("/api/auth/logout", post(logout))
        // Health + server info (no auth required for health)
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
        .route("/api/filter/rebuild-status", get(get_rebuild_status))
        .route("/api/registry/filters", get(get_registry_filters))
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
        .layer(axum::middleware::from_fn(
            crate::admin::csrf::csrf_origin_guard,
        ))
        .layer(axum::middleware::from_fn(crate::headers::no_store))
        .layer(axum::middleware::from_fn(crate::headers::security_headers))
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

/// Serve an embedded asset, or 404.
///
/// There is no SPA fallback any more. It existed so that a client-side route
/// like `/settings` — a path the server knew nothing about — still received the
/// shell for the router to act on. Every page path is a real route now, so a
/// request that reaches here and matches no file is simply not a thing noadd
/// serves, and answering it with HTML would hand the browser a document at an
/// address that has no page.
async fn serve_static(uri: Uri, headers: HeaderMap) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    match ADMIN_UI.get_file(path) {
        Some(file) => static_response(file, &headers),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

// --- Client IP extraction ---

/// Resolve the client IP for rate-limiting and audit purposes via the shared
/// `extract_client_ip` helper. Headers (`X-Forwarded-For`, `X-Real-IP`) are
/// trusted only when the TCP peer is loopback or matches a configured CIDR
/// in [`TrustedProxies`]; otherwise headers are client-controlled and would
/// let a remote caller spoof source IPs to evade per-IP rate limits.
pub(crate) fn client_ip(
    state: &AppState,
    connect: Option<&ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
) -> std::net::IpAddr {
    extract_client_ip(connect, headers, &state.trusted_proxies)
}

/// Bound on the client-controlled `User-Agent` / API-key-prefix text written
/// to an audit log line, so a hostile client cannot inflate log volume.
pub(crate) const LOG_SAFE_MAX: usize = 256;

/// Truncate a client-controlled string to a bounded, UTF-8-safe prefix before
/// it reaches a log line, cutting on a `char` boundary so multi-byte UTF-8 is
/// never split mid-sequence.
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

/// The value of `name` to log, distinguishing an absent header (`<none>`)
/// from one present but not representable as ASCII (`<non-ascii>`).
/// Collapsing both into a single `Option<&str>` — as
/// `headers.get(...).and_then(|v| v.to_str().ok())` does — loses that
/// distinction, so a request that simply sent no such header at all would
/// otherwise be logged with the false claim that it sent a garbled one.
///
/// The returned value is still caller-controlled text: pass it through
/// [`log_safe`] and render it with `%` at the call site.
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

// --- Auth helper ---

/// The **token hashes** of the session cookies on this request, innermost
/// name first. Both names are accepted so a deployment that gains or loses
/// `Secure` mid-session keeps working; the caller must try them **in order and
/// keep the first that validates**, not merely the first that is present. A
/// browser can hold both at once — a `__Host-` cookie set while noadd
/// terminated TLS survives a move to a TLS-terminating proxy, where the origin
/// is still https:// so the browser keeps sending it — and a stale one would
/// otherwise shadow the live cookie on every request with no way to clear it.
///
/// Hashing here rather than at each call site is what confines the raw token
/// to the cookie boundary: this function and `login`'s `Set-Cookie` are the
/// only places in noadd that ever hold one, and everything downstream — the
/// [`SessionStore`] key, `sessions.token_hash`, `session_log_id` — speaks only
/// in hashes. A future call site that reaches for `jar.get(SESSION_COOKIE)`
/// directly would quietly reintroduce a plaintext token; go through here.
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

/// Expire one cookie per accepted session-cookie name **present in the
/// jar**, not just the positionally-first. A browser can hold both accepted
/// names at once (see [`session_cookie_hashes`]) — the very case this
/// whole mechanism exists for — and clearing only one leaves the other
/// sitting in the browser with no later request able to clear it, since the
/// removal is driven by what *this* request's cookie header contains.
///
/// A `__Host-`-prefixed `Set-Cookie` is silently ignored by the browser
/// unless it also carries `Secure` (RFC 6265bis §5.5: a `__Host-` cookie can
/// only be overwritten — or cleared — by a cookie that itself satisfies the
/// prefix's conditions), so the `__Host-session` removal carries `Secure`
/// even when the plain `session` removal alongside it does not.
fn clear_session_cookies(jar: CookieJar) -> CookieJar {
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

/// The token hash of the session this request is actually authenticated by,
/// for handlers that act on "my current session" rather than merely reading a
/// cookie.
///
/// Naively taking the positionally-first present cookie answers "which
/// cookie is present", which is a different question: a browser can carry
/// both accepted names at once (see [`session_cookie_hashes`]), and
/// acting on the wrong one means logout revoking nothing while reporting
/// success, or revoke-others treating the caller's own session as somebody
/// else's. Membership in the store is checked rather than `validate_session`
/// because the authenticating token
/// was already validated for this request by `AuthedUser`, and a second
/// validation would refresh `last_seen` and evict entries as a side effect.
fn live_session_token_hash(state: &AppState, jar: &CookieJar) -> Option<String> {
    let sessions = state.sessions.lock();
    session_cookie_hashes(jar).find(|hash| sessions.contains_key(hash))
}

/// Returns `(user_id, token_hash)` for the current authenticated session, or
/// 401.
///
/// Walks [`session_cookie_hashes`] in order and keeps the first that
/// actually validates, rather than the positionally-first cookie
/// present — see that function's doc comment for why a stale `__Host-`
/// cookie must not be allowed to shadow a live `session` cookie.
///
/// `connect`/`headers` are only used to attribute a failed lookup to a source
/// IP; see [`note_invalid_session_cookie`].
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

/// Count one presentation of a session cookie that names no live session, and
/// warn once when a single source crosses
/// [`INVALID_SESSION_MAX_ATTEMPTS`] within the window.
///
/// This is the detection half of OWASP's "session ID guessing and brute force
/// detection": until now only `POST /api/auth/login` was counted, so guessing
/// session cookies directly was neither limited nor visible anywhere.
///
/// Deliberately **detect-only** — no 429, no blocking. The same code path is
/// walked by an entirely legitimate browser whose session expired while its
/// tab stayed open: the page's components keep polling with the stale cookie, so
/// blocking on this counter would lock operators out of their own appliance
/// on the strength of a benign event. The threshold exists for the same
/// reason (see [`INVALID_SESSION_MAX_ATTEMPTS`]).
///
/// Reported as `auth.failed` with a `method` field rather than a new event
/// name, matching how the password and API-key failures are already recorded,
/// so "every authentication failure" stays a single query.
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

/// An authenticated operator, resolved from either the browser `session` cookie,
/// an `Authorization: Bearer <api key>` header, or a reverse-proxy forward-auth
/// header. Most handlers depend only on `user_id`; `via_forward_auth` lets the
/// account page tell the operator their session is proxy-managed (SSO).
pub struct AuthedUser {
    pub user_id: i64,
    /// True only when the request was authenticated by the forward-auth header
    /// (SSO), i.e. neither a session cookie nor an API key.
    pub via_forward_auth: bool,
    /// The session's token hash when a browser cookie authenticated this
    /// request, `None` for an API key or forward auth.
    ///
    /// It is what [`ReauthedUser`] needs to find the re-authentication stamp,
    /// and carrying it here means that check does not have to re-walk the
    /// cookie jar and risk disagreeing with the extractor about *which*
    /// session authenticated — the two cookie names make that a real
    /// possibility, not a theoretical one (see [`session_cookie_hashes`]).
    pub session_token_hash: Option<String>,
}

impl axum::extract::FromRequestParts<AppState> for AuthedUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. Session cookie (browser path). Walk both candidate names,
        // in-order, and keep the first that validates — see
        // `session_cookie_hashes` for why a stale `__Host-` cookie must
        // not be allowed to shadow a live `session` cookie.
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
        // Counted here rather than deferred to the terminal rejection below
        // (the way `failed_key_prefix` is): the signal is "an unknown session
        // ID was presented", which is a fact about this request regardless of
        // whether a bearer token or forward-auth header later authenticates
        // it, and deferring would couple two unrelated detections.
        if presented_a_cookie {
            note_invalid_session_cookie(
                state,
                parts.extensions.get::<ConnectInfo<SocketAddr>>(),
                &parts.headers,
            );
        }
        // 2. Bearer API key (programmatic path).
        //
        // Emission of the `auth.failed` warning is deferred to the terminal
        // rejection below rather than fired inline here: the rule is to warn
        // whenever the request as a whole does not end up authenticated, not
        // whenever this one step fails. A bearer token that fails against the
        // API-key table may still go on to authenticate via step 3's
        // forward-auth header, and logging inline would emit a spurious
        // `auth.failed` on every such request even though authentication
        // ultimately succeeds. `failed_key_prefix` is only populated for a
        // token that actually looks like a noadd key (`noadd_` prefix), so it
        // is never `Some` on the request's eventual success path.
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
            // Not logged via `hash_api_key`'s output (that would still allow
            // reconstructing which key was tried offline against a known
            // set); the prefix is the same non-secret identifier already
            // shown to the operator when the key was created.
            if token.starts_with("noadd_") {
                failed_key_prefix = Some(log_safe(&token, 10).to_string());
            }
        }
        // 3. Reverse-proxy forward auth: a username header injected by a proxy
        //    whose TCP peer matches --forward-auth-trusted-proxies. Last in the
        //    chain so an explicit cookie/API key always wins.
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
                        // This exit bypasses the shared tail below, so the
                        // pending `auth.failed` warning must be emitted here
                        // too — otherwise a bad `noadd_…` key alongside a
                        // forward-auth header whose operator lookup hits a DB
                        // error drops the failed key attempt from the audit
                        // trail entirely.
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

/// Count a password failure against `user_id`, and record the crossing into
/// (or extension of) a lockout in the audit log.
///
/// The event carries no username: an operator reading the log has `user_id`,
/// and anyone who has obtained the log has no business being handed the
/// account names alongside evidence of which ones are under attack.
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

/// Error body for the two ways a sensitive action can be refused for want of
/// a recent password proof. `code` is what the admin UI keys off: a bare 403
/// is indistinguishable from the CSRF guard's, and the two cases need
/// different handling — one is fixed by typing a password, the other cannot
/// be fixed by this caller at all.
#[derive(Serialize)]
struct ReauthErrorResponse {
    error: String,
    code: &'static str,
}

/// An operator who has proved the account's password recently enough to
/// perform a sensitive action — minting an API key, or adding or removing an
/// operator. Anything that hands out durable access, in other words, which is
/// exactly what an attacker holding a stolen cookie wants before the theft is
/// noticed.
///
/// The three authentication methods are treated differently because they can
/// prove different things:
///
/// - **Session cookie** — the case this exists for. Requires a password proof
///   within [`REAUTH_WINDOW_SECS`]; login counts as one.
/// - **Forward auth (SSO)** — exempt. The proxy authenticated *this very
///   request*, which is a stronger claim than a stamp from minutes ago, and
///   these accounts store [`NO_PASSWORD_SENTINEL`] so there is no password
///   they could ever prove. Requiring one would lock SSO deployments out of
///   their own operator management.
/// - **API key** — refused outright. A key cannot present a password, and
///   letting one mint another would mean a short-lived key could quietly issue
///   itself a permanent successor. This matches the existing carve-out where
///   session management and password change are already cookie-only.
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

/// Emit the deferred `auth.failed` warning for a bearer token that looked
/// like a noadd API key (`failed_key_prefix`, see the comment at its
/// declaration in `from_request_parts`) but did not validate — a no-op when
/// `prefix` is `None`. Factored out so every non-success exit of
/// `from_request_parts` emits through the same call rather than each exit
/// needing its own copy of the lookup-and-log logic.
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

/// Map a forward-auth username to an operator id, provisioning the account on
/// first sight. A concurrent first request can win the INSERT race, so a
/// UNIQUE violation is resolved by re-reading rather than failing the
/// request.
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

/// Why a password sign-in was refused.
///
/// The API and the HTML form answer the same three outcomes in their own idiom
/// — a status code for `POST /api/auth/login`, a re-rendered form for `POST
/// /login` — so the decision is made once, here, and each caller phrases it.
pub(crate) enum LoginError {
    RateLimited,
    /// Unknown username, wrong password, a forward-auth account, or a locked
    /// one. Deliberately a single variant: a caller must not be able to tell
    /// these apart, which is why the API answers all four with the same 401.
    Invalid,
    Internal,
}

/// Verify a username and password and, on success, mint a session — returning
/// the jar carrying its `Set-Cookie`.
///
/// This is the whole of noadd's password sign-in: the rate limit, the constant
/// Argon2 cost that keeps an unknown username indistinguishable from a wrong
/// password, the per-account lockout, and the audit events. Both the JSON
/// endpoint and the HTML form go through here rather than each implementing it.
/// A second copy is how one of the two paths ends up missing the timing padding
/// or the lockout check, and that gap stays invisible until someone attacks it.
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

    // Every 401 out of this handler is an authentication failure worth
    // auditing, not just the wrong-password one: an unknown username is the
    // ordinary shape of a brute-force attempt, and a password login against a
    // forward-auth account is the same signal. The event deliberately carries
    // no username — the response does not distinguish these cases either.
    let log_failed = || {
        tracing::warn!(
            event = "auth.failed",
            method = "password",
            %ip,
            user_agent = %log_safe(user_agent_log_value(headers), LOG_SAFE_MAX),
            "login failed"
        );
    };

    // Bound the input handed to Argon2 before any hashing happens. The cap is
    // far looser than `MAX_PASSWORD_LENGTH` on purpose — see that constant —
    // and rejecting here leaks nothing, since the verdict does not depend on
    // which username was presented.
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
        // Same Argon2 cost a real account would have incurred, so the two
        // paths cannot be told apart by response time. See `spend_verify_cost`.
        spend_verify_cost(password);
        log_failed();
        return Err(LoginError::Invalid);
    };

    // Forward-auth-provisioned accounts store a sentinel in place of a hash and
    // can never authenticate with a password — same generic 401 as any other
    // failed login. This must precede `verify_password`, which would otherwise
    // fail to parse the sentinel and surface it as a 500, leaking which accounts
    // are forward-auth-provisioned. The sentinel is not a hash, so there is
    // nothing to verify against and this path needs the same padding an
    // unknown username gets — otherwise it returns early and becomes its own
    // oracle for which accounts are proxy-provisioned.
    if has_no_password(&auth.password_hash) {
        spend_verify_cost(password);
        log_failed();
        return Err(LoginError::Invalid);
    }

    // Checked only once a username has resolved, which is what stops the
    // lockout becoming the enumeration oracle the generic 401 exists to
    // prevent: an unknown username is never counted, so it can never be
    // locked, so the two cases cannot be told apart by whether a lock
    // appears. The Argon2 cost is spent here too, for the same reason it is
    // spent above — a locked account that answered faster than a wrong
    // password would leak just as loudly.
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
    // The one place a raw session token exists. It goes into the `Set-Cookie`
    // below and nowhere else: what is persisted, stored in memory and logged
    // is the hash, so a copy of the database yields no usable credential.
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
            // Typing the password *is* the proof, so a login satisfies
            // `ReauthedUser` on its own. Without this an operator would be
            // asked for the password twice in a row to do anything sensitive
            // straight after signing in.
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

/// `POST /api/auth/login` — the JSON face of [`start_password_session`].
///
/// Every outcome it can report is decided there; this only chooses the status
/// code. The 401 covers an unknown username, a wrong password, a forward-auth
/// account and a locked one alike, so none of them can be told apart.
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

/// The `Set-Cookie` carrying a freshly minted session token.
///
/// Shared by `login` and `change_own_password` rather than written out twice:
/// the two must agree on every attribute, and a rotation that quietly dropped
/// `HttpOnly` or `Secure` would downgrade the session it was issued to protect
/// — the failure would be invisible until someone read the header by hand.
fn build_session_cookie(token: String, cookie_secure: bool) -> Cookie<'static> {
    Cookie::build((
        crate::admin::auth::session_cookie_name(cookie_secure),
        token,
    ))
    .path("/")
    .http_only(true)
    .secure(cookie_secure)
    // Lax rather than Strict: Lax already withholds the cookie from every
    // cross-site POST / PUT / DELETE, which covers every mutation this API
    // exposes, and no GET handler writes. The only thing Strict would
    // additionally block — a cross-site top-level GET navigation carrying
    // the cookie — is not an attack vector here, so Strict buys no extra
    // protection, only logged-out deep links.
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
    /// Where the SPA should send the browser to end the upstream (proxy/SSO)
    /// session; `None` when no forward-auth logout URL is configured.
    pub redirect_to: Option<String>,
    /// Whether this request authenticated via the forward-auth proxy header.
    pub via_forward_auth: bool,
}

/// Minimum length for a password *set* through the API — `POST
/// /api/auth/setup`, `POST /api/users`, `POST /api/users/me/password`.
///
/// NIST SP 800-63B, via the OWASP Authentication Cheat Sheet, treats anything
/// under 15 characters as weak *when a second factor is not available*, which
/// is noadd's situation today. 12 is a deliberate compromise: a real
/// improvement on the 8 it replaces, and still short enough that an operator
/// bringing an appliance up on a phone keyboard does not route around it.
/// Raise it to 15 once a second factor exists.
///
/// Enforced only when a password is set. `login` deliberately does not check
/// it, so an operator whose password predates this constant keeps signing in
/// and meets the new floor at their next change rather than being locked out.
pub(crate) const MIN_PASSWORD_LENGTH: usize = 12;

/// Maximum length for a password set through the API.
///
/// A maximum exists at all because Argon2 hashes whatever it is handed and the
/// JSON body limit is measured in megabytes. 128 sits far above any real
/// passphrase and far below anything that costs measurable work. Over-long
/// passwords are rejected rather than truncated: silent truncation would make
/// two different passwords open the same account.
const MAX_PASSWORD_LENGTH: usize = 128;

/// Upper bound on a password accepted at *login*, as opposed to
/// [`MAX_PASSWORD_LENGTH`] when one is set.
///
/// Deliberately far looser, because the two bounds answer different questions.
/// The set-time bound is a policy an operator can be asked to satisfy; this one
/// only has to be low enough to bound the work an unauthenticated caller can
/// make Argon2 do, while staying above any password an existing operator may
/// already hold from before `MAX_PASSWORD_LENGTH` existed. Tightening this to
/// `MAX_PASSWORD_LENGTH` would lock those operators out of their own appliance.
const MAX_LOGIN_PASSWORD_LENGTH: usize = 1024;

/// Weakest zxcvbn score a new password may have. `Score::Three` is "safely
/// unguessable: moderate protection from an offline slow-hash scenario"
/// — 10^10 guesses.
///
/// Three rather than four because four asks for a genuinely long passphrase
/// and this is the credential an operator types to bring a box up; a floor
/// nobody can clear is a floor that gets removed. Three is also the level the
/// throttling on `login` and `change_own_password` is sized for: those cap an
/// online attacker at 5 attempts a minute, so 10^10 offline guesses is the
/// scenario that actually matters here.
const MIN_PASSWORD_SCORE: zxcvbn::Score = zxcvbn::Score::Three;

/// Check a to-be-set password, returning the message to show on rejection.
///
/// Shared by all three endpoints that set a password so they cannot drift
/// apart: a floor enforced at setup but not at change would let an operator
/// walk their own password straight back under it.
///
/// Length is checked first and separately from guessability. They fail for
/// different reasons and an operator can act on the length one immediately,
/// whereas zxcvbn's verdict on a 4-character password would just be noise on
/// top of "it is too short".
///
/// `user_inputs` carries the account's own username. zxcvbn scores a password
/// containing it far lower, which is the point: `noadd-admin-2026` looks
/// respectable to a length check and to a breach blocklist, and is the first
/// thing anyone guessing at this particular box would try.
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
    // zxcvbn's own diagnosis where it has one ("This is a top-100 password.",
    // "Straight rows of keys are easy to guess."), because "too weak" alone
    // tells an operator nothing about what to change. It is a fixed phrase
    // from the crate's own enum, not anything derived from the password, so
    // echoing it back reveals nothing a caller did not just type.
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

/// A machine-readable reason on a 4xx, for the handful of endpoints where the
/// status code alone leaves the caller unable to act.
///
/// Password rejection is the case that forces this: "400" tells an operator
/// nothing, and the whole value of a guessability check is the sentence
/// explaining what to change. Reserved for validation failures the caller
/// supplied the input for — authentication failures stay bare, so no error
/// body can become a user-enumeration oracle.
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

/// An opaque `500`. Deliberately says nothing: the caller cannot act on the
/// difference between a failed hash and a failed write, and naming it would
/// only describe this server's internals to whoever provoked it.
fn internal_error() -> (StatusCode, Json<ApiErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiErrorResponse {
            error: "internal error".to_string(),
        }),
    )
}

/// Why first-run setup was refused.
///
/// [`SetupError::Invalid`] carries the message because it is the only variant
/// the operator can act on — "password must be at least 12 characters" has to
/// reach them verbatim, whether they are looking at JSON or at the form.
pub(crate) enum SetupError {
    /// Forward auth is configured, so the wizard does not apply.
    Disabled,
    AlreadyConfigured,
    Invalid(String),
    Internal,
}

/// Create the first operator account.
///
/// Shared by `POST /api/auth/setup` and the HTML `POST /setup` for the same
/// reason [`start_password_session`] is shared: the forward-auth guard and the
/// already-configured check are what stop a second account being claimed, and a
/// copy of them is a copy that can drift out of step.
pub(crate) async fn create_first_operator(
    state: &AppState,
    username: &str,
    password: &str,
) -> Result<(), SetupError> {
    // Forward auth makes the setup wizard inapplicable: identity comes from
    // the proxy, and the first proxied request provisions the operator — which
    // is why `health` reports `needs_setup: false`. Leaving this
    // unauthenticated path live would let anyone who can reach the listener
    // directly, bypassing the proxy, claim the first operator account during
    // the window before that first proxied request arrives.
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

/// Prove the account's password again, refreshing this session's
/// [`REAUTH_WINDOW_SECS`] window so it may perform a sensitive action.
///
/// Cookie-only, because the thing it updates is a session. A forward-auth or
/// API-key caller reaching this endpoint has no session to stamp and gets the
/// same 401 as any other request without one — `ReauthedUser` already answers
/// for those two, and answering twice, differently, is how the two guards
/// would end up disagreeing.
///
/// Verifying a password makes this a guessing surface, so it is throttled on
/// the same budget as `login` and `change_own_password` — one IP, one
/// credential, one budget.
///
/// Returns 204 rather than a body: the caller's next request carries the
/// result, and there is nothing useful to say that the status does not.
async fn reauth(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<ReauthRequest>,
) -> Result<StatusCode, StatusCode> {
    let (user_id, token_hash) = current_session(&state, connect.as_deref(), &headers, &jar)?;
    let ip = client_ip(&state, connect.as_deref(), &headers);

    if !state.rate_limiter.check(ip) {
        tracing::warn!(
            event = "auth.failed",
            method = "password",
            reason = "rate_limited",
            user_id,
            %ip,
            "reauthentication rate limited"
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    state.rate_limiter.record(ip);

    // Same cap as `login`, and for the same reason: bound the work an
    // over-long input can make Argon2 do before it reaches the hasher.
    if body.password.len() > MAX_LOGIN_PASSWORD_LENGTH {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let hash = state
        .db
        .get_user_password_hash(user_id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    // A forward-auth-provisioned operator holds the sentinel rather than a
    // hash. They cannot reach a sensitive endpoint through this path anyway —
    // `ReauthedUser` exempts them on the strength of the proxy header — so the
    // answer here is a plain 401, not the 500 that verifying the sentinel
    // would produce.
    if has_no_password(&hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if state.lockout.is_locked(user_id) {
        spend_verify_cost(&body.password);
        return Err(StatusCode::UNAUTHORIZED);
    }
    let ok =
        verify_password(&body.password, &hash).map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !ok {
        note_account_failure(&state, user_id, ip, "reauth");
        tracing::warn!(
            event = "auth.failed",
            method = "password",
            reason = "reauth",
            user_id,
            %ip,
            "reauthentication rejected"
        );
        return Err(StatusCode::UNAUTHORIZED);
    }
    state.lockout.record_success(user_id);
    if !crate::admin::auth::mark_reauthenticated(&state.sessions, &token_hash) {
        // The session was validated moments ago, so losing it here means it
        // expired or was revoked in between. Nothing was stamped, and the
        // caller's next sensitive request will be rejected for want of a
        // session rather than for want of a stamp.
        return Err(StatusCode::UNAUTHORIZED);
    }
    tracing::info!(
        event = "auth.reauthenticated",
        user_id,
        sid_hash = %session_log_id(&token_hash),
        %ip,
        "password confirmed for a sensitive action"
    );
    Ok(StatusCode::NO_CONTENT)
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
    let revoked_rows = crate::admin::auth::revoke_other_sessions(
        &state.sessions,
        &state.db,
        current_hash.as_deref(),
    )
    .await
    .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    // `revoke_other_sessions` deletes globally (every operator's sessions
    // except `current_hash`), so `scope` and the `_rows` suffix are load
    // bearing: without them this reads as "this operator's other sessions",
    // and the count is DB rows, which can exceed the number of live sessions
    // actually taken down (a session `validate_session` already evicted from
    // memory keeps its row until the periodic sweep).
    tracing::info!(
        event = "session.destroyed",
        reason = "revoked_others",
        scope = "all_operators",
        user_id = auth.user_id,
        %ip,
        revoked_rows,
        "revoked other sessions across all operators"
    );
    Ok(StatusCode::OK)
}

/// Log out the current session: revoke every session named by a cookie on
/// this request, delete each from the DB, and expire the client's session
/// cookies. Other devices' sessions are untouched. Also reports whether the
/// caller authenticated via forward auth and, if so, hands back the
/// configured proxy/SSO logout URL so the SPA can complete the handoff — a
/// forward-auth caller holds no session for us to revoke, so that redirect
/// is the only way for them to actually end their session.
/// Ask the browser to drop this origin's cookies, cached responses and storage.
///
/// `Set-Cookie` already expires our own cookie; this is the belt-and-braces
/// version that also evicts cached API responses and any storage a future UI
/// revision might add.
///
/// Deliberately *not* including `executionContexts`: that directive
/// reloads/closes the browsing context. The JSON caller has to survive long
/// enough to read `redirect_to` out of the very response carrying this header,
/// and the form caller is mid-redirect — neither wants its context torn down
/// underneath it.
pub(crate) const CLEAR_SITE_DATA: (axum::http::HeaderName, &str) = (
    axum::http::HeaderName::from_static("clear-site-data"),
    r#""cache", "cookies", "storage""#,
);

/// Revoke every session this request's cookies name, clear the cookies, and
/// report where a forward-auth operator has to go to finish signing out.
///
/// Shared by `POST /api/auth/logout` and the HTML `POST /logout` for the same
/// reason [`start_password_session`] is shared — the revoke-both-cookies rule
/// below is subtle enough that a second copy would get it wrong.
pub(crate) async fn end_session(
    state: &AppState,
    auth: &AuthedUser,
    connect: Option<&ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    jar: CookieJar,
) -> (CookieJar, Option<String>) {
    let ip = client_ip(state, connect, headers);
    // Revoke *every* token named by a cookie on this request, not just the
    // one that authenticated it. A browser can hold both accepted cookie
    // names at once, each naming a live session (log in over plain HTTP,
    // then again once the operator turns on TLS / `--cookie-secure`), and
    // `clear_session_cookies` below clears both regardless — so revoking
    // only one would expire a cookie whose session stays live server-side,
    // orphaned and replayable, for up to the idle/absolute window.
    let candidates: Vec<String> = session_cookie_hashes(&jar).collect();
    for token_hash in &candidates {
        let revoked = crate::admin::auth::revoke_session(&state.sessions, token_hash);
        let _ = state.db.delete_session_by_token_hash(token_hash).await;
        // Only log a destruction event when a session actually existed under
        // this token. The cookie value is unvalidated client input and
        // `AuthedUser` may have resolved via API key or forward-auth, so a
        // stale or fabricated cookie must not be able to inject an arbitrary
        // `session.destroyed` event — nor be attributed to `auth.user_id`,
        // which may not even be the owner of whatever token was sent.
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

// --- Operator management ---

#[derive(Serialize)]
struct MeResponse {
    id: i64,
    username: String,
    /// True when this request was authenticated by the reverse-proxy
    /// forward-auth header (SSO), so the UI can note the session is
    /// proxy-managed and not listed/revocable here.
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

/// Provision another operator.
///
/// Every operator has full admin access, so this is the most privileged thing
/// the API does: it hands out a second key to the whole appliance. That is why
/// it is audited — see the `user.created` event below.
async fn create_user_handler(
    State(state): State<AppState>,
    ReauthedUser(auth): ReauthedUser,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<CreateUserRequest>,
) -> Result<StatusCode, (StatusCode, Json<ApiErrorResponse>)> {
    let ip = client_ip(&state, connect.as_deref(), &headers);
    let username = body.username.trim();
    if username.is_empty() || username.chars().count() > 64 {
        return Err(bad_request("invalid username".to_string()));
    }
    if let Err(error) = validate_new_password(&body.password, &[username]) {
        return Err(bad_request(error));
    }
    let hash = hash_password(&body.password).map_err(|_err| internal_error())?;
    match state
        .db
        .create_user(username, &hash, crate::now_unix())
        .await
    {
        Ok(id) => {
            // The counterpart to `user.deleted`: between them, every change to
            // who can administer this box is one query. `user_id` is the
            // operator who did it and `target_user_id` the account created,
            // matching the convention `delete_user_handler` already follows.
            //
            // The username is logged because an audit of "who was provisioned"
            // is unreadable without it, and it is bounded first — it is
            // caller-controlled text on a path that only a signed-in operator
            // can reach, but the 64-character limit above is a validation
            // rule, not a logging guarantee.
            tracing::info!(
                event = "user.created",
                user_id = auth.user_id,
                target_user_id = id,
                target_username = %log_safe(username, LOG_SAFE_MAX),
                %ip,
                "operator created"
            );
            Ok(StatusCode::CREATED)
        }
        // A UNIQUE violation means the username is taken (409); any other
        // database error is a genuine failure (500).
        //
        // Naming the reason is fine here even though the cheat sheet asks
        // registration to stay generic: that guidance is about *public*
        // sign-up, where the response is an enumeration oracle. This endpoint
        // is admin-only and the same caller can simply `GET /api/users`, so a
        // generic message would withhold nothing and only make a taken
        // username harder to diagnose.
        Err(e) if e.is_unique_violation() => Err((
            StatusCode::CONFLICT,
            Json(ApiErrorResponse {
                error: "username already exists".to_string(),
            }),
        )),
        Err(_) => Err(internal_error()),
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
            // `user_id` is the acting operator, matching every other event on
            // this branch; the deleted operator is `target_user_id`. Logging
            // `id` under `user_id` here would name the wrong user and discard
            // the only thing that makes this event auditable — who did it.
            tracing::info!(
                event = "session.destroyed",
                reason = "user_deleted",
                user_id = auth.user_id,
                target_user_id = id,
                %ip,
                revoked = tokens.len(),
                "revoked sessions for deleted user"
            );
            // Separate from the session event above, which records what
            // happened to the sessions rather than to the account. Pairing
            // this with `user.created` makes every change to who can
            // administer this box answerable from one event name.
            tracing::info!(
                event = "user.deleted",
                user_id = auth.user_id,
                target_user_id = id,
                %ip,
                "operator deleted"
            );
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}
/// Why a password change was refused.
///
/// `Rejected` carries the reason because it is the only outcome the operator
/// can act on — "at least 12 characters" or a zxcvbn verdict has to reach them
/// verbatim, whether they are looking at JSON or at the account page's form.
pub(crate) enum PasswordChangeError {
    RateLimited,
    Rejected(String),
    /// The current password did not match. Deliberately distinct from
    /// `Rejected`: one means "try a better new password", the other "you got
    /// your existing one wrong", and telling an operator the wrong one of those
    /// sends them fixing the field that was fine.
    WrongPassword,
    Internal,
}

/// Change the caller's own password, invalidate that operator's *other*
/// sessions, and rotate the caller's own session token (OWASP: renew the
/// session ID after any privilege level change, and invalidate other sessions).
///
/// The two halves defend against different things and neither substitutes for
/// the other. Revoking the other sessions ejects an attacker who is holding a
/// live cookie in a browser. Rotating this session's own token is what covers
/// a token that leaked through a channel needing no ongoing browser access — a
/// proxy log, a shared terminal's history, a screenshot — since such a leak is
/// entirely unaffected by revoking *other* sessions.
///
/// The rotation is ordered deliberately: the replacement session is minted and
/// stored *before* the old one is destroyed, so a failure anywhere in the
/// sequence leaves the caller holding a session that still works rather than
/// signed out with no replacement. The two destructions are also kept separate
/// — `reason = "password_change"` counts the other devices, `reason =
/// "rotated"` names this one — so an auditor summing the counts does not count
/// the caller's own session twice.
///
/// API keys are **not** touched by this endpoint. `revoke_user_sessions_except`
/// only deletes rows from `sessions`; `POST /api/api-keys` is gated by
/// `AuthedUser` alone and `validate_api_key` never consults the password
/// hash. So an attacker who already holds a stolen session cookie can mint a
/// long-lived `noadd_`-prefixed key before the victim reacts, and that key
/// keeps working after this call returns 204. An operator responding to a
/// suspected compromise must revoke their API keys separately — changing
/// the password alone does not lock out an attacker holding a session
/// cookie or a minted key.
///
/// This endpoint is cookie-only today, so `keep` passed to
/// [`revoke_user_sessions_except`] is always `Some` — the caller's own device
/// stays signed in. If this ever grows an `AuthedUser`-based path (API key /
/// forward-auth callers changing their own password), `keep` must become
/// `None` there and still go through `revoke_user_sessions_except`, never
/// `revoke_other_sessions` — the latter is global across all operators and
/// would log out unrelated accounts. Similarly, an admin-resets-another-user
/// password endpoint (none exists yet) must call
/// `revoke_user_sessions_except(store, db, target_user_id, None)` so the
/// reset account keeps no session at all.
///
/// If revocation or rotation fails after the password write has already
/// committed, the failure is logged via `tracing::error!` but the response
/// still succeeds with 204: the password change is done and cannot be un-done,
/// so returning 500 here would only mislead the caller into retrying. Worst
/// case, other sessions survive until they expire naturally and the caller
/// keeps their original token — strictly no worse than not having rotated.
///
/// Change the signed-in operator's password, revoke their other sessions and
/// rotate the one they are using.
///
/// Shared by `POST /api/users/me/password` and the account page's form. This is
/// the only password-verification path outside sign-in, and the one an attacker
/// holding a stolen session cookie uses to take an account over permanently —
/// the rate limit, the account lockout and the `auth.failed` audit line are all
/// load-bearing, and a second copy is a second chance to omit one.
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
    // This endpoint verifies a password, so it is a password-guessing surface
    // and has to be throttled like one — the scenario being closed is the
    // cheat sheet's own: someone walks up to a signed-in terminal and grinds
    // the current-password field until the account is theirs permanently.
    //
    // It shares `rate_limiter` with `login` rather than getting its own
    // instance. The usual objection to sharing a limiter — one signal
    // consuming another's budget from a NAT address, which is why
    // `invalid_session_limiter` is separate — does not apply here: both
    // signals are the *same* credential being guessed from the same IP, so a
    // shared budget is the behaviour you would build on purpose. The cost is
    // that an operator who mistypes their current password five times waits a
    // minute before signing in again from that address.
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

    // The account's own username feeds zxcvbn, so `admin` cannot set
    // `admin-admin-admin`. A failure to read it is not fatal to the change —
    // the length band and the dictionary checks still apply — so an empty
    // slice is the right fallback rather than a 500.
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
    // Unreachable today — this endpoint is cookie-only and a passwordless
    // account can never obtain a session — but guard anyway so the sentinel can
    // never reach `verify_password` and turn a 401 into a 500.
    if has_no_password(&hash) {
        return Err(PasswordChangeError::WrongPassword);
    }
    // Same account budget as `login`. This endpoint verifies the same
    // credential, so leaving it out would hand an attacker who already holds a
    // session an unmetered place to grind it.
    if state.lockout.is_locked(user_id) {
        spend_verify_cost(current_password);
        return Err(PasswordChangeError::WrongPassword);
    }
    let ok =
        verify_password(current_password, &hash).map_err(|_err| PasswordChangeError::Internal)?;
    if !ok {
        note_account_failure(state, user_id, ip, "change_password");
        // This is the only password-verification path outside `login`, and
        // exactly the one an attacker holding a stolen session cookie uses to
        // try to take the account over permanently — a rejected attempt here
        // must not be silent the way it is today.
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

/// `POST /api/users/me/password` — the JSON face of
/// [`change_password_for_session`].
///
/// Resolves the caller's session, then maps the shared outcome onto status
/// codes. The 401 covers both "current password wrong" and a missing account
/// for the same reason sign-in does: neither is something the caller should be
/// able to tell apart.
async fn change_own_password(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<(CookieJar, StatusCode), Response> {
    let (user_id, token_hash) = current_session(&state, connect.as_deref(), &headers, &jar)
        .map_err(IntoResponse::into_response)?;
    let ip = client_ip(&state, connect.as_deref(), &headers);
    let jar = change_password_for_session(
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
    .map_err(|err| match err {
        PasswordChangeError::RateLimited => StatusCode::TOO_MANY_REQUESTS.into_response(),
        PasswordChangeError::Rejected(message) => bad_request(message).into_response(),
        PasswordChangeError::WrongPassword => StatusCode::UNAUTHORIZED.into_response(),
        PasswordChangeError::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    })?;
    Ok((jar, StatusCode::NO_CONTENT))
}

/// Replace the caller's session with a freshly minted one and hand back the
/// jar carrying its `Set-Cookie`. On any failure the original session is left
/// untouched and the unchanged jar is returned — see
/// [`change_password_for_session`]'s doc comment for why that is the right
/// outcome rather than a 500.
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

    // Minted and persisted before anything is destroyed: if this fails, the
    // caller simply keeps the session they arrived with.
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
            // The rotation happens immediately after the current password was
            // verified, so the replacement session inherits that proof rather
            // than starting stale.
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

    // Evict from memory first: that is what actually stops the old token
    // authenticating. The row is deleted after, and a failure there is logged
    // rather than ignored — an orphaned row would be restored as a live
    // session by `load_sessions_from_db` on the next restart.
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
    _auth: AuthedUser,
    jar: CookieJar,
) -> Result<Json<Vec<SessionResponse>>, StatusCode> {
    // Authorization is `AuthedUser` (cookie, API key, or forward-auth header).
    // The session cookie is only used to flag which listed session is the
    // caller's own device; a forward-auth / API-key caller simply has none, so
    // no row is marked current rather than the whole request being rejected.
    let current_hash = live_session_token_hash(&state, &jar);
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
            let last_seen = live.get(&r.token_hash).map_or(r.last_seen, |i| i.last_seen);
            SessionResponse {
                id: r.id,
                username: r.username,
                created_at: r.created_at,
                last_seen,
                ip: r.ip,
                user_agent: r.user_agent,
                is_current: current_hash.as_deref() == Some(r.token_hash.as_str()),
            }
        })
        .collect();
    Ok(Json(out))
}

async fn revoke_session_by_id(
    State(state): State<AppState>,
    auth: AuthedUser,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<(CookieJar, StatusCode), StatusCode> {
    // Authorized via `AuthedUser`; the cookie only tells us whether the revoked
    // session is the caller's own device (so we clear its cookie). A forward-auth
    // / API-key caller has none and just revokes the target session.
    let ip = client_ip(&state, connect.as_deref(), &headers);
    // Captured before `revoke_session` below evicts the target from the
    // store: if the caller's own session is the one being revoked, this must
    // still see it as live to correctly clear its cookie.
    let current_hash = live_session_token_hash(&state, &jar);
    let removed = state
        .db
        .delete_session_by_id(id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    match removed {
        Some(token_hash) => {
            crate::admin::auth::revoke_session(&state.sessions, &token_hash);
            tracing::info!(
                event = "session.destroyed",
                reason = "revoked_by_id",
                user_id = auth.user_id,
                session_id = id,
                sid_hash = %session_log_id(&token_hash),
                %ip,
                "revoked session by id"
            );
            if current_hash.as_deref() == Some(token_hash.as_str()) {
                let jar = clear_session_cookies(jar);
                return Ok((jar, StatusCode::NO_CONTENT));
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
    /// still needs to be called before the admin UI is usable. Always false
    /// when forward auth is configured, since identity comes from the proxy
    /// and the first proxied request provisions an operator on its own.
    pub needs_setup: bool,
    /// Build version string (from `git describe`).
    pub version: &'static str,
}

/// Whether this appliance still has no operator and must show the setup wizard.
///
/// With forward auth on, identity comes from the proxy and the wizard would be
/// a dead end — the first proxied request provisions the operator — so it
/// reports `false` however empty the user table is. Shared with the page
/// handlers, which route an unauthenticated browser to `/setup` or `/login`
/// depending on this same answer.
pub(crate) async fn needs_setup(state: &AppState) -> bool {
    state.forward_auth.is_none() && state.db.count_users().await.is_ok_and(|n| n == 0)
}

/// Report basic service health.
///
/// Always unauthenticated so monitoring and the setup wizard can call it
/// before any operator exists. Reports whether initial setup is still pending.
///
/// Dropped query-log events are deliberately not reported here. A cumulative
/// per-process counter cannot say *when* the loss happened or how it compares
/// to total volume, so it could not tell an operator anything actionable;
/// each drop is logged at error level instead.
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

/// Why a settings save was refused.
///
/// The API answers any rejection with a bare 400. The settings page needs to
/// say *which* field was wrong and why — the operator is looking at a form with
/// eight of them, and "400" points at none. Same decision, two levels of
/// detail.
pub(crate) enum SettingsError {
    Invalid {
        field: &'static str,
        message: String,
    },
    Internal,
}

/// Validate, persist and apply a set of runtime settings.
///
/// Shared by `PUT /api/settings` and the settings page's form post. The order
/// here is the substance: everything is validated before anything is written,
/// so a malformed entry rejects the whole save rather than leaving half of it
/// applied, and the runtime handoffs at the end run only once the values are
/// persisted. A second copy would be a second chance to get that order wrong.
pub(crate) async fn apply_settings(
    state: &AppState,
    settings: &std::collections::HashMap<String, String>,
) -> Result<(), SettingsError> {
    // Validate upstream_servers before persisting anything — reject the whole
    // save on a bad entry so a broken value is never stored.
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

    // Validate block-mode settings before persisting anything.
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

    // Apply strategy change immediately if present
    if let Some(strategy_str) = settings.get("upstream_strategy")
        && let Ok(strategy) = strategy_str.parse::<crate::upstream::strategy::UpstreamStrategy>()
    {
        state.forwarder.set_strategy(strategy);
    }

    if let Some(v) = settings.get("dnssec_disabled") {
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
    match apply_settings(&state, &body.settings).await {
        Ok(()) => Ok(StatusCode::OK),
        // The API has always answered a rejected value with a bare 400, and the
        // field-level detail `SettingsError` carries is for the form. Widening
        // this to a body would change a published contract for no caller that
        // asked.
        Err(SettingsError::Invalid { .. }) => Err(StatusCode::BAD_REQUEST),
        Err(SettingsError::Internal) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
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

    Ok(Json(BatchAddResponse { added, failed }))
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
    ReauthedUser(auth): ReauthedUser,
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
    tracing::info!(
        event = "apikey.created",
        user_id = auth.user_id,
        key_id = id,
        %prefix,
        expires_at = body.expires_at,
        "api key created"
    );
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
        tracing::info!(
            event = "apikey.destroyed",
            user_id = auth.user_id,
            key_id = id,
            "api key deleted"
        );
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

// Each stats/v2 endpoint declares exactly the parameters it honours, and
// `deny_unknown_fields` makes anything else a 400 rather than a silent no-op.
// One shared struct used to cover them all, so `?range=` on the heatmap (a
// fixed 30-day window) and `?tz_offset=` on the range-only endpoints were
// accepted without complaint and quietly discarded — the API answering a
// question it had not been asked and reporting no problem.

/// Query for `/api/stats/v2/timeline`, the one endpoint that honours both.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimelineV2Query {
    pub range: Option<String>,
    /// Viewer's east-positive UTC offset in minutes (e.g. 480 for UTC+8), used
    /// to align buckets to their local calendar. Clamped to ±14h; missing ⇒ 0
    /// (UTC-aligned).
    pub tz_offset: Option<i64>,
}

/// Query for `/api/stats/v2/heatmap`. No `range`: the heatmap is a fixed
/// 30-day window by design (see [`stats::compute_heatmap`]).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeatmapQuery {
    /// See [`TimelineV2Query::tz_offset`].
    pub tz_offset: Option<i64>,
}

/// Query for the stats/v2 endpoints that select a window but do not align it
/// to the viewer's calendar, so they take no `tz_offset`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeQuery {
    pub range: Option<String>,
}

/// Parse a `range` parameter, defaulting to 7 days when absent.
fn parse_stats_range(raw: Option<&str>) -> Result<stats::StatsRange, StatusCode> {
    stats::StatsRange::parse(raw.unwrap_or("7d")).ok_or(StatusCode::BAD_REQUEST)
}

/// Resolve the viewer's UTC offset to seconds, clamped to the real-world range
/// (±14h) so a malformed value can't shift buckets to nonsense.
fn resolve_tz_offset_secs(tz_offset: Option<i64>) -> i64 {
    tz_offset.unwrap_or(0).clamp(-14 * 60, 14 * 60) * 60
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
    /// macOS 26.1 (Tahoe) and later refuse a `com.apple.dnsSettings.managed`
    /// profile that does not declare a scope, failing with "The 'VPN Service'
    /// payload could not be installed" — encrypted DNS and VPNs share the
    /// `NetworkExtension` machinery, and without this key the profile is
    /// evaluated as a user-scoped VPN service, which cannot be created.
    /// A DNS resolver is a system-wide setting anyway, and iOS ignores the key.
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

/// The helpers that make a caller-controlled string safe to put in a log line.
///
/// Every production caller sits in a `tracing` field position, which is only
/// evaluated once a subscriber has declared interest — so nothing else in the
/// suite reaches these, and both sentinels went untested until this module.
#[cfg(test)]
mod log_value_tests {
    use super::*;

    /// A request that simply sent no such header must not be logged with the
    /// false claim that it sent a garbled one — the whole reason
    /// [`header_log_value`] exists rather than
    /// `headers.get(..).and_then(|v| v.to_str().ok())`.
    #[test]
    fn header_log_value_separates_absent_from_unreadable() {
        let mut headers = HeaderMap::new();
        assert_eq!(header_log_value(&headers, "x-probe"), "<none>");
        assert_eq!(user_agent_log_value(&headers), "<none>");

        headers.insert("x-probe", axum::http::HeaderValue::from_static("plain"));
        assert_eq!(header_log_value(&headers, "x-probe"), "plain");

        // Latin-1 bytes are a legal header value but not `to_str`-able, which
        // is the case the second sentinel names.
        headers.insert(
            axum::http::header::USER_AGENT,
            axum::http::HeaderValue::from_bytes(b"caf\xe9").unwrap(),
        );
        assert_eq!(user_agent_log_value(&headers), "<non-ascii>");
    }

    /// `log_safe` cuts on a `char` boundary, so truncating multi-byte UTF-8
    /// cannot split a sequence and emit invalid text into a log line.
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
