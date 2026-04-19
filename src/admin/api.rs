use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::Cookie;
use include_dir::{Dir, include_dir};
use serde::{Deserialize, Serialize};

use crate::admin::auth::{
    RateLimiter, SessionStore, create_session, hash_password, validate_session, verify_password,
};
use crate::admin::stats;
use crate::cache::DnsCache;
use crate::db::Database;
use crate::dns::handler::DnsHandler;
use crate::filter::engine::FilterEngine;
use crate::filter::lists::ListManager;
use crate::filter::rebuild::RebuildCoordinator;
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

static APPLE_TOUCH_ICON: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/apple-touch-icon.png"));

async fn serve_apple_touch_icon() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            ("content-type", "image/png"),
            ("cache-control", "public, max-age=86400"),
        ],
        APPLE_TOUCH_ICON,
    )
}

async fn serve_static(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match ADMIN_UI.get_file(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                StatusCode::OK,
                [("content-type", mime.to_string())],
                file.contents().to_vec(),
            )
                .into_response()
        }
        None => {
            // Only fall back to index.html for extension-less paths (SPA
            // client-side routes like /dashboard, /settings). Requests for
            // missing assets (favicon.ico, robots.txt, *.map, etc.) must
            // 404 so the browser doesn't try to parse HTML as the asset.
            if std::path::Path::new(path).extension().is_some() {
                return (StatusCode::NOT_FOUND, "not found").into_response();
            }
            match ADMIN_UI.get_file("index.html") {
                Some(file) => {
                    Html(String::from_utf8_lossy(file.contents()).to_string()).into_response()
                }
                None => (StatusCode::NOT_FOUND, "not found").into_response(),
            }
        }
    }
}

// --- Client IP extraction ---

/// Resolve the client IP for rate-limiting and audit purposes.
///
/// Policy:
/// 1. Start from the TCP peer (`ConnectInfo`).
/// 2. Only if that peer is loopback (127.0.0.0/8 or ::1) — the usual shape
///    when a reverse proxy is in front — trust `X-Forwarded-For` (first hop)
///    or `X-Real-IP`. Otherwise the headers are client-controlled and must
///    NOT be honoured, or a remote caller could spoof arbitrary source IPs to
///    evade per-IP rate limits.
/// 3. Fall back to loopback when no information is available (e.g. unit tests
///    using `oneshot` that never populate `ConnectInfo`).
fn client_ip(connect: Option<&ConnectInfo<SocketAddr>>, headers: &HeaderMap) -> IpAddr {
    let peer = connect.map(|ci| ci.0.ip());

    let trust_headers = matches!(peer, Some(ip) if ip.is_loopback()) || peer.is_none();

    if trust_headers
        && let Some(hv) = headers.get("x-forwarded-for")
        && let Ok(s) = hv.to_str()
        && let Some(first) = s.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return ip;
    }
    if trust_headers
        && let Some(hv) = headers.get("x-real-ip")
        && let Ok(s) = hv.to_str()
        && let Ok(ip) = s.trim().parse::<IpAddr>()
    {
        return ip;
    }

    peer.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

// --- Auth helper ---

fn require_auth(state: &AppState, jar: &CookieJar) -> Result<(), StatusCode> {
    let token = jar
        .get("session")
        .map(|c| c.value().to_string())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if validate_session(&state.sessions, &token) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// --- Auth endpoints ---

#[derive(Deserialize)]
pub struct LoginRequest {
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
    let ip = client_ip(connect.as_deref(), &headers);
    if !state.rate_limiter.check(ip) {
        tracing::warn!(%ip, "login rate limited");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    state.rate_limiter.record(ip);

    let hash = state
        .db
        .get_setting("admin_password_hash")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let valid =
        verify_password(&body.password, &hash).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !valid {
        tracing::warn!("login failed: invalid password");
        return Err(StatusCode::UNAUTHORIZED);
    }

    tracing::info!("login successful");
    let token = create_session(&state.sessions);

    // Persist sessions to DB so they survive restarts
    let _ = crate::admin::auth::save_sessions_to_db(&state.sessions, &state.db).await;

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
    pub password: String,
}

#[derive(Serialize)]
pub struct SetupResponse {
    pub success: bool,
}

async fn setup(
    State(state): State<AppState>,
    Json(body): Json<SetupRequest>,
) -> Result<Json<SetupResponse>, StatusCode> {
    // Only allow setup if no password exists
    let existing = state
        .db
        .get_setting("admin_password_hash")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if existing.is_some() {
        return Err(StatusCode::CONFLICT);
    }

    let hash = hash_password(&body.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .db
        .set_setting("admin_password_hash", &hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
        .get_setting("admin_password_hash")
        .await
        .ok()
        .flatten()
        .is_none();
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

    let manager = state.list_manager.clone();
    state
        .rebuild
        .clone()
        .spawn_raw(move || async move { manager.rebuild_filter().await });

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

    let manager = state.list_manager.clone();
    state
        .rebuild
        .clone()
        .spawn_raw(move || async move { manager.rebuild_filter().await });

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

    let manager = state.list_manager.clone();
    state
        .rebuild
        .clone()
        .spawn_raw(move || async move { manager.rebuild_filter().await });

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
                    let now = crate::filter::rebuild::now_unix();
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

    let manager = state.list_manager.clone();
    state
        .rebuild
        .clone()
        .spawn_raw(move || async move { manager.rebuild_filter().await });

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
            tracing::error!(error = %e, "registry fetch failed");
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

    // Rebuild filter engine so the new rule takes effect immediately
    let manager = crate::filter::lists::ListManager::new(state.db.clone(), state.filter.clone());
    manager
        .rebuild_filter()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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

    // Rebuild filter engine so the deletion takes effect immediately
    let manager = crate::filter::lists::ListManager::new(state.db.clone(), state.filter.clone());
    manager
        .rebuild_filter()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
            .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
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

    let now = now_epoch();
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

    let now = now_epoch();
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

    let now = now_epoch();
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

    let now = now_epoch();
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

    let now = now_epoch();
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
}

fn parse_stats_range(q: &StatsRangeQuery) -> Result<stats::StatsRange, StatusCode> {
    let raw = q.range.as_deref().unwrap_or("7d");
    stats::StatsRange::parse(raw).ok_or(StatusCode::BAD_REQUEST)
}

async fn get_stats_v2_timeline(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<StatsRangeQuery>,
) -> Result<Json<Vec<crate::db::TimelineMultiPoint>>, StatusCode> {
    require_auth(&state, &jar)?;
    let range = parse_stats_range(&query)?;
    let now = now_epoch();
    let timeline = stats::compute_stats_timeline(&state.db, now, range)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(timeline))
}

async fn get_stats_v2_heatmap(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<crate::db::HeatmapCell>>, StatusCode> {
    require_auth(&state, &jar)?;
    let now = now_epoch();
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
    let now = now_epoch();
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
    let now = now_epoch();
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
    let now = now_epoch();
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
    })?;
    let limit = query.limit.unwrap_or(15);
    let now = now_epoch();
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
    })?;
    let limit = query.limit.unwrap_or(15);
    let now = now_epoch();
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
    let logs = state
        .db
        .query_logs(
            limit,
            offset,
            query.search.as_deref(),
            query.blocked,
            query.token.as_deref(),
            query.query_type.as_deref(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let total = state
        .db
        .count_logs(
            query.search.as_deref(),
            query.blocked,
            query.token.as_deref(),
            query.query_type.as_deref(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
