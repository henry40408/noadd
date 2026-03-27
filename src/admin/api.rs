use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::{Html, IntoResponse};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
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
use crate::filter::engine::FilterEngine;
use crate::upstream::forwarder::UpstreamForwarder;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub sessions: SessionStore,
    pub filter: Arc<ArcSwap<FilterEngine>>,
    pub cache: DnsCache,
    pub rate_limiter: Arc<RateLimiter>,
    pub forwarder: Arc<UpstreamForwarder>,
    pub server_info: ServerInfo,
}

#[derive(Clone, Serialize)]
pub struct ServerInfo {
    pub dns_addr: String,
    pub http_addr: String,
    pub tls_enabled: bool,
}

pub fn admin_router(
    db: Database,
    sessions: SessionStore,
    filter: Arc<ArcSwap<FilterEngine>>,
    cache: DnsCache,
    rate_limiter: Arc<RateLimiter>,
    forwarder: Arc<UpstreamForwarder>,
    server_info: ServerInfo,
) -> Router {
    let state = AppState {
        db,
        sessions,
        filter,
        cache,
        rate_limiter,
        forwarder,
        server_info,
    };

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
        .route("/api/lists/{id}", put(update_list).delete(delete_list))
        .route("/api/lists/update", post(trigger_list_update))
        // Rules
        .route("/api/rules", get(get_rules).post(add_rule))
        .route("/api/rules/{id}", delete(delete_rule))
        // Filter check
        .route("/api/filter/check", post(filter_check))
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
        // Logs
        .route("/api/logs", get(get_logs).delete(delete_logs))
        // Apple mobileconfig (no auth — token in URL is the credential)
        .route("/api/mobileconfig/{token}", get(get_mobileconfig))
        .fallback(serve_static)
        .with_state(state)
}

static ADMIN_UI: Dir = include_dir!("$CARGO_MANIFEST_DIR/admin-ui/dist");

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
            // SPA fallback: serve index.html for client-side routing
            match ADMIN_UI.get_file("index.html") {
                Some(file) => {
                    Html(String::from_utf8_lossy(file.contents()).to_string()).into_response()
                }
                None => (StatusCode::NOT_FOUND, "not found").into_response(),
            }
        }
    }
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
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), StatusCode> {
    // Rate limiting - use a default IP since we don't have access to ConnectInfo here
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    if !state.rate_limiter.check(ip) {
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
        return Err(StatusCode::UNAUTHORIZED);
    }

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
    pub enabled: bool,
}

async fn update_list(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
    Json(body): Json<UpdateListRequest>,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;

    state
        .db
        .update_filter_list_enabled(id, body.enabled)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let manager = crate::filter::lists::ListManager::new(state.db.clone(), state.filter.clone());
    manager
        .rebuild_filter()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
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

    let manager = crate::filter::lists::ListManager::new(state.db.clone(), state.filter.clone());
    manager
        .rebuild_filter()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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

    let manager = crate::filter::lists::ListManager::new(state.db.clone(), state.filter.clone());
    manager
        .update_all_lists()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ListUpdateResponse {
        message: "All lists updated and filter rebuilt".to_string(),
    }))
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
        crate::filter::engine::FilterResult::Allowed => {
            Ok(Json(serde_json::json!({
                "action": "allowed",
            })))
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

// --- Apple mobileconfig ---

async fn get_mobileconfig(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    // Validate token exists
    state
        .db
        .validate_doh_token(&token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Read public URL from server-side settings
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
    let payload_uuid = format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        crc32(&format!("{token}-payload")),
        0x4e6f,
        0x4164,
        0x6444,
        crc32(&token) as u64
    );
    let profile_uuid = format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        crc32(&format!("{token}-profile")),
        0x6e6f,
        0x6164,
        0x6400,
        crc32(&format!("{token}-root")) as u64
    );

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>{server_url}</string>
            </dict>
            <key>PayloadDisplayName</key>
            <string>noadd DNS ({token})</string>
            <key>PayloadIdentifier</key>
            <string>{profile_id}.dns</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>{payload_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>noadd DNS ({token})</string>
    <key>PayloadIdentifier</key>
    <string>{profile_id}</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadDescription</key>
    <string>Configures DNS-over-HTTPS to use noadd ad-blocking DNS server.</string>
</dict>
</plist>"#
    );

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

/// Simple CRC32 for deterministic UUID generation from token strings.
fn crc32(s: &str) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for byte in s.bytes() {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// --- Logs ---

#[derive(Deserialize)]
pub struct LogsQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub search: Option<String>,
    pub blocked: Option<bool>,
}

async fn get_logs(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<LogsQuery>,
) -> Result<Json<Vec<crate::db::QueryLogEntry>>, StatusCode> {
    require_auth(&state, &jar)?;

    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);
    let logs = state
        .db
        .query_logs(limit, offset, query.search.as_deref(), query.blocked)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(logs))
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
