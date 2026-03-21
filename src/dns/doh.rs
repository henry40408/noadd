use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use super::handler::DnsHandler;
use crate::db::Database;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

#[derive(Deserialize)]
struct DnsQueryParams {
    dns: String,
}

#[derive(Clone)]
pub struct DohState {
    pub handler: Arc<DnsHandler>,
    pub db: Database,
}

/// Create an axum Router with DoH endpoints per RFC 8484.
///
/// Access policy is controlled by the `doh_access_policy` setting:
/// - `"deny"` (default when tokens exist): unauthenticated requests are rejected (403)
/// - `"allow"`: all requests are allowed, even without a token
///
/// Token-authenticated route: `/dns-query/{token}`
pub fn doh_router(handler: Arc<DnsHandler>, db: Database) -> Router {
    let state = DohState { handler, db };
    Router::new()
        .route(
            "/dns-query/{token}",
            get(handle_get_with_token).post(handle_post_with_token),
        )
        .route("/dns-query", get(handle_get).post(handle_post))
        .with_state(state)
}

/// Extract client IP from headers or fall back to localhost.
fn extract_client_ip(headers: &HeaderMap) -> IpAddr {
    if let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(val) = forwarded.to_str()
        && let Some(first) = val.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return ip;
    }
    if let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(val) = real_ip.to_str()
        && let Ok(ip) = val.trim().parse::<IpAddr>()
    {
        return ip;
    }
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Determine if unauthenticated access is allowed.
/// Returns true unless policy is explicitly set to "deny".
async fn is_open_access(db: &Database) -> bool {
    if let Ok(Some(policy)) = db.get_setting("doh_access_policy").await {
        return policy.trim() != "deny";
    }
    // Default: allow
    true
}

/// Validate token and return the token name if valid.
async fn validate_token(db: &Database, token: &str) -> Result<String, StatusCode> {
    db.validate_doh_token(token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::FORBIDDEN)
}

// --- Token-authenticated routes ---

async fn handle_get_with_token(
    State(state): State<DohState>,
    Path(token): Path<String>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParams>,
) -> Response {
    let token_name = match validate_token(&state.db, &token).await {
        Ok(name) => Some(name),
        Err(status) => return status.into_response(),
    };
    let query_bytes = match URL_SAFE_NO_PAD.decode(&params.dns) {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid base64url encoding").into_response(),
    };
    let ip = extract_client_ip(&headers);
    handle_dns_query(&state.handler, &query_bytes, ip, token_name).await
}

async fn handle_post_with_token(
    State(state): State<DohState>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let token_name = match validate_token(&state.db, &token).await {
        Ok(name) => Some(name),
        Err(status) => return status.into_response(),
    };
    let ip = extract_client_ip(&headers);
    handle_dns_query(&state.handler, &body, ip, token_name).await
}

// --- Unauthenticated routes ---

async fn handle_get(
    State(state): State<DohState>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParams>,
) -> Response {
    if !is_open_access(&state.db).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    let query_bytes = match URL_SAFE_NO_PAD.decode(&params.dns) {
        Ok(bytes) => bytes,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid base64url encoding").into_response(),
    };
    let ip = extract_client_ip(&headers);
    handle_dns_query(&state.handler, &query_bytes, ip, None).await
}

async fn handle_post(State(state): State<DohState>, headers: HeaderMap, body: Bytes) -> Response {
    if !is_open_access(&state.db).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    let ip = extract_client_ip(&headers);
    handle_dns_query(&state.handler, &body, ip, None).await
}

async fn handle_dns_query(
    handler: &DnsHandler,
    query_bytes: &[u8],
    client_ip: IpAddr,
    doh_token: Option<String>,
) -> Response {
    match handler.handle(query_bytes, client_ip, doh_token).await {
        Ok(response) => {
            let mut resp = response.into_response();
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static(DNS_MESSAGE_CONTENT_TYPE),
            );
            resp
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DNS handler error: {e}"),
        )
            .into_response(),
    }
}
