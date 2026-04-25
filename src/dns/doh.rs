use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::Extension;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;

use super::handler::{self, DnsHandler};
use crate::db::Database;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// RFC 8484 §6: POST requests MUST use `application/dns-message` Content-Type.
/// Returns true if header is present and acceptable (or absent).
fn post_content_type_ok(headers: &HeaderMap) -> bool {
    let Some(ct) = headers.get(axum::http::header::CONTENT_TYPE) else {
        return true;
    };
    ct.to_str()
        .ok()
        .map(|s| {
            s.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case(DNS_MESSAGE_CONTENT_TYPE)
        })
        .unwrap_or(false)
}

/// Validate that the body parses as a DNS wire-format message.
fn is_valid_dns_wire(body: &[u8]) -> bool {
    Message::from_bytes(body).is_ok()
}

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

/// Resolve the client IP for logging and rate-limiting.
///
/// Trust policy mirrors the admin API: headers (`X-Forwarded-For`,
/// `X-Real-IP`) are honoured only when the TCP peer is loopback — the usual
/// shape when a reverse proxy is fronting noadd. If the peer is a remote
/// address, headers are client-controlled and must not be trusted, otherwise
/// a caller could spoof any source IP in the query log.
fn extract_client_ip(connect: Option<&ConnectInfo<SocketAddr>>, headers: &HeaderMap) -> IpAddr {
    let peer = connect.map(|ci| ci.0.ip());
    let trust_headers = matches!(peer, Some(ip) if ip.is_loopback()) || peer.is_none();

    if trust_headers
        && let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(val) = forwarded.to_str()
        && let Some(first) = val.split(',').next()
        && let Ok(ip) = first.trim().parse::<IpAddr>()
    {
        return ip;
    }
    if trust_headers
        && let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(val) = real_ip.to_str()
        && let Ok(ip) = val.trim().parse::<IpAddr>()
    {
        return ip;
    }
    peer.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
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
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
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
    if !is_valid_dns_wire(&query_bytes) {
        return (StatusCode::BAD_REQUEST, "malformed DNS message").into_response();
    }
    let ip = extract_client_ip(connect.as_deref(), &headers);
    handle_dns_query(&state.handler, &query_bytes, ip, token_name).await
}

async fn handle_post_with_token(
    State(state): State<DohState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !post_content_type_ok(&headers) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected Content-Type: application/dns-message",
        )
            .into_response();
    }
    let token_name = match validate_token(&state.db, &token).await {
        Ok(name) => Some(name),
        Err(status) => return status.into_response(),
    };
    if !is_valid_dns_wire(&body) {
        return (StatusCode::BAD_REQUEST, "malformed DNS message").into_response();
    }
    let ip = extract_client_ip(connect.as_deref(), &headers);
    handle_dns_query(&state.handler, &body, ip, token_name).await
}

// --- Unauthenticated routes ---

async fn handle_get(
    State(state): State<DohState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
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
    if !is_valid_dns_wire(&query_bytes) {
        return (StatusCode::BAD_REQUEST, "malformed DNS message").into_response();
    }
    let ip = extract_client_ip(connect.as_deref(), &headers);
    handle_dns_query(&state.handler, &query_bytes, ip, None).await
}

async fn handle_post(
    State(state): State<DohState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !post_content_type_ok(&headers) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected Content-Type: application/dns-message",
        )
            .into_response();
    }
    if !is_open_access(&state.db).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !is_valid_dns_wire(&body) {
        return (StatusCode::BAD_REQUEST, "malformed DNS message").into_response();
    }
    let ip = extract_client_ip(connect.as_deref(), &headers);
    handle_dns_query(&state.handler, &body, ip, None).await
}

async fn handle_dns_query(
    handler: &DnsHandler,
    query_bytes: &[u8],
    client_ip: IpAddr,
    doh_token: Option<String>,
) -> Response {
    match handler.handle(query_bytes, client_ip, doh_token).await {
        Ok(outcome) => dns_response(outcome.bytes, outcome.min_ttl as u64),
        Err(e) => {
            tracing::warn!("DNS handler error: {e}");
            // RFC 8484 §4.2.1: return HTTP 200 with DNS SERVFAIL, not HTTP 500.
            // HTTP 500 causes iOS to penalize/disable the resolver entirely.
            let servfail = handler::build_servfail(query_bytes);
            dns_response(servfail, 0)
        }
    }
}

fn dns_response(body: Vec<u8>, max_age: u64) -> Response {
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(DNS_MESSAGE_CONTENT_TYPE),
    );
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_str(&format!("max-age={max_age}"))
            .unwrap_or(HeaderValue::from_static("max-age=0")),
    );
    resp
}
