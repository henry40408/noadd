use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use super::handler::DnsHandler;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

#[derive(Deserialize)]
struct DnsQueryParams {
    dns: String,
}

/// Create an axum Router with DoH endpoints per RFC 8484.
pub fn doh_router(handler: Arc<DnsHandler>) -> Router {
    Router::new()
        .route(
            "/dns-query",
            get(handle_get).post(handle_post),
        )
        .with_state(handler)
}

/// Extract client IP from headers or fall back to localhost.
fn extract_client_ip(headers: &HeaderMap) -> IpAddr {
    // Try X-Forwarded-For, then X-Real-IP, then fall back to localhost
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(val) = forwarded.to_str() {
            if let Some(first) = val.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(val) = real_ip.to_str() {
            if let Ok(ip) = val.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

async fn handle_get(
    State(handler): State<Arc<DnsHandler>>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParams>,
) -> Response {
    let query_bytes = match URL_SAFE_NO_PAD.decode(&params.dns) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid base64url encoding").into_response();
        }
    };

    let ip = extract_client_ip(&headers);
    handle_dns_query(&handler, &query_bytes, ip).await
}

async fn handle_post(
    State(handler): State<Arc<DnsHandler>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ip = extract_client_ip(&headers);
    handle_dns_query(&handler, &body, ip).await
}

async fn handle_dns_query(
    handler: &DnsHandler,
    query_bytes: &[u8],
    client_ip: IpAddr,
) -> Response {
    match handler.handle(query_bytes, client_ip).await {
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
