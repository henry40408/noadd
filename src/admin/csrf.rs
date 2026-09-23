//! First-line CSRF defence: reject state-changing requests a browser reports,
//! or reveals, to be cross-origin. Header-only, stateless, no token.
//!
//! The guard is `tower_http::csrf::CsrfLayer` (Go 1.25's `CrossOriginProtection`
//! scheme), layered over the admin router in
//! [`admin_router`](crate::admin::api::admin_router). On every method but GET,
//! HEAD and OPTIONS:
//!
//! - **`Sec-Fetch-Site`** decides when present: `same-origin` and `none` pass,
//!   anything else is rejected — including `same-site` (a sibling subdomain or
//!   another port), exactly the request `SameSite=Lax` lets through with the
//!   session cookie.
//! - **`Origin`** is the fallback for browsers without `Sec-Fetch-Site` (Safari
//!   < 16.4). Its host *and port* must byte-match the request's authority (else
//!   `Host`); a mismatch or `Origin: null` is rejected. Scheme is ignored, so a
//!   TLS-terminating proxy still matches.
//! - **Neither header** means a non-browser client, which carries no ambient
//!   cookie and is allowed through.
//!
//! This module adds [`log_rejection`], which records each rejection as a
//! `csrf.rejected` warning. The 403 stays bodyless: the gap was that the
//! operator saw no trace, not that the caller got no explanation.

use axum::{
    extract::Request,
    http::{HeaderMap, HeaderName, Uri, header},
    middleware::Next,
    response::Response,
};
use tower_http::csrf::{ProtectionError, ProtectionErrorKind};

use crate::admin::api::{LOG_SAFE_MAX, header_log_value, log_safe};

const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

/// Record each rejection by `CsrfLayer`, which must be layered directly inside
/// this one.
///
/// The layer's rejection builder sees only the [`ProtectionError`], so the
/// method, URI and the three headers the layer reads are kept on the way in and
/// paired with the error on its 403 on the way out. Only those headers are
/// copied, since this runs on every admin request.
///
/// No threshold, unlike `note_invalid_session_cookie`: neither `DoH` (a sibling
/// router) nor a header-less client can reach the rejection, so what remains is
/// a real browser making a cross-origin write — a CSRF attempt or a proxy
/// rewriting `Host`, both worth seeing every time.
pub async fn log_rejection(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let mut headers = HeaderMap::new();
    for name in [SEC_FETCH_SITE, header::ORIGIN, header::HOST] {
        if let Some(value) = req.headers().get(&name) {
            headers.insert(name, value.clone());
        }
    }

    let res = next.run(req).await;
    if let Some(err) = res.extensions().get::<ProtectionError>() {
        record(err.kind(), method.as_str(), &uri, &headers);
    }
    res
}

/// Which check refused the request, as recorded in the `reason` field.
///
/// A browser that *said* the request was cross-origin is an attempted CSRF; an
/// old browser whose `Origin` merely failed to match `Host` is as likely a
/// proxy rewriting `Host`. Those want different fixes.
///
/// - `cross_site`: `Sec-Fetch-Site` said so (spelling kept for existing queries).
/// - `same_site_cross_origin`: `Sec-Fetch-Site: same-site` — the one shape a
///   current browser both labels and sends the session cookie with: an attack,
///   not a proxy.
/// - `opaque_origin`: `Origin: null` — a sandboxed iframe or cross-origin redirect.
/// - `origin_mismatch`: the `Origin` fallback disagreed; a misconfigured proxy
///   lands here.
fn reason(kind: ProtectionErrorKind, headers: &HeaderMap) -> &'static str {
    let is = |name: HeaderName, value: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case(value))
    };
    match kind {
        ProtectionErrorKind::CrossOriginRequest if is(SEC_FETCH_SITE, "same-site") => {
            "same_site_cross_origin"
        }
        ProtectionErrorKind::CrossOriginRequest => "cross_site",
        ProtectionErrorKind::CrossOriginRequestFromOldBrowser if is(header::ORIGIN, "null") => {
            "opaque_origin"
        }
        ProtectionErrorKind::CrossOriginRequestFromOldBrowser => "origin_mismatch",
        // `ProtectionErrorKind` is `#[non_exhaustive]`.
        _ => "other",
    }
}

/// Emit the one `csrf.rejected` event.
///
/// `Origin`, `Host` and `Sec-Fetch-Site` are logged together because telling a
/// cross-site POST from a proxy rewrite needs all three. `host` is the
/// authority the layer compared against (`:authority` if present, else `Host`).
/// Every value is caller-chosen, so each goes through [`log_safe`] to stop an
/// embedded newline forging a log entry.
///
/// Values are bound before the macro, not inline: `tracing` evaluates field
/// expressions only when a subscriber is interested, so inline truncation would
/// look covered while no test proves it ran.
fn record(kind: ProtectionErrorKind, method: &str, uri: &Uri, headers: &HeaderMap) {
    let reason = reason(kind, headers);
    let path = log_safe(uri.path(), LOG_SAFE_MAX);
    let sec_fetch_site = log_safe(header_log_value(headers, SEC_FETCH_SITE), LOG_SAFE_MAX);
    let origin = log_safe(header_log_value(headers, header::ORIGIN), LOG_SAFE_MAX);
    let host = log_safe(
        uri.authority()
            .map_or_else(|| header_log_value(headers, header::HOST), |a| a.as_str()),
        LOG_SAFE_MAX,
    );
    tracing::warn!(
        event = "csrf.rejected",
        reason,
        method,
        path,
        sec_fetch_site,
        origin,
        host,
        "state-changing request rejected as cross-origin"
    );
}
