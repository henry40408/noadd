//! First-line CSRF defence: reject state-changing requests that a browser
//! reports, or reveals, to be cross-origin. Header-only, stateless, no token.
//!
//! The guard itself is `tower_http::csrf::CsrfLayer` — the scheme Go 1.25
//! ships as `CrossOriginProtection` — layered over the whole admin router in
//! [`admin_router`](crate::admin::api::admin_router). On every method other
//! than GET, HEAD and OPTIONS:
//!
//! - **`Sec-Fetch-Site`** (sent by every current browser) decides when present.
//!   `same-origin` and `none` (a direct navigation or a user-typed URL) are
//!   allowed; any other value is rejected. That includes `same-site`, which a
//!   browser sends for a sibling subdomain or another port on the same host —
//!   precisely the request `SameSite=Lax` lets through carrying the session
//!   cookie, and precisely what this guard exists to refuse.
//! - **`Origin`** is the fallback for a browser too old to send
//!   `Sec-Fetch-Site` (Safari before 16.4). Its authority — host *and port* —
//!   must byte-match the request's own (the request-target authority, else
//!   `Host`); a mismatch, or an opaque `Origin: null`, is rejected. Matching the
//!   port is what stops another service on the same host passing as this one.
//!   Scheme is ignored, so a TLS-terminating proxy's scheme-less `Host` still
//!   matches the browser's `https://` `Origin`.
//! - **Neither header** means a non-browser client (an API-key/bearer CLI,
//!   `curl`, the OS stub resolver). Those do not carry the ambient session
//!   cookie, so they are not exposed to CSRF and are allowed through.
//!
//! What this module adds to that layer is [`log_rejection`]: every rejection
//! is recorded as a `csrf.rejected` warning carrying the inputs the layer read,
//! plus a `reason` naming what decided it. The 403 itself stays bodyless on
//! purpose: the gap this guard had was that a refusal left no trace for the
//! *operator*, not that it failed to explain itself to the caller.

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
/// The layer's rejection builder is handed the [`ProtectionError`] and nothing
/// else, so the request cannot be logged from there. Instead the request's
/// method, URI and the three headers the layer reads are kept on the way in and
/// paired with the error the layer attaches to its 403 on the way out. A
/// request the layer allows carries no such error and passes through without a
/// trace. Only those three headers are copied, since this runs on every admin
/// request and the copy is wasted on all but the refused ones.
///
/// A rejection is recorded as `csrf.rejected`, reported with an `event` field
/// rather than a distinct event name to match how `auth.failed` already
/// records the password, API-key and session-cookie failures — "every request
/// this appliance refused" stays a single query.
///
/// The event is a `warn!` with no threshold in front of it, unlike
/// [`note_invalid_session_cookie`](crate::admin::api) — this guard cannot be
/// driven in bulk. Neither the `DoH` router (merged as a sibling in `main`, so
/// this layer never sees it) nor a non-browser client reaches the rejection
/// at all: no `Sec-Fetch-Site` and no `Origin` passes through. What is left is
/// a real browser making a genuinely cross-origin state-changing request — a
/// CSRF attempt, or a reverse proxy rewriting `Host` — both of which an
/// operator wants to see every time.
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
/// `CsrfLayer` only says whether `Sec-Fetch-Site` or the `Origin` fallback
/// decided; the headers it read split each of those once more. The distinction
/// is operational: a browser that *said* the request was cross-origin is an
/// attempted CSRF, while a browser too old to say anything, whose `Origin`
/// merely failed to match `Host`, is as likely a reverse proxy rewriting `Host`
/// as it is an attack — and those two want different fixes.
///
/// - `cross_site`: `Sec-Fetch-Site` said so. The spelling predates the other
///   three, so a query written against it still finds the branch it was
///   written about.
/// - `same_site_cross_origin`: `Sec-Fetch-Site: same-site` — a sibling
///   subdomain, or another port on the same host. Recorded apart because it is
///   the one shape a current browser both labels and delivers the session
///   cookie to: an operator seeing this is looking at an attack, not a proxy.
/// - `opaque_origin`: `Origin: null` — a sandboxed iframe, or a cross-origin
///   redirect.
/// - `origin_mismatch`: the `Origin` fallback disagreed. Only a browser that
///   omits `Sec-Fetch-Site` gets this far, so a misconfigured proxy lands here.
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
/// All three classification inputs are logged together on purpose: telling a
/// real cross-site POST apart from a proxy that rewrote `Host` needs the
/// `Origin` *and* the `Host` *and* whether `Sec-Fetch-Site` decided it, and
/// recording one of the three only moves the guesswork rather than ending it.
/// `host` is the authority the layer compared against — the request-target
/// authority where there is one (HTTP/2's `:authority`), else `Host` — so the
/// value logged is the value that disagreed.
///
/// Every value here is chosen by the caller, so each goes through
/// [`log_safe`] and is rendered with `%` — the same treatment
/// `user_agent_log_value` already gets, and what stops an embedded newline
/// forging a second log entry.
///
/// The values are bound before the macro rather than written inline as field
/// expressions. `tracing` only evaluates a field expression once a subscriber
/// has declared interest, which puts the work on a line no test can be shown
/// to execute — the resulting code reads as covered while nothing proves the
/// truncation ran. Binding first costs four string operations on a request
/// that is already being refused, and this path is rare by construction (see
/// the note on [`log_rejection`] about why it needs no threshold).
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
