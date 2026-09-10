//! First-line CSRF defence: reject state-changing requests that a browser
//! reports, or reveals, to be cross-site. Header-only, stateless, no token.
//!
//! It runs on every unsafe-method request across the admin router, but only
//! ever *rejects* a request that is provably cross-site; anything it cannot
//! classify is passed through, so it never breaks a legitimate caller:
//!
//! - **`Sec-Fetch-Site`** (sent by every current browser) is authoritative when
//!   present. `same-origin`, `same-site`, and `none` (a direct navigation or a
//!   user-typed URL) are allowed; only `cross-site` is rejected.
//! - **`Origin`** is the fallback for the rare browser that omits
//!   `Sec-Fetch-Site`. Its host is compared against the request's own `Host`;
//!   a mismatch — or an opaque `Origin: null` — is rejected.
//! - **Neither header** means a non-browser client (an API-key/bearer CLI,
//!   `curl`, the OS stub resolver). Those do not carry the ambient session
//!   cookie, so they are not exposed to CSRF and are allowed through.
//!
//! Scheme and port are deliberately ignored in the `Origin`/`Host` comparison:
//! behind a TLS-terminating reverse proxy the browser's `Origin` is `https://`
//! while the forwarded `Host` carries no scheme, and the proxy commonly strips
//! the port. Matching on host alone is what keeps the check working in that
//! standard deployment without a configured public URL.
//!
//! Every rejection is recorded as a `csrf.rejected` warning carrying the three
//! inputs the classification read, plus a `reason` naming the branch that
//! decided it. The 403 itself stays bodyless on purpose:
//! the gap this guard had was that a refusal left no trace for the *operator*,
//! not that it failed to explain itself to the caller.

use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::admin::api::{LOG_SAFE_MAX, header_log_value, log_safe};

/// Reject a state-changing request that is provably cross-site. See the module
/// docs for the classification. Safe methods (GET/HEAD/OPTIONS/TRACE) never
/// change state and pass through untouched.
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
/// at all: no `Sec-Fetch-Site` and no `Origin` classifies as not-cross-site
/// and passes through. What is left is a real browser making a genuinely
/// cross-site state-changing request — a CSRF attempt, or a reverse proxy
/// rewriting `Host` — both of which an operator wants to see every time.
pub async fn csrf_origin_guard(req: Request, next: Next) -> Response {
    if is_safe(req.method()) {
        return next.run(req).await;
    }
    let Some(reason) = classify(&req) else {
        return next.run(req).await;
    };
    log_rejection(&req, reason);
    StatusCode::FORBIDDEN.into_response()
}

/// Which branch of the classification refused the request.
///
/// Recorded as the `reason` field rather than left for the reader to infer
/// from the three logged headers. The distinction is operational: a browser
/// that *said* the request was cross-site is an attempted CSRF, while a
/// browser too old to say anything, whose `Origin` merely failed to match
/// `Host`, is as likely a reverse proxy rewriting `Host` as it is an attack —
/// and those two want different fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejection {
    /// `Sec-Fetch-Site: cross-site`. The browser classified it, not us.
    CrossSite,
    /// `Origin: null` — a sandboxed iframe, or a cross-origin redirect.
    OpaqueOrigin,
    /// The `Origin`/`Host` fallback disagreed. Only a browser that omits
    /// `Sec-Fetch-Site` gets this far, so a misconfigured proxy lands here.
    OriginMismatch,
}

impl Rejection {
    /// The `reason` value. `cross_site` keeps the spelling the single-reason
    /// event already used, so a query written against it still finds the
    /// branch it was actually written about.
    fn as_str(self) -> &'static str {
        match self {
            Self::CrossSite => "cross_site",
            Self::OpaqueOrigin => "opaque_origin",
            Self::OriginMismatch => "origin_mismatch",
        }
    }
}

/// Record the one `csrf.rejected` event.
///
/// All three classification inputs are logged together on purpose: telling a
/// real cross-site POST apart from a proxy that rewrote `Host` needs the
/// `Origin` *and* the `Host` *and* whether `Sec-Fetch-Site` decided it, and
/// recording one of the three only moves the guesswork rather than ending it.
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
/// the note on `csrf_origin_guard` about why it needs no threshold).
fn log_rejection(req: &Request, reason: Rejection) {
    let headers = req.headers();
    let method = req.method().as_str();
    let path = log_safe(req.uri().path(), LOG_SAFE_MAX);
    let sec_fetch_site = log_safe(header_log_value(headers, "sec-fetch-site"), LOG_SAFE_MAX);
    let origin = log_safe(header_log_value(headers, header::ORIGIN), LOG_SAFE_MAX);
    let host = log_safe(header_log_value(headers, header::HOST), LOG_SAFE_MAX);
    tracing::warn!(
        event = "csrf.rejected",
        reason = reason.as_str(),
        method,
        path,
        sec_fetch_site,
        origin,
        host,
        "state-changing request rejected as cross-site"
    );
}

/// Whether `method` cannot change server state and so needs no CSRF check.
fn is_safe(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

/// Why the request is one a browser has told us — via `Sec-Fetch-Site` or a
/// mismatched `Origin` — is cross-site, or `None` when it is not. A request a
/// browser did not mark, and that carries no `Origin`, is treated as
/// not-cross-site (a non-browser client); see the module docs.
fn classify(req: &Request) -> Option<Rejection> {
    let headers = req.headers();

    // `Sec-Fetch-Site` is authoritative where the browser sends it.
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return site
            .eq_ignore_ascii_case("cross-site")
            .then_some(Rejection::CrossSite);
    }

    // Fall back to comparing the Origin's host with the request's own Host.
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())?;
    // `Origin: null` is opaque (a sandboxed iframe, a cross-origin redirect) and
    // never legitimate for a state-changing request here.
    if origin.eq_ignore_ascii_case("null") {
        return Some(Rejection::OpaqueOrigin);
    }
    let Some(origin_host) = host_of(origin) else {
        return Some(Rejection::OriginMismatch);
    };
    let request_host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(strip_port);
    // A missing/garbled Host with a present Origin cannot be confirmed
    // same-origin, so treat it as cross-site.
    (request_host != Some(origin_host)).then_some(Rejection::OriginMismatch)
}

/// The host of an `Origin` value (`scheme://host[:port]`), lower-cased and with
/// any port removed. `None` when there is no `://` authority to read.
fn host_of(origin: &str) -> Option<String> {
    let authority = origin.split_once("://").map(|(_, rest)| rest)?;
    Some(strip_port(authority).to_ascii_lowercase())
}

/// Strip a trailing `:port` from a host authority, leaving the host. Handles
/// bracketed IPv6 literals (`[::1]:8080` → `[::1]`).
fn strip_port(authority: &str) -> String {
    if let Some(end) = authority
        .strip_prefix('[')
        .and_then(|_| authority.find(']'))
    {
        // Bracketed IPv6: keep through the closing bracket, drop any `:port`.
        return authority[..=end].to_ascii_lowercase();
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn req(method: Method, headers: &[(&str, &str)]) -> Request {
        let mut b = Request::builder().method(method).uri("/anything");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::empty()).unwrap()
    }

    #[test]
    fn safe_methods_are_never_cross_site_checked() {
        // Even an obviously cross-site GET passes — GET must not change state.
        let r = req(Method::GET, &[("sec-fetch-site", "cross-site")]);
        assert!(is_safe(r.method()));
    }

    #[test]
    fn sec_fetch_site_is_authoritative() {
        for allowed in ["same-origin", "same-site", "none", "SAME-ORIGIN"] {
            assert_eq!(
                classify(&req(Method::POST, &[("sec-fetch-site", allowed)])),
                None,
                "{allowed} must be allowed"
            );
        }
        assert_eq!(
            classify(&req(Method::POST, &[("sec-fetch-site", "cross-site")])),
            Some(Rejection::CrossSite)
        );
        // It wins over a same-looking Origin/Host, in both directions.
        assert_eq!(
            classify(&req(
                Method::POST,
                &[
                    ("sec-fetch-site", "cross-site"),
                    ("origin", "https://app.example.com"),
                    ("host", "app.example.com"),
                ]
            )),
            Some(Rejection::CrossSite)
        );
    }

    #[test]
    fn origin_fallback_compares_host_ignoring_scheme_and_port() {
        // TLS-terminating proxy: Origin is https://, Host has no scheme/port.
        assert_eq!(
            classify(&req(
                Method::POST,
                &[
                    ("origin", "https://app.example.com"),
                    ("host", "app.example.com"),
                ]
            )),
            None
        );
        // Port on the Origin, none on Host → still same host.
        assert_eq!(
            classify(&req(
                Method::POST,
                &[("origin", "http://localhost:8080"), ("host", "localhost")]
            )),
            None
        );
        // Genuine cross-origin.
        assert_eq!(
            classify(&req(
                Method::POST,
                &[
                    ("origin", "https://evil.example.com"),
                    ("host", "app.example.com"),
                ]
            )),
            Some(Rejection::OriginMismatch)
        );
        // Opaque origin.
        assert_eq!(
            classify(&req(
                Method::POST,
                &[("origin", "null"), ("host", "app.example.com")]
            )),
            Some(Rejection::OpaqueOrigin)
        );
    }

    #[test]
    fn ipv6_literal_host_is_compared_without_its_port() {
        assert_eq!(
            classify(&req(
                Method::POST,
                &[("origin", "http://[::1]:8080"), ("host", "[::1]")]
            )),
            None
        );
    }

    #[test]
    fn non_browser_client_without_headers_passes() {
        // An API-key/bearer CLI / curl sends neither header and authenticates
        // by bearer token, so it is not a CSRF vector.
        assert_eq!(classify(&req(Method::POST, &[])), None);
    }

    #[test]
    fn each_rejection_reason_names_the_branch_that_decided_it() {
        // The three are logged, not just counted: an operator reading
        // `csrf.rejected` has to tell an attempted CSRF apart from a proxy
        // that rewrote `Host` for a browser too old to send `Sec-Fetch-Site`.
        assert_eq!(Rejection::CrossSite.as_str(), "cross_site");
        assert_eq!(Rejection::OpaqueOrigin.as_str(), "opaque_origin");
        assert_eq!(Rejection::OriginMismatch.as_str(), "origin_mismatch");

        // A garbled `Origin` and a missing `Host` are both the fallback
        // branch, so both read as `origin_mismatch` rather than as nothing.
        assert_eq!(
            classify(&req(
                Method::POST,
                &[("origin", "not-an-origin"), ("host", "app.example.com")]
            )),
            Some(Rejection::OriginMismatch)
        );
        assert_eq!(
            classify(&req(Method::POST, &[("origin", "https://app.example.com")])),
            Some(Rejection::OriginMismatch)
        );
    }
}
