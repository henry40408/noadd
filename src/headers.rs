//! Response-header middleware shared by the admin and `DoH` routers.

use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// `Cache-Control` for authenticated admin responses. `no-store` is the
/// operative directive; the rest are belt-and-braces for HTTP/1.0 caches and
/// intermediaries that mishandle `no-store` alone.
const NO_STORE: HeaderValue =
    HeaderValue::from_static("no-cache, no-store, must-revalidate, max-age=0");

/// Stamp `Cache-Control: no-store` (plus `Pragma`/`Expires` for HTTP/1.0) on
/// every admin response that does not already declare a caching policy.
///
/// Keying on "already has `Cache-Control`" rather than on the request path is
/// deliberate: the embedded SPA assets set their own `no-cache` + `ETag`
/// (see `static_response`) and must keep it — `no-store` there would defeat
/// the revalidation/304 design for no benefit, since the shell carries no user
/// data. Almost everything else — every `/api/*` JSON body, the mobileconfig
/// plist, and the 401/403 rejections emitted by extractors and the CSRF guard
/// — currently sets nothing and therefore gets `no-store`. The one exception
/// is `GET /api/logs/stream`: axum's `Sse` response sets its own
/// `Cache-Control: no-cache`, so the `contains_key` guard skips it and it
/// lands on `no-cache` instead. That is acceptable because an SSE body is a
/// stream of events, not a cacheable representation, so there is nothing for
/// `no-store` to protect there that `no-cache` does not already cover.
pub async fn no_store(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, NO_STORE);
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    }
    resp
}

/// `Content-Security-Policy` carrying **only** `frame-ancestors`.
///
/// A full policy is deliberately out of scope: the admin UI is one HTML file
/// of inline `<script>`/`<style>`, so any policy it could satisfy today would
/// need `'unsafe-inline'` — which gives up most of what CSP is for — and the
/// nonce alternative means rewriting the document per request, which is
/// incompatible with serving it from `include_dir!` behind a content-hash
/// `ETag`. `frame-ancestors` needs none of that and is the directive that
/// actually closes a live hole here, so it ships on its own.
const FRAME_ANCESTORS_NONE: HeaderValue = HeaderValue::from_static("frame-ancestors 'none'");

/// `DENY` rather than `SAMEORIGIN`: nothing in the admin UI frames anything
/// (there is not one `<iframe>` in the document), so the stricter value costs
/// nothing and does not depend on that staying true by accident.
const FRAME_DENY: HeaderValue = HeaderValue::from_static("DENY");

/// `X-Content-Type-Options`. Every admin response already declares an
/// accurate `Content-Type`, so this changes nothing today; it is here so that
/// a future response that gets one wrong fails closed instead of letting a
/// browser sniff an attacker-influenced body into something executable.
const NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");

/// Stamp the browser-hardening headers on every admin response.
///
/// Both headers say the same thing on purpose: `frame-ancestors` is the
/// modern directive and wins where both are understood, while
/// `X-Frame-Options` still covers browsers that never implemented it. Neither
/// is conditional on TLS the way HSTS is — an appliance reachable over plain
/// HTTP on a LAN is exactly the one an attacker can frame from a page the
/// victim is already browsing.
///
/// Unlike [`no_store`], these overwrite rather than defer to a value already
/// on the response: no handler sets either header, so an existing value would
/// mean something upstream is trying to make itself framable, which is never
/// what this router wants.
pub async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, FRAME_ANCESTORS_NONE);
    headers.insert(header::X_FRAME_OPTIONS, FRAME_DENY);
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, NOSNIFF);
    resp
}

/// Stamp `Strict-Transport-Security` on every response. Registered only when
/// [`crate::config::resolve_hsts`] says so, so the check is not repeated per
/// request.
pub async fn hsts(
    axum::extract::State(value): axum::extract::State<HeaderValue>,
    req: Request,
    next: Next,
) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .insert(header::STRICT_TRANSPORT_SECURITY, value);
    resp
}

/// Build the header value. `includeSubDomains` and `preload` are omitted on
/// purpose: noadd cannot know whether the operator serves other things on
/// sibling subdomains, and `preload` is effectively irreversible.
pub fn hsts_value(max_age: u64) -> HeaderValue {
    // `format!` over a `u64` can only ever produce ASCII digits, so this
    // truly cannot fail. A silent fallback here would be worse than a panic:
    // `--hsts-max-age 0` is the documented way to retract an HSTS pin (see
    // README), and substituting a one-year default in that case would
    // silently reinstate a policy the operator explicitly asked to remove.
    HeaderValue::from_str(&format!("max-age={max_age}"))
        .expect("max-age=<u64> is always valid ASCII and a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsts_value_formats_max_age() {
        let value = hsts_value(31_536_000);
        assert_eq!(value, HeaderValue::from_static("max-age=31536000"));
        let value = value.to_str().unwrap();
        assert!(!value.contains("includeSubDomains"));
        assert!(!value.contains("preload"));
    }

    #[tokio::test]
    async fn security_headers_refuse_framing_and_sniffing() {
        use axum::Router;
        use axum::body::Body;
        use axum::routing::get;
        use tower::ServiceExt;

        async fn ok() -> &'static str {
            "ok"
        }

        let app = Router::new()
            .route("/", get(ok))
            .layer(axum::middleware::from_fn(security_headers));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
        assert_eq!(
            response
                .headers()
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .unwrap(),
            "nosniff"
        );
        // Asserted exactly, not with `contains`: a policy that grew other
        // directives would need the deliberate design work the constant's doc
        // comment describes, and must not arrive here by accident.
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            "frame-ancestors 'none'"
        );
    }

    /// Positive counterpart to
    /// `hsts_header_is_not_sent_by_the_admin_router_alone` (in
    /// `tests/admin_api_test.rs`), which only proves the header is absent when
    /// the middleware was never attached. Nothing elsewhere drove a request
    /// through the `hsts` middleware itself, so a wrong header name, an
    /// inverted `resolve_hsts` branch, or a dropped `.layer(...)` call in
    /// `main.rs` would all pass the suite unnoticed. The middleware is
    /// router-agnostic, so this needs nothing from `main.rs`: build a minimal
    /// router, attach it directly, and assert the header lands on the
    /// response.
    #[tokio::test]
    async fn hsts_middleware_sets_the_header_on_a_response() {
        use axum::Router;
        use axum::body::Body;
        use axum::routing::get;
        use tower::ServiceExt;

        async fn ok() -> &'static str {
            "ok"
        }

        let app = Router::new()
            .route("/", get(ok))
            .layer(axum::middleware::from_fn_with_state(hsts_value(600), hsts));

        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response
                .headers()
                .get(header::STRICT_TRANSPORT_SECURITY)
                .unwrap(),
            "max-age=600"
        );
    }
}
