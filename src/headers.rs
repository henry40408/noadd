//! Response-header middleware shared by the admin and `DoH` routers.

use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// `Cache-Control` for admin responses. `no-store` is what matters; the rest
/// cover caches that mishandle it alone.
const NO_STORE: HeaderValue =
    HeaderValue::from_static("no-cache, no-store, must-revalidate, max-age=0");

/// Stamp `Cache-Control: no-store` (plus `Pragma`/`Expires` for HTTP/1.0) on
/// every admin response that does not already declare a caching policy.
///
/// Keyed on an existing `Cache-Control` rather than the path: the embedded
/// assets set `no-cache` + `ETag` (`static_response`) and must keep their 304
/// revalidation. `GET /api/events` also keeps axum's `no-cache` from `Sse`,
/// which is fine for an event stream.
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
/// A full policy is out of scope: `script-src 'self'` would now hold (no inline
/// scripts or `on*` attributes), but ~150 inline `style="…"` attributes would
/// still need `style-src 'unsafe-inline'`. Tightening `script-src` is left to
/// its own change.
const FRAME_ANCESTORS_NONE: HeaderValue = HeaderValue::from_static("frame-ancestors 'none'");

/// `DENY` rather than `SAMEORIGIN`: the admin UI frames nothing of its own.
const FRAME_DENY: HeaderValue = HeaderValue::from_static("DENY");

/// `X-Content-Type-Options`, so a future response with a wrong `Content-Type`
/// fails closed instead of being sniffed into something executable.
const NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");

/// Stamp the browser-hardening headers on every admin response.
///
/// `frame-ancestors` and `X-Frame-Options` overlap on purpose, for browsers
/// lacking the former. Not TLS-conditional: a plain-HTTP LAN appliance can be
/// framed just the same. Unlike [`no_store`], these overwrite existing values.
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
    // Cannot fail (ASCII digits). No fallback: `--hsts-max-age 0` retracts a
    // pin, and a default there would silently reinstate it.
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
        // Exact, not `contains`: other directives need deliberate design work.
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            "frame-ancestors 'none'"
        );
    }

    /// Positive counterpart to `hsts_header_is_not_sent_by_the_admin_router_alone`
    /// (`tests/admin_api_test.rs`): drives a request through the middleware.
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
