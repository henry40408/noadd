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
/// data. Everything else — every `/api/*` JSON body, the mobileconfig plist,
/// and the 401/403 rejections emitted by extractors and the CSRF guard —
/// currently sets nothing and therefore gets `no-store`.
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
