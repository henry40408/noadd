//! Server-rendered admin pages.
//!
//! These handlers serve the browser-facing HTML. They are deliberately separate
//! from the `/api/*` handlers in [`crate::admin::api`]: the API answers in JSON
//! with status codes, a page answers in HTML with redirects, and the two
//! contracts do not fit in one handler. The API remains the contract for API
//! keys and the `OpenAPI` spec; the UI no longer consumes it to decide who is
//! signed in or which screen to show.
//!
//! What actually moved to the server is that decision. The client used to ask
//! `/api/health` whether setup was needed, then `/api/settings` whether it was
//! authenticated, and repaint once the answers arrived — three round trips
//! before the first pixel was right, which is where the blank frame and the
//! flash of the sign-in form came from. Now an unauthenticated request is
//! redirected before any HTML is written.
//!
//! Sign-in and setup need no CSRF token. The origin guard
//! ([`crate::admin::csrf`]) is header-based and already covers every unsafe
//! method on this router: a form posted from another origin arrives as
//! `Sec-Fetch-Site: cross-site` and is refused before it reaches a handler.

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Form,
    extract::{ConnectInfo, Extension, FromRequestParts, Query, State},
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use std::convert::Infallible;
use std::net::SocketAddr;

use crate::admin::api::{
    AppState, AuthedUser, LoginError, MIN_PASSWORD_LENGTH, SetupError, create_first_operator,
    needs_setup, start_password_session,
};

// --- Templates ---

/// The sign-in screen.
///
/// `error` and `username` exist so a refused sign-in can re-render this same
/// page with the message and the typed username intact. Redirecting instead
/// would discard both, which is the difference between a form an operator can
/// correct and one they have to start over.
#[derive(Template, WebTemplate)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    version: &'static str,
    error: Option<String>,
    username: String,
    next: Option<String>,
}

/// The first-run wizard. Same re-render contract as [`LoginTemplate`].
#[derive(Template, WebTemplate)]
#[template(path = "setup.html")]
pub struct SetupTemplate {
    error: Option<String>,
    username: String,
    min_password_length: usize,
}

/// The signed-in shell.
///
/// The body is still painted by `app.js` at this stage — see
/// `templates/shell.html`. The version rides a `data-` attribute rather than an
/// inline `<script>`, which is what keeps the document free of inline script.
#[derive(Template, WebTemplate)]
#[template(path = "shell.html")]
pub struct ShellTemplate {
    version: &'static str,
}

// --- Extractors ---

/// An authenticated operator for a *page* request.
///
/// Wraps [`AuthedUser`] and changes only what happens on failure: an API caller
/// wants a 401, a browser wants to be sent to the sign-in page with its
/// destination remembered. Sharing the extractor underneath is what stops the
/// page and the API disagreeing about who is signed in.
pub struct SsrUser(#[allow(dead_code)] pub AuthedUser);

impl FromRequestParts<AppState> for SsrUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        if let Ok(user) = AuthedUser::from_request_parts(parts, state).await {
            return Ok(Self(user));
        }
        // An appliance with no operator yet must land on the wizard rather than
        // a sign-in form no one can satisfy.
        if needs_setup(state).await {
            return Err(Redirect::to("/setup").into_response());
        }
        let next = parts
            .uri
            .path_and_query()
            .map(axum::http::uri::PathAndQuery::as_str);
        Err(Redirect::to(&login_url(next)).into_response())
    }
}

/// The operator, if this request happens to carry a valid credential.
///
/// For the two pages that must answer differently depending on whether anyone
/// is signed in, rather than refuse — `/login` sends an already-authenticated
/// browser onwards instead of showing it a second sign-in form.
pub struct MaybeUser(pub Option<AuthedUser>);

impl FromRequestParts<AppState> for MaybeUser {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Infallible> {
        Ok(Self(
            AuthedUser::from_request_parts(parts, state).await.ok(),
        ))
    }
}

// --- Redirect targets ---

/// Accept only a same-origin destination expressed as an absolute path.
///
/// `next` is attacker-controlled — it arrives in the query string, and the
/// sign-in page is exactly what a phishing link would point at. Without this,
/// `/login?next=https://evil.example` sends the operator off-origin the moment
/// they authenticate, wearing noadd's own URL as the bait. The protocol-relative
/// `//evil.example` is the same attack without a scheme, and `/\evil.example` is
/// what several browsers normalise *into* it, so all three are refused.
///
/// A control character is rejected too: the value is interpolated into a
/// `Location` header, and a bare CR or LF there is header injection.
fn safe_next(raw: &str) -> Option<&str> {
    if !raw.starts_with('/') || raw.starts_with("//") || raw.starts_with("/\\") {
        return None;
    }
    if raw.chars().any(char::is_control) {
        return None;
    }
    Some(raw)
}

/// `/login`, carrying `next` when there is a destination worth returning to.
///
/// `/` is omitted deliberately: it is where sign-in lands anyway, and a
/// `?next=/` on the URL is noise an operator would see and wonder about.
fn login_url(next: Option<&str>) -> String {
    match next.and_then(safe_next) {
        Some(target) if target != "/" => format!("/login?next={}", encode_query_value(target)),
        _ => "/login".to_string(),
    }
}

/// Percent-encode a path so it survives as a single query-string value.
///
/// Deliberately conservative — unreserved characters and `/` pass, everything
/// else is escaped — because the alternative is reasoning about which of `?`,
/// `#` and `&` would end the value early, and being wrong there truncates the
/// destination rather than failing visibly.
fn encode_query_value(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    out
}

// --- Handlers ---

#[derive(Deserialize)]
pub struct NextQuery {
    next: Option<String>,
}

/// Every signed-in page. The body is still painted by `app.js`; what this
/// settles is that the request is authenticated before any HTML is written.
pub async fn shell_page(_user: SsrUser) -> ShellTemplate {
    ShellTemplate {
        version: env!("GIT_VERSION"),
    }
}

pub async fn login_page(
    State(state): State<AppState>,
    MaybeUser(user): MaybeUser,
    Query(query): Query<NextQuery>,
) -> Response {
    let next = query.next.as_deref().and_then(safe_next);
    if user.is_some() {
        return Redirect::to(next.unwrap_or("/")).into_response();
    }
    if needs_setup(&state).await {
        return Redirect::to("/setup").into_response();
    }
    LoginTemplate {
        version: env!("GIT_VERSION"),
        error: None,
        username: String::new(),
        next: next.map(str::to_string),
    }
    .into_response()
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    next: Option<String>,
}

/// `POST /login`.
///
/// A refusal re-renders the form rather than redirecting to it, so the message
/// and the typed username survive. The status code still says what happened —
/// 401 for a bad credential, 429 for the rate limit — because a form that
/// answers 200 to a rejected sign-in is lying to everything except the eye.
pub async fn login_submit(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    let next = form.next.as_deref().and_then(safe_next);
    match start_password_session(
        &state,
        connect.as_deref(),
        &headers,
        jar,
        &form.username,
        &form.password,
    )
    .await
    {
        Ok(jar) => (jar, Redirect::to(next.unwrap_or("/"))).into_response(),
        Err(err) => {
            let (status, message) = match err {
                LoginError::RateLimited => (
                    StatusCode::TOO_MANY_REQUESTS,
                    "ERR: too many attempts — wait a minute, then retry",
                ),
                LoginError::Invalid => (
                    StatusCode::UNAUTHORIZED,
                    "ERR: incorrect password — access denied",
                ),
                LoginError::Internal => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERR: internal error — check the server log",
                ),
            };
            (
                status,
                LoginTemplate {
                    version: env!("GIT_VERSION"),
                    error: Some(message.to_string()),
                    username: form.username,
                    next: next.map(str::to_string),
                },
            )
                .into_response()
        }
    }
}

pub async fn setup_page(State(state): State<AppState>) -> Response {
    if !needs_setup(&state).await {
        return Redirect::to("/login").into_response();
    }
    SetupTemplate {
        error: None,
        username: String::new(),
        min_password_length: MIN_PASSWORD_LENGTH,
    }
    .into_response()
}

#[derive(Deserialize)]
pub struct SetupForm {
    username: String,
    password: String,
    confirm: String,
}

/// `POST /setup`.
///
/// The confirm field is checked here and nowhere else: it exists only in the
/// form, so `create_first_operator` — which the JSON endpoint shares — has no
/// business knowing about it.
///
/// A successful setup signs the operator in on the spot. Making them type the
/// password they just chose into a second form would be pure ceremony, and the
/// JSON path already does the same thing (its client posts login straight
/// after setup).
pub async fn setup_submit(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<SetupForm>,
) -> Response {
    let reject = |status: StatusCode, message: String, username: String| {
        (
            status,
            SetupTemplate {
                error: Some(message),
                username,
                min_password_length: MIN_PASSWORD_LENGTH,
            },
        )
            .into_response()
    };

    if form.password != form.confirm {
        return reject(
            StatusCode::BAD_REQUEST,
            "Passwords do not match".to_string(),
            form.username,
        );
    }

    if let Err(err) = create_first_operator(&state, &form.username, &form.password).await {
        let (status, message) = match err {
            SetupError::Disabled => (
                StatusCode::FORBIDDEN,
                "setup is disabled when forward auth is configured".to_string(),
            ),
            SetupError::AlreadyConfigured => {
                (StatusCode::CONFLICT, "already configured".to_string())
            }
            SetupError::Invalid(message) => (StatusCode::BAD_REQUEST, message),
            SetupError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error — check the server log".to_string(),
            ),
        };
        return reject(status, message, form.username);
    }

    match start_password_session(
        &state,
        connect.as_deref(),
        &headers,
        jar,
        &form.username,
        &form.password,
    )
    .await
    {
        // `?welcome=1` drives the one-time strip the shell shows after setup.
        // It rides the URL rather than `sessionStorage` so the server, which
        // now knows setup just completed, is the one that says so.
        Ok(jar) => (jar, Redirect::to("/?welcome=1")).into_response(),
        // The account exists; only the automatic sign-in failed. Sending them
        // to `/login` is recoverable, where re-rendering the wizard would ask
        // them to create an account that is already there.
        Err(_) => Redirect::to("/login").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_next_accepts_only_same_origin_paths() {
        assert_eq!(safe_next("/settings"), Some("/settings"));
        assert_eq!(safe_next("/logs?page=2"), Some("/logs?page=2"));

        // Off-origin, in every spelling a browser would honour.
        assert_eq!(safe_next("https://evil.example"), None);
        assert_eq!(safe_next("//evil.example"), None);
        assert_eq!(safe_next("/\\evil.example"), None);
        // Not a path at all.
        assert_eq!(safe_next("settings"), None);
        // Header injection.
        assert_eq!(safe_next("/settings\r\nX-Injected: 1"), None);
    }

    #[test]
    fn login_url_carries_only_a_destination_worth_returning_to() {
        assert_eq!(login_url(None), "/login");
        assert_eq!(login_url(Some("/")), "/login");
        assert_eq!(login_url(Some("https://evil.example")), "/login");
        assert_eq!(login_url(Some("/settings")), "/login?next=/settings");
    }

    #[test]
    fn query_value_encoding_keeps_the_destination_whole() {
        // `?` and `&` would otherwise end the value early, silently truncating
        // the destination rather than failing where anyone would notice.
        assert_eq!(
            encode_query_value("/logs?page=2&type=blocked"),
            "/logs%3Fpage%3D2%26type%3Dblocked"
        );
        assert_eq!(encode_query_value("/settings"), "/settings");
    }
}
