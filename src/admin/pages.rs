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
    http::{HeaderMap, StatusCode, Uri, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use std::convert::Infallible;
use std::net::SocketAddr;

use crate::admin::api::{
    AppState, AuthedUser, CLEAR_SITE_DATA, LoginError, MIN_PASSWORD_LENGTH, SettingsError,
    SetupError, apply_settings, create_first_operator, end_session, needs_setup,
    start_password_session,
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

/// One entry in the navigation, and with it one of the paths the shell links to.
///
/// A single table drives the desktop strip and the mobile F-key bar both. They
/// were separate blocks of markup before, which meant adding a page involved
/// remembering to edit two places that nothing checked against each other.
pub struct NavItem {
    pub href: &'static str,
    pub testid: &'static str,
    /// The digit shown in the desktop strip (`1:` … `6:`).
    pub key: &'static str,
    /// The function key shown in the mobile bar (`F1` … `F6`).
    pub fkey: &'static str,
    pub label: &'static str,
    /// The abbreviated label the narrow mobile bar uses.
    pub short: &'static str,
}

const NAV: &[NavItem] = &[
    NavItem {
        href: "/",
        testid: "nav-dashboard",
        key: "1",
        fkey: "F1",
        label: "dashboard",
        short: "dash",
    },
    NavItem {
        href: "/stats",
        testid: "nav-stats",
        key: "2",
        fkey: "F2",
        label: "statistics",
        short: "stats",
    },
    NavItem {
        href: "/logs",
        testid: "nav-logs",
        key: "3",
        fkey: "F3",
        label: "query-log",
        short: "logs",
    },
    NavItem {
        href: "/filters",
        testid: "nav-filters",
        key: "4",
        fkey: "F4",
        label: "filters",
        short: "filt",
    },
    NavItem {
        href: "/settings",
        testid: "nav-settings",
        key: "5",
        fkey: "F5",
        label: "settings",
        short: "conf",
    },
    NavItem {
        href: "/account",
        testid: "nav-account",
        key: "6",
        fkey: "F6",
        label: "account",
        short: "acct",
    },
];

/// Everything the shell needs, independent of which page is inside it.
///
/// Carried as a field on each page's template rather than duplicated across
/// them: `shell.html` reads `shell.*`, so a page template only has to declare
/// its own data. Every page that grows a server-rendered body gets this for
/// free by embedding it.
pub struct ShellData {
    version: &'static str,
    /// The `Host` this request arrived on, shown in the status bar. Attacker-
    /// influenced (it is a request header), so it is only ever interpolated by
    /// the template, which escapes it.
    host: String,
    /// The path being served, so the matching navigation item renders active.
    current_path: String,
    nav: &'static [NavItem],
    welcome: bool,
    proxy_logout_notice: bool,
    /// Read by the settings page rather than `shell.html` — the confirmation
    /// belongs next to the save button, not in the shell's notice area. It is
    /// resolved here because this is where the flash is consumed, and consuming
    /// it in two places would mean one of them never sees it.
    settings_saved: bool,
}

impl ShellData {
    /// Build the shell's data for this request, consuming the pending flash.
    ///
    /// Returns the jar that clears it alongside, because reading a flash
    /// without clearing it is the bug this mechanism exists to prevent.
    fn build(uri: &Uri, headers: &HeaderMap, jar: CookieJar) -> (Self, CookieJar) {
        let (flash, jar) = take_flash(jar);
        (
            Self {
                version: env!("GIT_VERSION"),
                host: request_host(headers),
                current_path: uri.path().to_string(),
                nav: NAV,
                welcome: flash == Some(Flash::Welcome),
                proxy_logout_notice: flash == Some(Flash::ProxyLogout),
                settings_saved: flash == Some(Flash::SettingsSaved),
            },
            jar,
        )
    }
}

/// The settings page.
///
/// `error_field` names the one field a rejected save objected to, and is
/// compared by name in the template so the message lands next to the input it
/// is about — a page with eight fields and one message at the top makes the
/// operator hunt for which. Empty when there is nothing to report.
#[derive(Template, WebTemplate)]
#[template(path = "settings.html")]
pub struct SettingsTemplate {
    shell: ShellData,
    upstream_servers: String,
    upstream_strategy: String,
    dnssec_on: bool,
    block_mode: String,
    block_custom_ipv4: String,
    block_custom_ipv6: String,
    log_retention_days: String,
    public_url: String,
    doh_access_policy: String,
    error_field: &'static str,
    error_message: String,
    saved: bool,
}

/// The shell around a page whose body is still painted by `app.js`.
///
/// Every page still using this is one P3 has not reached yet; a page with a
/// server-rendered body has its own template that embeds [`ShellData`] instead.
#[derive(Template, WebTemplate)]
#[template(path = "shell.html")]
pub struct ShellTemplate {
    shell: ShellData,
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

// --- Flash notices ---

/// A one-shot notice left behind by a redirect.
///
/// A closed set rather than free text: the value round-trips through a cookie,
/// and a cookie holding an arbitrary message is one encoding bug away from
/// either breaking the header or carrying something the sender did not write.
/// The wording lives in the template; only the identifier travels.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Flash {
    /// First-run setup just completed.
    Welcome,
    /// Logout on a forward-auth session, which noadd cannot end on its own.
    ProxyLogout,
    /// A settings save went through.
    SettingsSaved,
}

impl Flash {
    fn as_str(self) -> &'static str {
        match self {
            Self::Welcome => "welcome",
            Self::ProxyLogout => "proxy_logout",
            Self::SettingsSaved => "settings_saved",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "welcome" => Some(Self::Welcome),
            "proxy_logout" => Some(Self::ProxyLogout),
            "settings_saved" => Some(Self::SettingsSaved),
            // An unrecognised value is a stale cookie from an older build, or
            // something hand-written. Either way there is no notice to show.
            _ => None,
        }
    }
}

/// The cookie a flash rides in.
///
/// A cookie rather than the query string: `?welcome=1` survives a refresh, a
/// bookmark and a shared link, so the strip it drives comes back where it has
/// no business coming back. It is deliberately session-scoped (no `Max-Age`) —
/// a notice nobody saw before closing the tab is not one worth keeping.
const FLASH_COOKIE: &str = "noadd_flash";

fn set_flash(jar: CookieJar, flash: Flash) -> CookieJar {
    jar.add(
        Cookie::build((FLASH_COOKIE, flash.as_str()))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .build(),
    )
}

/// Read the pending notice and hand back a jar that clears it.
///
/// Read and clear are one step on purpose: a flash that is rendered but not
/// cleared shows again on the next page, which is the failure this mechanism
/// exists to avoid.
fn take_flash(jar: CookieJar) -> (Option<Flash>, CookieJar) {
    let Some(flash) = jar.get(FLASH_COOKIE).and_then(|c| Flash::parse(c.value())) else {
        return (None, jar);
    };
    let jar = jar.remove(Cookie::build((FLASH_COOKIE, "")).path("/").build());
    (Some(flash), jar)
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

/// The `Host` this request arrived on.
///
/// Shown in the status bar, where it used to be read from `location.host`. It
/// is a request header, so it is whatever the client sent — fine for a label,
/// and the template escapes it — but never treat it as identity.
fn request_host(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// Every signed-in page. The shell is rendered here; only `#page-content` is
/// left for `app.js` to fill.
pub async fn shell_page(
    _user: SsrUser,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    let (shell, jar) = ShellData::build(&uri, &headers, jar);
    (jar, ShellTemplate { shell })
}

/// `POST /logout`.
///
/// A form rather than a `fetch`, so signing out works with JavaScript off. It
/// is a POST because it changes state — a `GET /logout` would be followed by
/// any link prefetcher that happened across it.
pub async fn logout_submit(
    State(state): State<AppState>,
    SsrUser(auth): SsrUser,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let via_forward_auth = auth.via_forward_auth;
    let (jar, redirect_to) = end_session(&state, &auth, connect.as_deref(), &headers, jar).await;

    if let Some(url) = redirect_to {
        // The proxy owns this session; hand the browser to its logout URL.
        return (jar, [CLEAR_SITE_DATA], Redirect::to(&url)).into_response();
    }
    if via_forward_auth {
        // Proxy-managed with nowhere to hand off to. Clearing our cookies
        // achieves nothing — the next request carries the same proxy header —
        // so say where the session actually has to be ended.
        //
        // No `Clear-Site-Data` here, deliberately: it would take the flash
        // cookie with it and the operator would be redirected to a page that
        // says nothing about why logging out did not work.
        return (set_flash(jar, Flash::ProxyLogout), Redirect::to("/")).into_response();
    }
    // No `next`: the session just ended is not somewhere to return to.
    (jar, [CLEAR_SITE_DATA], Redirect::to("/login")).into_response()
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
        // The welcome strip rides a flash cookie rather than the URL: a
        // `?welcome=1` would survive a refresh, a bookmark and a shared link,
        // and greet the operator again each time.
        Ok(jar) => (set_flash(jar, Flash::Welcome), Redirect::to("/")).into_response(),
        // The account exists; only the automatic sign-in failed. Sending them
        // to `/login` is recoverable, where re-rendering the wizard would ask
        // them to create an account that is already there.
        Err(_) => Redirect::to("/login").into_response(),
    }
}

// --- Settings ---

/// The settings the page renders. Absent keys come back as empty strings, which
/// is what an unset setting means to every input on the page.
async fn current_settings(state: &AppState) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for key in [
        "upstream_servers",
        "upstream_strategy",
        "log_retention_days",
        "doh_access_policy",
        "public_url",
        "dnssec_disabled",
        "block_mode",
        "block_custom_ipv4",
        "block_custom_ipv6",
    ] {
        if let Ok(Some(value)) = state.db.get_setting(key).await {
            out.insert(key.to_string(), value);
        }
    }
    out
}

/// Build the page from a set of values, whatever their source.
///
/// Called with the persisted settings on a GET and with the *submitted* ones on
/// a rejected save, which is what lets the operator correct the one field that
/// was wrong instead of retyping the seven that were fine.
fn settings_template(
    shell: ShellData,
    values: &std::collections::HashMap<String, String>,
    error_field: &'static str,
    error_message: String,
    saved: bool,
) -> SettingsTemplate {
    let get = |key: &str| values.get(key).cloned().unwrap_or_default();
    SettingsTemplate {
        shell,
        upstream_servers: get("upstream_servers"),
        // The defaults mirror what the DNS layer falls back to for an unset
        // value, so the page never shows a blank select for a setting that is
        // in fact in effect.
        upstream_strategy: match get("upstream_strategy").as_str() {
            "" => "sequential".to_string(),
            other => other.to_string(),
        },
        dnssec_on: get("dnssec_disabled").trim() != "true",
        block_mode: match get("block_mode").as_str() {
            "" => "null_ip".to_string(),
            other => other.to_string(),
        },
        block_custom_ipv4: get("block_custom_ipv4"),
        block_custom_ipv6: get("block_custom_ipv6"),
        log_retention_days: get("log_retention_days"),
        public_url: get("public_url"),
        doh_access_policy: match get("doh_access_policy").as_str() {
            "" => "allow".to_string(),
            other => other.to_string(),
        },
        error_field,
        error_message,
        saved,
    }
}

pub async fn settings_page(
    _user: SsrUser,
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    let (shell, jar) = ShellData::build(&uri, &headers, jar);
    let saved = shell.settings_saved;
    let values = current_settings(&state).await;
    (
        jar,
        settings_template(shell, &values, "", String::new(), saved),
    )
}

#[derive(Deserialize)]
pub struct SettingsForm {
    upstream_servers: String,
    upstream_strategy: String,
    /// `on` / `off`, the inverse of the stored `dnssec_disabled`. The form says
    /// what the operator sees; the storage key predates it.
    dnssec: String,
    block_mode: String,
    block_custom_ipv4: String,
    block_custom_ipv6: String,
    log_retention_days: String,
    public_url: String,
    doh_access_policy: String,
}

impl SettingsForm {
    fn into_map(self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        map.insert("upstream_servers".to_string(), self.upstream_servers);
        map.insert("upstream_strategy".to_string(), self.upstream_strategy);
        map.insert(
            "dnssec_disabled".to_string(),
            if self.dnssec == "off" {
                "true"
            } else {
                "false"
            }
            .to_string(),
        );
        map.insert("block_mode".to_string(), self.block_mode);
        map.insert("block_custom_ipv4".to_string(), self.block_custom_ipv4);
        map.insert("block_custom_ipv6".to_string(), self.block_custom_ipv6);
        map.insert("log_retention_days".to_string(), self.log_retention_days);
        map.insert("public_url".to_string(), self.public_url);
        map.insert("doh_access_policy".to_string(), self.doh_access_policy);
        map
    }
}

/// `POST /settings`.
///
/// One submit for every scalar setting, rather than one endpoint per field.
/// Without JavaScript that is what makes the page usable; with it, `app.js`
/// removes the button and restores per-field autosave against `/api/settings`.
///
/// A successful save redirects rather than rendering: a POST left in the
/// browser's history is one refresh away from being submitted again.
pub async fn settings_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<SettingsForm>,
) -> Response {
    let values = form.into_map();
    match apply_settings(&state, &values).await {
        Ok(()) => (
            set_flash(jar, Flash::SettingsSaved),
            Redirect::to("/settings"),
        )
            .into_response(),
        Err(err) => {
            let (status, field, message) = match err {
                SettingsError::Invalid { field, message } => {
                    (StatusCode::BAD_REQUEST, field, message)
                }
                SettingsError::Internal => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "",
                    "Could not save — check the server log".to_string(),
                ),
            };
            // Re-render with what was submitted, not what is stored: the whole
            // point is that the seven fields the operator got right survive the
            // one they did not.
            let (shell, jar) = ShellData::build(&uri, &headers, jar);
            (
                status,
                jar,
                settings_template(shell, &values, field, message, false),
            )
                .into_response()
        }
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
