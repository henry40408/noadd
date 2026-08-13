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
    AppState, AuthedUser, CLEAR_SITE_DATA, ListError, LoginError, MIN_PASSWORD_LENGTH,
    PasswordChangeError, RuleError, SettingsError, SetupError, apply_settings,
    change_password_for_session, create_custom_rule, create_filter_list, create_first_operator,
    end_session, modify_filter_list, needs_setup, start_password_session,
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
    /// Read by the account page, for the same reason as `settings_saved`.
    password_changed: bool,
    /// Read by the filters page. Every change there — a list toggled, added,
    /// edited or removed, a rule added or deleted — kicks off a rebuild, so one
    /// identifier covers them all; what the operator needs to know is the same
    /// sentence either way.
    filters_saved: bool,
    /// Read by the filters page. Separate from `filters_saved` because
    /// downloading every list is the one action whose effect is not immediate.
    lists_updating: bool,
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
                password_changed: flash == Some(Flash::PasswordChanged),
                filters_saved: flash == Some(Flash::FiltersSaved),
                lists_updating: flash == Some(Flash::ListsUpdating),
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

/// The account page.
///
/// Covers the shell, who is signed in, and the change-password form. The three
/// actions needing a separate password proof — add operator, delete operator,
/// create API key — and the tables' row actions still need JavaScript; they
/// follow in their own change.
#[derive(Template, WebTemplate)]
#[template(path = "account.html")]
pub struct AccountTemplate {
    shell: ShellData,
    username: String,
    via_sso: bool,
    min_password_length: usize,
    error: Option<String>,
    password_changed: bool,
}

/// One filter list, formatted the way the page shows it.
///
/// The numbers and the relative time are rendered here rather than in the
/// template because the same shapes have to come back out of `app.js` when it
/// re-draws a row after a change, and a formatting rule that lives in two
/// languages drifts.
pub struct FilterListView {
    id: i64,
    name: String,
    url: String,
    enabled: bool,
    /// Thousands-separated, for the desktop table.
    rule_count: String,
    /// Abbreviated (`12.3K`), for the mobile card where the column is narrow.
    rule_count_compact: String,
    /// `"never"`, or how long ago the list was last downloaded.
    last_updated_text: String,
    /// The raw timestamp `app.js` re-derives its own relative text from.
    last_updated: i64,
}

/// One custom rule, as the page shows it.
pub struct CustomRuleView {
    id: i64,
    rule: String,
    rule_type: String,
    allow: bool,
}

/// The filters page: domain test, filter lists, and custom rules.
///
/// Everything here works without JavaScript, which is what the shape of this
/// struct is about. The domain test is a GET so its verdict is in the URL and
/// survives a refresh; every mutation is a POST that redirects. `edit_id` is
/// how a row expands into an edit form on the server — with JavaScript that
/// same button opens the dialog instead, and the link is never followed.
#[derive(Template, WebTemplate)]
#[template(path = "filters.html")]
pub struct FiltersTemplate {
    shell: ShellData,
    lists: Vec<FilterListView>,
    rules: Vec<CustomRuleView>,
    /// Every list is off, so nothing is being blocked at all. Worth saying
    /// loudly — it is the one state where noadd looks healthy and does nothing.
    all_disabled: bool,
    test_domain: String,
    /// Whether a domain was tested at all. The verdict is flat rather than an
    /// `Option<…>` so the template needs nothing but `{% if %}`.
    tested: bool,
    verdict_blocked: bool,
    /// The rule that decided it. Empty when the domain is allowed by default —
    /// nothing matched, which is not the same as an allow rule matching.
    verdict_rule: String,
    /// The list the deciding rule came from. Only set for a block.
    verdict_list: String,
    /// The list whose row is expanded into an edit form; `0` for none.
    edit_id: i64,
    edit_name: String,
    edit_url: String,
    edit_error: String,
    list_name: String,
    list_url: String,
    /// `"name"` or `"url"`, so the message lands next to the input it is about.
    list_error_field: &'static str,
    list_error: String,
    rule_text: String,
    rule_error: String,
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
    /// The operator changed their own password.
    PasswordChanged,
    /// A filter list or custom rule changed; the engine is rebuilding.
    FiltersSaved,
    /// Every list is being downloaded again.
    ListsUpdating,
}

impl Flash {
    fn as_str(self) -> &'static str {
        match self {
            Self::Welcome => "welcome",
            Self::ProxyLogout => "proxy_logout",
            Self::SettingsSaved => "settings_saved",
            Self::PasswordChanged => "password_changed",
            Self::FiltersSaved => "filters_saved",
            Self::ListsUpdating => "lists_updating",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "welcome" => Some(Self::Welcome),
            "proxy_logout" => Some(Self::ProxyLogout),
            "settings_saved" => Some(Self::SettingsSaved),
            "password_changed" => Some(Self::PasswordChanged),
            "filters_saved" => Some(Self::FiltersSaved),
            "lists_updating" => Some(Self::ListsUpdating),
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

// --- Account ---

pub async fn account_page(
    SsrUser(auth): SsrUser,
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    let (shell, jar) = ShellData::build(&uri, &headers, jar);
    let changed = shell.password_changed;
    let username = state
        .db
        .get_username(auth.user_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    (
        jar,
        AccountTemplate {
            shell,
            username,
            via_sso: auth.via_forward_auth,
            min_password_length: MIN_PASSWORD_LENGTH,
            error: None,
            password_changed: changed,
        },
    )
}

#[derive(Deserialize)]
pub struct PasswordForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
}

/// `POST /account/password`.
///
/// The confirmation field is checked here and nowhere else — it exists only in
/// the form, so `change_password_for_session`, which the JSON endpoint shares,
/// has no business knowing about it.
///
/// A success redirects. It has to: the shared path rotates the session cookie,
/// and re-rendering would leave the operator on a page whose form still holds
/// the password they just replaced.
pub async fn account_password_submit(
    SsrUser(auth): SsrUser,
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<PasswordForm>,
) -> Response {
    let reject = |status: StatusCode, message: String, jar: CookieJar, username: String| {
        let (shell, jar) = ShellData::build(&uri, &headers, jar);
        (
            status,
            jar,
            AccountTemplate {
                shell,
                username,
                via_sso: auth.via_forward_auth,
                min_password_length: MIN_PASSWORD_LENGTH,
                error: Some(message),
                password_changed: false,
            },
        )
            .into_response()
    };
    let username = state
        .db
        .get_username(auth.user_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    if form.new_password != form.confirm_password {
        return reject(
            StatusCode::BAD_REQUEST,
            "Passwords do not match".to_string(),
            jar,
            username,
        );
    }
    // Cookie-only, like the JSON endpoint: an API-key or forward-auth caller
    // holds no session to rotate, and `SsrUser` alone does not prove which
    // session is being changed.
    let Some(token_hash) = auth.session_token_hash.clone() else {
        return reject(
            StatusCode::UNAUTHORIZED,
            "Changing a password needs a browser session".to_string(),
            jar,
            username,
        );
    };
    let ip = crate::admin::api::client_ip(&state, connect.as_deref(), &headers);

    match change_password_for_session(
        &state,
        &headers,
        jar,
        auth.user_id,
        &token_hash,
        ip,
        &form.current_password,
        &form.new_password,
    )
    .await
    {
        Ok(jar) => (
            set_flash(jar, Flash::PasswordChanged),
            Redirect::to("/account"),
        )
            .into_response(),
        Err(err) => {
            let (status, message) = match err {
                PasswordChangeError::RateLimited => (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many attempts — wait a minute, then retry".to_string(),
                ),
                PasswordChangeError::Rejected(message) => (StatusCode::BAD_REQUEST, message),
                PasswordChangeError::WrongPassword => (
                    StatusCode::UNAUTHORIZED,
                    "Current password is incorrect".to_string(),
                ),
                PasswordChangeError::Internal => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not change the password — check the server log".to_string(),
                ),
            };
            // The jar was consumed by the failed attempt; a fresh one is fine
            // because nothing was set on it.
            reject(status, message, CookieJar::new(), username)
        }
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

// --- Filters ---

/// Thousands-separate an integer, matching what `Intl.NumberFormat` produces
/// for the counts `app.js` renders into the same column.
fn thousands(n: i64) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if n < 0 {
        out.push('-');
    }
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Abbreviate a count to at most one decimal (`12.3K`, `1.2M`).
///
/// The mobile card has room for a number, not for seven digits of one.
fn compact(n: i64) -> String {
    let scaled = |value: f64, suffix: &str| {
        let rounded = (value * 10.0).round() / 10.0;
        if (rounded.fract()).abs() < f64::EPSILON {
            format!("{}{suffix}", rounded as i64)
        } else {
            format!("{rounded:.1}{suffix}")
        }
    };
    #[allow(clippy::cast_precision_loss)]
    match n {
        n if n >= 1_000_000 => scaled(n as f64 / 1_000_000.0, "M"),
        n if n >= 1_000 => scaled(n as f64 / 1_000.0, "K"),
        n => thousands(n),
    }
}

/// How long ago a timestamp was, in the wording `app.js` uses for the same
/// column, so a row does not change its phrasing when the client redraws it.
fn time_ago(ts: i64) -> String {
    if ts == 0 {
        return "never".to_string();
    }
    let unit =
        |count: i64, name: &str| format!("{count} {name}{} ago", if count == 1 { "" } else { "s" });
    let diff = (crate::now_unix() - ts).max(0);
    match diff {
        d if d < 60 => unit(d, "second"),
        d if d < 3_600 => unit(d / 60, "minute"),
        d if d < 86_400 => unit(d / 3_600, "hour"),
        d => unit(d / 86_400, "day"),
    }
}

/// The page's mutable bits: what was typed, what was rejected, what is expanded.
///
/// One struct rather than a dozen arguments, because every handler that
/// re-renders sets one or two of these and leaves the rest alone.
#[derive(Default)]
struct FiltersView {
    test_domain: String,
    edit_id: i64,
    edit_name: String,
    edit_url: String,
    edit_error: String,
    list_name: String,
    list_url: String,
    list_error_field: &'static str,
    list_error: String,
    rule_text: String,
    rule_error: String,
}

/// Build the page from live storage plus whatever the caller is carrying.
///
/// `shell.current_path` is forced to `/filters`: a rejected POST arrives on
/// `/filters/lists` or `/filters/rules`, and the navigation would otherwise
/// render with nothing active on a page the operator is very much looking at.
async fn render_filters(
    state: &AppState,
    mut shell: ShellData,
    view: FiltersView,
) -> FiltersTemplate {
    shell.current_path = "/filters".to_string();

    let rows = state.db.get_filter_lists().await.unwrap_or_default();
    let all_disabled = !rows.is_empty() && rows.iter().all(|l| !l.enabled);
    let lists = rows
        .into_iter()
        .map(|l| FilterListView {
            id: l.id,
            name: l.name,
            url: l.url,
            enabled: l.enabled,
            rule_count: thousands(l.rule_count),
            rule_count_compact: compact(l.rule_count),
            last_updated_text: time_ago(l.last_updated),
            last_updated: l.last_updated,
        })
        .collect();

    let rules = state
        .db
        .get_all_custom_rules()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| CustomRuleView {
            id: r.id,
            rule: r.rule,
            allow: r.rule_type == "allow",
            rule_type: r.rule_type,
        })
        .collect();

    // The test runs against the live engine, which is what `POST
    // /api/filter/check` does; sharing the check itself would be sharing one
    // line, and the two answer in different shapes.
    let domain = view.test_domain.trim().trim_end_matches('.');
    let tested = !domain.is_empty();
    let (verdict_blocked, verdict_rule, verdict_list) = if tested {
        match state.filter.load().check(domain) {
            crate::filter::engine::FilterResult::Blocked { rule, list } => (true, rule, list),
            crate::filter::engine::FilterResult::Allowed { rule } => {
                (false, rule.unwrap_or_default(), String::new())
            }
        }
    } else {
        (false, String::new(), String::new())
    };

    FiltersTemplate {
        shell,
        lists,
        rules,
        all_disabled,
        test_domain: view.test_domain,
        tested,
        verdict_blocked,
        verdict_rule,
        verdict_list,
        edit_id: view.edit_id,
        edit_name: view.edit_name,
        edit_url: view.edit_url,
        edit_error: view.edit_error,
        list_name: view.list_name,
        list_url: view.list_url,
        list_error_field: view.list_error_field,
        list_error: view.list_error,
        rule_text: view.rule_text,
        rule_error: view.rule_error,
    }
}

#[derive(Deserialize)]
pub struct FiltersQuery {
    /// A domain to test. In the query string rather than a POST body so the
    /// verdict survives a refresh and can be linked to.
    test: Option<String>,
    /// The list to expand into an edit form. Parsed leniently — a hand-edited
    /// value expands nothing rather than 400-ing a page that otherwise renders.
    edit: Option<String>,
}

pub async fn filters_page(
    _user: SsrUser,
    State(state): State<AppState>,
    Query(query): Query<FiltersQuery>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    let (shell, jar) = ShellData::build(&uri, &headers, jar);
    let edit_id = query
        .edit
        .as_deref()
        .and_then(|raw| raw.parse::<i64>().ok())
        .unwrap_or_default();

    // The expanded row is filled from storage, not from the URL: the operator
    // asked to edit a list, not to pre-fill a form with values a link carried.
    let (edit_name, edit_url) = if edit_id == 0 {
        (String::new(), String::new())
    } else {
        state
            .db
            .get_filter_lists()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|l| l.id == edit_id)
            .map_or_else(
                || (String::new(), String::new()),
                |list| (list.name, list.url),
            )
    };

    let view = FiltersView {
        test_domain: query.test.unwrap_or_default(),
        edit_id,
        edit_name,
        edit_url,
        ..FiltersView::default()
    };
    (jar, render_filters(&state, shell, view).await)
}

/// Everything that changed a filter answers the same way: redirect back to the
/// page with a notice, so a refresh cannot resubmit it.
fn filters_saved(jar: CookieJar, flash: Flash) -> Response {
    (set_flash(jar, flash), Redirect::to("/filters")).into_response()
}

#[derive(Deserialize)]
pub struct AddListForm {
    name: String,
    url: String,
}

/// `POST /filters/lists`.
pub async fn filters_list_add_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<AddListForm>,
) -> Response {
    match create_filter_list(&state, &form.name, &form.url).await {
        Ok(_id) => {
            // Adding a list does not fetch it, so there is nothing to rebuild
            // yet — but the row appearing is the confirmation that matters.
            filters_saved(jar, Flash::FiltersSaved)
        }
        Err(err) => {
            let (status, field, message) = list_error_parts(err);
            let (shell, jar) = ShellData::build(&uri, &headers, jar);
            let view = FiltersView {
                list_name: form.name,
                list_url: form.url,
                list_error_field: field,
                list_error: message,
                ..FiltersView::default()
            };
            (status, jar, render_filters(&state, shell, view).await).into_response()
        }
    }
}

/// Split a [`ListError`] into what the form needs: a status, the field to blame
/// and the message to show beside it.
fn list_error_parts(err: ListError) -> (StatusCode, &'static str, String) {
    match err {
        ListError::Invalid { field, message } => (StatusCode::BAD_REQUEST, field, message),
        ListError::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "",
            "Could not save — check the server log".to_string(),
        ),
    }
}

#[derive(Deserialize)]
pub struct EditListForm {
    name: String,
    url: String,
}

/// `POST /filters/lists/{id}/edit`.
///
/// A rejected edit re-renders with the row still expanded and the submitted
/// values in it, which is the only way the operator gets to correct the one
/// field that was wrong.
pub async fn filters_list_edit_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<EditListForm>,
) -> Response {
    match modify_filter_list(&state, id, &form.name, &form.url).await {
        Ok(()) => {
            state.trigger_rebuild();
            filters_saved(jar, Flash::FiltersSaved)
        }
        Err(err) => {
            let (status, _field, message) = list_error_parts(err);
            let (shell, jar) = ShellData::build(&uri, &headers, jar);
            let view = FiltersView {
                edit_id: id,
                edit_name: form.name,
                edit_url: form.url,
                edit_error: message,
                ..FiltersView::default()
            };
            (status, jar, render_filters(&state, shell, view).await).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct ToggleListForm {
    /// Absent when the checkbox is unticked — that is how a browser posts an
    /// unchecked box, and it is the only signal that the list is being turned
    /// off.
    enabled: Option<String>,
}

/// `POST /filters/lists/{id}/toggle`.
pub async fn filters_list_toggle_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    jar: CookieJar,
    Form(form): Form<ToggleListForm>,
) -> Response {
    if state
        .db
        .update_filter_list_enabled(id, form.enabled.is_some())
        .await
        .is_ok()
    {
        state.trigger_rebuild();
    }
    filters_saved(jar, Flash::FiltersSaved)
}

/// `POST /filters/lists/{id}/delete`.
pub async fn filters_list_delete_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    jar: CookieJar,
) -> Response {
    if state.db.delete_filter_list(id).await.is_ok() {
        state.trigger_rebuild();
    }
    filters_saved(jar, Flash::FiltersSaved)
}

/// `POST /filters/lists/update`.
///
/// Downloads every list before answering, exactly as `POST /api/lists/update`
/// does. Without JavaScript there is nowhere to report progress to, so the
/// request is the progress indicator.
pub async fn filters_lists_update_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Response {
    if state
        .list_manager
        .update_all_lists_no_rebuild()
        .await
        .is_ok()
    {
        state.trigger_rebuild();
    }
    filters_saved(jar, Flash::ListsUpdating)
}

/// `POST /filters/lists/enable-recommended`.
///
/// The escape hatch from the state where every list is off: turn one back on
/// without making the operator work out which. Same pick as `app.js` makes.
pub async fn filters_enable_recommended_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Response {
    let lists = state.db.get_filter_lists().await.unwrap_or_default();
    let pick = lists
        .iter()
        .find(|l| l.name == "AdGuard DNS filter")
        .or_else(|| lists.first());
    if let Some(list) = pick
        && state
            .db
            .update_filter_list_enabled(list.id, true)
            .await
            .is_ok()
    {
        state.trigger_rebuild();
    }
    filters_saved(jar, Flash::FiltersSaved)
}

#[derive(Deserialize)]
pub struct AddRuleForm {
    rule: String,
}

/// `POST /filters/rules`.
pub async fn filters_rule_add_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<AddRuleForm>,
) -> Response {
    match create_custom_rule(&state, &form.rule).await {
        // A duplicate is not worth an error: the rule the operator wanted is
        // there, which is what they asked for.
        Ok(_) => filters_saved(jar, Flash::FiltersSaved),
        Err(err) => {
            let (status, message) = match err {
                RuleError::Unparseable => (
                    StatusCode::BAD_REQUEST,
                    "Not a rule noadd understands — see the syntax reference below".to_string(),
                ),
                RuleError::Internal => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not save — check the server log".to_string(),
                ),
            };
            let (shell, jar) = ShellData::build(&uri, &headers, jar);
            let view = FiltersView {
                rule_text: form.rule,
                rule_error: message,
                ..FiltersView::default()
            };
            (status, jar, render_filters(&state, shell, view).await).into_response()
        }
    }
}

/// `POST /filters/rules/{id}/delete`.
pub async fn filters_rule_delete_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    jar: CookieJar,
) -> Response {
    if state.db.delete_custom_rule(id).await.is_ok() {
        state.trigger_rebuild();
    }
    filters_saved(jar, Flash::FiltersSaved)
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

    #[test]
    fn counts_are_grouped_the_way_the_client_groups_them() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(87_654), "87,654");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn compact_counts_lose_nothing_a_reader_needs() {
        assert_eq!(compact(999), "999");
        // A whole thousand keeps no pointless `.0`.
        assert_eq!(compact(1_000), "1K");
        assert_eq!(compact(12_345), "12.3K");
        assert_eq!(compact(1_250_000), "1.3M");
    }

    #[test]
    fn a_list_that_never_downloaded_says_so_rather_than_dating_from_1970() {
        assert_eq!(time_ago(0), "never");
    }

    #[test]
    fn relative_times_are_singular_where_they_should_be() {
        let now = crate::now_unix();
        assert_eq!(time_ago(now), "0 seconds ago");
        assert_eq!(time_ago(now - 1), "1 second ago");
        assert_eq!(time_ago(now - 90), "1 minute ago");
        assert_eq!(time_ago(now - 7_200), "2 hours ago");
        assert_eq!(time_ago(now - 172_800), "2 days ago");
        // A clock that moved backwards must not render a negative age.
        assert_eq!(time_ago(now + 60), "0 seconds ago");
    }
}
