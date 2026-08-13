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
    ApiKeyError, AppState, AuthedUser, CLEAR_SITE_DATA, ListError, LoginError, MIN_PASSWORD_LENGTH,
    OperatorError, PasswordChangeError, ReauthError, RuleError, SettingsError, SetupError,
    apply_settings, change_password_for_session, create_custom_rule, create_filter_list,
    create_first_operator, create_operator, end_session, issue_api_key, modify_filter_list,
    needs_setup, remove_operator, start_password_session,
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
    /// Read by the account page: an operator or API key was added or removed.
    account_saved: bool,
    /// Read by the account page. Separate from `account_saved` because signing
    /// devices out is worth confirming in its own words.
    sessions_revoked: bool,
}

impl ShellData {
    /// Build the shell's data for this request, consuming the pending flash.
    ///
    /// Returns the jar that clears it alongside, because reading a flash
    /// without clearing it is the bug this mechanism exists to prevent.
    fn build(uri: &Uri, headers: &HeaderMap, jar: CookieJar) -> (Self, CookieJar) {
        Self::build_for(uri.path(), headers, jar)
    }

    /// The same, for a response whose page is known regardless of the path the
    /// request arrived on.
    ///
    /// A rejected `POST /account/operators` re-renders the account page, and
    /// the navigation has to say `/account` — taking it from the request URI
    /// would leave nothing active on a page the operator is looking straight at.
    fn build_for(path: &str, headers: &HeaderMap, jar: CookieJar) -> (Self, CookieJar) {
        let (flash, jar) = take_flash(jar);
        (
            Self {
                version: env!("GIT_VERSION"),
                host: request_host(headers),
                current_path: path.to_string(),
                nav: NAV,
                welcome: flash == Some(Flash::Welcome),
                proxy_logout_notice: flash == Some(Flash::ProxyLogout),
                settings_saved: flash == Some(Flash::SettingsSaved),
                password_changed: flash == Some(Flash::PasswordChanged),
                filters_saved: flash == Some(Flash::FiltersSaved),
                lists_updating: flash == Some(Flash::ListsUpdating),
                account_saved: flash == Some(Flash::AccountSaved),
                sessions_revoked: flash == Some(Flash::SessionsRevoked),
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

/// One operator, as the page lists them.
pub struct OperatorView {
    id: i64,
    username: String,
    created_text: String,
    is_you: bool,
    /// False for yourself and for the last operator standing. Deleting either
    /// is refused by the server; the row says so rather than offering a button
    /// that exists to be turned down.
    deletable: bool,
}

/// One live session.
pub struct SessionView {
    id: i64,
    username: String,
    ip: String,
    user_agent: String,
    created_text: String,
    last_seen_text: String,
    is_current: bool,
}

/// One API key. The secret is not here — it never is again after creation.
pub struct ApiKeyView {
    id: i64,
    name: String,
    prefix: String,
    created_text: String,
    last_used_text: String,
    expires_text: String,
}

/// The account page: this account, operators, sessions and API keys.
///
/// The three actions that need a password proof — add an operator, delete one,
/// mint an API key — carry a password field in the form itself. That is the
/// whole mechanism: no dialog, no stale-proof round trip, and the same path
/// whether or not there is JavaScript. `POST /api/auth/reauth` still exists for
/// API callers, and [`crate::admin::api::confirm_password`] is the one place
/// either of them checks a password.
#[derive(Template, WebTemplate)]
#[template(path = "account.html")]
pub struct AccountTemplate {
    shell: ShellData,
    username: String,
    via_sso: bool,
    min_password_length: usize,
    /// The change-password form's message.
    error: Option<String>,
    password_changed: bool,

    operators: Vec<OperatorView>,
    sessions: Vec<SessionView>,
    api_keys: Vec<ApiKeyView>,

    /// Submitted values kept across a rejection, so only the field that was
    /// wrong has to be retyped. Passwords are never among them.
    operator_username: String,
    operator_error: String,

    /// The operator whose row is expanded into a delete confirmation, and the
    /// password field that goes with it; `0` for none.
    confirm_operator_id: i64,
    confirm_operator_name: String,
    confirm_operator_error: String,

    api_key_name: String,
    api_key_expires: String,
    api_key_error: String,

    /// The one and only sight of a newly minted token. Empty except on the
    /// response that created it — it is not stored, so this is the only
    /// chance anyone gets to copy it.
    new_key_name: String,
    new_key_token: String,

    account_saved: bool,
    sessions_revoked: bool,
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

/// One row of a "top N" table: a label, a count, and its share of the visible
/// total.
pub struct TopRowView {
    label: String,
    /// A second line under the label — the `DoH` token a client came in on.
    /// Empty when there is none.
    sub_label: String,
    count: String,
    /// `"12.3%"`, or empty when the total is zero and a share would be a lie.
    share: String,
    /// Only the upstreams table has this column.
    avg_ms: String,
}

/// The dashboard.
///
/// Everything here is a reading rather than a control, so there is not a form
/// on the page. What that buys is a first paint with the real numbers in it:
/// the six stat cards, the three top-N tables and the onboarding notice all
/// arrive filled in, where they used to appear empty and then populate over
/// five API calls.
///
/// The chart is the exception, and the one place the no-JS rule was always
/// going to stop: it is drawn from a timeline series by `app.js`. Without
/// scripting the card says so rather than sitting empty.
#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    shell: ShellData,

    queries_today: String,
    queries_today_full: String,
    queries_7d: String,
    queries_30d: String,
    blocked_today: String,
    blocked_today_full: String,
    blocked_7d: String,
    blocked_30d: String,
    block_rate: String,
    block_rate_7d: String,
    block_rate_30d: String,
    cache_rate: String,
    cache_rate_7d: String,
    cache_rate_30d: String,
    avg_ms: String,
    avg_ms_7d: String,
    avg_ms_30d: String,
    /// The live rate from the server's 60-second window, which is what the
    /// card's label and its flash-on-change both promise.
    qps_now: String,
    qps_today: String,
    qps_7d: String,

    /// False only on an appliance that has never answered a query, which is
    /// the one state worth explaining at length.
    has_queries: bool,
    /// Where to point a device, shown by the onboarding notice.
    dns_addr: String,

    top_domains: Vec<TopRowView>,
    top_clients: Vec<TopRowView>,
    top_upstreams: Vec<TopRowView>,
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
    /// An operator or API key was added or removed.
    AccountSaved,
    /// One or more sessions were signed out.
    SessionsRevoked,
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
            Self::AccountSaved => "account_saved",
            Self::SessionsRevoked => "sessions_revoked",
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
            "account_saved" => Some(Self::AccountSaved),
            "sessions_revoked" => Some(Self::SessionsRevoked),
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

// --- Dashboard ---

/// Full digits below a million, abbreviated above it.
///
/// Mirrors `formatNumAdaptive` in `app.js`, which draws the same cards every
/// ten seconds: a count that changed its own notation when the poll landed
/// would read as a change in the number.
fn format_num_adaptive(n: i64) -> String {
    if n < 1_000_000 {
        thousands(n)
    } else {
        compact(n)
    }
}

/// A fraction as a one-decimal percentage, the way every rate on the page is
/// written.
fn percent1(value: f64) -> String {
    format!("{:.1}", value * 100.0)
}

/// One row's share of the visible total. Empty when there is no total to take
/// a share of.
fn share_percent(count: i64, sum: i64) -> String {
    if sum <= 0 || count <= 0 {
        return String::new();
    }
    #[allow(clippy::cast_precision_loss)]
    let pct = count as f64 / sum as f64 * 100.0;
    format!("{pct:.1}%")
}

/// Queries per second, with the precision the size of the number deserves.
///
/// Two decimals on a trickle and none on a flood: `0.03 q/s` says something
/// `0 q/s` does not, and `1,234.00 q/s` says nothing `1234` does not.
fn format_qps(value: f64) -> String {
    if value >= 100.0 {
        format!("{:.0}", value.round())
    } else if value >= 10.0 {
        format!("{value:.1}")
    } else {
        format!("{value:.2}")
    }
}

/// Where to point a device's DNS, for the onboarding notice.
///
/// The host comes from the request and the port from the configured DNS
/// listener: the browser reached us on a name that resolves, and the DNS
/// listener's own bind address is frequently `0.0.0.0`, which is not something
/// to tell anyone to type in.
fn dns_target(headers: &HeaderMap, dns_addr: &str) -> String {
    let host = request_host(headers);
    // Strip the HTTP port; the DNS one is what belongs here.
    let host = host.split(':').next().unwrap_or_default();
    match dns_addr.rsplit_once(':') {
        Some((_, port)) if !port.is_empty() => format!("{host}:{port}"),
        _ => host.to_string(),
    }
}

pub async fn dashboard_page(
    _user: SsrUser,
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    let (shell, jar) = ShellData::build(&uri, &headers, jar);
    let now = crate::now_unix();

    // The same five reads `app.js` makes on its poll, in one request. A failure
    // renders zeroes rather than an error page: the dashboard is a reading, and
    // a page that says nothing is more useful than one that will not load.
    let summary = crate::admin::stats::compute_summary(&state.db, now)
        .await
        .unwrap_or_default();
    // Ten rows each, which is what the page shows — the API's larger default is
    // for callers who want to do their own slicing.
    let domains = crate::admin::stats::compute_top_domains(&state.db, now, 10)
        .await
        .unwrap_or_default();
    let clients = crate::admin::stats::compute_top_clients(&state.db, now, 10)
        .await
        .unwrap_or_default();
    let upstreams = crate::admin::stats::compute_top_upstreams(&state.db, now, 10)
        .await
        .unwrap_or_default();

    let domains_sum: i64 = domains.iter().map(|d| d.count).sum();
    let top_domains = domains
        .into_iter()
        .map(|d| TopRowView {
            label: d.domain,
            sub_label: String::new(),
            count: thousands(d.count),
            share: share_percent(d.count, domains_sum),
            avg_ms: String::new(),
        })
        .collect();

    let clients_sum: i64 = clients.iter().map(|c| c.count).sum();
    let top_clients = clients
        .into_iter()
        .map(|c| TopRowView {
            label: c.client_ip,
            sub_label: c.doh_token.unwrap_or_default(),
            count: thousands(c.count),
            share: share_percent(c.count, clients_sum),
            avg_ms: String::new(),
        })
        .collect();

    let upstreams_sum: i64 = upstreams.iter().map(|u| u.count).sum();
    let top_upstreams = upstreams
        .into_iter()
        .map(|u| TopRowView {
            label: u.upstream,
            sub_label: String::new(),
            count: thousands(u.count),
            share: share_percent(u.count, upstreams_sum),
            avg_ms: format!("{:.1}ms", u.avg_ms),
        })
        .collect();

    #[allow(clippy::cast_precision_loss)]
    let per_second = |count: i64, seconds: f64| format_qps(count as f64 / seconds);

    (
        jar,
        DashboardTemplate {
            shell,
            queries_today: format_num_adaptive(summary.total_today),
            queries_today_full: thousands(summary.total_today),
            queries_7d: compact(summary.total_7d),
            queries_30d: compact(summary.total_30d),
            blocked_today: format_num_adaptive(summary.blocked_today),
            blocked_today_full: thousands(summary.blocked_today),
            blocked_7d: compact(summary.blocked_7d),
            blocked_30d: compact(summary.blocked_30d),
            block_rate: percent1(summary.block_ratio_today),
            block_rate_7d: percent1(summary.block_ratio_7d),
            block_rate_30d: percent1(summary.block_ratio_30d),
            cache_rate: percent1(summary.cache_hit_rate_today),
            cache_rate_7d: percent1(summary.cache_hit_rate_7d),
            cache_rate_30d: percent1(summary.cache_hit_rate_30d),
            avg_ms: format!("{:.1}", summary.avg_response_ms_today),
            avg_ms_7d: format!("{:.1}", summary.avg_response_ms_7d),
            avg_ms_30d: format!("{:.1}", summary.avg_response_ms_30d),
            qps_now: per_second(summary.queries_1m, 60.0),
            qps_today: per_second(summary.total_today, 86_400.0),
            qps_7d: per_second(summary.total_7d, 7.0 * 86_400.0),
            has_queries: summary.total_today + summary.total_7d + summary.total_30d > 0,
            dns_addr: dns_target(&headers, &state.server_info.dns_addr),
            top_domains,
            top_clients,
            top_upstreams,
        },
    )
}

// --- Account ---

/// When an API key stops working.
///
/// Three states in one column: no expiry, one still ahead, one already past.
/// "in 30 days" and "expired" say which without the reader having to work out
/// whether a relative time is in the future.
fn expiry_text(ts: Option<i64>) -> String {
    let Some(ts) = ts.filter(|t| *t != 0) else {
        return "never".to_string();
    };
    let remaining = ts - crate::now_unix();
    if remaining <= 0 {
        return "expired".to_string();
    }
    let unit =
        |count: i64, name: &str| format!("in {count} {name}{}", if count == 1 { "" } else { "s" });
    match remaining {
        d if d < 3_600 => unit((d / 60).max(1), "minute"),
        d if d < 86_400 => unit(d / 3_600, "hour"),
        d => unit(d / 86_400, "day"),
    }
}

/// A timestamp that may not be set, for the columns where "never used" and
/// "used at the epoch" are different answers.
fn maybe_time_ago(ts: Option<i64>) -> String {
    match ts.filter(|t| *t != 0) {
        Some(ts) => time_ago(ts),
        None => "—".to_string(),
    }
}

/// The page's mutable bits: what was typed, what was rejected, what is expanded.
#[derive(Default)]
struct AccountView {
    error: Option<String>,
    password_changed: bool,
    operator_username: String,
    operator_error: String,
    confirm_operator_id: i64,
    confirm_operator_error: String,
    api_key_name: String,
    api_key_expires: String,
    api_key_error: String,
    new_key_name: String,
    new_key_token: String,
}

/// Build the page from live storage plus whatever the caller is carrying.
///
/// The shell comes in already built — by `ShellData::build_for("/account", …)`
/// on the POST paths, so a rejected `POST /account/operators` still renders
/// with the account tab active.
async fn render_account(
    state: &AppState,
    auth: &AuthedUser,
    shell: ShellData,
    view: AccountView,
) -> AccountTemplate {
    let account_saved = shell.account_saved;
    let sessions_revoked = shell.sessions_revoked;

    let username = state
        .db
        .get_username(auth.user_id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    let rows = state.db.list_users().await.unwrap_or_default();
    let last_one = rows.len() <= 1;
    let operators: Vec<OperatorView> = rows
        .into_iter()
        .map(|u| {
            let is_you = u.id == auth.user_id;
            OperatorView {
                id: u.id,
                username: u.username,
                created_text: maybe_time_ago(Some(u.created_at)),
                is_you,
                deletable: !is_you && !last_one,
            }
        })
        .collect();

    let confirm_operator_name = operators
        .iter()
        .find(|o| o.id == view.confirm_operator_id)
        .map(|o| o.username.clone())
        .unwrap_or_default();
    // An id that names nobody expands nothing, rather than showing a
    // confirmation for an operator who is not there.
    let confirm_operator_id = if confirm_operator_name.is_empty() {
        0
    } else {
        view.confirm_operator_id
    };

    let sessions = crate::admin::api::sessions_snapshot(state, auth.session_token_hash.as_deref())
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|s| SessionView {
            id: s.id,
            username: s.username,
            ip: s.ip.unwrap_or_else(|| "—".to_string()),
            user_agent: s.user_agent.unwrap_or_else(|| "—".to_string()),
            created_text: maybe_time_ago(Some(s.created_at)),
            last_seen_text: maybe_time_ago(Some(s.last_seen)),
            is_current: s.is_current,
        })
        .collect();

    let api_keys = state
        .db
        .list_api_keys_for_user(auth.user_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|k| ApiKeyView {
            id: k.id,
            name: k.name,
            prefix: k.prefix,
            created_text: maybe_time_ago(Some(k.created_at)),
            last_used_text: maybe_time_ago(k.last_used_at),
            expires_text: expiry_text(k.expires_at),
        })
        .collect();

    AccountTemplate {
        shell,
        username,
        via_sso: auth.via_forward_auth,
        min_password_length: MIN_PASSWORD_LENGTH,
        error: view.error,
        password_changed: view.password_changed,
        operators,
        sessions,
        api_keys,
        operator_username: view.operator_username,
        operator_error: view.operator_error,
        confirm_operator_id,
        confirm_operator_name,
        confirm_operator_error: view.confirm_operator_error,
        api_key_name: view.api_key_name,
        api_key_expires: view.api_key_expires,
        api_key_error: view.api_key_error,
        new_key_name: view.new_key_name,
        new_key_token: view.new_key_token,
        account_saved,
        sessions_revoked,
    }
}

#[derive(Deserialize)]
pub struct AccountQuery {
    /// The operator whose row is expanded into a delete confirmation. Parsed
    /// leniently: a hand-edited value expands nothing rather than 400-ing a
    /// page that otherwise renders.
    confirm_delete: Option<String>,
}

pub async fn account_page(
    SsrUser(auth): SsrUser,
    State(state): State<AppState>,
    Query(query): Query<AccountQuery>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    let (shell, jar) = ShellData::build(&uri, &headers, jar);
    let view = AccountView {
        password_changed: shell.password_changed,
        confirm_operator_id: query
            .confirm_delete
            .as_deref()
            .and_then(|raw| raw.parse::<i64>().ok())
            .unwrap_or_default(),
        ..AccountView::default()
    };
    (jar, render_account(&state, &auth, shell, view).await)
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
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<PasswordForm>,
) -> Response {
    let reject = async |status: StatusCode, message: String, jar: CookieJar| {
        let (shell, jar) = ShellData::build_for("/account", &headers, jar);
        let view = AccountView {
            error: Some(message),
            ..AccountView::default()
        };
        (
            status,
            jar,
            render_account(&state, &auth, shell, view).await,
        )
            .into_response()
    };

    if form.new_password != form.confirm_password {
        return reject(
            StatusCode::BAD_REQUEST,
            "Passwords do not match".to_string(),
            jar,
        )
        .await;
    }
    // Cookie-only, like the JSON endpoint: an API-key or forward-auth caller
    // holds no session to rotate, and `SsrUser` alone does not prove which
    // session is being changed.
    let Some(token_hash) = auth.session_token_hash.clone() else {
        return reject(
            StatusCode::UNAUTHORIZED,
            "Changing a password needs a browser session".to_string(),
            jar,
        )
        .await;
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
            reject(status, message, CookieJar::new()).await
        }
    }
}

/// Everything that changed the account answers the same way: redirect back with
/// a notice, so a refresh cannot resubmit it.
fn account_saved(jar: CookieJar, flash: Flash) -> Response {
    (set_flash(jar, flash), Redirect::to("/account")).into_response()
}

/// Check the password a sensitive form carried, mapping the shared verdict onto
/// what the form has to show.
///
/// Every one of the three sensitive forms starts here, and none of them reaches
/// its action if this does not return `Ok` — which is the whole of the reauth
/// mechanism now that the dialog is gone.
async fn confirm_form_password(
    state: &AppState,
    auth: &AuthedUser,
    ip: std::net::IpAddr,
    password: &str,
) -> Result<(), (StatusCode, String)> {
    // A proxy-managed operator has no password to check — the proxy already
    // vouched for them, which is the same exemption `ReauthedUser` makes.
    if auth.via_forward_auth {
        return Ok(());
    }
    let Some(token_hash) = auth.session_token_hash.as_deref() else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "This action needs a browser session".to_string(),
        ));
    };
    match crate::admin::api::confirm_password(state, auth.user_id, token_hash, ip, password).await {
        Ok(()) => Ok(()),
        Err(ReauthError::RateLimited) => Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts — wait a minute, then retry".to_string(),
        )),
        Err(ReauthError::Invalid) => Err((
            StatusCode::UNAUTHORIZED,
            "Your password is incorrect".to_string(),
        )),
        Err(ReauthError::Internal) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not confirm your password — check the server log".to_string(),
        )),
    }
}

#[derive(Deserialize)]
pub struct AddOperatorForm {
    username: String,
    password: String,
    confirm: String,
    /// The acting operator's own password. In the form rather than behind a
    /// dialog, so this works identically with and without JavaScript.
    your_password: String,
}

/// `POST /account/operators`.
pub async fn account_operator_add_submit(
    SsrUser(auth): SsrUser,
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<AddOperatorForm>,
) -> Response {
    let ip = crate::admin::api::client_ip(&state, connect.as_deref(), &headers);
    // The username is kept across a rejection; neither password is. Re-rendering
    // a password field with its value in the markup would put it in the page
    // source, the browser's cache and any proxy along the way.
    let reject = async |status: StatusCode, message: String, jar: CookieJar| {
        let (shell, jar) = ShellData::build_for("/account", &headers, jar);
        let view = AccountView {
            operator_username: form.username.clone(),
            operator_error: message,
            ..AccountView::default()
        };
        (
            status,
            jar,
            render_account(&state, &auth, shell, view).await,
        )
            .into_response()
    };

    if form.password != form.confirm {
        return reject(
            StatusCode::BAD_REQUEST,
            "Passwords do not match".to_string(),
            jar,
        )
        .await;
    }
    if let Err((status, message)) =
        confirm_form_password(&state, &auth, ip, &form.your_password).await
    {
        return reject(status, message, jar).await;
    }

    match create_operator(&state, auth.user_id, ip, &form.username, &form.password).await {
        Ok(_id) => account_saved(jar, Flash::AccountSaved),
        Err(err) => {
            let (status, message) = match err {
                OperatorError::Invalid(message) => (StatusCode::BAD_REQUEST, message),
                OperatorError::Conflict => (
                    StatusCode::CONFLICT,
                    "That username is already taken".to_string(),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not add the operator — check the server log".to_string(),
                ),
            };
            reject(status, message, jar).await
        }
    }
}

#[derive(Deserialize)]
pub struct DeleteOperatorForm {
    your_password: String,
}

/// `POST /account/operators/{id}/delete`.
///
/// The row is expanded into this form by `?confirm_delete={id}`, so the
/// password field belongs to one named operator rather than sitting on every
/// row at once.
pub async fn account_operator_delete_submit(
    SsrUser(auth): SsrUser,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<DeleteOperatorForm>,
) -> Response {
    let ip = crate::admin::api::client_ip(&state, connect.as_deref(), &headers);
    let reject = async |status: StatusCode, message: String, jar: CookieJar| {
        let (shell, jar) = ShellData::build_for("/account", &headers, jar);
        let view = AccountView {
            confirm_operator_id: id,
            confirm_operator_error: message,
            ..AccountView::default()
        };
        (
            status,
            jar,
            render_account(&state, &auth, shell, view).await,
        )
            .into_response()
    };

    if let Err((status, message)) =
        confirm_form_password(&state, &auth, ip, &form.your_password).await
    {
        return reject(status, message, jar).await;
    }

    match remove_operator(&state, auth.user_id, ip, id).await {
        Ok(()) => account_saved(jar, Flash::AccountSaved),
        Err(err) => {
            let (status, message) = match err {
                OperatorError::LastOperator => (
                    StatusCode::CONFLICT,
                    "This is the last operator — deleting it would lock everyone out".to_string(),
                ),
                OperatorError::NotFound => (
                    StatusCode::NOT_FOUND,
                    "That operator is already gone".to_string(),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not delete the operator — check the server log".to_string(),
                ),
            };
            reject(status, message, jar).await
        }
    }
}

/// `POST /account/sessions/{id}/revoke`.
///
/// No password: any operator can already revoke any session through the API,
/// and a session that has to be killed in a hurry is exactly the one nobody
/// should have to stop and authenticate for.
pub async fn account_session_revoke_submit(
    SsrUser(auth): SsrUser,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let ip = crate::admin::api::client_ip(&state, connect.as_deref(), &headers);
    match crate::admin::api::revoke_session_row(
        &state,
        auth.user_id,
        ip,
        id,
        auth.session_token_hash.as_deref(),
    )
    .await
    {
        // Revoking your own session signs you out; there is no page left to
        // send a notice to, so the browser goes to sign-in with its cookies
        // cleared.
        Ok(true) => (
            crate::admin::api::clear_session_cookies(jar),
            [crate::admin::api::CLEAR_SITE_DATA],
            Redirect::to("/login"),
        )
            .into_response(),
        // A session that was already gone is the state the operator asked for,
        // so it reports the same as one this request took down.
        Ok(false) | Err(_) => account_saved(jar, Flash::SessionsRevoked),
    }
}

/// `POST /account/sessions/revoke-others`.
pub async fn account_sessions_revoke_others_submit(
    SsrUser(auth): SsrUser,
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let ip = crate::admin::api::client_ip(&state, connect.as_deref(), &headers);
    let _ = crate::admin::api::revoke_every_other_session(
        &state,
        auth.user_id,
        ip,
        auth.session_token_hash.as_deref(),
    )
    .await;
    account_saved(jar, Flash::SessionsRevoked)
}

#[derive(Deserialize)]
pub struct CreateApiKeyForm {
    name: String,
    /// `YYYY-MM-DD` from a date input, or empty for a key that never expires.
    expires: String,
    your_password: String,
}

/// `POST /account/api-keys`.
///
/// The one success on this page that does **not** redirect. The token exists
/// in this response and nowhere else — it is not stored — so a redirect would
/// throw away the only copy. The form is re-rendered empty, which is what stops
/// a refresh looking like it lost something; a refresh does re-post, and mints
/// a second key the operator can see and delete.
pub async fn account_api_key_create_submit(
    SsrUser(auth): SsrUser,
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<CreateApiKeyForm>,
) -> Response {
    let ip = crate::admin::api::client_ip(&state, connect.as_deref(), &headers);
    let reject = async |status: StatusCode, message: String, jar: CookieJar| {
        let (shell, jar) = ShellData::build_for("/account", &headers, jar);
        let view = AccountView {
            api_key_name: form.name.clone(),
            api_key_expires: form.expires.clone(),
            api_key_error: message,
            ..AccountView::default()
        };
        (
            status,
            jar,
            render_account(&state, &auth, shell, view).await,
        )
            .into_response()
    };

    let expires_at = match parse_expiry_date(&form.expires) {
        Ok(value) => value,
        Err(message) => return reject(StatusCode::BAD_REQUEST, message, jar).await,
    };
    if let Err((status, message)) =
        confirm_form_password(&state, &auth, ip, &form.your_password).await
    {
        return reject(status, message, jar).await;
    }

    match issue_api_key(&state, auth.user_id, &form.name, expires_at).await {
        Ok(created) => {
            let (shell, jar) = ShellData::build_for("/account", &headers, jar);
            let view = AccountView {
                new_key_name: created.name,
                new_key_token: created.token,
                ..AccountView::default()
            };
            (jar, render_account(&state, &auth, shell, view).await).into_response()
        }
        Err(ApiKeyError::Invalid(message)) => reject(StatusCode::BAD_REQUEST, message, jar).await,
        Err(ApiKeyError::Internal) => {
            reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not create the key — check the server log".to_string(),
                jar,
            )
            .await
        }
    }
}

/// Turn a `YYYY-MM-DD` date into the instant that day ends.
///
/// End of day rather than start: an operator who types today's date means the
/// key should last until today is over, not that it expired this morning. UTC,
/// because the server has no way to know the browser's zone and a key's expiry
/// is not worth guessing about.
fn parse_expiry_date(raw: &str) -> Result<Option<i64>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let invalid = || "Expiry must be a date (YYYY-MM-DD)".to_string();
    let mut parts = raw.split('-');
    let year: i64 = parts
        .next()
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_e| invalid())?;
    let month: i64 = parts
        .next()
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_e| invalid())?;
    let day: i64 = parts
        .next()
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_e| invalid())?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(invalid());
    }
    Ok(Some(days_from_civil(year, month, day) * 86_400 + 86_399))
}

/// Days since the Unix epoch for a civil date, by Howard Hinnant's `days_from_civil`.
///
/// Written out rather than pulled in: this is the only date arithmetic in the
/// codebase, and a dependency for one function is a dependency to audit forever.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `POST /account/api-keys/{id}/delete`.
///
/// No password, matching `DELETE /api/api-keys/{id}`: revoking a key you own
/// only ever reduces access.
pub async fn account_api_key_delete_submit(
    SsrUser(auth): SsrUser,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    jar: CookieJar,
) -> Response {
    let _ = crate::admin::api::revoke_api_key(&state, auth.user_id, id).await;
    account_saved(jar, Flash::AccountSaved)
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
    fn counts_switch_notation_only_above_a_million() {
        // The client draws these same cards every ten seconds; a count that
        // changed its own notation on the poll would read as a change in the
        // number.
        assert_eq!(format_num_adaptive(999_999), "999,999");
        assert_eq!(format_num_adaptive(1_000_000), "1M");
        assert_eq!(format_num_adaptive(1_250_000), "1.3M");
    }

    #[test]
    fn a_rate_is_one_decimal_of_a_percent() {
        assert_eq!(percent1(0.0), "0.0");
        assert_eq!(percent1(0.755), "75.5");
        assert_eq!(percent1(1.0), "100.0");
    }

    #[test]
    fn a_share_of_nothing_is_not_a_share() {
        assert_eq!(share_percent(0, 0), "");
        assert_eq!(share_percent(5, 0), "");
        // A row with no count takes no share, rather than "0.0%".
        assert_eq!(share_percent(0, 10), "");
        assert_eq!(share_percent(3, 4), "75.0%");
    }

    #[test]
    fn throughput_keeps_the_precision_the_number_deserves() {
        // `0.03 q/s` says something `0 q/s` does not.
        assert_eq!(format_qps(0.0333), "0.03");
        assert_eq!(format_qps(9.99), "9.99");
        assert_eq!(format_qps(12.34), "12.3");
        // And two decimals on a flood say nothing the integer does not.
        assert_eq!(format_qps(1234.56), "1235");
    }

    #[test]
    fn the_dns_target_pairs_the_browsers_host_with_the_dns_port() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::HOST, "noadd.lan:8080".parse().unwrap());
        // The HTTP port is dropped and the DNS listener's is used — that is the
        // one a device has to be told about.
        assert_eq!(dns_target(&headers, "0.0.0.0:53"), "noadd.lan:53");
        assert_eq!(dns_target(&headers, "127.0.0.1:5353"), "noadd.lan:5353");
        // Nothing port-shaped to take: the host alone is still useful.
        assert_eq!(dns_target(&headers, "53"), "noadd.lan");
    }

    #[test]
    fn civil_dates_convert_to_the_days_the_epoch_counts() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        // 2000 is a leap year (the 400 rule) and 2100 is not (the 100 rule);
        // both land the day after a February that differs in length.
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2100, 3, 1), 47_541);
    }

    #[test]
    fn an_expiry_date_lasts_until_that_day_is_over() {
        // Blank means a key that never expires, not one expiring at the epoch.
        assert_eq!(parse_expiry_date(""), Ok(None));
        assert_eq!(parse_expiry_date("   "), Ok(None));

        // 1970-01-01 ends one second before the second day begins. An operator
        // who types today's date means "until today is over", not "this
        // morning".
        assert_eq!(parse_expiry_date("1970-01-01"), Ok(Some(86_399)));
        assert_eq!(parse_expiry_date("1970-01-02"), Ok(Some(86_400 + 86_399)));

        for bad in [
            "not-a-date",
            "2027-13-01",
            "2027-01-32",
            "2027-01",
            "2027-01-01-01",
        ] {
            assert!(parse_expiry_date(bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn an_expiry_says_which_side_of_now_it_is_on() {
        let now = crate::now_unix();
        assert_eq!(expiry_text(None), "never");
        // A stored zero is "unset", not 1970.
        assert_eq!(expiry_text(Some(0)), "never");
        assert_eq!(expiry_text(Some(now - 60)), "expired");
        assert_eq!(expiry_text(Some(now + 86_400 * 30 + 10)), "in 30 days");
        assert_eq!(expiry_text(Some(now + 7_200 + 10)), "in 2 hours");
        // Under a minute still reads as time remaining rather than as "in 0".
        assert_eq!(expiry_text(Some(now + 5)), "in 1 minute");
    }

    #[test]
    fn a_column_with_nothing_in_it_says_so() {
        assert_eq!(maybe_time_ago(None), "—");
        assert_eq!(maybe_time_ago(Some(0)), "—");
        assert_eq!(maybe_time_ago(Some(crate::now_unix())), "0 seconds ago");
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
