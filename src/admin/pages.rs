//! Server-rendered admin pages.
//!
//! Kept apart from the JSON `/api/*` handlers in [`crate::admin::api`]: a page
//! answers in HTML with redirects, the API with status codes. The session is
//! resolved before any HTML is written, so an unauthenticated request is
//! redirected rather than painted and then repainted.
//!
//! Sign-in and setup need no CSRF token: the header-based origin guard
//! ([`crate::admin::csrf`]) refuses a cross-origin form post on every unsafe
//! method before it reaches a handler.

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

/// The sign-in screen.
///
/// `error` and `username` let a refused sign-in re-render with the message and
/// the typed username intact, which a redirect would discard.
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

/// One navigation entry. The single `NAV` table drives both the desktop strip
/// and the mobile F-key bar.
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

/// Everything the shell needs, independent of the page inside it. Each page
/// template embeds it as `shell`, which `shell.html` reads.
pub struct ShellData {
    version: &'static str,
    /// The request's `Host`, shown in the status bar. Attacker-influenced, so
    /// only ever interpolated by the (escaping) template.
    host: String,
    /// The path being served, so the matching navigation item renders active.
    current_path: String,
    nav: &'static [NavItem],
    welcome: bool,
    proxy_logout_notice: bool,
    /// Read by the settings page, next to its save button. Resolved here because
    /// this is where the flash is consumed; consuming it twice would lose it.
    settings_saved: bool,
    /// Read by the account page, for the same reason as `settings_saved`.
    password_changed: bool,
    /// Read by the filters page. Every change there triggers a rebuild, so one
    /// flag covers them all.
    filters_saved: bool,
    /// Read by the filters page. Separate because downloading every list is the
    /// one action whose effect is not immediate.
    lists_updating: bool,
    /// Read by the account page: an operator or API key was added or removed.
    account_saved: bool,
    /// Read by the account page; signing devices out gets its own wording.
    sessions_revoked: bool,
    /// Read by the query log: the history was emptied.
    logs_cleared: bool,
    /// Show the onboarding notice: never answered a query, not dismissed, and
    /// not on the dashboard.
    show_next_step: bool,
    /// Where to point a device, for that notice. Empty when it is not shown.
    next_step_addr: String,
}

impl ShellData {
    /// Build the shell's data for this request, consuming the pending flash.
    /// The returned jar clears it; a flash read but not cleared would repeat.
    async fn build(
        state: &AppState,
        uri: &Uri,
        headers: &HeaderMap,
        jar: CookieJar,
    ) -> (Self, CookieJar) {
        Self::build_for(state, uri.path(), headers, jar).await
    }

    /// The same, for a response whose page differs from the request path — e.g.
    /// a rejected `POST /account/operators` re-renders `/account`, and the
    /// navigation must mark that.
    async fn build_for(
        state: &AppState,
        path: &str,
        headers: &HeaderMap,
        jar: CookieJar,
    ) -> (Self, CookieJar) {
        let (flash, jar) = take_flash(jar);
        let next_step_addr = next_step_target(state, path, headers).await;
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
                logs_cleared: flash == Some(Flash::LogsCleared),
                show_next_step: next_step_addr.is_some(),
                next_step_addr: next_step_addr.unwrap_or_default(),
            },
            jar,
        )
    }
}

/// Where to tell an operator to point a device, or `None` when the notice is
/// not shown.
///
/// Checks run cheapest first: the hub's traffic latch settles it without a
/// database read on any install that has served traffic.
async fn next_step_target(state: &AppState, path: &str, headers: &HeaderMap) -> Option<String> {
    // The dashboard has its own empty state; both would read as two notices.
    if path == "/" || state.events.has_traffic() {
        return None;
    }
    match state.db.has_any_query_logs().await {
        Ok(true) => {
            // Set the latch now so these reads stop.
            state.events.note_traffic();
            return None;
        }
        Ok(false) => {}
        // A failed read hides the notice: wrongly showing it to a working
        // appliance is worse than briefly missing it on a fresh one.
        Err(_) => return None,
    }
    let dismissed = state.db.get_setting("onboarding_banner_dismissed").await;
    if matches!(dismissed, Ok(Some(value)) if value == "true") {
        return None;
    }
    Some(dns_target(headers, &state.server_info.dns_addr))
}

/// The settings page.
///
/// `error_field` names the field a rejected save objected to, so the template
/// puts the message next to that input. Empty when there is nothing to report.
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
    /// Back the three free-text fields' `<datalist>`s; the same constants the
    /// tests prove acceptable.
    block_custom_ipv4_suggestions: &'static [&'static str],
    block_custom_ipv6_suggestions: &'static [&'static str],
    log_retention_suggestions: &'static [i64],
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
    /// False for yourself and for the last operator, whose deletion the server
    /// refuses anyway.
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
/// Adding or deleting an operator and minting an API key carry a password field
/// in the form itself — no dialog, and the same path with or without
/// JavaScript. [`crate::admin::api::confirm_password`] is the one place this
/// and `POST /api/auth/reauth` check a password.
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

    /// Submitted values kept across a rejection. Never passwords.
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

    /// A newly minted token, set only on the response that created it: it is
    /// not stored, so this is the only chance to copy it.
    new_key_name: String,
    new_key_token: String,

    account_saved: bool,
    sessions_revoked: bool,
}

/// One filter list, formatted the way the page shows it.
///
/// Numbers and relative time are formatted here to match what `app.js`
/// produces when it re-draws a row.
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
    /// What stopping this list would cost, already phrased: `"41,200 rules"`,
    /// `"No impact"`, or why there is no number to give.
    impact_text: String,
    /// Zero impact — every rule is also in another list. Drawn as a badge.
    impact_none: bool,
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
/// Works without JavaScript: the domain test is a GET (the verdict lives in
/// the URL), every mutation a POST that redirects, and `edit_id` expands a row
/// into an edit form — which, with JavaScript, is a dialog instead.
#[derive(Template, WebTemplate)]
#[template(path = "filters.html")]
pub struct FiltersTemplate {
    shell: ShellData,
    lists: Vec<FilterListView>,
    rules: Vec<CustomRuleView>,
    /// Every list is off: noadd looks healthy but blocks nothing.
    all_disabled: bool,
    test_domain: String,
    /// Recently-queried domains for the tester's `<datalist>`; empty renders none.
    domain_suggestions: Vec<String>,
    /// Whether a domain was tested. Flat fields rather than an `Option<…>`, so
    /// the template needs only `{% if %}`.
    tested: bool,
    verdict_blocked: bool,
    /// The deciding rule. Empty when allowed by default (nothing matched, as
    /// opposed to an allow rule matching).
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

/// The dashboard: all readings, no forms. The six stat cards, three top-N
/// tables and the empty-state guide arrive filled in the first response.
///
/// The chart is the exception — `app.js` draws it — and without scripting the
/// card says so.
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
    /// The live rate from the server's 60-second window.
    qps_now: String,
    qps_today: String,
    qps_7d: String,

    /// False only on an appliance that has never answered a query.
    has_queries: bool,
    /// Where to point a device, for the empty-state guide.
    dns_addr: String,

    top_domains: Vec<TopRowView>,
    top_clients: Vec<TopRowView>,
    top_upstreams: Vec<TopRowView>,
}

/// One row of a horizontal bar list on the statistics page. Bar width (against
/// the largest row) and share (against the visible total) are computed here,
/// not in the template.
pub struct BarRowView {
    label: String,
    /// The fill's width as a percentage of the widest row, `"42.1"`. Always a
    /// number: it goes into a `style` attribute.
    width: String,
    /// The count as the cell shows it.
    count: String,
    /// `"12.3%"`, or empty when the total is zero and a share would be a lie.
    share: String,
    /// The full count (and share, if any) for the cell's `title`.
    count_title: String,
}

/// One tile in a `stat-grid`, for the two grids the statistics page builds from
/// values rather than from a fixed list of labels.
pub struct StatCardView {
    label: String,
    value: String,
    /// A class for the value's colour, e.g. `"accent"`. Never empty.
    value_class: &'static str,
    /// A unit set small after the value, e.g. `"ms"`. Empty for a dash.
    unit: &'static str,
    /// The second line under the value. Empty when there is none.
    sub: String,
    /// The value's `title`, for a number the cell abbreviated. Empty otherwise.
    title: String,
    /// Unix seconds behind a value the server could only write in UTC, for
    /// `app.js` to re-state in the browser's locale. Zero on every other card.
    ts: i64,
}

/// One of the three range links.
pub struct RangeOptionView {
    label: &'static str,
    active: bool,
}

/// The statistics page: the range switcher, four bar lists and two stat grids.
///
/// Only the three charts need a calendar, which needs the viewer's UTC offset —
/// known to the browser, not the request. So the charts ship as `series`
/// (quarter-hour counts on UTC boundaries, from the same scan as the
/// breakdowns) for `app.js` to fold; everything else is a plain `now - range`
/// window rendered on the server. The range picks the server's window, so the
/// switcher is links and the range lives in the URL.
#[derive(Template, WebTemplate)]
#[template(path = "stats.html")]
pub struct StatsTemplate {
    shell: ShellData,
    /// `"7d"` / `"30d"` / `"90d"`, for the card titles.
    range: &'static str,
    ranges: Vec<RangeOptionView>,
    /// A [`crate::db::QuarterSeries`] as JSON, for the charts to fold.
    series_json: String,
    /// The timeline's bucket width for this range, in seconds.
    bucket_secs: i64,

    highlights: Vec<StatCardView>,
    query_types: Vec<BarRowView>,
    outcomes: Vec<BarRowView>,
    top_domains: Vec<BarRowView>,
    top_clients: Vec<BarRowView>,
    health: Vec<StatCardView>,
}

/// One `<option>`, with `selected` decided here — comparing `String` to `&&str`
/// in askama is awkward.
pub struct OptionView {
    value: String,
    selected: bool,
}

/// One logged query, formatted the way the table shows it.
pub struct LogRowView {
    /// Milliseconds, matching `query_logs.timestamp` and what the client's
    /// per-second ticker reads out of `data-ts`.
    timestamp_ms: i64,
    time_text: String,
    blocked: bool,
    domain: String,
    /// The answer, when there was one worth showing. Empty otherwise.
    result: String,
    dnssec: bool,
    query_type: String,
    client_ip: String,
    doh_token: String,
    cached: bool,
    upstream: String,
    response_ms: i64,
    /// The rule this row's one-click action would add — an allow rule for a
    /// blocked query, a block rule for an allowed one.
    action_rule: String,
    action_label: String,
}

/// The query log.
///
/// Every filter and the page number live in the URL, so the page works without
/// JavaScript: the filters are a GET form, the pager two links. The live tail
/// needs the event stream, so its button ships hidden.
#[derive(Template, WebTemplate)]
#[template(path = "logs.html")]
pub struct LogsTemplate {
    shell: ShellData,
    rows: Vec<LogRowView>,
    /// The `DoH` tokens that exist, for the filter's dropdown.
    tokens: Vec<OptionView>,
    /// The record types the filter offers: a fixed list, not the ones present
    /// in the log, so a type is never mysteriously missing.
    query_types: Vec<OptionView>,

    /// Recently-queried domains for the search box's `<datalist>`; empty renders
    /// none.
    domain_suggestions: Vec<String>,

    /// The filters as submitted, so the form comes back showing what is applied.
    q: String,
    action: String,
    query_type: String,
    token: String,

    page: i64,
    total_pages: i64,
    total: String,
    has_prev: bool,
    has_next: bool,
    /// Complete query strings for the pager, so paging keeps the filters.
    prev_href: String,
    next_href: String,
    /// The current view as a path, carried by row actions to return here.
    current_href: String,
    /// Whether any filter is applied: an empty table then means "nothing
    /// matched" rather than "nothing has happened yet".
    filtered: bool,
}

/// An authenticated operator for a *page* request.
///
/// Wraps [`AuthedUser`], changing only the failure: a redirect to sign-in (with
/// the destination remembered) instead of a 401. Sharing the extractor keeps
/// pages and the API agreeing on who is signed in.
pub struct SsrUser(#[allow(dead_code)] pub AuthedUser);

impl FromRequestParts<AppState> for SsrUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        if let Ok(user) = AuthedUser::from_request_parts(parts, state).await {
            return Ok(Self(user));
        }
        // With no operator yet, sign-in cannot succeed; go to the wizard.
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

/// The operator, if the request carries a valid credential — for a page that
/// answers differently when signed in rather than refusing (e.g. `/login`
/// sends a signed-in browser onwards).
pub struct MaybeUser(pub Option<AuthedUser>);

impl FromRequestParts<AppState> for MaybeUser {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Infallible> {
        Ok(Self(
            AuthedUser::from_request_parts(parts, state).await.ok(),
        ))
    }
}

/// A one-shot notice left behind by a redirect.
///
/// A closed set, not free text: only the identifier travels in the cookie, so
/// it cannot break the header or carry text the server did not write. The
/// wording lives in the template.
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
    /// The query log was emptied.
    LogsCleared,
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
            Self::LogsCleared => "logs_cleared",
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
            "logs_cleared" => Some(Self::LogsCleared),
            // A stale or hand-written cookie: no notice.
            _ => None,
        }
    }
}

/// The cookie a flash rides in.
///
/// A cookie rather than the query string, which would survive refreshes,
/// bookmarks and shared links. Session-scoped (no `Max-Age`) on purpose.
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
/// One step, so a rendered flash cannot survive to show again.
fn take_flash(jar: CookieJar) -> (Option<Flash>, CookieJar) {
    let Some(flash) = jar.get(FLASH_COOKIE).and_then(|c| Flash::parse(c.value())) else {
        return (None, jar);
    };
    let jar = jar.remove(Cookie::build((FLASH_COOKIE, "")).path("/").build());
    (Some(flash), jar)
}

/// Accept only a same-origin destination expressed as an absolute path.
///
/// `next` is attacker-controlled: `/login?next=https://evil.example` would be
/// an open redirect behind noadd's own URL. Protocol-relative `//evil.example`
/// and `/\evil.example` (which browsers normalise into it) are refused too, as
/// are control characters, since the value lands in a `Location` header.
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
/// `/` is omitted: sign-in lands there anyway.
fn login_url(next: Option<&str>) -> String {
    match next.and_then(safe_next) {
        Some(target) if target != "/" => format!("/login?next={}", encode_query_value(target)),
        _ => "/login".to_string(),
    }
}

/// Percent-encode a path so it survives as a single query-string value.
///
/// Conservative: only unreserved characters and `/` pass, so no `?`, `#` or `&`
/// can silently truncate the value.
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

#[derive(Deserialize)]
pub struct NextQuery {
    next: Option<String>,
}

/// The `Host` this request arrived on.
///
/// Client-supplied: fine for the status bar label (the template escapes it),
/// never for identity.
fn request_host(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// `POST /logout`.
///
/// A form, so it works without JavaScript; a POST, so a link prefetcher cannot
/// sign anyone out.
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
        // Proxy-managed with nowhere to hand off to: the next request carries
        // the same header, so tell the operator where to end the session. No
        // `Clear-Site-Data`, which would also wipe the flash explaining this.
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
/// A refusal re-renders the form (keeping the message and username) with a
/// real status: 401 for a bad credential, 429 for the rate limit, never 200.
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
/// The confirm field exists only in the form, so it is checked here rather than
/// in the shared `create_first_operator`. A successful setup signs the operator
/// straight in.
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
        Ok(jar) => (set_flash(jar, Flash::Welcome), Redirect::to("/")).into_response(),
        // The account exists; only the automatic sign-in failed, so `/login`
        // rather than a wizard that would refuse to run again.
        Err(_) => Redirect::to("/login").into_response(),
    }
}

/// Rows per page of the log; matches `app.js`'s `limit`.
const LOGS_PAGE_SIZE: i64 = 50;

#[derive(Deserialize)]
pub struct LogsQuery {
    /// Domain prefix, or a `*pattern*` for a substring match.
    q: Option<String>,
    /// `""`, `"allowed"` or `"blocked"`.
    action: Option<String>,
    /// A DNS record type, e.g. `A`.
    #[serde(rename = "type")]
    query_type: Option<String>,
    /// A `DoH` URL token.
    token: Option<String>,
    /// 1-based. Parsed leniently: a bad value means page one, not a 400.
    page: Option<String>,
}

impl LogsQuery {
    /// The filters, trimmed, with empty strings treated as "not applied".
    fn applied(&self) -> (String, String, String, String) {
        let clean =
            |value: Option<&String>| value.map(|v| v.trim().to_string()).unwrap_or_default();
        (
            clean(self.q.as_ref()),
            clean(self.action.as_ref()),
            clean(self.query_type.as_ref()),
            clean(self.token.as_ref()),
        )
    }
}

/// Rebuild the page's query string, with `page` replaced.
///
/// The pager must carry every filter, or paging silently drops them.
fn logs_query_string(q: &str, action: &str, query_type: &str, token: &str, page: i64) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut push = |key: &str, value: &str| {
        if !value.is_empty() {
            parts.push(format!("{key}={}", encode_query_value(value)));
        }
    };
    push("q", q);
    push("action", action);
    push("type", query_type);
    push("token", token);
    if page > 1 {
        parts.push(format!("page={page}"));
    }
    parts.join("&")
}

/// `/logs`, with a query string when there is one.
fn logs_href(query: &str) -> String {
    if query.is_empty() {
        "/logs".to_string()
    } else {
        format!("/logs?{query}")
    }
}

pub async fn logs_page(
    _user: SsrUser,
    State(state): State<AppState>,
    Query(query): Query<LogsQuery>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    let (shell, jar) = ShellData::build(&state, &uri, &headers, jar).await;
    let (q, action, query_type, token) = query.applied();
    let page = query
        .page
        .as_deref()
        .and_then(|raw| raw.parse::<i64>().ok())
        .unwrap_or(1)
        .max(1);

    let blocked = match action.as_str() {
        "blocked" => Some(true),
        "allowed" => Some(false),
        _ => None,
    };
    let as_filter = |value: &str| {
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    };
    let search = as_filter(&q);
    let type_filter = as_filter(&query_type);
    let token_filter = as_filter(&token);

    let offset = (page - 1) * LOGS_PAGE_SIZE;
    // Run concurrently rather than as two sequential round trips.
    let (entries, total) = tokio::join!(
        state.db.query_logs(
            LOGS_PAGE_SIZE,
            offset,
            search.as_deref(),
            blocked,
            token_filter.as_deref(),
            type_filter.as_deref(),
        ),
        state.db.count_logs(
            search.as_deref(),
            blocked,
            token_filter.as_deref(),
            type_filter.as_deref(),
        ),
    );
    let entries = entries.unwrap_or_default();
    let total = total.unwrap_or_default();

    let rows = entries
        .into_iter()
        .map(|entry| {
            let blocked = entry.blocked;
            let domain = entry.domain;
            LogRowView {
                // The column is milliseconds; `time_ago` counts seconds.
                time_text: time_ago(entry.timestamp / 1000),
                timestamp_ms: entry.timestamp,
                blocked,
                // The one-click action is the opposite of the verdict.
                action_rule: if blocked {
                    format!("@@||{domain}^")
                } else {
                    format!("||{domain}^")
                },
                action_label: if blocked { "Allow" } else { "Block" }.to_string(),
                domain,
                result: entry.result.unwrap_or_default(),
                dnssec: entry.authenticated_data,
                query_type: entry.query_type,
                client_ip: entry.client_ip,
                doh_token: entry.doh_token.unwrap_or_default(),
                cached: entry.cached,
                upstream: entry.upstream.unwrap_or_default(),
                response_ms: entry.response_ms,
            }
        })
        .collect();

    let tokens = state
        .db
        .get_doh_tokens()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|t| OptionView {
            selected: t.token == token,
            value: t.token,
        })
        .collect();
    let query_types = LOG_QUERY_TYPES
        .iter()
        .map(|t| OptionView {
            value: (*t).to_string(),
            selected: query_type == *t,
        })
        .collect();

    // `i64::div_ceil` is unstable (only the unsigned one is stable).
    let total_pages = ((total + LOGS_PAGE_SIZE - 1) / LOGS_PAGE_SIZE).max(1);
    let href_for =
        |page: i64| logs_href(&logs_query_string(&q, &action, &query_type, &token, page));

    let domain_suggestions =
        crate::admin::stats::domain_suggestions(&state.db, crate::now_unix()).await;

    (
        jar,
        LogsTemplate {
            shell,
            rows,
            tokens,
            query_types,
            domain_suggestions,
            filtered: !(q.is_empty()
                && action.is_empty()
                && query_type.is_empty()
                && token.is_empty()),
            page,
            total_pages,
            total: thousands(total),
            has_prev: page > 1,
            has_next: page < total_pages,
            prev_href: href_for(page - 1),
            next_href: href_for(page + 1),
            current_href: href_for(page),
            q,
            action,
            query_type,
            token,
        },
    )
}

/// The record types the log's filter offers.
const LOG_QUERY_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA", "HTTPS",
];

#[derive(Deserialize)]
pub struct LogRuleForm {
    rule: String,
    /// The view to return to, keeping the filters and page.
    next: Option<String>,
}

/// `POST /logs/rules`.
///
/// The one-click Allow/Block on a row, through the same `create_custom_rule`
/// as `POST /api/rules` and the filters page.
pub async fn logs_rule_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LogRuleForm>,
) -> Response {
    let _ = create_custom_rule(&state, &form.rule).await;
    let target = form
        .next
        .as_deref()
        .and_then(safe_next)
        .unwrap_or("/logs")
        .to_string();
    (set_flash(jar, Flash::FiltersSaved), Redirect::to(&target)).into_response()
}

/// `POST /logs/clear`.
///
/// Always answers on the unfiltered first page: a filtered view would read "No
/// logs found", as if the filter broke.
pub async fn logs_clear_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    jar: CookieJar,
) -> Response {
    let _ = state.db.delete_all_logs().await;
    (set_flash(jar, Flash::LogsCleared), Redirect::to("/logs")).into_response()
}

/// Full digits below a million, abbreviated above it.
///
/// Mirrors `formatNumAdaptive` in `app.js`, which redraws the same cards from
/// each pushed snapshot; a count that switched notation would look like it
/// changed.
fn format_num_adaptive(n: i64) -> String {
    format_num_adaptive_at(n, 1_000_000)
}

/// The same with a custom threshold — the statistics tiles for totals that
/// run to eight digits hold off until ten million.
fn format_num_adaptive_at(n: i64, threshold: i64) -> String {
    if n < threshold {
        thousands(n)
    } else {
        compact(n)
    }
}

/// A fraction as a one-decimal percentage.
fn percent1(value: f64) -> String {
    format!("{:.1}", value * 100.0)
}

/// One row's share of the visible total; empty when there is none.
fn share_percent(count: i64, sum: i64) -> String {
    if sum <= 0 || count <= 0 {
        return String::new();
    }
    #[allow(clippy::cast_precision_loss)]
    let pct = count as f64 / sum as f64 * 100.0;
    format!("{pct:.1}%")
}

/// Queries per second: two decimals on a trickle, none on a flood. Matches
/// `fmtQps` in `app.js`.
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
/// Host from the request (a name that resolves), port from the DNS listener —
/// whose bind address is often `0.0.0.0`, useless to type in.
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
    let (shell, jar) = ShellData::build(&state, &uri, &headers, jar).await;
    let now = crate::now_unix();

    // The same reads as the pushed `stats` snapshot, minus the chart's timeline.
    // A failure renders zeroes rather than an error page.
    let summary = crate::admin::stats::compute_summary(&state.db, now)
        .await
        .unwrap_or_default();
    // Ten rows each, what the page shows.
    let (domains, clients) =
        crate::admin::stats::compute_top_domains_and_clients(&state.db, now, 10)
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

/// The statistics page's one parameter.
#[derive(Deserialize)]
pub struct StatsQuery {
    range: Option<String>,
}

/// Bytes at the precision the size deserves, for the database-health grid.
fn format_bytes(bytes: i64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    #[allow(clippy::cast_precision_loss)]
    let value = bytes as f64;
    if value >= GB {
        format!("{:.2} GB", value / GB)
    } else if value >= MB {
        format!("{:.2} MB", value / MB)
    } else if value >= KB {
        format!("{:.1} KB", value / KB)
    } else {
        format!("{bytes} B")
    }
}

/// The same, with a dash where zero means "no data" rather than "zero bytes".
fn format_bytes_or_dash(value: f64) -> String {
    if value > 0.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
        format_bytes(value.round() as i64)
    } else {
        "—".to_string()
    }
}

/// A date the way the server can write one: an ISO day, in UTC.
///
/// The cell also carries its timestamp for `app.js` to restate in the browser's
/// locale, which the server cannot know.
fn iso_date(ts: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(ts).map_or_else(
        |_err| "—".to_string(),
        |dt| {
            format!(
                "{:04}-{:02}-{:02}",
                dt.year(),
                u8::from(dt.month()),
                dt.day()
            )
        },
    )
}

/// Turn counted labels into a bar list, largest first.
///
/// Bars are scaled to the largest count, so near-equal rows stay readable; the
/// percentage is the share of the total.
fn bar_rows(entries: Vec<(String, i64)>) -> Vec<BarRowView> {
    let mut entries = entries;
    entries.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    let max = entries.iter().map(|(_, count)| *count).max().unwrap_or(0);
    let sum: i64 = entries.iter().map(|(_, count)| *count).sum();
    entries
        .into_iter()
        .map(|(label, count)| {
            let share = share_percent(count, sum);
            #[allow(clippy::cast_precision_loss)]
            let width = if max > 0 {
                format!("{:.1}", count as f64 / max as f64 * 100.0)
            } else {
                "0.0".to_string()
            };
            let full = thousands(count);
            let count_title = if share.is_empty() {
                full
            } else {
                format!("{full} ({share})")
            };
            BarRowView {
                label,
                width,
                count: format_num_adaptive(count),
                share,
                count_title,
            }
        })
        .collect()
}

/// A stat tile, for the two grids the page builds from values.
fn stat_card(label: &str, value: String, value_class: &'static str) -> StatCardView {
    StatCardView {
        label: label.to_string(),
        value,
        value_class,
        unit: "",
        sub: String::new(),
        title: String::new(),
        ts: 0,
    }
}

/// How many rows the two ranged bar lists show. (The `/api/stats/v2` lists
/// default to 15.)
const STATS_TOP_N: i64 = 10;

/// The statistics page.
///
/// Every reading is in this response, charts included: they ship as a UTC
/// quarter-hour `series` that `app.js` folds into the viewer's calendar, with
/// no request of its own. A failed read renders as an empty list or a dash.
pub async fn stats_page(
    _user: SsrUser,
    State(state): State<AppState>,
    Query(query): Query<StatsQuery>,
    uri: Uri,
    headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    use crate::admin::stats;

    let (shell, jar) = ShellData::build(&state, &uri, &headers, jar).await;
    let now = crate::now_unix();
    // An unrecognised range renders the default rather than a 400.
    let range = query
        .range
        .as_deref()
        .and_then(stats::StatsRange::parse)
        .unwrap_or(stats::StatsRange::Days7);

    // Independent reads, run concurrently.
    let (range_stats, health) = tokio::join!(
        stats::compute_range_stats(&state.db, now, range, STATS_TOP_N),
        stats::compute_db_health(&state.db, now),
    );

    let range_stats = range_stats.ok();
    let latency = range_stats.as_ref().map(|s| &s.metrics.latency);
    // No samples means no percentiles; a zero would read as impossibly fast.
    let has_latency = latency.is_some_and(|l| l.sample_count > 0);
    let latency_card = |label: &str, value: i64, class: &'static str| StatCardView {
        unit: if has_latency { "ms" } else { "" },
        ..stat_card(
            label,
            if has_latency {
                compact(value)
            } else {
                "—".to_string()
            },
            class,
        )
    };
    let unique_domains = range_stats.as_ref().map_or(0, |s| s.domains.unique);
    let highlight_cards = vec![
        StatCardView {
            title: thousands(unique_domains),
            ..stat_card(
                "Unique Domains",
                format_num_adaptive_at(unique_domains, 10_000_000),
                "accent",
            )
        },
        latency_card("Latency p50", latency.map_or(0, |l| l.p50_ms), "text-green"),
        latency_card(
            "Latency p95",
            latency.map_or(0, |l| l.p95_ms),
            "text-orange",
        ),
        latency_card("Latency p99", latency.map_or(0, |l| l.p99_ms), "text-red"),
    ];

    let series_json = serde_json::to_string(
        &range_stats
            .as_ref()
            .map(|s| s.series.clone())
            .unwrap_or_default(),
    )
    .expect("a series of integers always serializes");

    let (query_types, outcomes, top_domains, top_clients) = range_stats
        .map(|s| {
            (
                bar_rows(s.metrics.query_types),
                bar_rows(s.metrics.outcomes),
                bar_rows(
                    s.domains
                        .top
                        .into_iter()
                        .map(|d| (d.domain, d.count))
                        .collect(),
                ),
                // Name a `DoH` client by IP and token; the IP alone would merge
                // every token behind one proxy.
                bar_rows(
                    s.clients
                        .into_iter()
                        .map(|c| {
                            let label = match c.doh_token {
                                Some(token) if !token.is_empty() => {
                                    format!("{} · {token}", c.client_ip)
                                }
                                _ => c.client_ip,
                            };
                            (label, c.count)
                        })
                        .collect(),
                ),
            )
        })
        .unwrap_or_default();

    let health_cards = health.map(build_health_cards).unwrap_or_default();

    let ranges = ["7d", "30d", "90d"]
        .into_iter()
        .map(|label| RangeOptionView {
            label,
            active: label == range.label(),
        })
        .collect();

    (
        jar,
        StatsTemplate {
            shell,
            range: range.label(),
            ranges,
            series_json,
            bucket_secs: range.bucket_secs(),
            highlights: highlight_cards,
            query_types,
            outcomes,
            top_domains,
            top_clients,
            health: health_cards,
        },
    )
}

/// The ten database-health tiles, in the order the grid shows them.
fn build_health_cards(health: crate::admin::stats::DbHealth) -> Vec<StatCardView> {
    #[allow(clippy::cast_possible_truncation)]
    let frag_pct = (health.fragmentation_ratio * 100.0).round() as i64;
    let coverage = if health.log_coverage_days > 0.0 {
        if health.log_coverage_days >= 10.0 {
            format!("{:.0}d", health.log_coverage_days.round())
        } else {
            format!("{:.1}d", health.log_coverage_days)
        }
    } else {
        "—".to_string()
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    let avg_per_day = if health.avg_new_rows_per_day > 0.0 {
        compact(health.avg_new_rows_per_day.round() as i64)
    } else {
        "—".to_string()
    };
    let growth_per_day = format_bytes_or_dash(health.bytes_per_log * health.avg_new_rows_per_day);
    let oldest = health.oldest_log_timestamp.filter(|ts| *ts > 0);

    vec![
        stat_card(
            "Database Size",
            format_bytes(health.db_size_bytes),
            "accent",
        ),
        StatCardView {
            title: thousands(health.total_log_count),
            ..stat_card(
                "Total Logs",
                format_num_adaptive_at(health.total_log_count, 10_000_000),
                "accent",
            )
        },
        stat_card(
            "Bytes / Log",
            format_bytes_or_dash(health.bytes_per_log),
            "accent",
        ),
        StatCardView {
            sub: format!("{frag_pct}% of file"),
            ..stat_card(
                "Reclaimable",
                format_bytes(health.reclaimable_bytes.max(0)),
                "accent",
            )
        },
        StatCardView {
            ts: oldest.unwrap_or(0),
            ..stat_card(
                "Oldest Log",
                oldest.map_or_else(|| "—".to_string(), iso_date),
                "stat-date",
            )
        },
        stat_card("Log Coverage", coverage, "accent"),
        stat_card(
            "Retention",
            health
                .log_retention_days
                .map_or_else(|| "—".to_string(), |days| format!("{days}d")),
            "accent",
        ),
        stat_card("Avg / Day", avg_per_day, "accent"),
        stat_card("Growth / Day", growth_per_day, "accent"),
        StatCardView {
            sub: "at full retention".to_string(),
            ..stat_card(
                "Projected Full",
                if health.projected_full_bytes > 0 {
                    format_bytes(health.projected_full_bytes)
                } else {
                    "—".to_string()
                },
                "accent",
            )
        },
    ]
}

/// When an API key stops working.
///
/// `never`, `in 30 days`, or `expired`.
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

/// A timestamp that may be unset (`0` or `None`), rendered as a dash.
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

/// Phrase what removing one list would cost, from the engine's per-list counts.
///
/// Distinct phrases rather than one number: only a list in the engine gets a
/// count, and a zero anywhere else would falsely read as "redundant". Must
/// phrase it the same as `listImpact` in `app.js`.
pub fn list_impact<S: std::hash::BuildHasher>(
    unique: &std::collections::HashMap<i64, u32, S>,
    list: &crate::db::FilterListRow,
) -> (String, bool) {
    match unique.get(&list.id) {
        Some(0) => ("No impact".to_string(), true),
        Some(&1) => ("1 rule".to_string(), false),
        Some(&count) => (format!("{} rules", thousands(i64::from(count))), false),
        None if !list.enabled => ("Disabled".to_string(), false),
        // Enabled but not in the engine: its rules are all allow rules, or it
        // has none (failed download or empty parse) — say which.
        None if list.rule_count > 0 => ("No block rules".to_string(), false),
        None => ("No rules".to_string(), false),
    }
}

/// Build the page from live storage plus whatever the caller is carrying.
///
/// The shell comes in built — via `ShellData::build_for("/account", …)` on the
/// POST paths, so the account tab stays active.
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
    // An id naming nobody expands nothing.
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
    /// leniently: a bad value expands nothing rather than 400ing.
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
    let (shell, jar) = ShellData::build(&state, &uri, &headers, jar).await;
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
/// The confirmation field exists only in the form, so it is checked here, not
/// in the shared `change_password_for_session`. A success redirects: the
/// session cookie was rotated, and a re-render would keep the old password in
/// the form.
pub async fn account_password_submit(
    SsrUser(auth): SsrUser,
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<PasswordForm>,
) -> Response {
    let reject = async |status: StatusCode, message: String, jar: CookieJar| {
        let (shell, jar) = ShellData::build_for(&state, "/account", &headers, jar).await;
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
    // Cookie-only, like the JSON endpoint: API-key and forward-auth callers
    // hold no session to rotate.
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
            // The failed attempt consumed the jar without setting anything on it.
            reject(status, message, CookieJar::new()).await
        }
    }
}

/// Redirect back with a notice, so a refresh cannot resubmit the change.
fn account_saved(jar: CookieJar, flash: Flash) -> Response {
    (set_flash(jar, flash), Redirect::to("/account")).into_response()
}

/// Check the password a sensitive form carried, mapped onto the form's message.
/// All three sensitive forms gate their action on this returning `Ok`.
async fn confirm_form_password(
    state: &AppState,
    auth: &AuthedUser,
    ip: std::net::IpAddr,
    password: &str,
) -> Result<(), (StatusCode, String)> {
    // The proxy already vouched for a forward-auth operator, as in `ReauthedUser`.
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
    /// The acting operator's own password.
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
    // Keep the username across a rejection, never a password (it would land in
    // the page source and caches).
    let reject = async |status: StatusCode, message: String, jar: CookieJar| {
        let (shell, jar) = ShellData::build_for(&state, "/account", &headers, jar).await;
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
/// The form appears on the row expanded by `?confirm_delete={id}`, so the
/// password field belongs to one named operator.
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
        let (shell, jar) = ShellData::build_for(&state, "/account", &headers, jar).await;
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
/// No password, like `DELETE /api/sessions/{id}`: a session killed in a hurry
/// should not wait on authentication.
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
        // Revoking your own session signs you out: go to sign-in, cookies cleared.
        Ok(true) => (
            crate::admin::api::clear_session_cookies(jar),
            [crate::admin::api::CLEAR_SITE_DATA],
            Redirect::to("/login"),
        )
            .into_response(),
        // Already gone is the state asked for, so it reports the same.
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
pub struct DismissNextStepForm {
    /// The page to return to, validated by `safe_next`.
    next: String,
}

/// `POST /onboarding/dismiss`.
///
/// A real form, so dismissal works without JavaScript. Writes the same setting
/// as the JSON API.
pub async fn onboarding_dismiss_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<DismissNextStepForm>,
) -> Response {
    // On failure the notice just comes back later, which beats a 500.
    let _ = state
        .db
        .set_setting("onboarding_banner_dismissed", "true")
        .await;
    // No flash: the operator asked for one less notice, not another.
    let target = safe_next(&form.next).unwrap_or("/");
    (jar, Redirect::to(target)).into_response()
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
/// The one success here that does **not** redirect: the token is not stored,
/// so a redirect would discard the only copy. A refresh re-posts and mints a
/// second key, which the operator can see and delete.
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
        let (shell, jar) = ShellData::build_for(&state, "/account", &headers, jar).await;
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
            let (shell, jar) = ShellData::build_for(&state, "/account", &headers, jar).await;
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
/// End of day, so today's date means "until today is over". UTC, since the
/// server does not know the browser's zone.
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

/// The settings the page renders; absent keys are simply missing (read as empty).
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
/// The persisted settings on a GET, the *submitted* ones on a rejected save, so
/// only the wrong field needs correcting.
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
        // Defaults mirror the DNS layer's fallbacks for an unset value.
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
        block_custom_ipv4_suggestions: crate::admin::api::BLOCK_CUSTOM_IPV4_SUGGESTIONS,
        block_custom_ipv6_suggestions: crate::admin::api::BLOCK_CUSTOM_IPV6_SUGGESTIONS,
        log_retention_suggestions: crate::admin::stats::LOG_RETENTION_DAYS_SUGGESTIONS,
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
    let (shell, jar) = ShellData::build(&state, &uri, &headers, jar).await;
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
    /// `on` / `off`, the inverse of the stored `dnssec_disabled`.
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
/// One submit for every scalar setting, for use without JavaScript; `app.js`
/// removes the button and autosaves per field against `/api/settings`. Success
/// redirects so a refresh cannot resubmit.
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
            // Re-render with what was submitted, not what is stored.
            let (shell, jar) = ShellData::build(&state, &uri, &headers, jar).await;
            (
                status,
                jar,
                settings_template(shell, &values, field, message, false),
            )
                .into_response()
        }
    }
}

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

/// How long ago a timestamp was, worded as `app.js` words it, so a redrawn row
/// keeps its phrasing.
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
/// `shell.current_path` is forced to `/filters`, since a rejected POST arrives
/// on a sub-path and the navigation must still mark the page.
async fn render_filters(
    state: &AppState,
    mut shell: ShellData,
    view: FiltersView,
) -> FiltersTemplate {
    shell.current_path = "/filters".to_string();

    let rows = state.db.get_filter_lists().await.unwrap_or_default();
    let all_disabled = !rows.is_empty() && rows.iter().all(|l| !l.enabled);
    // From the live engine, not storage: it describes the loaded rule set, and
    // every list change already triggers the rebuild that recomputes it.
    let unique = state.filter.load().unique_rules_by_list();
    let lists = rows
        .into_iter()
        .map(|l| {
            let (impact_text, impact_none) = list_impact(&unique, &l);
            FilterListView {
                id: l.id,
                name: l.name,
                url: l.url,
                enabled: l.enabled,
                rule_count: thousands(l.rule_count),
                rule_count_compact: compact(l.rule_count),
                last_updated_text: time_ago(l.last_updated),
                last_updated: l.last_updated,
                impact_text,
                impact_none,
            }
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

    // Checked against the live engine, as `POST /api/filter/check` does.
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

    let domain_suggestions =
        crate::admin::stats::domain_suggestions(&state.db, crate::now_unix()).await;

    FiltersTemplate {
        shell,
        lists,
        rules,
        all_disabled,
        test_domain: view.test_domain,
        domain_suggestions,
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
    /// A domain to test; in the URL so the verdict survives refresh and links.
    test: Option<String>,
    /// The list to expand into an edit form. Parsed leniently: a bad value
    /// expands nothing rather than 400ing.
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
    let (shell, jar) = ShellData::build(&state, &uri, &headers, jar).await;
    let edit_id = query
        .edit
        .as_deref()
        .and_then(|raw| raw.parse::<i64>().ok())
        .unwrap_or_default();

    // Filled from storage, never the URL, so a link cannot pre-fill the form.
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

/// Redirect back with a notice, so a refresh cannot resubmit the change.
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
            // Adding does not fetch the list, so there is nothing to rebuild yet.
            filters_saved(jar, Flash::FiltersSaved)
        }
        Err(err) => {
            let (status, field, message) = list_error_parts(err);
            let (shell, jar) = ShellData::build(&state, &uri, &headers, jar).await;
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
/// A rejected edit re-renders the row expanded with the submitted values.
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
            let (shell, jar) = ShellData::build(&state, &uri, &headers, jar).await;
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
    /// Absent when unticked: a browser does not post an unchecked box.
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
/// Downloads every list before answering, as `POST /api/lists/update` does; the
/// pending request is the progress indicator.
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
/// The escape hatch when every list is off: re-enable one. Same pick as
/// `app.js`.
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
        // A duplicate is not an error: the wanted rule is there.
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
            let (shell, jar) = ShellData::build(&state, &uri, &headers, jar).await;
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

/// A link that is safe to put in an `href`.
///
/// Escaping keeps a value inside its attribute but does not make it safe to
/// navigate to: a third-party registry could supply a `javascript:` homepage.
/// Only absolute `http(s)` survives; anything else yields an empty string and
/// no link.
fn safe_url(raw: Option<&str>) -> String {
    let candidate = raw.unwrap_or_default().trim();
    let lowered = candidate.to_ascii_lowercase();
    if lowered.starts_with("http://") || lowered.starts_with("https://") {
        candidate.to_string()
    } else {
        String::new()
    }
}

/// The registry page's filters, all three of them in the URL.
#[derive(Deserialize, Default)]
pub struct RegistryQuery {
    q: Option<String>,
    group: Option<String>,
    deprecated: Option<String>,
}

impl RegistryQuery {
    /// The search term, trimmed, as both the filter and the value the box keeps.
    fn search(&self) -> String {
        self.q.as_deref().unwrap_or_default().trim().to_string()
    }

    fn group_id(&self) -> Option<i64> {
        self.group.as_deref().and_then(|raw| raw.parse().ok())
    }

    fn show_deprecated(&self) -> bool {
        self.deprecated.is_some()
    }

    /// The query string that returns to this exact view, for the form the page
    /// posts to and for the link back from a failure.
    fn to_query_string(&self) -> String {
        let mut parts = Vec::new();
        let search = self.search();
        if !search.is_empty() {
            parts.push(format!("q={}", encode_query_value(&search)));
        }
        if let Some(group) = self.group_id() {
            parts.push(format!("group={group}"));
        }
        if self.show_deprecated() {
            parts.push("deprecated=1".to_string());
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("?{}", parts.join("&"))
        }
    }
}

/// One registry entry as the list shows it.
pub struct RegistryRowView {
    filter_id: i64,
    /// The entry's group, for the client's in-place filtering; the same id the
    /// `<select>` carries.
    group_id: i64,
    name: String,
    description: String,
    /// The list's own page if safe to link; empty renders no link.
    homepage: String,
    group_name: String,
    /// The pill's colour class.
    group_class: &'static str,
    /// Already among the operator's lists: shown checked and disabled, not hidden.
    already_added: bool,
    deprecated: bool,
}

/// One `<option>` in the group filter.
pub struct RegistryGroupView {
    value: String,
    label: String,
    selected: bool,
}

/// One list the batch could not add, and why.
pub struct RegistryFailureView {
    name: String,
    error: String,
}

/// The registry browser.
///
/// A page (not a modal) so it works without JavaScript: three filters in the
/// URL and one form posting what is ticked. The registry is a third party, so
/// `load_failed` is a rendered state whose retry is a link to the same URL.
#[derive(Template, WebTemplate)]
#[template(path = "registry.html")]
pub struct RegistryTemplate {
    shell: ShellData,
    /// What the search box keeps.
    q: String,
    groups: Vec<RegistryGroupView>,
    show_deprecated: bool,
    rows: Vec<RegistryRowView>,
    /// The registry could not be fetched (a third-party outage).
    load_failed: bool,
    /// How many entries the filters let through, and how many exist.
    shown: usize,
    total: usize,
    /// The query string that returns to this view, carried by the form.
    current_query: String,
    /// How many lists the batch just added. Zero on a plain GET.
    added_count: usize,
    /// What it could not add. Empty on a plain GET.
    failures: Vec<RegistryFailureView>,
    /// The cap the page will not let a selection exceed.
    limit: usize,
}

/// Which colour class a group's pill gets, from its name.
fn registry_group_class(group_name: &str) -> &'static str {
    let lowered = group_name.to_ascii_lowercase();
    if lowered.contains("security") {
        "security"
    } else if lowered.contains("regional") {
        "regional"
    } else if lowered.contains("general") {
        "general"
    } else {
        ""
    }
}

/// Build the page for this view, whatever brought the operator to it.
async fn build_registry(
    state: &AppState,
    query: &RegistryQuery,
    shell: ShellData,
    added_count: usize,
    failures: Vec<RegistryFailureView>,
) -> RegistryTemplate {
    let search = query.search();
    let group_id = query.group_id();
    let show_deprecated = query.show_deprecated();

    let mut template = RegistryTemplate {
        shell,
        q: search.clone(),
        groups: Vec::new(),
        show_deprecated,
        rows: Vec::new(),
        load_failed: false,
        shown: 0,
        total: 0,
        current_query: query.to_query_string(),
        added_count,
        failures,
        limit: crate::admin::api::BATCH_ADD_LIMIT,
    };

    let Ok(data) = state.registry.list().await else {
        template.load_failed = true;
        return template;
    };

    // What the operator already has, so a row is not offered twice.
    let existing: std::collections::HashSet<String> = state
        .db
        .get_filter_lists()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|list| list.url)
        .collect();

    let group_names: std::collections::HashMap<i64, String> = data
        .groups
        .iter()
        .map(|group| (group.group_id, group.group_name.clone()))
        .collect();

    template.groups = data
        .groups
        .iter()
        .map(|group| RegistryGroupView {
            value: group.group_id.to_string(),
            label: group.group_name.clone(),
            selected: group_id == Some(group.group_id),
        })
        .collect();

    let needle = search.to_lowercase();
    template.total = data.filters.len();
    template.rows = data
        .filters
        .into_iter()
        .filter(|filter| show_deprecated || !filter.deprecated)
        .filter(|filter| group_id.is_none_or(|id| filter.group_id == id))
        .filter(|filter| {
            needle.is_empty()
                || format!("{} {}", filter.name, filter.description)
                    .to_lowercase()
                    .contains(&needle)
        })
        .map(|filter| {
            let group_name = group_names
                .get(&filter.group_id)
                .cloned()
                .unwrap_or_default();
            RegistryRowView {
                already_added: existing.contains(&filter.download_url),
                group_class: registry_group_class(&group_name),
                group_name,
                homepage: safe_url(filter.homepage.as_deref()),
                filter_id: filter.filter_id,
                group_id: filter.group_id,
                name: filter.name,
                description: filter.description,
                deprecated: filter.deprecated,
            }
        })
        .collect();
    template.shown = template.rows.len();

    template
}

pub async fn registry_page(
    _user: SsrUser,
    State(state): State<AppState>,
    Query(query): Query<RegistryQuery>,
    headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    // Reached from the filters page, so the navigation keeps marking Filters.
    let (shell, jar) = ShellData::build_for(&state, "/filters", &headers, jar).await;
    (
        jar,
        build_registry(&state, &query, shell, 0, Vec::new()).await,
    )
}

/// `POST /filters/registry/add` — add every ticked list.
///
/// The body is one `filter_id` per ticked box. `Vec<(String, String)>` is the
/// one shape `Form` deserialises that keeps repeated keys.
pub async fn registry_add_submit(
    _user: SsrUser,
    State(state): State<AppState>,
    Query(query): Query<RegistryQuery>,
    headers: HeaderMap,
    jar: CookieJar,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    let picked: std::collections::HashSet<i64> = fields
        .iter()
        .filter(|(key, _)| key == "filter_id")
        .filter_map(|(_, value)| value.parse().ok())
        .collect();

    // One failure shape for every error path, so the response is built once.
    let one = |name: &str, error: String| {
        vec![RegistryFailureView {
            name: name.to_string(),
            error,
        }]
    };

    let outcome = if picked.is_empty() {
        // Nothing ticked: say so here rather than redirect as if it worked.
        Err((
            0,
            one(
                "No lists selected",
                "tick at least one list before adding".to_string(),
            ),
        ))
    } else {
        // Names and URLs come from the registry, not the form: the server
        // decides what an id means.
        match state.registry.list().await {
            Err(_err) => Err((
                0,
                one(
                    "Registry unavailable",
                    "could not re-read the registry to resolve the selection".to_string(),
                ),
            )),
            Ok(data) => {
                let items: Vec<crate::admin::api::BatchAddItem> = data
                    .filters
                    .into_iter()
                    .filter(|filter| picked.contains(&filter.filter_id))
                    .map(|filter| crate::admin::api::BatchAddItem {
                        name: filter.name,
                        url: filter.download_url,
                    })
                    .collect();
                match crate::admin::api::add_lists_batch(&state, items).await {
                    // All added: redirect, so a refresh cannot add them twice.
                    Ok(result) if result.failed.is_empty() => Ok(()),
                    // Partial failure renders: a redirect would lose the reasons.
                    Ok(result) => Err((
                        result.added.len(),
                        result
                            .failed
                            .into_iter()
                            .map(|entry| RegistryFailureView {
                                name: entry.name,
                                error: entry.error,
                            })
                            .collect(),
                    )),
                    Err(_status) => Err((
                        0,
                        one(
                            "Nothing was added",
                            format!(
                                "a batch must have between 1 and {} lists in it",
                                crate::admin::api::BATCH_ADD_LIMIT
                            ),
                        ),
                    )),
                }
            }
        }
    };

    let (shell, jar) = ShellData::build_for(&state, "/filters", &headers, jar).await;
    match outcome {
        Ok(()) => filters_saved(jar, Flash::FiltersSaved),
        Err((added, failures)) => (
            jar,
            build_registry(&state, &query, shell, added, failures).await,
        )
            .into_response(),
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
        // `?` and `&` would otherwise silently truncate the value.
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
        // Must match the client's redraws, or the notation would flip.
        assert_eq!(format_num_adaptive(999_999), "999,999");
        assert_eq!(format_num_adaptive(1_000_000), "1M");
        assert_eq!(format_num_adaptive(1_250_000), "1.3M");
    }

    #[test]
    fn only_absolute_http_urls_survive_into_an_href() {
        assert_eq!(
            safe_url(Some("https://example.com/list")),
            "https://example.com/list"
        );
        assert_eq!(safe_url(Some("http://example.com")), "http://example.com");
        // Case is not a disguise.
        assert_eq!(safe_url(Some("HTTPS://example.com")), "HTTPS://example.com");

        // What a third party could put in `homepage` to run code on click.
        assert_eq!(safe_url(Some("javascript:alert(1)")), "");
        assert_eq!(safe_url(Some("JaVaScRiPt:alert(1)")), "");
        assert_eq!(safe_url(Some("data:text/html,<script>")), "");
        assert_eq!(safe_url(Some("//evil.example")), "");
        assert_eq!(safe_url(Some("/relative")), "");
        assert_eq!(safe_url(Some("")), "");
        assert_eq!(safe_url(None), "");
    }

    #[test]
    fn a_group_pill_takes_its_colour_from_the_group_name() {
        assert_eq!(registry_group_class("Security"), "security");
        assert_eq!(registry_group_class("Regional lists"), "regional");
        assert_eq!(registry_group_class("General"), "general");
        assert_eq!(registry_group_class("Other"), "");
    }

    #[test]
    fn the_registry_view_rebuilds_only_the_filters_that_are_set() {
        let none = RegistryQuery::default();
        assert_eq!(none.to_query_string(), "");

        let all = RegistryQuery {
            q: Some("  ads  ".to_string()),
            group: Some("2".to_string()),
            deprecated: Some("1".to_string()),
        };
        assert_eq!(all.search(), "ads");
        assert_eq!(all.to_query_string(), "?q=ads&group=2&deprecated=1");

        // A group that is not a number is no filter at all, rather than a 400.
        let bad = RegistryQuery {
            q: None,
            group: Some("nonsense".to_string()),
            deprecated: None,
        };
        assert_eq!(bad.group_id(), None);
        assert_eq!(bad.to_query_string(), "");
    }

    #[test]
    fn the_health_grid_holds_off_abbreviating_until_ten_million() {
        assert_eq!(format_num_adaptive_at(9_999_999, 10_000_000), "9,999,999");
        assert_eq!(format_num_adaptive_at(10_000_000, 10_000_000), "10M");
    }

    #[test]
    fn sizes_are_written_the_way_the_client_writes_them() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1_536), "1.5 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.00 MB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
    }

    #[test]
    fn an_average_over_no_rows_is_a_dash_rather_than_zero_bytes() {
        assert_eq!(format_bytes_or_dash(0.0), "—");
        assert_eq!(format_bytes_or_dash(2_048.4), "2.0 KB");
    }

    #[test]
    fn a_date_the_server_writes_is_an_unambiguous_one() {
        // 2026-08-13T00:00:00Z; readable even when no script restates it.
        assert_eq!(iso_date(1_786_579_200), "2026-08-13");
    }

    #[test]
    fn bars_are_sized_against_the_largest_row_and_shares_against_the_total() {
        let rows = bar_rows(vec![
            ("b.example".to_string(), 25),
            ("a.example".to_string(), 75),
        ]);
        // Largest first, whatever order they arrived in.
        assert_eq!(rows[0].label, "a.example");
        assert_eq!(rows[0].width, "100.0");
        assert_eq!(rows[0].share, "75.0%");
        assert_eq!(rows[0].count_title, "75 (75.0%)");
        // The second bar is a third of the first, but a quarter of the total.
        assert_eq!(rows[1].width, "33.3");
        assert_eq!(rows[1].share, "25.0%");
    }

    #[test]
    fn a_bar_list_of_nothing_divides_by_nothing() {
        assert!(bar_rows(vec![]).is_empty());
        let rows = bar_rows(vec![("none".to_string(), 0)]);
        assert_eq!(rows[0].width, "0.0");
        // No total, so no share rather than 0%.
        assert_eq!(rows[0].share, "");
        assert_eq!(rows[0].count_title, "0");
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
        // No count, no share, rather than "0.0%".
        assert_eq!(share_percent(0, 10), "");
        assert_eq!(share_percent(3, 4), "75.0%");
    }

    #[test]
    fn throughput_keeps_the_precision_the_number_deserves() {
        // `0.03 q/s` says something `0 q/s` does not.
        assert_eq!(format_qps(0.0333), "0.03");
        assert_eq!(format_qps(9.99), "9.99");
        assert_eq!(format_qps(12.34), "12.3");
        // No decimals on a flood.
        assert_eq!(format_qps(1234.56), "1235");
    }

    #[test]
    fn the_dns_target_pairs_the_browsers_host_with_the_dns_port() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::HOST, "noadd.lan:8080".parse().unwrap());
        // The HTTP port is swapped for the DNS listener's.
        assert_eq!(dns_target(&headers, "0.0.0.0:53"), "noadd.lan:53");
        assert_eq!(dns_target(&headers, "127.0.0.1:5353"), "noadd.lan:5353");
        // No port to take: the host alone.
        assert_eq!(dns_target(&headers, "53"), "noadd.lan");
    }

    #[test]
    fn civil_dates_convert_to_the_days_the_epoch_counts() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
        // 2000 is a leap year (the 400 rule), 2100 is not (the 100 rule).
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2100, 3, 1), 47_541);
    }

    #[test]
    fn an_expiry_date_lasts_until_that_day_is_over() {
        // Blank means a key that never expires, not one expiring at the epoch.
        assert_eq!(parse_expiry_date(""), Ok(None));
        assert_eq!(parse_expiry_date("   "), Ok(None));

        // A date lasts until the end of that day.
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
        // Under a minute reads as "in 1 minute", not "in 0".
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
