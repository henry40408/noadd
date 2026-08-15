//! The step definitions, ported from `e2e/steps/*.js`.
//!
//! The Gherkin is unchanged — `cucumber` reads the same `.feature` files — so
//! every step text here is the text that was there before, including the two
//! that had to stay regular expressions because a Cucumber Expression cannot
//! spell them (`I (add|have added)`, and the allow/block alternation).
//!
//! One step definition did not come across: `I am recording uncaught page
//! errors` / `no uncaught page errors were recorded`. No feature file used
//! either half, and porting a page-error stream that nothing calls would have
//! meant a CDP event subscription for dead code.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use cucumber::{given, then, when};
use noadd_e2e::api::{ADMIN_PASSWORD, ADMIN_USERNAME};
use noadd_e2e::browser::override_summary;
use noadd_e2e::dom::{Page, StepResult, ensure};
use noadd_e2e::world::NoaddWorld;
use noadd_e2e::{dns, wait};

/// The human nav label used in the features, and the `data-testid` it means.
///
/// Only the desktop strip carries the test ids — the mobile F-key bar renders
/// the same table without them — so each of these matches exactly one element.
const NAV: &[(&str, &str)] = &[
    ("Dashboard", "nav-dashboard"),
    ("Statistics", "nav-stats"),
    ("Query Log", "nav-logs"),
    ("Filters", "nav-filters"),
    ("Settings", "nav-settings"),
    ("Account", "nav-account"),
];

/// The filter-list name whose double quote used to escape its own attribute.
///
/// Kept out of the `.feature` file, as it was before: a `{string}` argument
/// cannot carry a double quote reliably, and the payload only needs to be
/// readable here.
const INJECTED_NAME: &str = r#"q" onmouseover="window.__xss=1"#;
const INJECTED_URL: &str = "https://example.com/e2e-attr-injection.txt";

/// How long the two filter-rebuild polls wait.
///
/// The `expect.poll` calls these replace allowed ten seconds, under a runner
/// that drove one browser at a time. A rebuild is the one thing in this suite
/// whose cost is not the browser's — it reparses the enabled lists, and the
/// built-in one carries tens of thousands of rules — so under a machine that is
/// also running the spec files it is the first thing to run late. Reusing the
/// element wait keeps one number to reason about, and a rebuild that genuinely
/// never finishes still fails.
const REBUILD_TIMEOUT: Duration = noadd_e2e::browser::WAIT_TIMEOUT;

fn testid_for(tab: &str) -> Result<&'static str> {
    NAV.iter()
        .find(|(label, _)| *label == tab)
        .map(|(_, id)| *id)
        .with_context(|| format!("unknown tab: {tab}"))
}

async fn go_to_tab(page: &Page, tab: &str) -> Result<()> {
    let id = testid_for(tab)?;
    page.testid(id).click().await?;
    page.testid(id).expect_class("active").await
}

/// Drives the boot screen to a signed-in shell, whichever state the instance is
/// in: unconfigured (setup), configured but signed out (login), or already
/// authenticated (a session cookie the runner replayed).
async fn ensure_signed_in(page: &Page) -> Result<()> {
    page.goto("/").await?;

    let shell = page.testid("app-shell");
    let setup_pw = page.testid("setup-password");
    let login_pw = page.testid("login-password");
    wait::eventually("one of the shell, setup or sign-in screens", || async {
        let seen = shell.is_visible().await?
            || setup_pw.is_visible().await?
            || login_pw.is_visible().await?;
        Ok((seen, "none of the three on screen".into()))
    })
    .await?;

    if setup_pw.is_visible().await? {
        page.testid("setup-username").fill(ADMIN_USERNAME).await?;
        setup_pw.fill(ADMIN_PASSWORD).await?;
        page.testid("setup-password-confirm")
            .fill(ADMIN_PASSWORD)
            .await?;
        page.testid("setup-submit").click().await?;
    } else if login_pw.is_visible().await? {
        page.testid("login-username").fill(ADMIN_USERNAME).await?;
        login_pw.fill(ADMIN_PASSWORD).await?;
        page.testid("login-submit").click().await?;
    }
    shell.expect_visible().await
}

/// A filter-list row, addressed by its visible name.
fn list_row(page: &Page, name: &str) -> noadd_e2e::Locator {
    page.loc(format!(
        "[data-testid=\"filter-list-row\"][data-name=\"{name}\"]"
    ))
}

/// Clicks a row's toggle if it is not already in the wanted state.
///
/// The label is what gets clicked, not the input: the checkbox is visually
/// hidden and clicking the label flips it however the toggle is styled.
async fn set_list_enabled(page: &Page, name: &str, enabled: bool) -> Result<()> {
    let row = list_row(page, name);
    let toggle = row.testid("filter-list-toggle");
    if toggle.is_checked().await? != enabled {
        row.loc("label.toggle").click().await?;
    }
    toggle.expect_checked(enabled).await
}

// --- common ---------------------------------------------------------------

#[given("I am signed in to the admin UI")]
async fn signed_in(world: &mut NoaddWorld) -> StepResult {
    ensure_signed_in(world.page()?).await?;
    Ok(())
}

#[when(expr = "I go to the {string} tab")]
async fn go_to_tab_when(world: &mut NoaddWorld, tab: String) -> StepResult {
    go_to_tab(world.page()?, &tab).await?;
    Ok(())
}

#[given(expr = "I am on the {string} tab")]
async fn on_tab(world: &mut NoaddWorld, tab: String) -> StepResult {
    go_to_tab(world.page()?, &tab).await?;
    Ok(())
}

/// Shared by the dashboard ("Database Health") and filters ("Filter Lists").
#[then(expr = "I see the {string} section")]
async fn see_section(world: &mut NoaddWorld, name: String) -> StepResult {
    world.page()?.expect_text(&name).await?;
    Ok(())
}

// --- first-run setup and authentication -----------------------------------

#[given("the admin UI has never been configured")]
async fn never_configured(world: &mut NoaddWorld) -> StepResult {
    ensure(
        world.api()?.needs_setup().await?,
        "expected a fresh, unconfigured instance",
    )?;
    Ok(())
}

#[when("I open the admin UI")]
async fn open_admin_ui(world: &mut NoaddWorld) -> StepResult {
    world.page()?.goto("/").await?;
    Ok(())
}

#[then("I am shown the first-run setup screen")]
async fn shown_setup(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("setup-username")
        .expect_visible()
        .await?;
    Ok(())
}

#[when(expr = "I enter {string} as the username")]
async fn enter_username(world: &mut NoaddWorld, username: String) -> StepResult {
    world
        .page()?
        .testid("setup-username")
        .fill(&username)
        .await?;
    Ok(())
}

#[when(expr = "I enter {string} as the new password")]
async fn enter_new_password(world: &mut NoaddWorld, password: String) -> StepResult {
    world
        .page()?
        .testid("setup-password")
        .fill(&password)
        .await?;
    Ok(())
}

#[when(expr = "I enter {string} as the confirmation")]
async fn enter_confirmation(world: &mut NoaddWorld, password: String) -> StepResult {
    world
        .page()?
        .testid("setup-password-confirm")
        .fill(&password)
        .await?;
    Ok(())
}

#[when("I submit the setup form")]
async fn submit_setup(world: &mut NoaddWorld) -> StepResult {
    world.page()?.testid("setup-submit").click().await?;
    Ok(())
}

#[then("I see a setup error about the passwords not matching")]
async fn setup_mismatch_error(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("setup-error")
        .expect_text_contains("do not match")
        .await?;
    Ok(())
}

#[then("the admin password has still not been set")]
async fn still_not_set(world: &mut NoaddWorld) -> StepResult {
    ensure(
        world.api()?.needs_setup().await?,
        "the instance reports it has been configured",
    )?;
    Ok(())
}

#[then("I land on the dashboard")]
async fn land_on_dashboard(world: &mut NoaddWorld) -> StepResult {
    let page = world.page()?;
    page.testid("app-shell").expect_visible().await?;
    page.testid("nav-dashboard").expect_visible().await?;
    Ok(())
}

#[given(expr = "the admin password has been set to {string}")]
async fn password_set_to(world: &mut NoaddWorld, password: String) -> StepResult {
    // Idempotent: a 409 means an account is already configured, which is fine.
    world.api()?.setup(ADMIN_USERNAME, &password).await?;
    Ok(())
}

#[when(expr = "I sign in with the password {string}")]
async fn sign_in_with(world: &mut NoaddWorld, password: String) -> StepResult {
    let page = world.page()?;
    page.testid("login-username").fill(ADMIN_USERNAME).await?;
    page.testid("login-password").fill(&password).await?;
    page.testid("login-submit").click().await?;
    Ok(())
}

#[then("I remain on the sign-in screen")]
async fn remain_on_sign_in(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("login-submit")
        .expect_visible()
        .await?;
    Ok(())
}

#[then("I see a sign-in error telling me the password is incorrect")]
async fn sign_in_error(world: &mut NoaddWorld) -> StepResult {
    let error = world.page()?.testid("login-error");
    error.expect_visible().await?;
    error.expect_text_contains("incorrect password").await?;
    Ok(())
}

#[when("I log out all other sessions")]
async fn log_out_others(world: &mut NoaddWorld) -> StepResult {
    let page = world.page()?;
    page.testid("logout-other-sessions").click().await?;
    page.accept_dialog().await?;
    Ok(())
}

#[then("I stay signed in on the account page")]
async fn stay_signed_in(world: &mut NoaddWorld) -> StepResult {
    // The current session is kept, so we remain on the account page rather
    // than being bounced to the sign-in screen.
    let page = world.page()?;
    page.testid("logout-other-sessions")
        .expect_visible()
        .await?;
    page.testid("login-submit").expect_count(0).await?;
    Ok(())
}

#[then("reloading the admin UI keeps me signed in")]
async fn reload_keeps_signed_in(world: &mut NoaddWorld) -> StepResult {
    let page = world.page()?;
    page.reload().await?;
    page.testid("app-shell").expect_visible().await?;
    page.testid("login-submit").expect_count(0).await?;
    Ok(())
}

// --- dashboard and statistics ---------------------------------------------

#[then(expr = "I see the {string} summary card")]
async fn see_summary_card(world: &mut NoaddWorld, name: String) -> StepResult {
    let id = match name.as_str() {
        "Blocked Today" => "stat-blocked-today",
        "Block Rate" => "stat-block-rate",
        other => return Err(anyhow!("unknown summary card: {other}").into()),
    };
    world.page()?.testid(id).expect_visible().await?;
    Ok(())
}

#[then(expr = "I see the {string} card")]
async fn see_card(world: &mut NoaddWorld, name: String) -> StepResult {
    let id = match name.as_str() {
        "Top Queried Domains" => "top-domains-card",
        other => return Err(anyhow!("unknown card: {other}").into()),
    };
    world.page()?.testid(id).expect_visible().await?;
    Ok(())
}

#[then(expr = "I see the {string} metric")]
async fn see_metric(world: &mut NoaddWorld, name: String) -> StepResult {
    world
        .page()?
        .testid("db-health-card")
        .expect_text_contains(&name)
        .await?;
    Ok(())
}

#[then("live updates are active")]
async fn live_active(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("live-toggle")
        .expect_text_contains("LIVE")
        .await?;
    Ok(())
}

#[then("live updates are paused")]
async fn live_paused(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("live-toggle")
        .expect_text_contains("PAUSED")
        .await?;
    Ok(())
}

#[when("I toggle live mode")]
async fn toggle_live(world: &mut NoaddWorld) -> StepResult {
    world.page()?.testid("live-toggle").click().await?;
    Ok(())
}

/// The `▌` before each stat label is tinted by a `:has()` rule that reads the
/// value's class. It once read the inline style attribute instead, so moving a
/// colour to a utility class silently reverted the marker to green.
const MARKER_COLOURS: &str = r"
    const root = getComputedStyle(document.documentElement);
    // Resolve a custom property to the same rgb() form getComputedStyle returns.
    const rgb = (name) => {
        const d = document.createElement('div');
        d.style.color = root.getPropertyValue(name).trim();
        document.body.appendChild(d);
        const v = getComputedStyle(d).color;
        d.remove();
        return v;
    };
    const out = [];
    for (const card of document.querySelectorAll('.stat-card')) {
        const value = card.querySelector('.stat-value');
        const label = card.querySelector('.stat-label');
        if (!value || !label) continue;
        const cl = value.classList;
        const expected = cl.contains('red') || cl.contains('text-red') ? rgb('--red')
            : cl.contains('text-orange') ? rgb('--orange')
                : rgb('--green');
        const actual = getComputedStyle(label, '::before').color;
        if (actual !== expected) {
            out.push(`${label.textContent.trim()} [${value.className}]: marker ${actual}, expected ${expected}`);
        }
    }
    return out;
";

#[then("every stat card marker matches its value colour")]
async fn markers_match(world: &mut NoaddWorld) -> StepResult {
    let page = world.page()?;
    page.loc(".stat-card").first().expect_visible().await?;
    let mismatches = page.eval(MARKER_COLOURS).await?;
    let mismatches: Vec<String> = mismatches
        .as_array()
        .map(|rows| rows.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    ensure(
        mismatches.is_empty(),
        format!("stat markers not matching their value colour: {mismatches:?}"),
    )?;
    Ok(())
}

/// A fragment that should be markup but reaches a template as a plain string is
/// escaped and shows up as visible source. Assertions on specific elements sail
/// straight past that, so this sweeps every tab for text nodes that look like
/// tags.
const LEAKED_MARKUP: &str = r"
    // The admin UI ships its script in the document, so a <script> body would
    // match everything; only rendered text counts.
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
        acceptNode(node) {
            const tag = node.parentElement && node.parentElement.tagName;
            return (tag === 'SCRIPT' || tag === 'STYLE')
                ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
        },
    });
    // Named tags rather than any identifier: copy legitimately contains
    // placeholders like 'Authorization: Bearer <token>'.
    const TAG = /<\/?(span|div|a|button|code|td|tr|table|tbody|thead|th|svg|path|input|label|p|br|strong|em|ul|li|select|option)\b[^<>]*>/i;
    const out = [];
    while (walker.nextNode()) {
        const text = walker.currentNode.nodeValue || '';
        if (TAG.test(text)) out.push(text.trim().slice(0, 100));
    }
    return out;
";

#[when("I visit every tab")]
async fn visit_every_tab(world: &mut NoaddWorld) -> StepResult {
    let mut leaked = Vec::new();
    {
        let page = world.page()?;
        for (label, id) in NAV {
            page.testid(id).click().await?;
            page.testid(id).expect_class("active").await?;
            // Each page fetches on connect; let those renders land.
            page.wait_for_network_idle().await?;
            let hits = page.eval(LEAKED_MARKUP).await?;
            if let Some(rows) = hits.as_array() {
                for row in rows {
                    leaked.push(format!("{label}: {row}"));
                }
            }
        }
    }
    world.leaked_markup = leaked;
    Ok(())
}

#[then("no tab showed raw markup as text")]
fn no_leaked_markup(world: &mut NoaddWorld) -> StepResult {
    ensure(
        world.leaked_markup.is_empty(),
        format!("markup rendered as visible text: {:?}", world.leaked_markup),
    )?;
    Ok(())
}

#[given(expr = "the summary reports {int} queries in the last minute and {int} today")]
async fn summary_reports(world: &mut NoaddWorld, queries_1m: i64, today: i64) -> StepResult {
    world
        .browser()?
        .add_init_script(override_summary(queries_1m, today))
        .await?;
    Ok(())
}

// The slash is escaped because a bare `/` is alternation in a Cucumber
// Expression — the same escape the JavaScript step carried.
#[then(expr = r"the Throughput card reads {string} q\/s")]
async fn throughput_reads(world: &mut NoaddWorld, value: String) -> StepResult {
    world
        .page()?
        .testid("stat-throughput-value")
        .expect_text_eq(&format!("{value}q/s"))
        .await?;
    Ok(())
}

#[then(expr = "the Throughput card shows a 24h mean of {string}")]
async fn throughput_mean(world: &mut NoaddWorld, value: String) -> StepResult {
    world
        .page()?
        .testid("stat-throughput")
        .expect_text_contains(&format!("24h: {value}"))
        .await?;
    Ok(())
}

// --- filter lists ---------------------------------------------------------

#[then(expr = "I see a filter list named {string}")]
async fn see_list_named(world: &mut NoaddWorld, name: String) -> StepResult {
    list_row(world.page()?, &name).expect_visible().await?;
    Ok(())
}

#[then("each filter list shows an enabled state and a rule count")]
async fn lists_have_state(world: &mut NoaddWorld) -> StepResult {
    let page = world.page()?;
    let rows = page.testid("filter-list-row");
    rows.expect_count_at_least(1).await?;
    let count = rows.count().await?;
    page.loc("[data-testid=\"filter-list-row\"] [data-testid=\"filter-list-toggle\"]")
        .expect_count(count)
        .await?;
    Ok(())
}

#[given(expr = "the filter list {string} is enabled")]
async fn list_is_enabled(world: &mut NoaddWorld, name: String) -> StepResult {
    set_list_enabled(world.page()?, &name, true).await?;
    Ok(())
}

#[when(expr = "I disable the filter list {string}")]
async fn disable_list(world: &mut NoaddWorld, name: String) -> StepResult {
    set_list_enabled(world.page()?, &name, false).await?;
    Ok(())
}

#[then(expr = "the filter list {string} is shown as disabled")]
async fn list_shown_disabled(world: &mut NoaddWorld, name: String) -> StepResult {
    list_row(world.page()?, &name)
        .testid("filter-list-toggle")
        .expect_checked(false)
        .await?;
    Ok(())
}

#[when(expr = "I enable the filter list {string}")]
async fn enable_list(world: &mut NoaddWorld, name: String) -> StepResult {
    set_list_enabled(world.page()?, &name, true).await?;
    Ok(())
}

#[then(expr = "the filter list {string} is shown as enabled")]
async fn list_shown_enabled(world: &mut NoaddWorld, name: String) -> StepResult {
    list_row(world.page()?, &name)
        .testid("filter-list-toggle")
        .expect_checked(true)
        .await?;
    Ok(())
}

#[when(expr = "I add a custom filter list named {string} with URL {string}")]
async fn add_custom_list(world: &mut NoaddWorld, name: String, url: String) -> StepResult {
    let page = world.page()?;
    page.testid("list-name-input").fill(&name).await?;
    page.testid("list-url-input").fill(&url).await?;
    page.testid("list-add-submit").click().await?;
    Ok(())
}

#[then(expr = "the filter lists table shows a list named {string}")]
async fn table_shows_list(world: &mut NoaddWorld, name: String) -> StepResult {
    list_row(world.page()?, &name).expect_visible().await?;
    Ok(())
}

#[when("I add a filter list whose name contains a double quote")]
async fn add_quoted_list(world: &mut NoaddWorld) -> StepResult {
    let page = world.page()?;
    page.testid("list-name-input").fill(INJECTED_NAME).await?;
    page.testid("list-url-input").fill(INJECTED_URL).await?;
    page.testid("list-add-submit").click().await?;
    // Both inputs are cleared once the POST resolves and the table reloads.
    page.testid("list-url-input").expect_value("").await?;
    Ok(())
}

/// Any `on*` attribute on a row means an interpolated value escaped its
/// attribute: nothing in the template writes one.
#[then("no filter list row carries an inline event handler")]
async fn no_inline_handlers(world: &mut NoaddWorld) -> StepResult {
    let handlers = world
        .page()?
        .eval(
            r#"return [...document.querySelectorAll('[data-testid="filter-list-row"]')]
                 .flatMap((row) => [...row.attributes].map((a) => a.name))
                 .filter((name) => name.startsWith('on'));"#,
        )
        .await?;
    let handlers: Vec<String> = handlers
        .as_array()
        .map(|names| names.iter().map(ToString::to_string).collect())
        .unwrap_or_default();
    ensure(
        handlers.is_empty(),
        format!("inline event handlers injected onto filter list rows: {handlers:?}"),
    )?;
    Ok(())
}

/// Matched as text rather than through a `[data-name="…"]` selector, which the
/// quote in the name would break.
#[then("the quoted filter list name is shown as text")]
async fn quoted_name_shown(world: &mut NoaddWorld) -> StepResult {
    world.page()?.expect_text(INJECTED_NAME).await?;
    Ok(())
}

/// An ordinary link now, so following it is an ordinary navigation.
#[when("I open the registry browser")]
async fn open_registry(world: &mut NoaddWorld) -> StepResult {
    world.page()?.loc("#browse-registry").click().await?;
    Ok(())
}

/// Slashes are alternation in a Cucumber Expression, so the path stays out of
/// the step text and lives in the assertion.
#[then("the registry browser is a page of its own")]
async fn registry_is_a_page(world: &mut NoaddWorld) -> StepResult {
    let page = world.page()?;
    page.expect_url_ends_with("/filters/registry").await?;
    page.loc("registry-page").expect_visible().await?;
    // Filters marks the page it is a view of, so the navigation still says
    // where the operator is. Both bars carry the mark, so this asks the named
    // one.
    page.testid("nav-filters").expect_class("active").await?;
    Ok(())
}

// --- custom rules and the domain test -------------------------------------

#[when(regex = r#"^I (?:add|have added) the custom rule "(.*)"$"#)]
#[given(regex = r#"^I (?:add|have added) the custom rule "(.*)"$"#)]
async fn add_rule(world: &mut NoaddWorld, rule: String) -> StepResult {
    let page = world.page()?;
    page.testid("rule-input").fill(&rule).await?;
    page.testid("rule-submit").click().await?;
    Ok(())
}

#[then(regex = r#"^the custom rules list shows an? "(allow|block)" rule for "(.*)"$"#)]
async fn rules_show(world: &mut NoaddWorld, kind: String, domain: String) -> StepResult {
    world
        .page()?
        .loc(format!("[data-testid=\"rule-row\"][data-type=\"{kind}\"]"))
        .having_text(domain)
        .expect_visible()
        .await?;
    Ok(())
}

#[when(expr = "I delete the rule for {string}")]
async fn delete_rule(world: &mut NoaddWorld, domain: String) -> StepResult {
    world
        .page()?
        .testid("rule-row")
        .having_text(domain)
        .testid("rule-delete")
        .click()
        .await?;
    Ok(())
}

#[then(expr = "the custom rules list no longer shows {string}")]
async fn rule_gone(world: &mut NoaddWorld, domain: String) -> StepResult {
    world
        .page()?
        .testid("rule-row")
        .having_text(domain)
        .expect_count(0)
        .await?;
    Ok(())
}

#[given("the filter engine has finished rebuilding")]
async fn rebuild_settled(world: &mut NoaddWorld) -> StepResult {
    // Adding a rule kicks off an async rebuild; wait for any in-flight one to
    // settle.
    let instance = world.instance()?.clone();
    let session = instance
        .session
        .as_deref()
        .context("this instance has no session to ask with")?;
    let api = world.api()?;
    let deadline = Instant::now() + REBUILD_TIMEOUT;
    loop {
        if !api.rebuilding(session).await? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                anyhow!("a filter rebuild was still running after {REBUILD_TIMEOUT:?}").into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[when(expr = "I run a domain test for {string}")]
async fn run_domain_test(world: &mut NoaddWorld, domain: String) -> StepResult {
    let page = world.page()?;
    page.testid("domain-test-input").fill(&domain).await?;
    page.testid("domain-test-submit").click().await?;
    Ok(())
}

#[then(expr = "the domain test reports the domain as {string}")]
async fn domain_test_verdict(world: &mut NoaddWorld, verdict: String) -> StepResult {
    // Re-run the check while polling to absorb the async filter rebuild: the
    // verdict comes from the live engine, and a rebuild swaps a new one in.
    let page = world.page()?;
    let deadline = Instant::now() + REBUILD_TIMEOUT;
    loop {
        page.testid("domain-test-submit").click().await?;
        let text = page
            .testid("domain-test-result")
            .text()
            .await
            .unwrap_or_default();
        if text.contains(&verdict) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                anyhow!("the domain test never reported {verdict:?}; last read {text:?}").into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

#[then(expr = "the domain test result mentions {string}")]
async fn domain_test_mentions(world: &mut NoaddWorld, text: String) -> StepResult {
    world
        .page()?
        .testid("domain-test-result")
        .expect_text_contains(&text)
        .await?;
    Ok(())
}

// --- onboarding guidance --------------------------------------------------

#[then("I see a setup error about the password being too short")]
async fn setup_too_short(world: &mut NoaddWorld) -> StepResult {
    // Minimum-agnostic on purpose: the figure lives in `MIN_PASSWORD_LENGTH`
    // (`src/admin/api.rs`) and has already moved once. What this scenario is
    // about is that the UI blocks a too-short password before any API call.
    world
        .page()?
        .testid("setup-error")
        .expect_text_contains("at least")
        .await?;
    Ok(())
}

#[then("I see a welcome message confirming the setup is complete")]
async fn setup_welcome(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("setup-welcome")
        .expect_visible()
        .await?;
    Ok(())
}

#[then("I see the next-step banner explaining how to point a device at noadd")]
#[given("I see the next-step banner explaining how to point a device at noadd")]
async fn next_step_banner(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("next-step-banner")
        .expect_visible()
        .await?;
    Ok(())
}

#[when("I dismiss the next-step banner")]
async fn dismiss_banner(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("next-step-banner-dismiss")
        .click()
        .await?;
    Ok(())
}

#[then("the next-step banner is no longer shown")]
async fn banner_gone(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("next-step-banner")
        .expect_count(0)
        .await?;
    Ok(())
}

#[then("reloading the admin UI does not show the next-step banner again")]
async fn banner_stays_gone(world: &mut NoaddWorld) -> StepResult {
    let page = world.page()?;
    page.reload().await?;
    page.testid("next-step-banner").expect_count(0).await?;
    Ok(())
}

#[then("I see onboarding guidance explaining how to point a device at noadd")]
async fn dashboard_guidance(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("dashboard-empty-state")
        .expect_visible()
        .await?;
    Ok(())
}

#[then("the guidance shows this server's DNS address")]
async fn guidance_shows_dns(world: &mut NoaddWorld) -> StepResult {
    // The empty state should print where to point a device. The HTTP origin's
    // hostname is the same address noadd serves DNS on, so assert the guidance
    // surfaces that host.
    let host = world
        .instance()?
        .base
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or_default()
        .to_string();
    world
        .page()?
        .testid("dashboard-empty-state")
        .expect_text_contains(&host)
        .await?;
    Ok(())
}

#[then("I see onboarding guidance explaining that no DNS queries have been logged yet")]
async fn logs_guidance(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("logs-empty-state")
        .expect_visible()
        .await?;
    Ok(())
}

#[when("I disable every filter list")]
async fn disable_every_list(world: &mut NoaddWorld) -> StepResult {
    let page = world.page()?;
    let toggles = page.testid("filter-list-toggle");
    let count = toggles.count().await?;
    ensure(count > 0, "expected at least one filter list to disable")?;
    for i in 0..count {
        let toggle = page.testid("filter-list-toggle").nth(i);
        if toggle.is_checked().await? {
            // Click the wrapping label (the input itself is visually hidden),
            // which flips the toggle and fires the PUT. Awaiting the unchecked
            // state lets that settle without a flaky explicit response-wait.
            page.testid("filter-list-row")
                .nth(i)
                .loc("label.toggle")
                .click()
                .await?;
            toggle.expect_checked(false).await?;
        }
    }
    Ok(())
}

#[then("I see a warning that no filter list is enabled")]
async fn all_disabled_warning(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("filters-all-disabled-warning")
        .expect_visible()
        .await?;
    Ok(())
}

#[then("the warning offers a way to enable a recommended list")]
async fn warning_offers_recommended(world: &mut NoaddWorld) -> StepResult {
    world
        .page()?
        .testid("filters-enable-recommended")
        .expect_visible()
        .await?;
    Ok(())
}

#[when("noadd resolves a real DNS query")]
async fn resolve_real_query(world: &mut NoaddWorld) -> StepResult {
    // noadd logs every handled query and the logger flushes about once a
    // second; the assertion that follows polls under the element wait, which
    // absorbs that window. No response is needed.
    dns::send_query(world.instance()?.dns_port, "onboarding-probe.example").await?;
    Ok(())
}
