//! The three pages the no-JS suites had not reached: the dashboard, settings
//! and account. Filters, the query log and statistics each have their own file
//! because each seeds heavily or empties something; these three do not, so they
//! share one instance rather than booting three more binaries for it.
//!
//! What each is here to prove:
//!   dashboard — a page of pure readings arrives with the readings in it, and
//!               says so where the chart would be.
//!   settings  — the no-JS save row is real: it posts, it persists, and a
//!               rejected value comes back in the field with a reason.
//!   account   — the actions that need a password proof carry the password in
//!               their own form, so the path is identical with scripting off.
//!
//! Account spends password confirmations against the five-per-minute budget, so
//! there is exactly one here plus the sign-in — the same reason
//! `account_sensitive_actions` is self-contained.

use anyhow::Result;
use noadd_e2e::dom::Page;
use noadd_e2e::{ADMIN_PASSWORD, Api, Profile, Server, Suite, ports};

async fn open(page: &Page, session: &str, path: &str) -> Result<()> {
    page.adopt_session(session).await?;
    page.goto(path).await?;
    page.testid("app-shell").expect_visible().await
}

/// Settings is the one form here that does not submit on Enter: implicit
/// submission is skipped when a form holds more than one field and the browser
/// cannot pick a default button for it, so this activates the real one.
/// `click_js` skips the hit-target check the fixed status bar can fail on a
/// short viewport — the assertions after it only pass if the POST landed.
async fn save_settings(page: &Page) -> Result<()> {
    page.testid("save-settings").click_js().await
}

pub async fn run() -> Result<Vec<String>> {
    let server = Server::fresh("pages-no-js", ports::PAGES_NO_JS.0, ports::PAGES_NO_JS.1).await?;
    let session = Api::new(server.base_url()).provision().await?;

    let mut suite = Suite::new(
        "The remaining pages work with no JavaScript",
        server.base_url(),
        Profile::no_js(),
    );

    suite
        .case(
            "the dashboard arrives with its readings, and says what needs a browser",
            async |_browser, page| {
                open(page, &session, "/").await?;

                // Six stat cards, filled in. This appliance has answered
                // nothing, so the rates are a real zero rather than a blank.
                page.testid("stat-blocked-today").expect_visible().await?;
                page.testid("stat-block-rate")
                    .expect_text_contains("0.0%")
                    .await?;
                page.testid("stat-throughput-value")
                    .expect_visible()
                    .await?;
                // The top-N tables are rendered, not fetched.
                page.testid("top-domains-card").expect_visible().await?;

                // The control that only works with a client ships hidden rather
                // than sitting there doing nothing.
                page.testid("live-toggle").expect_hidden().await?;

                // Nothing has been queried, so the page explains what to do
                // about it — and hides the chart card rather than drawing an
                // empty axis, which is why the "drawn in the browser" note is
                // in the markup but not on screen yet.
                page.testid("dashboard-empty-state")
                    .expect_visible()
                    .await?;
                page.testid("dashboard-empty-state")
                    .expect_text_contains("Point a device at noadd")
                    .await?;
                page.loc("#chart-card").expect_hidden().await?;
                page.testid("chart-needs-js").expect_count(1).await
            },
        )
        .await;

    suite
        .case(
            "settings saves through its form and persists",
            async |_browser, page| {
                open(page, &session, "/settings").await?;

                // The no-JS save row is real markup, not a hidden fallback:
                // `app.js` removes it when it takes the form over.
                page.testid("save-settings").expect_visible().await?;

                // A browser posts the whole form, so every field has to be valid —
                // an appliance that has never been configured has no upstream yet,
                // and saving without one is a rejection rather than a partial write.
                page.loc("#s-upstream").fill("1.1.1.1:53").await?;
                page.loc("#s-retention").fill("21").await?;
                save_settings(page).await?;

                // PRG: a flash on the redirected page, not a re-render.
                page.testid("settings-saved").expect_visible().await?;
                page.expect_url_ends_with("/settings").await?;

                // And it is really stored — a fresh load shows it.
                page.goto("/settings").await?;
                page.loc("#s-retention").expect_value("21").await?;
                page.loc("#s-upstream").expect_value("1.1.1.1:53").await
            },
        )
        .await;

    suite
        .case(
            "a rejected setting comes back in the field with a reason",
            async |_browser, page| {
                open(page, &session, "/settings").await?;

                // Store a known-good state first, so this case does not depend
                // on another one having run.
                page.loc("#s-upstream").fill("9.9.9.9:53").await?;
                page.loc("#s-retention").fill("14").await?;
                save_settings(page).await?;
                page.testid("settings-saved").expect_visible().await?;

                page.loc("#s-upstream").fill("not a server").await?;
                save_settings(page).await?;

                // Re-rendered with what was submitted rather than redirected,
                // which would have discarded it, and the reason sits next to
                // the field that caused it.
                page.loc("#s-upstream").expect_value("not a server").await?;
                page.expect_text("Not a valid upstream").await?;
                page.testid("settings-saved").expect_count(0).await?;

                // Nothing was written: the whole save is rejected rather than
                // half applied.
                page.goto("/settings").await?;
                page.loc("#s-upstream").expect_value("9.9.9.9:53").await?;
                page.loc("#s-retention").expect_value("14").await
            },
        )
        .await;

    suite
        .case(
            "the account page renders its tables and its delete confirmation",
            async |_browser, page| {
                open(page, &session, "/account").await?;

                // All three tables are in the first response.
                page.testid("operator-row").expect_count(1).await?;
                page.testid("session-row").expect_count_at_least(1).await?;
                // The password field rides in the form that needs it — no
                // dialog to open.
                page.testid("operator-your-password")
                    .expect_visible()
                    .await?;
                page.testid("api-key-your-password")
                    .expect_visible()
                    .await?;

                // A destructive row action expands into a named confirmation,
                // which exists without scripting because it is a link to a URL.
                page.goto("/account?confirm_delete=1").await?;
                page.testid("operator-confirm-row").expect_visible().await?;
                page.testid("operator-delete-password")
                    .expect_visible()
                    .await
            },
        )
        .await;

    suite
        .case(
            "minting an API key shows the token in the response that created it",
            async |_browser, page| {
                open(page, &session, "/account").await?;

                page.testid("api-key-name").fill("nojs-key").await?;
                page.testid("api-key-your-password")
                    .fill(ADMIN_PASSWORD)
                    .await?;
                page.testid("api-key-your-password").press_enter().await?;

                // The one deliberate exception to PRG on these pages: the token
                // exists in this response and nowhere else, so it renders
                // rather than redirecting.
                page.testid("api-key-token").expect_visible().await?;
                page.testid("api-key-token")
                    .expect_value_not_empty()
                    .await?;
                page.testid("api-key-row")
                    .expect_text_contains("nojs-key")
                    .await?;

                // And the password is never echoed back into the markup.
                page.testid("api-key-your-password").expect_value("").await
            },
        )
        .await;

    Ok(suite.finish())
}
