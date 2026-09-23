//! The dashboard, settings and account with JavaScript off. None seeds or
//! empties anything, so they share one instance.
//!
//!   dashboard — the readings arrive rendered; the chart says it needs a browser.
//!   settings  — the no-JS save row posts and persists; a rejected value comes
//!               back in the field with a reason.
//!   account   — password-proofed actions carry the password in their own form.
//!
//! Password confirmations share the five-per-minute login budget, so there is
//! exactly one here plus the sign-in.

use anyhow::Result;
use noadd_e2e::dom::Page;
use noadd_e2e::{ADMIN_PASSWORD, Api, Profile, Server, Suite, ports};

async fn open(page: &Page, session: &str, path: &str) -> Result<()> {
    page.adopt_session(session).await?;
    page.goto(path).await?;
    page.testid("app-shell").expect_visible().await
}

/// Settings does not submit on Enter (no default button for implicit
/// submission), so this activates the real button; `click_js` because the fixed
/// status bar can cover it. Callers' assertions prove the POST landed.
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

                // No traffic yet, so the rates are a real zero, not a blank.
                page.testid("stat-blocked-today").expect_visible().await?;
                page.testid("stat-block-rate")
                    .expect_text_contains("0.0%")
                    .await?;
                page.testid("stat-throughput-value")
                    .expect_visible()
                    .await?;
                // The top-N tables are rendered, not fetched.
                page.testid("top-domains-card").expect_visible().await?;

                // The client-only control ships hidden.
                page.testid("live-toggle").expect_hidden().await?;

                // So does the status indicator: without the event stream it
                // cannot know the server is up, so it must not claim it.
                page.testid("server-status").expect_hidden().await?;

                // No traffic: the empty state shows and the chart card is hidden,
                // so its "drawn in the browser" note is in the markup, not on screen.
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

                // The no-JS save row ships visible; `app.js` would remove it.
                page.testid("save-settings").expect_visible().await?;

                // A browser posts the whole form, and a fresh appliance has no
                // upstream, so saving without one would be rejected outright.
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

                // Store a known-good state first, independent of earlier cases.
                page.loc("#s-upstream").fill("9.9.9.9:53").await?;
                page.loc("#s-retention").fill("14").await?;
                save_settings(page).await?;
                page.testid("settings-saved").expect_visible().await?;

                page.loc("#s-upstream").fill("not a server").await?;
                save_settings(page).await?;

                // Re-rendered with the submitted value, reason next to the field.
                page.loc("#s-upstream").expect_value("not a server").await?;
                page.expect_text("Not a valid upstream").await?;
                page.testid("settings-saved").expect_count(0).await?;

                // Nothing was written: the save is rejected whole, not half applied.
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
                // The password field rides in the form that needs it.
                page.testid("operator-your-password")
                    .expect_visible()
                    .await?;
                page.testid("api-key-your-password")
                    .expect_visible()
                    .await?;

                // A destructive row action expands into a named confirmation via URL.
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

                // The one exception to PRG: this response holds the only copy.
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

    // Last: the dismissal is stored, removing the notice for good.
    suite
        .case(
            "the onboarding notice is rendered, and dismissing it is a form post",
            async |_browser, page| {
                open(page, &session, "/account").await?;

                // Server-rendered, so it exists with scripting off.
                page.testid("next-step-banner").expect_visible().await?;
                page.testid("next-step-banner-addr")
                    .expect_text_contains(":")
                    .await?;

                page.testid("next-step-banner-dismiss").click().await?;

                // The `next` field returns the operator to where they dismissed it.
                page.expect_url_ends_with("/account").await?;
                page.testid("next-step-banner").expect_count(0).await?;

                // And it stays dismissed.
                page.goto("/settings").await?;
                page.testid("next-step-banner").expect_count(0).await
            },
        )
        .await;

    Ok(suite.finish())
}
