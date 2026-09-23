//! The account actions that need a password proof — mint an API key, add an
//! operator, delete one — carry a "your password" field in their own form, so
//! the path is the same with or without JavaScript. (`POST /api/auth/reauth`
//! is covered in `tests/admin_api_test.rs`.)
//!
//! Own instance: password confirmations share the five-per-minute login
//! budget, which is why there are exactly three of them plus the one sign-in.

use anyhow::Result;
use noadd_e2e::dom::Page;
use noadd_e2e::{ADMIN_PASSWORD, Api, Profile, Server, Suite, ports};

/// Replays the file's one login as a cookie, sparing the login budget.
async fn open_account(page: &Page, session: &str, query: &str) -> Result<()> {
    page.adopt_session(session).await?;
    page.goto(&format!("/account{query}")).await?;
    page.testid("app-shell").expect_visible().await
}

pub async fn run() -> Result<Vec<String>> {
    let server = Server::fresh(
        "account-sensitive-actions",
        ports::ACCOUNT.0,
        ports::ACCOUNT.1,
    )
    .await?;
    let session = Api::new(server.base_url()).provision().await?;

    let mut suite = Suite::new(
        "The account page's password-proofed actions",
        server.base_url(),
        Profile::desktop(),
    );

    suite
        .case(
            "an API key is minted when the form carries the right password",
            async |_browser, page| {
                open_account(page, &session, "").await?;

                page.testid("api-key-name").fill("ci").await?;
                page.testid("api-key-your-password")
                    .fill(ADMIN_PASSWORD)
                    .await?;
                // Enter, not a click: on this long page the fixed status bar can
                // cover a button near the fold.
                page.testid("api-key-your-password").press_enter().await?;

                // Rendered, not redirected: this response holds the only copy.
                page.testid("api-key-reveal").expect_visible().await?;
                page.testid("api-key-token")
                    .expect_value_starts_with("noadd_")
                    .await?;
                page.loc(r#"[data-testid="api-key-row"][data-name="ci"]"#)
                    .expect_visible()
                    .await?;
                // No reauth dialog exists.
                page.testid("reauth-password").expect_count(0).await
            },
        )
        .await;

    suite
        .case(
            "a wrong password creates nothing and keeps what was typed",
            async |_browser, page| {
                open_account(page, &session, "").await?;

                page.testid("api-key-name").fill("rejected").await?;
                page.testid("api-key-your-password")
                    .fill("not the password")
                    .await?;
                page.testid("api-key-your-password").press_enter().await?;

                page.testid("api-key-error")
                    .expect_text_contains("password is incorrect")
                    .await?;
                // The name survives so only the password has to be retyped.
                page.testid("api-key-name").expect_value("rejected").await?;
                page.testid("api-key-reveal").expect_hidden().await?;
                page.loc(r#"[data-testid="api-key-row"][data-name="rejected"]"#)
                    .expect_count(0)
                    .await
            },
        )
        .await;

    suite
        .case(
            "adding an operator needs the password, and deleting one asks by name",
            async |_browser, page| {
                open_account(page, &session, "").await?;

                page.testid("operator-username")
                    .fill("second-operator")
                    .await?;
                page.testid("operator-password")
                    .fill("correct-horse-battery-staple-2")
                    .await?;
                page.testid("operator-password-confirm")
                    .fill("correct-horse-battery-staple-2")
                    .await?;
                page.testid("operator-your-password")
                    .fill(ADMIN_PASSWORD)
                    .await?;
                page.testid("operator-your-password").press_enter().await?;

                let row = page.loc(r#"[data-testid="operator-row"][data-name="second-operator"]"#);
                row.expect_visible().await?;
                // Redirected, so a refresh cannot add a second one.
                page.expect_url_ends_with("/account").await?;

                // Delete expands a confirmation naming the operator, with its own
                // password field. It is a GET, so no password is spent.
                row.loc(".del-op").click_js().await?;
                page.testid("operator-confirm-row").expect_visible().await?;
                page.testid("operator-confirm-row")
                    .expect_text_contains("second-operator")
                    .await?;
                page.testid("operator-delete-password")
                    .expect_visible()
                    .await?;

                // Cancelling leaves the operator alone.
                page.testid("operator-confirm-row")
                    .loc("a, button")
                    .having_text("Cancel")
                    .click_js()
                    .await?;
                page.testid("operator-confirm-row").expect_count(0).await?;
                row.expect_visible().await
            },
        )
        .await;

    Ok(suite.finish())
}
