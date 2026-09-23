//! Regression: changing your own password revokes every other session and
//! rotates this one, and the account page that comes back must list exactly
//! that, with the operator still signed in.
//!
//! Own instance: the case is destructive, and needs its own five-per-minute
//! login budget.

use anyhow::Result;
use noadd_e2e::{ADMIN_PASSWORD, ADMIN_USERNAME, Api, Profile, Server, Suite, ensure, ports};

const NEW_PASSWORD: &str = "an entirely different passphrase";

pub async fn run() -> Result<Vec<String>> {
    let server = Server::fresh(
        "password-change-session-list",
        ports::PASSWORD_CHANGE.0,
        ports::PASSWORD_CHANGE.1,
    )
    .await?;
    let api = Api::new(server.base_url());
    api.setup(ADMIN_USERNAME, ADMIN_PASSWORD).await?;

    let mut suite = Suite::new(
        "Changing my password revokes the others and rotates this one",
        server.base_url(),
        Profile::desktop(),
    );

    suite
        .case(
            "changing my password revokes the others and rotates this one",
            async |_browser, page| {
                // A second, API-minted session, so there is another row to revoke.
                api.login(ADMIN_USERNAME, ADMIN_PASSWORD).await?;

                page.goto("/").await?;
                page.testid("login-username").fill(ADMIN_USERNAME).await?;
                page.testid("login-password").fill(ADMIN_PASSWORD).await?;
                page.testid("login-submit").click().await?;
                page.testid("app-shell").expect_visible().await?;

                page.testid("nav-account").click().await?;
                let rows = page.testid("session-row");
                rows.expect_count(2).await?;
                let mut ids_before = Vec::new();
                for i in 0..2 {
                    ids_before.push(rows.clone().nth(i).attr("data-id").await?);
                }
                ensure(
                    ids_before.iter().all(Option::is_some),
                    format!("a session row carried no id: {ids_before:?}"),
                )?;

                page.testid("password-current").fill(ADMIN_PASSWORD).await?;
                page.testid("password-new").fill(NEW_PASSWORD).await?;
                page.testid("password-confirm").fill(NEW_PASSWORD).await?;
                page.testid("password-save").click().await?;
                // The confirmation is rendered after the redirect, so the table
                // below reflects the post-change state.
                page.testid("password-changed").expect_visible().await?;

                // The other session is gone; this one was rotated to a new id.
                rows.expect_count(1).await?;
                let id_after = rows.attr("data-id").await?.unwrap_or_default();
                ensure(
                    !id_after.is_empty() && id_after.bytes().all(|b| b.is_ascii_digit()),
                    format!("the surviving session id is not a number: {id_after:?}"),
                )?;
                ensure(
                    !ids_before.contains(&Some(id_after.clone())),
                    format!("the session id {id_after} was not rotated"),
                )?;

                // Still signed in, not bounced to login by a stale cookie.
                page.testid("logout-other-sessions")
                    .expect_visible()
                    .await?;
                page.testid("login-submit").expect_count(0).await
            },
        )
        .await;

    Ok(suite.finish())
}
