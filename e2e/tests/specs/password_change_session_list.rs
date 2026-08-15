//! Regression: changing your own password rewrites this operator's sessions
//! server-side — every other device is revoked and this one's token is rotated
//! — so the session table on the same account page is stale the moment the
//! request returns. It must refresh in place, without a manual reload.
//!
//! Self-contained noadd instance on dedicated ports, for two reasons: the
//! scenario is destructive (it changes the admin password), and it needs its
//! own login rate-limit budget — the shared `@auth` instance already spends its
//! five attempts per minute on the sign-in scenarios.

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
                // A second session for the same operator, minted straight
                // against the API. Its cookie is discarded — all this needs is
                // for the session to exist server-side, so the account page has
                // something to list besides this browser.
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
                // The form posts and the server redirects back, so the
                // confirmation it renders is the barrier: seeing it means the
                // navigation finished and the table below was built from the
                // post-change state.
                page.testid("password-changed").expect_visible().await?;

                // The other device is gone and this device's row is a
                // *different* session — its token was rotated, so it carries a
                // new id.
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

                // And the rotation kept us signed in rather than bouncing us to
                // the login screen, which is what a stale cookie would have
                // produced.
                page.testid("logout-other-sessions")
                    .expect_visible()
                    .await?;
                page.testid("login-submit").expect_count(0).await
            },
        )
        .await;

    Ok(suite.finish())
}
