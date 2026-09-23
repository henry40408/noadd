//! Regression: the settings page uses ONE "change = saved" model. Every control
//! auto-saves on change/blur; there is no "Save Settings" button; mid-typing
//! fires zero requests (`onchange`, not `oninput`); invalid/partial values never
//! hit the network.
//!
//! `WebDriver` has no request stream, so [`RECORD_REQUESTS`] records every
//! `fetch` the page makes.

use std::time::Duration;

use anyhow::Result;
use noadd_e2e::browser::RECORD_REQUESTS;
use noadd_e2e::dom::Page;
use noadd_e2e::{ADMIN_PASSWORD, ADMIN_USERNAME, Api, Profile, Server, Suite, ensure, ports};

/// How long a wrong handler gets to fire before a case concludes none did.
const SETTLE: Duration = Duration::from_millis(300);

async fn goto_settings(page: &Page) -> Result<()> {
    page.goto("/").await?;
    page.testid("login-username").fill(ADMIN_USERNAME).await?;
    page.testid("login-password").fill(ADMIN_PASSWORD).await?;
    page.testid("login-submit").click().await?;
    page.testid("app-shell").expect_visible().await?;
    page.goto("/settings").await?;
    page.loc("#s-block-mode").expect_visible().await
}

pub async fn run() -> Result<Vec<String>> {
    let server = Server::fresh("settings-autosave", ports::SETTINGS.0, ports::SETTINGS.1).await?;
    Api::new(server.base_url())
        .setup(ADMIN_USERNAME, ADMIN_PASSWORD)
        .await?;

    let mut suite = Suite::new(
        "Settings page uses one consistent save model",
        server.base_url(),
        Profile::desktop().with_init_script(RECORD_REQUESTS),
    );

    suite
        .case(
            "there is no Save Settings button",
            async |_browser, page| {
                goto_settings(page).await?;
                page.loc("#save-settings").expect_count(0).await
            },
        )
        .await;

    suite
        .case(
            "changing block mode persists across reload (no button click)",
            async |_browser, page| {
                goto_settings(page).await?;
                let before = page.request_count("PUT", "/api/settings").await?;
                page.loc("#s-block-mode").select_value("nxdomain").await?;
                page.expect_request("PUT", "/api/settings", before).await?;
                page.reload().await?;
                page.loc("#s-block-mode").expect_value("nxdomain").await
            },
        )
        .await;

    suite
        .case(
            "custom IP persists across reload",
            async |_browser, page| {
                goto_settings(page).await?;
                page.loc("#s-block-mode").select_value("custom_ip").await?;
                page.loc("#s-block-custom").expect_visible().await?;
                let before = page.request_count("PUT", "/api/settings").await?;
                page.loc("#s-block-ipv4").fill("192.0.2.1").await?;
                page.loc("#s-block-ipv4").blur().await?;
                page.expect_request("PUT", "/api/settings", before).await?;
                page.reload().await?;
                page.loc("#s-block-mode").expect_value("custom_ip").await?;
                page.loc("#s-block-ipv4").expect_value("192.0.2.1").await
            },
        )
        .await;

    suite
        .case(
            "typing a partial IP fires no request until blur, and invalid IP never PUTs",
            async |_browser, page| {
                goto_settings(page).await?;
                page.loc("#s-block-mode").select_value("custom_ip").await?;
                let before = page.request_count("PUT", "/api/settings").await?;

                // Type an incomplete IPv4 key by key. Not cleared first:
                // clearing is itself a change, and the result is invalid either way.
                page.loc("#s-block-ipv4").click().await?;
                page.loc("#s-block-ipv4").type_text("192.168.1").await?;
                ensure(
                    page.request_count("PUT", "/api/settings").await? == before,
                    "a PUT went out mid-typing",
                )?;

                page.loc("#s-block-ipv4").blur().await?;
                // Give a wrong handler a chance to fire, then assert none did.
                tokio::time::sleep(SETTLE).await;
                ensure(
                    page.request_count("PUT", "/api/settings").await? == before,
                    "an invalid IPv4 was sent to the server",
                )?;

                // The error is inline next to the IPv4 field, not a shared line.
                page.loc("#msg-block-ipv4")
                    .expect_text_contains("IPv4")
                    .await
            },
        )
        .await;

    suite
        .case(
            "log retention auto-saves on blur, accepts blank (default), rejects non-numeric",
            async |_browser, page| {
                goto_settings(page).await?;

                // Valid: persists.
                let before = page.request_count("PUT", "/api/settings").await?;
                page.loc("#s-retention").fill("14").await?;
                page.loc("#s-retention").blur().await?;
                page.expect_request("PUT", "/api/settings", before).await?;
                page.reload().await?;
                page.loc("#s-retention").expect_value("14").await?;

                // Blank means "use the default": saved, not rejected.
                let before = page.request_count("PUT", "/api/settings").await?;
                page.loc("#s-retention").fill("").await?;
                page.loc("#s-retention").blur().await?;
                page.expect_request("PUT", "/api/settings", before).await?;
                page.reload().await?;
                page.loc("#s-retention").expect_value("").await?;

                // Invalid non-numeric: no request.
                let before = page.request_count("PUT", "/api/settings").await?;
                page.loc("#s-retention").fill("abc").await?;
                page.loc("#s-retention").blur().await?;
                tokio::time::sleep(SETTLE).await;
                ensure(
                    page.request_count("PUT", "/api/settings").await? == before,
                    "a non-numeric retention was sent to the server",
                )
            },
        )
        .await;

    Ok(suite.finish())
}
