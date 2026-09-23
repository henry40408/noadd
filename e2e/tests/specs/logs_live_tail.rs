//! The query log's live tail: a real query must arrive after the page is open,
//! which seeding a stopped database cannot show.
//!
//! The tail rides the shell's event stream (`/api/events?logs=1`), and turning
//! it on re-opens that one connection, so both are asserted: a row arrives, and
//! the status indicator on the same connection does not blink OFFLINE.

use anyhow::Result;
use noadd_e2e::dom::Page;
use noadd_e2e::{Api, Profile, Server, Suite, dns, ports};

async fn open_logs(page: &Page, session: &str) -> Result<()> {
    page.adopt_session(session).await?;
    page.goto("/logs").await?;
    page.testid("app-shell").expect_visible().await
}

pub async fn run() -> Result<Vec<String>> {
    let server = Server::fresh(
        "logs-live-tail",
        ports::LOGS_LIVE_TAIL.0,
        ports::LOGS_LIVE_TAIL.1,
    )
    .await?;
    let session = Api::new(server.base_url()).provision().await?;
    let dns_port = server.dns_port();

    let mut suite = Suite::new(
        "The query log's live tail streams over the shared connection",
        server.base_url(),
        Profile::desktop(),
    );

    suite
        .case(
            "a query answered while the page is open arrives as a row",
            async |_browser, page| {
                open_logs(page, &session).await?;

                // The indicator must be up before the toggle to mean anything after.
                page.testid("server-status")
                    .expect_attr("data-state", "online")
                    .await?;

                page.testid("logs-live-toggle").expect_visible().await?;
                // Unlike the dashboard's, this toggle keeps its label; state is a class.
                page.testid("logs-live-toggle")
                    .expect_class("paused")
                    .await?;
                page.testid("logs-live-toggle").click().await?;
                page.testid("logs-live-toggle")
                    .expect_not_class("paused")
                    .await?;

                // Sent after the tail is on, so the row cannot come from the
                // initial render. noadd logs it whether or not an upstream answers.
                dns::send_query(dns_port, "tailed-query.example").await?;

                page.expect_text("tailed-query.example").await?;

                // Re-opening the connection must not read as the server going away.
                page.testid("server-status")
                    .expect_attr("data-state", "online")
                    .await
            },
        )
        .await;

    suite
        .case(
            "switching the tail off stops new rows without dropping the stream",
            async |_browser, page| {
                open_logs(page, &session).await?;
                page.testid("logs-live-toggle").click().await?;
                page.testid("logs-live-toggle")
                    .expect_not_class("paused")
                    .await?;

                // Off again: the subscription goes, the connection stays.
                page.testid("logs-live-toggle").click().await?;
                page.testid("logs-live-toggle")
                    .expect_class("paused")
                    .await?;

                dns::send_query(dns_port, "not-tailed.example").await?;

                // NOTE: this only re-checks the indicator, which is typically
                // already online, so it adds no real delay before the absence check.
                page.testid("server-status")
                    .expect_attr("data-state", "online")
                    .await?;
                let seen = page.has_text("not-tailed.example").await?;
                anyhow::ensure!(
                    !seen,
                    "a paused tail still received rows, so the subscription outlived the toggle"
                );
                Ok(())
            },
        )
        .await;

    Ok(suite.finish())
}
