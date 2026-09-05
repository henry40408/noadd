//! The query log's live tail, which is the one thing on that page that only
//! exists with a client.
//!
//! It earns its own file because it is the only test here that needs the
//! appliance to *answer* something while a browser is watching: the tail is
//! server-pushed, so proving it works means making a real query arrive after
//! the page is already open. Seeding the database the way `logs_no_js` does
//! cannot show this — those rows are written while the server is stopped.
//!
//! The tail rides the shell's shared event stream (`/api/events?logs=1`) rather
//! than a connection of its own, and switching it on re-opens that one
//! connection with the subscription added. Two things therefore have to hold at
//! once, and both are asserted here: a row arrives, and the status indicator on
//! the other end of the same connection does not blink OFFLINE while it does.

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

                // The status indicator is driven by the same connection the
                // tail is about to join, so it has to be up before the toggle
                // to mean anything after it.
                page.testid("server-status")
                    .expect_attr("data-state", "online")
                    .await?;

                page.testid("logs-live-toggle").expect_visible().await?;
                // Unlike the dashboard's, this button keeps its label and
                // carries its state in a class, so that is what is asserted.
                page.testid("logs-live-toggle")
                    .expect_class("paused")
                    .await?;
                page.testid("logs-live-toggle").click().await?;
                page.testid("logs-live-toggle")
                    .expect_not_class("paused")
                    .await?;

                // Answered after the tail is on, so a row that appears cannot
                // have come from the page's initial render. Whether an upstream
                // resolves it is beside the point — noadd logs what it handled.
                dns::send_query(dns_port, "tailed-query.example").await?;

                page.expect_text("tailed-query.example").await?;

                // Switching the tail on re-opens the shared connection. If that
                // were reported as the server going away, the operator would
                // watch the status bar drop to OFFLINE for clicking a toggle.
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

                // Off again. The subscription goes with it; the connection, and
                // so the indicator, stays.
                page.testid("logs-live-toggle").click().await?;
                page.testid("logs-live-toggle")
                    .expect_class("paused")
                    .await?;

                dns::send_query(dns_port, "not-tailed.example").await?;

                // A bounded negative: long enough that a row would have been
                // pushed and prepended had the subscription survived.
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
