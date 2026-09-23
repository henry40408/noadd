//! The query log's live tail: a real query must arrive after the page is open,
//! which seeding a stopped database cannot show.
//!
//! The tail rides the shell's event stream (`/api/events?logs=1`), and turning
//! it on re-opens that one connection, so both are asserted: a row arrives, and
//! the status indicator on the same connection does not blink OFFLINE.

use std::time::Duration;

use anyhow::Result;
use noadd_e2e::dom::Page;
use noadd_e2e::{Api, Profile, Server, Suite, dns, ports, wait};

/// How long a pushed row gets to reach the page once the server has sent it.
const PUSH_GRACE: Duration = Duration::from_millis(500);

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
    let api = Api::new(server.base_url());
    let session = api.provision().await?;
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

                // An absence proves nothing until the row could have arrived. The
                // logger broadcasts an entry before it flushes it, so once
                // `/api/logs` has the row a live subscription has already been sent
                // it; the grace covers the push reaching the page.
                wait::eventually("the query reaching the log", async || {
                    let body = api
                        .get_json(&session, "/api/logs?search=not-tailed.example")
                        .await?;
                    let total = body["total"].as_i64().unwrap_or(0);
                    Ok((total > 0, format!("total={total}")))
                })
                .await?;
                tokio::time::sleep(PUSH_GRACE).await;

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
