//! The query log with JavaScript switched off entirely. Filtering and paging
//! are the claim this page makes — both live in the URL, so the filters are a
//! GET form and the pager is two links, and neither needs a client.
//!
//! The live tail is the documented exception (it is an `EventSource`), so its
//! button must not even be visible here.
//!
//! Its own noadd instance on dedicated ports, seeded through `sqlite3` against
//! the stopped database: several pages of history is what makes paging
//! testable, and sending that many real DNS queries would be slow and
//! dependent on an upstream.

use anyhow::Result;
use noadd_e2e::dom::Page;
use noadd_e2e::{Api, Profile, Server, Suite, ensure, ports, seed};

async fn open(page: &Page, session: &str, query: &str) -> Result<()> {
    page.adopt_session(session).await?;
    page.goto(&format!("/logs{query}")).await?;
    page.testid("app-shell").expect_visible().await
}

pub async fn run() -> Result<Vec<String>> {
    // Boot once to create the schema, set the operator up, then stop and seed.
    let mut server = Server::fresh("logs-no-js", ports::LOGS_NO_JS.0, ports::LOGS_NO_JS.1).await?;
    let api = Api::new(server.base_url());
    api.setup(noadd_e2e::ADMIN_USERNAME, noadd_e2e::ADMIN_PASSWORD)
        .await?;
    server.stop().await?;

    server.seed(&seed::query_log(seed::now_ms())).await?;

    server.start().await?;
    let session = api
        .login(noadd_e2e::ADMIN_USERNAME, noadd_e2e::ADMIN_PASSWORD)
        .await?;

    let mut suite = Suite::new(
        "The query log works with no JavaScript",
        server.base_url(),
        Profile::no_js(),
    );

    suite
        .case(
            "a page of rows arrives rendered, with the live tail marked client-only",
            async |_browser, page| {
                open(page, &session, "").await?;
                // A full page, not the whole log.
                page.testid("log-row").expect_count(50).await?;
                page.loc("#log-pagination")
                    .expect_text_contains("Page 1 / 3")
                    .await?;
                page.loc("#log-pagination")
                    .expect_text_contains(&format!("{} queries", seed::LOG_ROWS))
                    .await?;
                // The one thing that genuinely needs a client is not offered.
                page.testid("logs-live-toggle").expect_hidden().await
            },
        )
        .await;

    suite
        .case(
            "the pager walks pages and keeps the filters",
            async |_browser, page| {
                open(page, &session, "?action=blocked").await?;
                // 40 of the 120 rows are blocked, so a filtered log is one page.
                page.testid("log-row").expect_count(40).await?;
                page.loc("#log-pagination")
                    .expect_text_contains("Page 1 / 1")
                    .await?;

                open(page, &session, "").await?;
                // `click_js`, as in filters-no-js and for the same reason: the
                // pager sits at the foot of a long page and the status bar is fixed
                // to the bottom of the viewport, so a plain click is a function of
                // the window height. The URL assertions below only pass if the
                // navigation actually happened.
                page.testid("logs-next").click_js().await?;
                page.expect_url_contains("page=2").await?;
                page.loc("#log-pagination")
                    .expect_text_contains("Page 2 / 3")
                    .await?;
                // And back again.
                page.testid("logs-prev").click_js().await?;
                page.loc("#log-pagination")
                    .expect_text_contains("Page 1 / 3")
                    .await
            },
        )
        .await;

    suite
        .case(
            "filters submit as a GET and land in the URL",
            async |_browser, page| {
                open(page, &session, "").await?;
                page.testid("logs-search").fill("ads").await?;
                page.testid("logs-type").select_value("AAAA").await?;
                page.testid("logs-filter-apply").click_js().await?;

                page.expect_url_contains("q=ads").await?;
                page.expect_url_contains("type=AAAA").await?;
                // Every visible row matches both filters.
                let rows = page.testid("log-row");
                rows.expect_count_at_least(1).await?;
                let count = rows.count().await?;
                for i in 0..count {
                    rows.clone().nth(i).expect_text_contains("AAAA").await?;
                    rows.clone().nth(i).expect_text_contains("ads").await?;
                }
                // The form comes back showing what is applied, so it can be
                // adjusted rather than retyped.
                page.testid("logs-search").expect_value("ads").await?;
                page.testid("logs-type").expect_value("AAAA").await
            },
        )
        .await;

    suite
        .case(
            "a filter that matches nothing says so, and is not the empty-log guide",
            async |_browser, page| {
                open(page, &session, "?q=nothing-matches-this").await?;
                page.testid("log-row").expect_count(0).await?;
                page.loc("#log-body")
                    .expect_text_contains("No logs found")
                    .await?;
                page.testid("logs-empty-state").expect_count(0).await
            },
        )
        .await;

    suite
        .case(
            "a row's one-click rule posts and comes back to the same view",
            async |_browser, page| {
                open(page, &session, "?action=blocked&page=1").await?;
                let row = page.testid("log-row").first();
                // The cell carries the domain on its first line and metadata
                // under it, so the whole thing is trimmed before the split —
                // `textContent` starts with the newline after the `<td>`.
                let cell = row.loc("td").nth(2).text_raw().await?;
                let domain = cell
                    .trim()
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                ensure(!domain.is_empty(), "the first row carried no domain")?;
                row.loc(".log-action").click_js().await?;

                // Straight back to the filtered view it was invoked from.
                page.expect_url_contains("action=blocked").await?;
                // And the rule is on the filters page.
                page.goto("/filters").await?;
                page.testid("rule-row")
                    .first()
                    .expect_text_contains(&domain)
                    .await
            },
        )
        .await;

    suite
        .case(
            "clearing the log empties it and lands on an unfiltered first page",
            async |_browser, page| {
                open(page, &session, "?action=blocked&page=1").await?;
                page.testid("logs-clear").click_js().await?;

                page.expect_url_ends_with("/logs").await?;
                page.testid("logs-cleared").expect_visible().await?;
                // The empty-log guide, not "No logs found" — nothing is filtered.
                page.testid("logs-empty-state").expect_visible().await
            },
        )
        .await;

    Ok(suite.finish())
}
