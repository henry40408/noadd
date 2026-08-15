//! The statistics page with JavaScript switched off entirely.
//!
//! The claim this page makes is that the readings are readings: five of the
//! seven arrive in the first response and stay put. The three that do not are
//! the timeline, the rate trend drawn from it and the heatmap — the only three
//! that bucket a query against a calendar, which needs a UTC offset that
//! arrives with the browser rather than with the request. Those say so here
//! instead of sitting empty.
//!
//! The range switcher is the other half: it selects the *server's* window, so
//! it is three links and it works with nothing running.
//!
//! Its own noadd instance on dedicated ports, seeded through `sqlite3` against
//! the stopped database — the rows have to span more than seven days for
//! switching the range to change any number.

use anyhow::Result;
use noadd_e2e::dom::Page;
use noadd_e2e::{Api, Profile, Server, Suite, ports, seed};

async fn open(page: &Page, session: &str, query: &str) -> Result<()> {
    page.adopt_session(session).await?;
    page.goto(&format!("/stats{query}")).await?;
    page.testid("app-shell").expect_visible().await
}

pub async fn run() -> Result<Vec<String>> {
    let mut server =
        Server::fresh("stats-no-js", ports::STATS_NO_JS.0, ports::STATS_NO_JS.1).await?;
    let api = Api::new(server.base_url());
    api.setup(noadd_e2e::ADMIN_USERNAME, noadd_e2e::ADMIN_PASSWORD)
        .await?;
    server.stop().await?;

    server.seed(&seed::stats(seed::now_ms())).await?;

    server.start().await?;
    let session = api
        .login(noadd_e2e::ADMIN_USERNAME, noadd_e2e::ADMIN_PASSWORD)
        .await?;

    let mut suite = Suite::new(
        "The statistics page works with no JavaScript",
        server.base_url(),
        Profile::no_js(),
    );

    suite
        .case(
            "every reading that does not need a calendar arrives rendered",
            async |_browser, page| {
                open(page, &session, "").await?;

                // Highlights: two domains were queried inside the 7-day window.
                page.loc("#highlights-grid")
                    .expect_text_contains("Unique Domains")
                    .await?;
                page.loc("#highlights-grid")
                    .expect_text_contains("2")
                    .await?;
                // Latency percentiles, from a seeded 12 ms on every row.
                page.loc("#highlights-grid")
                    .expect_text_contains("Latency p50")
                    .await?;

                // Both breakdowns, as bars rather than as a chart.
                page.loc("#qtypes-chart .bar-row").expect_count(2).await?;
                page.loc("#qtypes-chart").expect_text_contains("A").await?;
                page.loc("#qtypes-chart")
                    .expect_text_contains("AAAA")
                    .await?;
                page.loc("#outcomes-chart")
                    .expect_text_contains("Blocked")
                    .await?;

                // Both ranged lists. 30 of 40 queries were blocked ads.
                page.testid("ranged-domains")
                    .expect_text_contains("ads.recent.example")
                    .await?;
                page.testid("ranged-domains")
                    .expect_text_contains("75.0%")
                    .await?;
                page.testid("ranged-clients")
                    .expect_text_contains("10.0.0.7")
                    .await?;
                // Nothing from outside the window leaked into the default range.
                page.testid("ranged-domains")
                    .expect_text_excludes("old.example")
                    .await?;

                // And the health grid, which reports on the file rather than on
                // traffic.
                page.testid("db-health-card")
                    .expect_text_contains("Database Size")
                    .await?;
                page.testid("db-health-card")
                    .expect_text_contains("Total Logs")
                    .await?;
                // The date the server could only write in UTC is still a
                // readable date.
                let health = page.testid("db-health-card").text().await?;
                noadd_e2e::ensure(
                    contains_iso_day(&health),
                    format!("no YYYY-MM-DD date in the health card: {health:?}"),
                )
            },
        )
        .await;

    suite
        .case(
            "the three charts say they are drawn in the browser",
            async |_browser, page| {
                open(page, &session, "").await?;

                page.testid("timeline-needs-js").expect_visible().await?;
                page.testid("rate-trend-needs-js").expect_visible().await?;
                page.testid("heatmap-needs-js").expect_visible().await?;
                // Nothing was drawn — these are the elements the client would
                // have made.
                page.loc("#timeline-chart .tl-svg").expect_count(0).await?;
                page.loc("#heatmap-container .heatmap-cell")
                    .expect_count(0)
                    .await
            },
        )
        .await;

    suite
        .case(
            "the range switcher is links, and switching one widens the window",
            async |_browser, page| {
                open(page, &session, "").await?;

                let switcher = page.testid("range-switcher");
                switcher.loc("a").expect_count(3).await?;
                switcher.loc("a.active").expect_text_eq("7d").await?;
                page.loc("#ranged-domains-title")
                    .expect_text_eq("Top Domains (last 7d)")
                    .await?;

                // Follow the link. No client: this is an ordinary navigation.
                //
                // `click_js` skips the stability check, which the page header's
                // fade-in fails for its first frames — with scripting off the
                // page is interactive the moment it parses, so the card is
                // still sliding when the click lands. The assertions below only
                // pass if the navigation actually happened, so a link that did
                // nothing still fails this case.
                switcher.loc("a").having_text("30d").click_js().await?;
                page.expect_url_ends_with("/stats?range=30d").await?;

                switcher.loc("a.active").expect_text_eq("30d").await?;
                page.loc("#ranged-domains-title")
                    .expect_text_eq("Top Domains (last 30d)")
                    .await?;
                page.loc("#timeline-title")
                    .expect_text_eq("Queries (last 30d)")
                    .await?;
                // The wider window reaches the older traffic the 7-day one
                // could not.
                page.testid("ranged-domains")
                    .expect_text_contains("old.example")
                    .await?;
                page.loc("#highlights-grid").expect_text_contains("3").await
            },
        )
        .await;

    suite
        .case(
            "a range nobody offers renders the default window rather than an error",
            async |_browser, page| {
                open(page, &session, "?range=nonsense").await?;
                page.loc("#ranged-domains-title")
                    .expect_text_eq("Top Domains (last 7d)")
                    .await?;
                page.testid("range-switcher")
                    .loc("a.active")
                    .expect_text_eq("7d")
                    .await
            },
        )
        .await;

    Ok(suite.finish())
}

/// Is a `YYYY-MM-DD` anywhere in this text?
///
/// The old assertion was `toContainText(/\d{4}-\d{2}-\d{2}/)`; this slides the
/// same shape along the string rather than pulling in a regex crate for one
/// check. It has to slide rather than split on whitespace: the label and the
/// date share a text node, so the card reads `Oldest Log2026-08-05`.
fn contains_iso_day(text: &str) -> bool {
    text.as_bytes().windows(10).any(|window| {
        window.iter().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                *b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
    })
}
