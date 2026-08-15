//! The filters page with JavaScript switched off entirely. Everything on it is
//! a real form, so the page has to keep working: add a rule, delete it, add a
//! list, toggle it, edit it, remove it, test a domain. `app.js` never loads
//! here, which is the point — what these exercise is the markup the server
//! sent, not the enhancement layered over it.
//!
//! Its own noadd instance on dedicated ports, like the other specs here: it
//! mutates the very lists and rules the shared instance's scenarios assert on,
//! and it signs in for itself.

use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use noadd_e2e::dom::Page;
use noadd_e2e::{Api, Profile, Server, Suite, ports};

/// One login for the whole file, replayed as a cookie: a UI sign-in per case
/// would spend the five-per-minute budget on setup rather than on what is
/// under test. The sign-in form's own no-JS behaviour is covered by the auth
/// feature.
async fn open(page: &Page, session: &str, query: &str) -> Result<()> {
    page.adopt_session(session).await?;
    page.goto(&format!("/filters{query}")).await?;
    page.testid("app-shell").expect_visible().await
}

pub async fn run() -> Result<Vec<String>> {
    let server = Server::fresh(
        "filters-no-js",
        ports::FILTERS_NO_JS.0,
        ports::FILTERS_NO_JS.1,
    )
    .await?;
    let session = Api::new(server.base_url()).provision().await?;

    let mut suite = Suite::new(
        "The filters page works with no JavaScript",
        server.base_url(),
        Profile::no_js(),
    );

    suite
        .case(
            "the page renders its lists, rules and controls from the server",
            async |_browser, page| {
                open(page, &session, "").await?;
                page.testid("rules-list").expect_visible().await?;
                page.testid("nav-filters").expect_class("active").await?;
                // The registry browser used to be the one control that needed a
                // client, so it shipped hidden. It is a page of its own now,
                // and this is a link.
                page.loc("#browse-registry").expect_visible().await?;
                page.loc("#browse-registry")
                    .expect_attr("href", "/filters/registry")
                    .await
            },
        )
        .await;

    suite
        .case(
            "a custom rule can be added and deleted through the forms",
            async |_browser, page| {
                open(page, &session, "").await?;
                page.testid("rule-input")
                    .fill("||nojs-added.example.com^")
                    .await?;
                page.testid("rule-input").press_enter().await?;

                let row = page
                    .testid("rule-row")
                    .having_text("nojs-added.example.com");
                row.expect_visible().await?;
                row.expect_attr("data-type", "block").await?;
                // The POST redirected, so the URL is the page and not the
                // endpoint — a refresh here re-renders rather than re-submitting.
                page.expect_url_ends_with("/filters").await?;

                row.testid("rule-delete").click_js().await?;
                page.testid("rule-row")
                    .having_text("nojs-added.example.com")
                    .expect_count(0)
                    .await
            },
        )
        .await;

    suite
        .case(
            "a rule that does not parse comes back in the field with a reason",
            async |_browser, page| {
                open(page, &session, "").await?;
                page.testid("rule-input").fill("   ").await?;
                page.testid("rule-input").press_enter().await?;

                page.testid("rule-add-error")
                    .expect_text_contains("Not a rule noadd understands")
                    .await?;
                // Still the filters page, with the navigation knowing it, even
                // though the POST arrived on `/filters/rules`.
                page.testid("nav-filters").expect_class("active").await
            },
        )
        .await;

    suite
        .case(
            "a list can be added, toggled off, edited and deleted",
            async |_browser, page| {
                open(page, &session, "").await?;
                page.testid("list-name-input").fill("No JS List").await?;
                page.testid("list-url-input")
                    .fill("https://example.com/no-js.txt")
                    .await?;
                page.testid("list-name-input").press_enter().await?;

                let row = page.loc(r#"[data-testid="filter-list-row"][data-name="No JS List"]"#);
                row.expect_visible().await?;
                row.testid("filter-list-toggle")
                    .expect_checked(true)
                    .await?;

                // Untick, then submit — two steps without a script, which is
                // the trade the no-JS path makes. The submit is the button
                // `app.js` would have removed.
                row.loc("label.toggle").click_js().await?;
                row.loc(".nojs-only").click_js().await?;
                page.loc(r#"[data-testid="filter-list-row"][data-name="No JS List"]"#)
                    .testid("filter-list-toggle")
                    .expect_checked(false)
                    .await?;

                // Edit expands the row on the server rather than opening a dialog.
                page.loc(r#"[data-testid="filter-list-row"][data-name="No JS List"] .edit-list"#)
                    .click_js()
                    .await?;
                page.testid("filter-list-edit-row").expect_visible().await?;
                page.testid("list-edit-name")
                    .expect_value("No JS List")
                    .await?;
                page.testid("list-edit-name")
                    .fill("Renamed Without JS")
                    .await?;
                page.testid("list-edit-name").press_enter().await?;

                let renamed =
                    page.loc(r#"[data-testid="filter-list-row"][data-name="Renamed Without JS"]"#);
                renamed.expect_visible().await?;

                renamed.loc(".del-list").click_js().await?;
                page.loc(r#"[data-testid="filter-list-row"][data-name="Renamed Without JS"]"#)
                    .expect_count(0)
                    .await
            },
        )
        .await;

    suite
        .case(
            "a list with no URL comes back with the name still typed",
            async |_browser, page| {
                open(page, &session, "").await?;
                page.testid("list-name-input").fill("Missing URL").await?;
                page.testid("list-name-input").press_enter().await?;

                page.testid("list-add-error")
                    .expect_text_contains("URL is required")
                    .await?;
                page.testid("list-name-input")
                    .expect_value("Missing URL")
                    .await?;
                page.loc(r#"[data-testid="filter-list-row"][data-name="Missing URL"]"#)
                    .expect_count(0)
                    .await
            },
        )
        .await;

    suite
        .case(
            "a domain test is answered in the page and stays in the URL",
            async |_browser, page| {
                open(page, &session, "").await?;
                page.testid("rule-input")
                    .fill("||nojs-tested.example.com^")
                    .await?;
                page.testid("rule-input").press_enter().await?;
                // Wait for the row the POST's redirect renders before asking
                // anything else. Pressing Enter only dispatches the key: the
                // submission is still in flight, and navigating away from it —
                // which the poll below does immediately — cancels it. That is a
                // race the old suite had too; it just lost it less often.
                page.testid("rule-row")
                    .having_text("nojs-tested.example.com")
                    .expect_visible()
                    .await?;

                // The verdict comes from the live engine, which a background
                // rebuild refreshes; re-run the GET until the rule has landed.
                //
                // The wait is the element wait rather than the ten seconds the
                // old `expect.poll` allowed: a rebuild reparses the enabled
                // lists, so it is the one thing here whose cost is not the
                // browser's, and it is the first thing to run late when the
                // eight spec files share a machine.
                let deadline = Instant::now() + noadd_e2e::browser::WAIT_TIMEOUT;
                loop {
                    page.goto("/filters?test=nojs-tested.example.com").await?;
                    let verdict = page
                        .testid("domain-test-result")
                        .text()
                        .await
                        .unwrap_or_default();
                    if verdict.contains("Blocked") {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(anyhow!(
                            "the domain test never reported Blocked; last read {verdict:?}"
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }

                page.expect_url_contains("test=nojs-tested.example.com")
                    .await?;
                // Refreshable and linkable: the domain came back in the field too.
                page.testid("domain-test-input")
                    .expect_value("nojs-tested.example.com")
                    .await
            },
        )
        .await;

    suite
        .case(
            "Browse Registry is a link that reaches its page",
            async |_browser, page| {
                open(page, &session, "").await?;
                // This was the one control here that did nothing without
                // JavaScript.
                page.loc("#browse-registry").click_js().await?;
                page.expect_url_ends_with("/filters/registry").await?;
                page.loc("registry-page").expect_visible().await?;
                // What the page then says depends on whether the third-party
                // registry is reachable from wherever this is running, and both
                // answers are the page working: entries to tick, or an
                // explanation and a retry.
                page.loc(r#"#registry-form, [data-testid="registry-unavailable"]"#)
                    .first()
                    .expect_visible()
                    .await
            },
        )
        .await;

    Ok(suite.finish())
}
