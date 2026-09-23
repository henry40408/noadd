//! Touch on the statistics charts: `:hover` and `pointermove` tooltips never
//! fire on a tap. On a touch-enabled Pixel 5, a tap reveals the tooltip, it
//! persists after the finger lifts, and a tap elsewhere dismisses it — while
//! mouse hover keeps working.
//!
//! Own instance, seeded with the 90-day screenshot traffic so every chart has
//! a real multi-point series.

use std::time::Duration;

use anyhow::Result;
use noadd_e2e::browser::Browser;
use noadd_e2e::dom::Page;
use noadd_e2e::{ADMIN_PASSWORD, ADMIN_USERNAME, Api, Profile, Server, Suite, ports, seed};

/// A point outside every chart, for the "tap outside dismisses" half.
const OUTSIDE: (f64, f64) = (10.0, 10.0);

/// Wait after lifting, long enough for the synthetic mouse events a tap triggers.
const AFTER_LIFT: Duration = Duration::from_millis(400);

/// Signs in and lands on the statistics page with all three charts drawn.
///
/// Navigates by URL: the desktop nav strip is hidden at mobile widths.
async fn goto_stats(page: &Page) -> Result<()> {
    page.goto("/").await?;
    page.testid("login-username").fill(ADMIN_USERNAME).await?;
    page.testid("login-password").fill(ADMIN_PASSWORD).await?;
    page.testid("login-submit").click().await?;
    page.testid("app-shell").expect_visible().await?;
    page.goto("/stats").await?;
    // Wait for all three interactive charts to render real data.
    page.loc("#timeline-chart .tl-svg").expect_visible().await?;
    page.loc("#rate-trend-chart .rate-svg")
        .expect_visible()
        .await?;
    page.loc("#heatmap-container .heatmap-cell")
        .first()
        .expect_visible()
        .await
}

/// Taps the centre of whatever the selector matches.
async fn tap(browser: &Browser, page: &Page, css: &str) -> Result<()> {
    let (x, y) = page.loc(css).viewport_center().await?;
    browser.tap(x, y).await
}

pub async fn run() -> Result<Vec<String>> {
    // Boot #1: create the schema and defaults, create the operator, stop.
    let mut server =
        Server::fresh("chart-touch", ports::CHART_TOUCH.0, ports::CHART_TOUCH.1).await?;
    Api::new(server.base_url())
        .setup(ADMIN_USERNAME, ADMIN_PASSWORD)
        .await?;
    server.stop().await?;

    // Seed backdated traffic, then boot #2 with data the charts can render.
    server.seed(&seed::screenshots(seed::now_ms())).await?;
    server.start().await?;

    let mut suite = Suite::new(
        "Statistics charts respond to touch",
        server.base_url(),
        Profile::mobile(),
    );

    suite
        .case(
            "tapping the timeline chart shows a tooltip that persists, then dismisses",
            async |browser, page| {
                goto_stats(page).await?;
                let tooltip = page.loc("#timeline-chart .rate-tooltip");
                tooltip.expect_hidden().await?;

                tap(browser, page, "#timeline-chart .tl-svg").await?;
                tooltip.expect_visible().await?;

                // Persists after the finger lifts.
                tokio::time::sleep(AFTER_LIFT).await;
                tooltip.expect_visible().await?;

                // A tap outside the chart dismisses it.
                browser.tap(OUTSIDE.0, OUTSIDE.1).await?;
                tooltip.expect_hidden().await
            },
        )
        .await;

    suite
        .case(
            "tapping the rate-trend chart shows a tooltip",
            async |browser, page| {
                goto_stats(page).await?;
                let tooltip = page.loc("#rate-trend-chart .rate-tooltip");
                tooltip.expect_hidden().await?;

                tap(browser, page, "#rate-trend-chart .rate-svg").await?;
                tooltip.expect_visible().await?;

                browser.tap(OUTSIDE.0, OUTSIDE.1).await?;
                tooltip.expect_hidden().await
            },
        )
        .await;

    suite
        .case(
            "tapping a heatmap cell shows its tooltip and switches between cells",
            async |browser, page| {
                goto_stats(page).await?;
                let cells = page.loc("#heatmap-container .heatmap-cell");
                // Mid-grid cells, comfortably tappable.
                let first = cells.clone().nth(30);
                let second = cells.nth(60);

                let (x, y) = first.viewport_center().await?;
                browser.tap(x, y).await?;
                first.expect_class("touch-active").await?;
                first.loc(".heatmap-tooltip").expect_visible().await?;

                // Another tap moves the active tooltip rather than stacking.
                let (x, y) = second.viewport_center().await?;
                browser.tap(x, y).await?;
                second.expect_class("touch-active").await?;
                first.expect_not_class("touch-active").await?;

                // Tapping outside the heatmap dismisses it.
                browser.tap(OUTSIDE.0, OUTSIDE.1).await?;
                second.expect_not_class("touch-active").await
            },
        )
        .await;

    suite
        .case(
            "mouse hover still shows and hides the timeline tooltip",
            async |browser, page| {
                goto_stats(page).await?;
                let tooltip = page.loc("#timeline-chart .rate-tooltip");
                let (x, y, width, height) =
                    page.loc("#timeline-chart .tl-svg").viewport_rect().await?;

                browser
                    .mouse_move(x + width / 2.0, y + height / 2.0)
                    .await?;
                tooltip.expect_visible().await?;

                // Moving off the chart dismisses; no outside tap needed.
                browser.mouse_move(x + width / 2.0, y - 40.0).await?;
                tooltip.expect_hidden().await
            },
        )
        .await;

    Ok(suite.finish())
}
