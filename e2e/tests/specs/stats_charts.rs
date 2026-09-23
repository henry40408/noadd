//! The browser's chart folds (`timelineFromQuarters` / `heatmapFromQuarters` in
//! `app.js`, over the page's UTC quarter-hour series) must equal what
//! `/api/stats/v2/timeline` and `…/heatmap` answer for the same `tz_offset`,
//! for every range and for offsets either side of UTC, including half- and
//! three-quarter-hour zones. The folds take the offset as an argument, so the
//! machine's own zone does not matter.
//!
//! The seed keeps every row at least an hour clear of every window's edge, so
//! the page and the API, asked seconds apart, see the same rows.

use anyhow::{Context, Result};
use noadd_e2e::dom::Page;
use noadd_e2e::{Api, Profile, Server, Suite, ports};
use serde_json::{Value, json};

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 24 * HOUR_MS;

/// East-positive offsets in minutes: UTC, Taipei, New York, India, Nepal, the
/// Marquesas, Kiritimati and Baker Island.
const OFFSETS: [i64; 8] = [0, 480, -300, 330, 345, -570, 840, -720];

/// Traffic every seven minutes and a few seconds across the last six days, plus
/// rows twenty days back (inside 30d and the heatmap, outside 7d) and sixty
/// days back (inside 90d only).
fn seed(now: i64) -> String {
    let row = |ts: i64, i: i64| {
        format!(
            "({ts}, 'host{}.example', '{}', '10.0.0.{}', {}, {}, {}, '1.1.1.1:53', NULL, '1.2.3.4', 0)",
            i % 40,
            ["A", "AAAA", "HTTPS"][usize::try_from(i % 3).unwrap_or_default()],
            i % 9,
            i32::from(i % 7 == 0),
            i32::from(i % 5 == 0),
            (i * 13) % 90,
        )
    };
    let mut rows = Vec::new();
    let mut ts = now - HOUR_MS;
    let mut i = 0;
    while ts > now - 6 * DAY_MS {
        rows.push(row(ts, i));
        ts -= 7 * 60_000 + 3_217;
        i += 1;
    }
    for k in 0..50 {
        rows.push(row(now - 20 * DAY_MS - k * 11 * 60_000, k));
        rows.push(row(now - 60 * DAY_MS - k * 11 * 60_000, k));
    }
    // Retention would otherwise prune the older rows at boot.
    format!(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('log_retention_days', '120');\n\
         INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, \
         response_ms, upstream, doh_token, result, authenticated_data) VALUES\n{};\n",
        rows.join(",\n")
    )
}

/// What the page's folds produce for each of [`OFFSETS`].
async fn folds(page: &Page) -> Result<Value> {
    page.eval(&format!(
        "const el = document.querySelector('stats-page');
         const series = JSON.parse(el.dataset.series);
         const bucket = Number(el.dataset.bucketSecs);
         return {OFFSETS:?}.map(offset => ({{
           timeline: timelineFromQuarters(series, bucket, offset),
           heatmap: heatmapFromQuarters(series, offset),
         }}));"
    ))
    .await
}

pub async fn run() -> Result<Vec<String>> {
    let mut server =
        Server::fresh("stats-charts", ports::STATS_CHARTS.0, ports::STATS_CHARTS.1).await?;
    let api = Api::new(server.base_url());
    api.setup(noadd_e2e::ADMIN_USERNAME, noadd_e2e::ADMIN_PASSWORD)
        .await?;
    server.stop().await?;
    server.seed(&seed(noadd_e2e::seed::now_ms())).await?;
    server.start().await?;
    let session = api
        .login(noadd_e2e::ADMIN_USERNAME, noadd_e2e::ADMIN_PASSWORD)
        .await?;

    let mut suite = Suite::new(
        "The statistics charts agree with the API",
        server.base_url(),
        Profile::desktop(),
    );

    for range in ["7d", "30d", "90d"] {
        suite
            .case(
                &format!("the {range} timeline and the heatmap fold to what the API answers"),
                async |_browser, page| {
                    page.adopt_session(&session).await?;
                    page.goto(&format!("/stats?range={range}")).await?;
                    // Drawn from the embedded series, with no request of its own.
                    page.loc("#timeline-chart .tl-svg").expect_visible().await?;
                    page.loc("#heatmap-container .heatmap-cell")
                        .first()
                        .expect_visible()
                        .await?;

                    let folds = folds(page).await?;
                    for (i, offset) in OFFSETS.iter().enumerate() {
                        let timeline = api
                            .get_json(
                                &session,
                                &format!("/api/stats/v2/timeline?range={range}&tz_offset={offset}"),
                            )
                            .await?;
                        let heatmap = api
                            .get_json(&session, &format!("/api/stats/v2/heatmap?tz_offset={offset}"))
                            .await?;
                        let fold = folds.get(i).context("a fold per offset")?;
                        noadd_e2e::ensure(
                            timeline.as_array().is_some_and(|t| t.len() > 1),
                            format!("the API timeline for {range} is too short to compare: {timeline}"),
                        )?;
                        noadd_e2e::ensure(
                            fold["timeline"] == timeline,
                            format!(
                                "timeline {range}, offset {offset} min:\n  page {}\n  api  {timeline}",
                                fold["timeline"]
                            ),
                        )?;
                        noadd_e2e::ensure(
                            fold["heatmap"] == sorted_cells(&heatmap),
                            format!(
                                "heatmap, offset {offset} min:\n  page {}\n  api  {heatmap}",
                                fold["heatmap"]
                            ),
                        )?;
                    }
                    Ok(())
                },
            )
            .await;
    }

    Ok(suite.finish())
}

/// The API's cells in weekday-then-hour order, the fold's order, so the
/// comparison does not depend on the server's ordering.
fn sorted_cells(cells: &Value) -> Value {
    let mut cells = cells.as_array().cloned().unwrap_or_default();
    cells.sort_by_key(|c| (c["weekday"].as_i64(), c["hour"].as_i64()));
    json!(cells)
}
