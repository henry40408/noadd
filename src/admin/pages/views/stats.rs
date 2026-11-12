//! The statistics page.
//!
//! Only the three charts need a calendar, and calendar buckets need the viewer's
//! UTC offset, which only the browser knows. So they are drawn client-side from
//! `data-series`: quarter-hour counts on UTC boundaries, from the same scan as
//! the breakdowns, which `app.js` folds into local hours and days.
//!
//! Everything else is a plain `now - range` window, rendered here and never
//! redrawn by `app.js`.

use maud::{Markup, html};

use crate::admin::pages::{BarRowView, StatCardView, StatsTemplate};

/// Shared by the page's four bar lists, so they cannot drift apart.
fn bar_row(row: &BarRowView, color: &str) -> Markup {
    let fill_style = format!("width:{}%;background:{}", row.width, color);
    html! {
        div class="bar-row" {
            div class="bar-row-label" title=(row.label) { (row.label) }
            div class="bar-row-track" { div class="bar-row-fill" style=(fill_style) {} }
            div class="bar-row-count" title=(row.count_title) {
                div { (row.count) }
                @if !row.share.is_empty() { div class="bar-row-pct" { (row.share) } }
            }
        }
    }
}

/// One bar list, or the empty-state line.
fn bar_list(rows: &[BarRowView], color: &str) -> Markup {
    html! {
        @if rows.is_empty() {
            p class="text-dim" { "No data yet" }
        } @else {
            div class="bar-list" {
                @for row in rows { (bar_row(row, color)) }
            }
        }
    }
}

fn stat_card(card: &StatCardView, with_date_ts: bool) -> Markup {
    let show_ts = with_date_ts && card.ts != 0;
    html! {
        div class="stat-card" {
            div class="stat-label" { (card.label) }
            div class={"stat-value " (card.value_class)}
                title=[(!card.title.is_empty()).then_some(&card.title)]
                data-date-ts=[show_ts.then_some(card.ts)]
            {
                (card.value)
                @if !card.unit.is_empty() {
                    span style="font-size:0.9rem;color:var(--text-dim)" { (card.unit) }
                }
            }
            @if with_date_ts && !card.sub.is_empty() { div class="stat-sub" { (card.sub) } }
        }
    }
}

pub fn render(page: &StatsTemplate) -> Markup {
    let body = html! {
        stats-page data-series=(page.series_json) data-bucket-secs=(page.bucket_secs) {
            div class="page-header fade-in" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px" {
                div { h2 { "Statistics" } p { "Long-term traffic patterns" } }
                div class="range-switcher" id="range-switcher" data-testid="range-switcher" {
                    @for option in &page.ranges {
                        " "
                        a href=(format!("/stats?range={}", option.label))
                            class=[option.active.then_some("active")]
                            aria-current=[option.active.then_some("page")] { (option.label) }
                    }
                }
            }
            div class="stat-grid fade-in" id="highlights-grid" style="animation-delay:0.03s" {
                @for card in &page.highlights { (stat_card(card, false)) }
            }
            div class="stats-row-2col fade-in" style="animation-delay:0.05s" {
                div class="card" id="timeline-card" {
                    div class="card-title" id="timeline-title" { "Queries (last " (page.range) ")" }
                    div class="chart-container" id="timeline-chart" {
                        p class="panel-empty" data-testid="timeline-needs-js" { "This chart is drawn in the browser, aligned to its calendar. The figures around it are complete without it." }
                    }
                }
                div class="card" id="rate-trend-card" {
                    div class="card-title" id="rate-trend-title" { "Block & Cache rate (last " (page.range) ")" }
                    div class="rate-chart-container" id="rate-trend-chart" {
                        p class="panel-empty" data-testid="rate-trend-needs-js" { "Drawn in the browser from the same series as the chart beside it." }
                    }
                }
            }
            div class="card fade-in" style="animation-delay:0.08s" id="heatmap-card" {
                div class="card-title" { "Activity by hour (last 30d)" }
                div id="heatmap-container" {
                    p class="panel-empty" data-testid="heatmap-needs-js" { "Drawn in the browser: hour-of-day rows need the viewer's time zone to line up." }
                }
            }
            div class="stats-row-2col fade-in" style="animation-delay:0.1s" {
                div class="card" id="qtypes-card" {
                    div class="card-title" { "Query Types" }
                    div id="qtypes-chart" { (bar_list(&page.query_types, "var(--accent)")) }
                }
                div class="card" id="outcomes-card" {
                    div class="card-title" { "Outcomes" }
                    div id="outcomes-chart" { (bar_list(&page.outcomes, "var(--orange)")) }
                }
            }
            div class="stats-row-2col fade-in" style="animation-delay:0.15s" {
                div class="card" id="ranged-domains-card" {
                    div class="card-title" id="ranged-domains-title" { "Top Domains (last " (page.range) ")" }
                    div id="ranged-domains" data-testid="ranged-domains" { (bar_list(&page.top_domains, "var(--accent)")) }
                }
                div class="card" id="ranged-clients-card" {
                    div class="card-title" id="ranged-clients-title" { "Top Sources (last " (page.range) ")" }
                    div id="ranged-clients" data-testid="ranged-clients" { (bar_list(&page.top_clients, "var(--green)")) }
                }
            }
            div class="card fade-in" style="animation-delay:0.2s" id="health-card" data-testid="db-health-card" {
                div class="card-title" { "Database Health" }
                div class="stat-grid" id="health-grid" {
                    @for card in &page.health { (stat_card(card, true)) }
                }
            }
        }
    };
    super::layout::shell(&page.shell, &body)
}
