//! The dashboard: readings only, with the real numbers in the first response.
//!
//! `app.js` re-draws the same markup from each `stats` snapshot on the event
//! stream, so every shape below has a counterpart in `DashboardPage`, formatted
//! identically — a number that changed notation on update would read as a change.
//!
//! The chart is the documented no-JS exception: the client draws it.

use maud::{Markup, html};

use super::layout::shell;
use crate::admin::pages::{DashboardTemplate, TopRowView};

/// The count, followed by its share when there is one.
fn count_cell(row: &TopRowView) -> Markup {
    html! {
        (row.count)
        @if !row.share.is_empty() {
            " " span style="color:var(--text-dim);font-size:0.75em" { "(" (row.share) ")" }
        }
    }
}

fn no_data() -> Markup {
    html! { p class="text-dim" { "No data" } }
}

fn domains_table(rows: &[TopRowView]) -> Markup {
    html! {
        table class="top-table" {
            colgroup { col; col style="width:140px"; }
            thead { tr { th { "Domain" } th style="text-align:right" { "Count" } } }
            tbody {
                @for row in rows {
                    tr {
                        td { div class="truncate-cell" title=(row.label) { (row.label) } }
                        td class="mono" style="text-align:right;white-space:nowrap" { (count_cell(row)) }
                    }
                }
            }
        }
    }
}

fn clients_table(rows: &[TopRowView]) -> Markup {
    html! {
        table class="top-table" {
            colgroup { col; col style="width:140px"; }
            thead { tr { th { "Client" } th style="text-align:right" { "Count" } } }
            tbody {
                @for row in rows {
                    tr {
                        td {
                            div class="truncate-cell mono" title=(row.label) { (row.label) }
                            @if !row.sub_label.is_empty() {
                                div class="truncate-cell" title=(row.sub_label) style="color:var(--accent);font-size:0.7rem" { (row.sub_label) }
                            }
                        }
                        td class="mono" style="text-align:right;white-space:nowrap" { (count_cell(row)) }
                    }
                }
            }
        }
    }
}

fn upstreams_table(rows: &[TopRowView]) -> Markup {
    html! {
        table class="top-table" {
            thead {
                tr {
                    th { "Upstream" }
                    th style="text-align:right;width:140px" { "Queries" }
                    th class="hide-mobile" style="text-align:right;width:120px" { "Avg Latency" }
                }
            }
            tbody {
                @for row in rows {
                    tr {
                        td { div class="truncate-cell mono" title=(row.label) { (row.label) } }
                        td class="mono" style="text-align:right;white-space:nowrap" { (count_cell(row)) }
                        td class="mono hide-mobile" style="text-align:right;white-space:nowrap" { (row.avg_ms) }
                    }
                }
            }
        }
    }
}

pub fn render(page: &DashboardTemplate) -> Markup {
    let chart_card_style = if page.has_queries {
        "animation-delay:0.1s"
    } else {
        "animation-delay:0.1s;display:none"
    };
    let body = html! {
        dashboard-page {
            div class="page-header fade-in" style="display:flex;align-items:center;justify-content:space-between" {
                div { h2 { "Dashboard" } p { "DNS query statistics overview" } }
                button class="live-toggle js-only" id="live-btn" data-testid="live-toggle" title="Auto-refresh every 10s. Click to toggle." hidden { span class="live-dot" {} " LIVE" }
            }
            div class="card fade-in" id="onboard-empty" data-testid="dashboard-empty-state" style=[page.has_queries.then_some("display:none")] {
                @if !page.has_queries {
                    div class="card-title" { "Point a device at noadd to get started" }
                    p style="color:var(--text-secondary);font-size:0.9rem;margin:8px 0" {
                        "noadd hasn't served any DNS queries yet. To start filtering, configure a device or router to use this server as its DNS resolver, then send some traffic."
                    }
                    p style="color:var(--text-secondary);font-size:0.9rem;margin:8px 0" {
                        "Set the device's DNS server to: "
                        code class="mono text-primary" { (page.dns_addr) }
                    }
                }
            }
            div class="stat-grid fade-in" id="stats" {
                div class="stat-card" data-i="0" { div class="stat-label" { "Queries 24h" } div class="stat-value accent" title=(page.queries_today_full) { (page.queries_today) } div class="stat-sub" { "7d: " (page.queries_7d) " / 30d: " (page.queries_30d) } }
                div class="stat-card" data-i="1" data-testid="stat-blocked-today" { div class="stat-label" { "Blocked 24h" } div class="stat-value red" title=(page.blocked_today_full) { (page.blocked_today) } div class="stat-sub" { "7d: " (page.blocked_7d) " / 30d: " (page.blocked_30d) } }
                div class="stat-card" data-i="2" data-testid="stat-block-rate" { div class="stat-label" { "Block Rate" } div class="stat-value red" { (page.block_rate) "%" } div class="stat-sub" { "7d: " (page.block_rate_7d) "% / 30d: " (page.block_rate_30d) "%" } }
                div class="stat-card" data-i="3" { div class="stat-label" { "Cache Hit Rate" } div class="stat-value text-orange" { (page.cache_rate) "%" } div class="stat-sub" { "7d: " (page.cache_rate_7d) "% / 30d: " (page.cache_rate_30d) "%" } }
                div class="stat-card" data-i="4" { div class="stat-label" { "Avg Response" } div class="stat-value text-orange" { (page.avg_ms) span style="font-size:0.9rem;color:var(--text-dim)" { "ms" } } div class="stat-sub" { "7d: " (page.avg_ms_7d) " ms / 30d: " (page.avg_ms_30d) " ms" } }
                div class="stat-card" data-i="5" data-testid="stat-throughput" { div class="stat-label" { "Throughput" } div class="stat-value accent" data-testid="stat-throughput-value" { (page.qps_now) span style="font-size:0.9rem;color:var(--text-dim)" { "q/s" } } div class="stat-sub" { "24h: " (page.qps_today) " / 7d: " (page.qps_7d) } }
            }
            div class="card fade-in" id="chart-card" style=(chart_card_style) {
                div class="card-title" { "Queries (24h)" }
                div class="chart-container" id="chart" {
                    p class="panel-empty" data-testid="chart-needs-js" { "The 24-hour chart is drawn in the browser. The numbers above and below it are complete without it." }
                }
            }
            div class="dashboard-grid-2col" style="display:grid;grid-template-columns:1fr 1fr;gap:16px" {
                div class="card fade-in" style="animation-delay:0.15s" id="domains-card" data-testid="top-domains-card" {
                    div class="card-title" { "Top Queried Domains" }
                    div id="top-domains" {
                        @if page.top_domains.is_empty() { (no_data()) } @else { (domains_table(&page.top_domains)) }
                    }
                }
                div class="card fade-in" style="animation-delay:0.2s" id="clients-card" {
                    div class="card-title" { "Top Sources" }
                    div id="top-clients" {
                        @if page.top_clients.is_empty() { (no_data()) } @else { (clients_table(&page.top_clients)) }
                    }
                }
            }
            div class="card fade-in" style="animation-delay:0.25s" id="upstreams-card" {
                div class="card-title" { "Upstream DNS Servers" }
                div id="top-upstreams" {
                    @if page.top_upstreams.is_empty() { (no_data()) } @else { (upstreams_table(&page.top_upstreams)) }
                }
            }
        }
    };
    shell(&page.shell, &body)
}
