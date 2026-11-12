//! The query log.
//!
//! Every filter and the page number are in the URL: the filters are a GET form
//! and the pager is two links, so the page works without JavaScript, and
//! `app.js` reads the same query string back when it takes over.
//!
//! The live tail needs the event stream, so its button ships hidden.
//!
//! Row actions and Clear All are POSTs that redirect. A row action carries its
//! view in `next`, so it returns to the same filtered page.

use maud::{Markup, html};

use super::layout::shell;
use crate::admin::pages::{LogRowView, LogsTemplate, OptionView};

fn status_mark(row: &LogRowView) -> Markup {
    html! {
        span class={ "st " @if row.blocked { "st-block" } @else { "st-ok" } } title=(if row.blocked { "blocked" } else { "allowed" }) { @if row.blocked { "✖" } @else { "✔" } }
    }
}

fn dnssec_badge() -> Markup {
    html! { span class="badge badge-dnssec" style="flex:0 0 auto" { "dnssec" } }
}

fn action_form(row: &LogRowView, current_href: &str, style: Option<&str>) -> Markup {
    html! {
        form method="post" action="/logs/rules" class="inline-form" style=[style] {
            input type="hidden" name="rule" value=(row.action_rule);
            " "
            input type="hidden" name="next" value=(current_href);
            " "
            button type="submit" class={ "btn btn-sm log-action " @if row.blocked { "btn-allow" } @else { "btn-danger" } } data-domain=(row.domain) data-blocked=(row.blocked.to_string()) { (row.action_label) }
        }
    }
}

fn option_list(options: &[OptionView]) -> Markup {
    html! {
        @for opt in options {
            option value=(opt.value) selected[opt.selected] { (opt.value) }
        }
    }
}

fn empty_state_box(testid: Option<&str>) -> Markup {
    html! {
        div data-testid=[testid] style="text-align:center;color:var(--text-secondary);padding:24px 12px" {
            div style="color:var(--text-primary);font-weight:600;margin-bottom:6px" { "No DNS queries logged yet" }
            div style="font-size:0.9rem" { "Once a device uses noadd as its DNS resolver, its queries will appear here." }
        }
    }
}

fn table_row(row: &LogRowView, current_href: &str) -> Markup {
    html! {
        tr data-testid="log-row" {
            td { span class="timeago" data-ts=(row.timestamp_ms) { (row.time_text) } }
            td style="text-align:center" { (status_mark(row)) }
            td {
                div style="display:flex;align-items:center;gap:6px;max-width:300px" {
                    span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;color:var(--text-primary)" title=(row.domain) { (row.domain) }
                    @if row.dnssec { (dnssec_badge()) }
                }
                @if !row.result.is_empty() {
                    div class="mono" style="font-size:0.85rem;color:var(--text-dim);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title=(row.result) { "→ " (row.result) }
                }
            }
            td class="mono" { (row.query_type) }
            td class="mono" {
                (row.client_ip)
                @if !row.doh_token.is_empty() {
                    br;
                    span style="color:var(--accent);font-size:0.85rem" { (row.doh_token) }
                }
            }
            td { (action_form(row, current_href, None)) }
            td {
                @if row.cached {
                    span class="badge badge-cached" { "cached" }
                } @else if !row.upstream.is_empty() {
                    span class="mono" style="font-size:0.9rem" { (row.upstream) }
                } @else {
                    span class="text-dim" { "-" }
                }
            }
            td class="mono" { (row.response_ms) }
        }
    }
}

fn table_body(page: &LogsTemplate) -> Markup {
    html! {
        @if page.rows.is_empty() {
            tr {
                td colspan="8" style=(if page.filtered { "text-align:center;color:var(--text-dim)" } else { "padding:0" }) {
                    @if page.filtered {
                        "No logs found"
                    } @else {
                        (empty_state_box(Some("logs-empty-state")))
                    }
                }
            }
        } @else {
            @for row in &page.rows { (table_row(row, &page.current_href)) }
        }
    }
}

fn card(row: &LogRowView, current_href: &str) -> Markup {
    html! {
        div class="log-card" {
            div class="log-card-row1" {
                span class={ "st " @if row.blocked { "st-block" } @else { "st-ok" } } title=(if row.blocked { "blocked" } else { "allowed" }) style="flex:0 0 auto" { @if row.blocked { "✖" } @else { "✔" } }
                " "
                span class="log-card-domain" title=(row.domain) { (row.domain) }
                @if row.dnssec { (dnssec_badge()) }
                " "
                (action_form(row, current_href, Some("flex-shrink:0")))
            }
            @if !row.result.is_empty() {
                div class="mono" style="font-size:0.85rem;color:var(--text-dim);margin-bottom:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title=(row.result) { "→ " (row.result) }
            }
            div class="log-card-row2" {
                span class="lc-time" { span class="timeago" data-ts=(row.timestamp_ms) { (row.time_text) } }
                " "
                span class="lc-type" { (row.query_type) }
                " "
                span class="lc-client text-secondary" { (row.client_ip) }
                @if row.cached {
                    span class="lc-cached" { "cached" }
                } @else if !row.upstream.is_empty() {
                    span class="lc-up" { (row.upstream) }
                }
                @if !row.doh_token.is_empty() { span class="lc-token" { (row.doh_token) } }
                " "
                span class="lc-ms" { (row.response_ms) "ms" }
            }
        }
    }
}

fn cards(page: &LogsTemplate) -> Markup {
    html! {
        @if page.rows.is_empty() {
            @if page.filtered {
                p style="color:var(--text-dim);text-align:center;padding:16px" { "No logs found" }
            } @else {
                (empty_state_box(None))
            }
        } @else {
            @for row in &page.rows { (card(row, &page.current_href)) }
        }
    }
}

fn filters(page: &LogsTemplate) -> Markup {
    let has_suggestions = !page.domain_suggestions.is_empty();
    html! {
        form method="get" action="/logs" class="filters-row fade-in" id="log-filters" {
            input type="text" id="log-search" name="q" value=(page.q) data-testid="logs-search" placeholder="Domain prefix, or *pattern*" title="Plain text matches the domain prefix (fast). Use * or % anywhere for a substring/wildcard match (slower)." list=[has_suggestions.then_some("log-domain-list")] autocomplete="off";
            " "
            @if has_suggestions {
                datalist id="log-domain-list" {
                    @for d in &page.domain_suggestions { option value=(d) {} }
                }
                " "
            }
            select id="log-action" name="action" data-testid="logs-action" {
                option value="" selected[page.action.is_empty()] { "All" }
                option value="allowed" selected[page.action == "allowed"] { "Allowed" }
                option value="blocked" selected[page.action == "blocked"] { "Blocked" }
            }
            " "
            select id="log-type" name="type" data-testid="logs-type" {
                option value="" selected[page.query_type.is_empty()] { "All Types" }
                (option_list(&page.query_types))
            }
            " "
            select id="log-token" name="token" data-testid="logs-token" {
                option value="" selected[page.token.is_empty()] { "All Tokens" }
                (option_list(&page.tokens))
            }
            " "
            button type="submit" class="btn btn-sm nojs-only" data-testid="logs-filter-apply" { "Filter" }
            " "
            button type="submit" form="clear-logs-form" class="btn btn-danger btn-sm" id="clear-logs" data-testid="logs-clear" {
                svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" {
                    polyline points="3 6 5 6 21 6" {}
                    path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" {}
                }
                " Clear All"
            }
        }
    }
}

fn pagination(page: &LogsTemplate) -> Markup {
    html! {
        div class="pagination" id="log-pagination" {
            @if page.has_prev {
                a class="btn btn-sm" id="pg-prev" data-testid="logs-prev" href=(page.prev_href) { "Prev" }
            } @else {
                span class="btn btn-sm" id="pg-prev" aria-disabled="true" style="opacity:.45" { "Prev" }
            }
            " "
            span {
                "Page " (page.page) " / " (page.total_pages)
                @if page.total != "0" { " · " (page.total) " queries" }
            }
            " "
            @if page.has_next {
                a class="btn btn-sm" id="pg-next" data-testid="logs-next" href=(page.next_href) { "Next" }
            } @else {
                span class="btn btn-sm" id="pg-next" aria-disabled="true" style="opacity:.45" { "Next" }
            }
        }
    }
}

pub fn render(page: &LogsTemplate) -> Markup {
    let body = html! {
        logs-page {
            div class="page-header fade-in" style="display:flex;align-items:center;justify-content:space-between" {
                div { h2 { "Query Log" } p { "DNS query history" } }
                button class="live-toggle paused js-only" id="log-live-btn" data-testid="logs-live-toggle" title="Stream new queries live as they arrive. Click to toggle." hidden { span class="live-dot" {} " LIVE" }
            }
            @if page.shell.logs_cleared {
                div class="rebuild-banner show done" data-testid="logs-cleared" {
                    div class="text" { span class="label" { "Query log cleared" } }
                }
            }
            (filters(page))
            form method="post" action="/logs/clear" id="clear-logs-form" hidden {}
            div class="card fade-in" style="animation-delay:0.05s" {
                div class="table-wrap hide-mobile-block" {
                    table {
                        thead {
                            tr {
                                th { "Time" } th { "Status" } th { "Query" } th { "Type" } th { "Client" } th {} th { "Source" } th { "ms" }
                            }
                        }
                        tbody id="log-body" { (table_body(page)) }
                    }
                }
                div id="log-cards" class="show-mobile" { (cards(page)) }
                (pagination(page))
            }
        }
    };
    shell(&page.shell, &body)
}
