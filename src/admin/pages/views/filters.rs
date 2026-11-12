//! The filters page: domain test, filter lists, custom rules.
//!
//! Every action is a real form: the domain test is a GET, so its verdict lands
//! in the URL; every change is a POST that redirects. `app.js` takes each over
//! — same buttons, same ids — and talks to `/api/*` instead.

use maud::{Markup, html};

use super::layout::shell;
use crate::admin::pages::FiltersTemplate;

fn refresh_icon() -> Markup {
    html! {
        svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" {
            polyline points="23 4 23 10 17 10" {}
            path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" {}
        }
    }
}

fn search_icon() -> Markup {
    html! {
        svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" {
            circle cx="11" cy="11" r="8" {}
            line x1="21" y1="21" x2="16.65" y2="16.65" {}
        }
    }
}

fn plus_icon() -> Markup {
    html! {
        svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" {
            line x1="12" y1="5" x2="12" y2="19" {}
            line x1="5" y1="12" x2="19" y2="12" {}
        }
    }
}

fn trash_icon() -> Markup {
    html! {
        svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" {
            polyline points="3 6 5 6 21 6" {}
            path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" {}
        }
    }
}

pub fn render(page: &FiltersTemplate) -> Markup {
    let body = html! {
        filters-page {
            div class="page-header fade-in" { h2 { "Filters" } p { "Domain test, filter lists, and custom rules" } }
            @if page.shell.filters_saved {
                div class="rebuild-banner show done" data-testid="filters-saved" {
                    div class="text" {
                        span class="label" { "Saved" }
                        " "
                        span class="meta" { "The filter engine is rebuilding; the change takes effect in a moment." }
                    }
                }
            }
            @if page.shell.lists_updating {
                div class="rebuild-banner show done" data-testid="lists-updated" {
                    div class="text" {
                        span class="label" { "All lists downloaded" }
                        " "
                        span class="meta" { "The filter engine is rebuilding with the new rules." }
                    }
                }
            }
            div class="card fade-in" {
                div class="card-title" { "Domain Test" }
                p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:8px" { "Check whether a domain is allowed or blocked by your current filters." }
                form method="get" action="/filters" class="input-row" id="domain-test-form" {
                    input type="text" id="test-domain" name="test" data-testid="domain-test-input" placeholder="ads.example.com" value=(page.test_domain) list=[(!page.domain_suggestions.is_empty()).then_some("domain-list")] autocomplete="off";
                    " "
                    @if !page.domain_suggestions.is_empty() {
                        datalist id="domain-list" {
                            @for d in &page.domain_suggestions { option value=(d); }
                        }
                        " "
                    }
                    button type="submit" class="btn btn-primary btn-sm" id="test-btn" data-testid="domain-test-submit" { (refresh_icon()) " Test" }
                }
                div id="test-result" data-testid="domain-test-result" style="margin-top:12px" {
                    @if page.tested {
                        @if page.verdict_blocked {
                            span class="badge badge-blocked" { "Blocked" }
                            " "
                            span style="color:var(--text-secondary);font-size:0.85rem;margin-left:8px" {
                                "Rule: " code class="text-primary" { (page.verdict_rule) }
                                " · List: " code class="text-primary" { (page.verdict_list) }
                            }
                        } @else {
                            span class="badge badge-allowed" { "Allowed" }
                            @if !page.verdict_rule.is_empty() {
                                " "
                                span style="color:var(--text-secondary);font-size:0.85rem;margin-left:8px" { "Rule: " code class="text-primary" { (page.verdict_rule) } }
                            }
                        }
                    }
                }
            }
            div class="card fade-in" style="animation-delay:0.05s" {
                div class="card-title" { "Filter Lists" }
                div data-testid="filters-all-disabled-warning" style=[(!page.all_disabled).then_some("display:none")] class="all-disabled-warning" {
                    div style="color:var(--text-primary);font-weight:600;margin-bottom:4px" { "No filter list is enabled" }
                    div style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:8px" { "Every filter list is turned off, so noadd is not blocking anything. Enable a recommended list to start filtering." }
                    form method="post" action="/filters/lists/enable-recommended" {
                        button type="submit" class="btn btn-primary btn-sm" data-testid="filters-enable-recommended" id="enable-recommended" { "Enable AdGuard DNS filter" }
                    }
                }
                div class="filters-row" style="margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap" {
                    form method="post" action="/filters/lists/update" {
                        button type="submit" class="btn btn-primary btn-sm" id="update-all" { (refresh_icon()) " Update All" }
                    }
                    " "
                    a class="btn btn-sm" href="/filters/registry" id="browse-registry" { (search_icon()) " Browse Registry" }
                }
                p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:8px" { "Impact is what you would stop blocking by turning a list off. Two lists holding the same rules both read " em { "No impact" } " — turn one off at a time, and the rest recompute." }
                div class="table-wrap hide-mobile-block" {
                    table {
                        thead { tr {
                            th { "Enabled" } th { "Name" } th { "Rules" } th { "Impact" } th { "Updated" } th {}
                        } }
                        tbody id="lists-body" {
                            @for l in &page.lists {
                                tr data-testid="filter-list-row" data-name=(l.name) {
                                    td {
                                        form method="post" action={"/filters/lists/" (l.id) "/toggle"} class="list-toggle-form" {
                                            label class="toggle" {
                                                " "
                                                input type="checkbox" name="enabled" data-testid="filter-list-toggle" data-id=(l.id) checked[l.enabled];
                                                div class="toggle-track" {}
                                                div class="toggle-thumb" {}
                                            }
                                            " "
                                            button type="submit" class="btn btn-sm nojs-only" { "apply" }
                                        }
                                    }
                                    td class="text-primary" { (l.name) }
                                    td { (l.rule_count) }
                                    td data-testid="filter-list-impact" {
                                        @if l.impact_none { span class="badge badge-off" { (l.impact_text) } } @else { (l.impact_text) }
                                    }
                                    td { span class="timeago" data-ts=(l.last_updated) { (l.last_updated_text) } }
                                    td style="white-space:nowrap" {
                                        a href={"/filters?edit=" (l.id)} class="btn btn-sm edit-list" data-id=(l.id) data-name=(l.name) data-url=(l.url) { "Edit" }
                                        " "
                                        form method="post" action={"/filters/lists/" (l.id) "/delete"} class="inline-form" {
                                            button type="submit" class="btn btn-danger btn-sm del-list" data-id=(l.id) { (trash_icon()) }
                                        }
                                    }
                                }
                                @if page.edit_id == l.id {
                                    tr class="edit-row" data-testid="filter-list-edit-row" {
                                        td colspan="6" {
                                            form method="post" action={"/filters/lists/" (l.id) "/edit"} {
                                                div class="input-row" {
                                                    input type="text" name="name" value=(page.edit_name) placeholder="List name" data-testid="list-edit-name";
                                                    " "
                                                    input type="url" name="url" value=(page.edit_url) placeholder="https://..." data-testid="list-edit-url";
                                                    " "
                                                    button type="submit" class="btn btn-primary btn-sm" data-testid="list-edit-save" { "Save" }
                                                    " "
                                                    a href="/filters" class="btn btn-sm" { "Cancel" }
                                                }
                                                @if !page.edit_error.is_empty() {
                                                    div class="field-msg error" data-testid="list-edit-error" { (page.edit_error) }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                div id="lists-cards" class="show-mobile" {
                    @for l in &page.lists {
                        div class="log-card" {
                            div class="log-card-row1" {
                                form method="post" action={"/filters/lists/" (l.id) "/toggle"} class="list-toggle-form" {
                                    label class="toggle" {
                                        " "
                                        input type="checkbox" name="enabled" data-id=(l.id) checked[l.enabled];
                                        div class="toggle-track" {}
                                        div class="toggle-thumb" {}
                                    }
                                    " "
                                    button type="submit" class="btn btn-sm nojs-only" { "apply" }
                                }
                                " "
                                span style="flex:1;color:var(--text-primary);font-size:0.85rem" { (l.name) }
                                " "
                                a href={"/filters?edit=" (l.id)} class="btn btn-sm edit-list" data-id=(l.id) data-name=(l.name) data-url=(l.url) style="flex-shrink:0" { "Edit" }
                                " "
                                form method="post" action={"/filters/lists/" (l.id) "/delete"} class="inline-form" style="flex-shrink:0" {
                                    button type="submit" class="btn btn-danger btn-sm del-list" data-id=(l.id) { (trash_icon()) }
                                }
                            }
                            div class="log-card-row2" {
                                span { (l.rule_count_compact) " rules" }
                                " "
                                span data-testid="filter-list-impact-card" { (l.impact_text) }
                                " "
                                span { (l.last_updated_text) }
                            }
                        }
                    }
                }
                div class="card-title" style="margin-top:16px" { "Add Custom List" }
                form method="post" action="/filters/lists" class="input-row" id="add-list-form" {
                    input type="text" id="list-name" name="name" data-testid="list-name-input" placeholder="List name" value=(page.list_name);
                    " "
                    input type="url" id="list-url" name="url" data-testid="list-url-input" placeholder="https://..." value=(page.list_url);
                    " "
                    button type="submit" class="btn btn-primary btn-sm" id="add-list" data-testid="list-add-submit" { (plus_icon()) " Add" }
                }
                @if !page.list_error.is_empty() {
                    div class="field-msg error" id="msg-add-list" data-testid="list-add-error" {
                        (page.list_error)
                        @if !page.list_error_field.is_empty() { " (" (page.list_error_field) ")" }
                    }
                }
            }
            div class="card fade-in" style="animation-delay:0.1s" {
                div class="card-title" { "Custom Rules" }
                form method="post" action="/filters/rules" class="input-row" id="add-rule-form" {
                    input type="text" id="add-rule-input" name="rule" data-testid="rule-input" placeholder="||ads.example.com^ or @@||safe.example.com^" value=(page.rule_text);
                    " "
                    button type="submit" class="btn btn-primary btn-sm" id="add-rule-btn" data-testid="rule-submit" { (plus_icon()) " Add" }
                }
                @if !page.rule_error.is_empty() {
                    div class="field-msg error" id="msg-add-rule" data-testid="rule-add-error" { (page.rule_error) }
                }
                div id="rules-list" data-testid="rules-list" style="margin-top:12px" {
                    @if page.rules.is_empty() {
                        p style="color:var(--text-dim);font-size:0.85rem" { "No rules" }
                    } @else {
                        table { tbody {
                            @for r in &page.rules {
                                tr data-testid="rule-row" data-rule=(r.rule) data-type=(r.rule_type) {
                                    td style="width:70px" {
                                        @if r.allow { span class="badge badge-allowed" { "allow" } } @else { span class="badge badge-blocked" { "block" } }
                                    }
                                    td class="mono" style="color:var(--text-primary);font-size:0.85rem" { (r.rule) }
                                    td style="width:40px" {
                                        form method="post" action={"/filters/rules/" (r.id) "/delete"} class="inline-form" {
                                            button type="submit" class="btn btn-danger btn-sm del-rule" data-testid="rule-delete" data-id=(r.id) { (trash_icon()) }
                                        }
                                    }
                                }
                            }
                        } }
                    }
                }
                div class="syntax-ref" {
                    strong class="text-secondary" { "Syntax Reference" }
                    " "
                    div class="syntax-ref-list" {
                        div { code { "||ads.example.com^" } br; "Block domain and all subdomains" }
                        div { code { "@@||safe.example.com^" } br; "Allow domain and all subdomains" }
                        div { code { "example.com" } br; "Block exact domain only" }
                        div { code { "0.0.0.0 example.com" } br; "Block exact domain (hosts format)" }
                    }
                }
            }
        }
    };
    shell(&page.shell, &body)
}
