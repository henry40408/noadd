//! The filter registry browser.
//!
//! Two forms, not nested (forms cannot nest, and a GET form cannot POST): the
//! filters are a GET form whose state lands in the URL; the selection is a POST
//! form wrapping the rows. The registry is a third party, so failing to fetch
//! it is a state this page renders, with a retry link back to the same URL.

use maud::{Markup, html};

use super::layout::shell;
use crate::admin::pages::RegistryTemplate;

pub fn render(page: &RegistryTemplate) -> Markup {
    let body = html! {
        registry-page data-limit=(page.limit) {
            div class="page-header fade-in" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px" {
                div { h2 { "Browse Filter Registry" } p { "Add lists from the AdGuard HostlistsRegistry" } }
                " "
                a class="btn btn-sm" href="/filters" data-testid="registry-back" { "Back to Filters" }
            }
            @if page.added_count != 0 {
                div class="rebuild-banner show done" data-testid="registry-added" {
                    div class="text" {
                        span class="label" { "Added " (page.added_count) }
                        " "
                        span class="meta" { "The filter engine is rebuilding; the change takes effect in a moment." }
                    }
                }
            }
            @if !page.failures.is_empty() {
                div class="card fade-in registry-summary error" data-testid="registry-failures" {
                    div class="card-title" { "Not added" }
                    ul style="margin:8px 0 0;padding-left:18px" {
                        @for failure in &page.failures {
                            li { span class="mono" { (failure.name) } " — " (failure.error) }
                        }
                    }
                }
            }
            @if page.load_failed {
                div class="card fade-in" {
                    div class="registry-error" data-testid="registry-unavailable" {
                        "Failed to load the registry." br;
                        " "
                        a class="btn btn-sm" style="margin-top:14px" href={"/filters/registry" (page.current_query)} { "Retry" }
                    }
                }
            } @else {
                div class="card fade-in" style="animation-delay:0.05s" {
                    form method="get" action="/filters/registry" class="registry-toolbar" id="registry-filters" data-testid="registry-filters" {
                        input type="text" id="reg-search" name="q" value=(page.q) placeholder="Search name or description";
                        " "
                        select id="reg-group" name="group" {
                            option value="" { "All groups" }
                            @for group in &page.groups {
                                option value=(group.value) selected[group.selected] { (group.label) }
                            }
                        }
                        " "
                        label class="check" { input type="checkbox" id="reg-deprecated" name="deprecated" value="1" checked[page.show_deprecated]; " Show deprecated" }
                        " "
                        button type="submit" class="btn btn-sm nojs-only" id="reg-filter-submit" { "Apply" }
                    }
                }
                form method="post" action={"/filters/registry/add" (page.current_query)} id="registry-form" {
                    div class="card fade-in" style="animation-delay:0.08s" {
                        div class="card-title" id="registry-count" data-testid="registry-count" { "Showing " (page.shown) " of " (page.total) }
                        div class="registry-body" id="reg-body" {
                            div class="registry-empty" data-testid="registry-empty" hidden[!page.rows.is_empty()] { "No filters match your search." }
                            @for row in &page.rows {
                                label class="registry-row" data-testid="registry-row" data-name=(row.name) data-group-id=(row.group_id) data-deprecated=[row.deprecated.then_some("1")] {
                                    input type="checkbox" name="filter_id" value=(row.filter_id) disabled[row.already_added];
                                    div class="info" {
                                        div class="name-row" {
                                            span class="name" { (row.name) }
                                            @if !row.group_name.is_empty() { span class={"group-pill " (row.group_class)} { (row.group_name) } }
                                            @if row.already_added { span class="added-pill" { "Added" } }
                                            @if row.deprecated { span class="dep-pill" { "Deprecated" } }
                                        }
                                        div class="desc" { (row.description) }
                                        @if !row.homepage.is_empty() {
                                            a class="home" href=(row.homepage) target="_blank" rel="noopener noreferrer" {
                                                svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" {
                                                    path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" {}
                                                    polyline points="15 3 21 3 21 9" {}
                                                    line x1="10" y1="14" x2="21" y2="3" {}
                                                }
                                                span { "Homepage" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div class="card fade-in registry-foot" style="animation-delay:0.1s" {
                        div class="count" data-testid="registry-selected" { "Up to " (page.limit) " lists at a time" }
                        " "
                        a class="btn btn-sm" href="/filters" { "Cancel" }
                        " "
                        button type="submit" class="btn btn-primary btn-sm" id="reg-add" data-testid="registry-add" { "Add Selected" }
                    }
                }
            }
        }
    };
    shell(&page.shell, &body)
}
