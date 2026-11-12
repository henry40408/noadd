//! The settings page.
//!
//! Every scalar setting is in one form with one submit; `app.js` removes the
//! button and autosaves per field instead.
//!
//! Server info, upstream health, EMA latency and the `DoH` token list stay
//! client-rendered: they are live data, not settings.

use maud::{Markup, PreEscaped, html};

use crate::admin::pages::SettingsTemplate;

/// The `field-msg` line under a field: carries the error text when `field` failed.
fn field_msg(page: &SettingsTemplate, id: &str, field: &str) -> Markup {
    let failed = page.error_field == field;
    html! {
        div class={"field-msg" @if failed { " error" }} id=(id) {
            @if failed { (page.error_message) }
        }
    }
}

pub fn render(page: &SettingsTemplate) -> Markup {
    let body = html! {
        settings-page {
            div class="page-header fade-in" { h2 { "Settings" } p { "Server configuration" } }
            div class="card fade-in" {
                div class="card-title" { "Server Info" }
                p style="color:var(--text-dim);font-size:0.8rem;margin-bottom:12px" { "These values are set via CLI arguments and cannot be changed at runtime." }
                div id="server-info" style="font-family:var(--font-sans);font-size:0.85rem;color:var(--text-secondary)" { "Loading..." }
            }
            form method="post" action="/settings" id="settings-form" {
                div class="card fade-in" style="animation-delay:0.05s" {
                    div class="card-title" { "Upstream DNS" }
                    p style="color:var(--text-secondary);font-size:0.8rem;margin-bottom:6px" {
                        "One server per line — "
                        code class="text-accent" { "ip:port" }
                        ", "
                        code class="text-accent" { "tls://host" }
                        " (DoT), or "
                        code class="text-accent" { "https://host/dns-query" }
                        " (DoH)"
                    }
                    textarea id="s-upstream" name="upstream_servers" rows="4" placeholder=(PreEscaped("1.1.1.1:53&#10;tls://dns.quad9.net:853")) { (page.upstream_servers) }
                    (field_msg(page, "msg-upstream", "upstream_servers"))
                    div style="margin-top:8px;display:flex;align-items:center;gap:10px" {
                        button type="submit" class="btn btn-sm btn-primary" id="apply-upstream" { "Save & apply" }
                        " "
                        span id="upstream-apply-msg" style="font-size:0.8rem" {}
                    }
                    div id="upstream-health" style="margin-top:14px" {}
                    div class="card-title" style="margin-top:16px" { "Strategy" }
                    p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:8px" {
                        "How upstream servers are selected for each DNS query."
                    }
                    div class="input-row" style="margin-bottom:2px" {
                        select id="s-strategy" name="upstream_strategy" {
                            option value="sequential" selected[page.upstream_strategy == "sequential"] { "Sequential (try in order)" }
                            option value="round-robin" selected[page.upstream_strategy == "round-robin"] { "Round Robin (rotate)" }
                            option value="lowest-latency" selected[page.upstream_strategy == "lowest-latency"] { "Lowest Latency (fastest first)" }
                        }
                    }
                    div class="field-msg" id="msg-strategy" {}
                    div id="ema-latency" style="margin-top:12px" {}
                    div class="card-title" style="margin-top:16px" { "DNSSEC" }
                    p class="card-desc" {
                        "Surfaces the upstream's DNSSEC verdict (AD flag) per query in the log. This is transparency, not local validation — for end-to-end trustworthy results: use a validating upstream (1.1.1.1 / 9.9.9.9), set the upstream to "
                        code style="color:var(--accent);font-size:0.8rem" { "tls://…" }
                        " so the verdict reaches noadd untampered, and point devices at noadd's DoH endpoint."
                    }
                    label class="field-label" for="s-dnssec" { "DNSSEC status" }
                    div class="input-row" style="margin-bottom:2px" {
                        select id="s-dnssec" name="dnssec" {
                            option value="on" selected[page.dnssec_on] { "On (surface AD)" }
                            option value="off" selected[!page.dnssec_on] { "Off" }
                        }
                    }
                    div class="field-msg" id="msg-dnssec" {}
                    div class="card-title" style="margin-top:16px" { "Block mode" }
                    p class="card-desc" {
                        "How blocked queries are answered. Default returns a null IP (0.0.0.0 / ::)."
                    }
                    label class="field-label" for="s-block-mode" { "Response" }
                    div class="input-row" style="margin-bottom:2px" {
                        select id="s-block-mode" name="block_mode" {
                            option value="null_ip" selected[page.block_mode == "null_ip"] { "Null IP (0.0.0.0 / ::)" }
                            option value="nxdomain" selected[page.block_mode == "nxdomain"] { "NXDOMAIN" }
                            option value="refused" selected[page.block_mode == "refused"] { "REFUSED" }
                            option value="custom_ip" selected[page.block_mode == "custom_ip"] { "Custom IP" }
                        }
                    }
                    (field_msg(page, "msg-block-mode", "block_mode"))
                    div id="s-block-custom" style=[(page.block_mode != "custom_ip").then_some("display:none")] {
                        div class="input-row" style="margin-bottom:2px" { input type="text" id="s-block-ipv4" name="block_custom_ipv4" value=(page.block_custom_ipv4) placeholder="Custom IPv4 for A, e.g. 192.0.2.1" list="block-ipv4-list" autocomplete="off"; }
                        datalist id="block-ipv4-list" {
                            @for ip in page.block_custom_ipv4_suggestions { option value=(ip) {} }
                        }
                        (field_msg(page, "msg-block-ipv4", "block_custom_ipv4"))
                        div class="input-row" style="margin-bottom:2px" { input type="text" id="s-block-ipv6" name="block_custom_ipv6" value=(page.block_custom_ipv6) placeholder="Custom IPv6 for AAAA, e.g. 100::1" list="block-ipv6-list" autocomplete="off"; }
                        datalist id="block-ipv6-list" {
                            @for ip in page.block_custom_ipv6_suggestions { option value=(ip) {} }
                        }
                        (field_msg(page, "msg-block-ipv6", "block_custom_ipv6"))
                    }
                }
                div class="card fade-in" style="animation-delay:0.1s" {
                    div class="card-title" { "Log Retention" }
                    div class="input-row" style="margin-bottom:2px" {
                        input type="text" id="s-retention" name="log_retention_days" value=(page.log_retention_days) placeholder="7" style="max-width:80px" list="retention-list" autocomplete="off";
                        span style="color:var(--text-dim);font-size:0.85rem" { "days" }
                    }
                    datalist id="retention-list" {
                        @for d in page.log_retention_suggestions { option value=(d) {} }
                    }
                    (field_msg(page, "msg-retention", "log_retention_days"))
                }
                div class="card fade-in" style="animation-delay:0.12s" {
                    div class="card-title" { "Public URL" }
                    p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:8px" { "Used for Apple mobileconfig profiles. Must be HTTPS with a valid domain." }
                    div class="input-row" style="margin-bottom:2px" { input type="url" id="s-public-url" name="public_url" value=(page.public_url) placeholder="https://dns.example.com"; }
                    (field_msg(page, "msg-public-url", "public_url"))
                }
                div class="card fade-in" style="animation-delay:0.2s;margin-top:24px" {
                    div class="card-title" { "DoH Access Control" }
                    p class="card-desc" {
                        "Default policy for unauthenticated DoH requests (without a token in URL)."
                    }
                    label class="field-label" for="s-doh-policy" { "Default Policy" }
                    div class="input-row" {
                        select id="s-doh-policy" name="doh_access_policy" {
                            option value="allow" selected[page.doh_access_policy == "allow"] { "Allow (open access)" }
                            option value="deny" selected[page.doh_access_policy == "deny"] { "Deny (require token)" }
                        }
                    }
                    div class="field-msg" id="msg-doh-policy" {}
                }
                div class="fade-in" id="settings-save-row" style="animation-delay:0.15s;margin-top:4px;display:flex;align-items:center;gap:10px" {
                    button type="submit" class="btn btn-primary btn-sm" id="save-settings" data-testid="save-settings" { "Save settings" }
                    @if page.saved {
                        " "
                        span style="color:var(--accent);font-size:0.8rem" data-testid="settings-saved" { "✔ saved" }
                    }
                }
            }
            div class="card fade-in" style="animation-delay:0.22s;margin-top:24px" {
                div class="card-title" { "DoH Tokens" }
                p class="card-desc" {
                    "Each token becomes a DoH URL path: "
                    code style="color:var(--accent);font-size:0.8rem" { "/dns-query/your-token" }
                    ". Always works regardless of policy."
                }
                div class="input-row" {
                    input type="text" id="token-value" placeholder="e.g. my-phone, home-network";
                    " "
                    button type="button" class="btn btn-primary btn-sm" id="add-token" { "Add" }
                }
                div id="doh-tokens-list" {}
            }
        }
    };
    super::layout::shell(&page.shell, &body)
}
