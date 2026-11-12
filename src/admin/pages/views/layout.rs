//! The document and the signed-in shell around every page body.

use maud::{DOCTYPE, Markup, PreEscaped, html};

use crate::admin::pages::ShellData;

/// The bare document: `content` goes in `#app`, `scripts` after it. Login and
/// setup pass no scripts, since they work without any.
pub fn document(content: &Markup, scripts: Option<Markup>) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                link rel="apple-touch-icon" href="/apple-touch-icon.png";
                title { "noadd" }
                link rel="preconnect" href="https://fonts.bunny.net";
                // Unescaped on purpose: the `&` is part of the URL as served before.
                link href=(PreEscaped("https://fonts.bunny.net/css?family=ibm-plex-mono:400,500,600,700&display=swap")) rel="stylesheet";
                link rel="stylesheet" href="/app.css";
            }
            body {
                div id="app" { (content) }
                @if let Some(scripts) = scripts { (scripts) }
            }
        }
    }
}

/// The signed-in application shell, settled entirely by the server: the active
/// nav item, the version, the status-bar host and any one-shot notice. The page
/// body fills `#page-content`; its custom element upgrades in place.
pub fn shell(shell: &ShellData, page: &Markup) -> Markup {
    let content = html! {
        div class="app-shell" data-testid="app-shell" {
            header class="topbar" {
                div class="brand" { "noadd " span class="v" { (shell.version) } }
                nav class="nav-strip" {
                    @for item in shell.nav {
                        " "
                        a.nav-item.active[shell.current_path == item.href] href=(item.href) data-testid=(item.testid) {
                            b { (item.key) ":" } (item.label)
                        }
                    }
                }
                div class="topbar-meta" { "dns sinkhole" }
                form method="post" action="/logout" class="topbar-logout" {
                    button type="submit" class="nav-item" id="topbar-logout" data-testid="topbar-logout" title="Log out of this session" { "[ logout ]" }
                }
            }
            main class="main-content" {
                @if shell.welcome {
                    div class="rebuild-banner show done" data-testid="setup-welcome" {
                        div class="icon" { svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" { polyline points="20 6 9 17 4 12" {} } }
                        div class="text" {
                            span class="label" { "Setup complete — welcome to noadd!" }
                            " "
                            span class="meta" { "Your admin password is set and you're signed in." }
                        }
                    }
                }
                @if shell.proxy_logout_notice {
                    div class="rebuild-banner show" data-testid="proxy-logout-notice" {
                        div class="text" {
                            span class="label" { "This session is managed by your reverse proxy" }
                            " "
                            span class="meta" { "noadd cannot end it — log out at your proxy or SSO provider instead." }
                        }
                    }
                }
                div id="notice-host" {}
                rebuild-banner {}
                @if shell.show_next_step {
                    // Decided by the server (`next_step_target`), not fetched by the client.
                    next-step-banner {
                        div class="rebuild-banner show" role="status" aria-live="polite" data-testid="next-step-banner" {
                            span class="icon" {
                                svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" {
                                    rect x="3" y="3" width="7" height="7" rx="1" {}
                                    rect x="14" y="3" width="7" height="7" rx="1" {}
                                    rect x="3" y="14" width="7" height="7" rx="1" {}
                                    rect x="14" y="14" width="7" height="7" rx="1" {}
                                }
                            }
                            " "
                            span class="text" {
                                " "
                                span class="label" {
                                    "Point a device's DNS at noadd to start blocking — set its DNS server to "
                                    strong data-testid="next-step-banner-addr" { (shell.next_step_addr) }
                                    "."
                                }
                                " "
                            }
                            form method="post" action="/onboarding/dismiss" style="margin-left:auto" {
                                input type="hidden" name="next" value=(shell.current_path);
                                " "
                                button class="btn" type="submit" data-testid="next-step-banner-dismiss" title="Dismiss" {
                                    svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" {
                                        line x1="18" y1="6" x2="6" y2="18" {}
                                        line x1="6" y1="6" x2="18" y2="18" {}
                                    }
                                }
                            }
                        }
                    }
                }
                div id="page-content" { (page) }
            }
            footer class="statusbar" {
                // Ships hidden: without a client it cannot sense the server, so must not claim it is up.
                server-status class="live" data-testid="server-status" hidden { "ONLINE" }
                " "
                span { "noadd " (shell.version) }
                " "
                span class="right" { (shell.host) }
            }
            nav class="fnbar" {
                @for item in shell.nav {
                    " "
                    a.nav-item.active[shell.current_path == item.href] href=(item.href) {
                        span class="fk" { (item.fkey) } b { (item.short) }
                    }
                }
            }
        }
    };
    document(&content, Some(html! { script src="/app.js" {} }))
}
