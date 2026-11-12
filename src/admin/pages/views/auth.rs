//! Sign-in and first-run setup: the two pages that exist before a session does.

use maud::{Markup, html};

use super::layout::document;
use crate::admin::pages::{LoginTemplate, SetupTemplate};

fn boot_logo() -> Markup {
    html! {
        pre class="boot-logo" aria-hidden="true" {
            "\n"
            "███╗   ██╗ ██████╗  █████╗ ██████╗ ██████╗\n"
            "████╗  ██║██╔═══██╗██╔══██╗██╔══██╗██╔══██╗\n"
            "██╔██╗ ██║██║   ██║███████║██║  ██║██║  ██║\n"
            "██║╚██╗██║██║   ██║██╔══██║██║  ██║██║  ██║\n"
            "██║ ╚████║╚██████╔╝██║  ██║██████╔╝██████╔╝\n"
            "╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═════╝"
        }
    }
}

/// The message box both pages share. Hidden until there is a message, which is
/// what `app.js`-free rendering needs.
fn error_box(id: &str, testid: &str, error: Option<&String>) -> Markup {
    html! {
        div class="login-error" id=(id) data-testid=(testid) role="alert" style=[error.map(|_| "display:block")] {
            @if let Some(message) = error { (message) }
        }
    }
}

pub fn login(page: &LoginTemplate) -> Markup {
    let content = html! {
        div class="login-container" {
            div class="login-box boot fade-in" {
                (boot_logo())
                div class="boot-log" {
                    "noadd dns sinkhole"
                    @if !page.version.is_empty() { " · " (page.version) }
                    br;
                    "admin console ............ " span class="ok" { "ok" } br;
                    "session .................. " span class="ok" { "awaiting operator" } br;
                }
                (error_box("login-error", "login-error", page.error.as_ref()))
                form method="post" action="/login" {
                    @if let Some(target) = &page.next { input type="hidden" name="next" value=(target); }
                    div class="login-line" {
                        label for="li-user" { "username:" }
                        " "
                        input type="text" id="li-user" name="username" autocomplete="username" data-testid="login-username" value=(page.username) autofocus;
                    }
                    div class="login-line" {
                        label for="pw" { "password:" }
                        " "
                        input type="password" id="pw" name="password" autocomplete="current-password" data-testid="login-password";
                    }
                    button type="submit" class="btn btn-primary boot-submit" id="login-btn" data-testid="login-submit" { "authenticate" }
                }
            }
        }
    };
    document(&content, None)
}

pub fn setup(page: &SetupTemplate) -> Markup {
    let content = html! {
        div class="login-container" {
            div class="login-box boot fade-in" {
                (boot_logo())
                div class="boot-log" {
                    "noadd dns sinkhole · first boot" br;
                    "admin account ............ " span class="warn" { "none" } br;
                    "create operator credentials to continue_"
                }
                (error_box("setup-error", "setup-error", page.error.as_ref()))
                form method="post" action="/setup" {
                    div class="login-line" {
                        label for="setup-user" { "username:" }
                        " "
                        input type="text" id="setup-user" name="username" autocomplete="username" data-testid="setup-username" value=(page.username) autofocus;
                    }
                    div class="login-line" {
                        label for="setup-pw" { "password:" }
                        " "
                        input type="password" id="setup-pw" name="password" autocomplete="new-password" data-testid="setup-password";
                    }
                    div class="login-line" {
                        label for="setup-pw2" { "confirm:" }
                        " "
                        input type="password" id="setup-pw2" name="confirm" autocomplete="new-password" data-testid="setup-password-confirm";
                    }
                    div class="login-line" {
                        label for="setup-token" { "setup token:" }
                        " "
                        input type="text" id="setup-token" name="setup_token" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="XXXXX-XXXXX" data-testid="setup-token";
                    }
                    button type="submit" class="btn btn-primary boot-submit" id="setup-btn" data-testid="setup-submit" { "create account" }
                    div class="boot-hint" { "minimum " (page.min_password_length) " characters — a few unrelated words work best" }
                    div class="boot-hint" { "setup token: printed to the server's stderr when noadd started with no operator" }
                }
            }
        }
    };
    document(&content, None)
}
