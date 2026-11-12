//! The account page: this account, operators, sessions and API keys.
//!
//! Adding an operator, deleting one and minting an API key carry a "your
//! password" field in the form itself, so the path is the same with and without
//! JavaScript. Deleting expands the row via `?confirm_delete={id}` rather than
//! putting a password field on every row.

use maud::{Markup, html};

use crate::admin::pages::AccountTemplate;

fn trash_icon() -> Markup {
    html! {
        svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" {
            polyline points="3 6 5 6 21 6" {}
            path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" {}
        }
    }
}

fn this_account_card(page: &AccountTemplate) -> Markup {
    html! {
        div class="card fade-in" {
            div class="card-title" { "This Account" }
            p id="acct-whoami" class="card-desc" {
                "Signed in as " code style="color:var(--accent);font-size:0.85rem" { (page.username) }
                @if page.via_sso { " " span class="text-dim" { "· via SSO" } }
            }
            div class="card-title" style="margin-top:4px" { "Change Password" }
            div class="login-error" id="pw-error" style=[page.error.as_ref().map(|_| "display:block")] {
                @if let Some(message) = &page.error { (message) }
            }
            @if page.password_changed {
                p class="card-desc" data-testid="password-changed" style="color:var(--accent)" { "✔ Password changed. Your other sessions were signed out." }
            }
            form method="post" action="/account/password" {
                div class="input-row" { input type="password" id="pw-current" name="current_password" autocomplete="current-password" data-testid="password-current" placeholder="current password" style="max-width:220px"; }
                div class="input-row" style="margin-top:8px" { input type="password" id="pw-new" name="new_password" autocomplete="new-password" data-testid="password-new" placeholder={"new password (min " (page.min_password_length) ")"} style="max-width:220px"; }
                div class="input-row" style="margin-top:8px" { input type="password" id="pw-confirm" name="confirm_password" autocomplete="new-password" data-testid="password-confirm" placeholder="confirm new password" style="max-width:220px"; }
                button type="submit" class="btn btn-primary btn-sm" id="pw-save" data-testid="password-save" style="margin-top:12px" { "Change Password" }
            }
        }
    }
}

fn operator_rows(page: &AccountTemplate) -> Markup {
    html! {
        @for op in &page.operators {
            tr data-testid="operator-row" data-name=(op.username) {
                td class="mono text-primary" {
                    (op.username)
                    @if op.is_you { " " span class="badge badge-allowed" { "you" } }
                }
                td { (op.created_text) }
                td style="text-align:right" {
                    @if op.deletable {
                        a href={"/account?confirm_delete=" (op.id)} class="btn btn-danger btn-sm del-op" data-id=(op.id) aria-label={"Delete " (op.username)} { (trash_icon()) }
                    } @else {
                        span class="btn btn-danger btn-sm" aria-disabled="true" style="opacity:.35" { (trash_icon()) }
                    }
                }
            }
            @if page.confirm_operator_id == op.id {
                tr class="edit-row" data-testid="operator-confirm-row" {
                    td colspan="3" {
                        form method="post" action={"/account/operators/" (op.id) "/delete"} {
                            p class="card-desc" style="margin-bottom:8px" {
                                "Delete " code class="text-primary" { (page.confirm_operator_name) } " and revoke all their sessions? Confirm with your own password."
                            }
                            div class="input-row" {
                                input type="password" name="your_password" autocomplete="current-password" data-testid="operator-delete-password" placeholder="your password" style="max-width:220px";
                                " "
                                button type="submit" class="btn btn-danger btn-sm" data-testid="operator-delete-confirm" { "Delete operator" }
                                " "
                                a href="/account" class="btn btn-sm" { "Cancel" }
                            }
                            @if !page.confirm_operator_error.is_empty() {
                                div class="field-msg error" data-testid="operator-delete-error" { (page.confirm_operator_error) }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn operators_card(page: &AccountTemplate) -> Markup {
    html! {
        div class="card fade-in" style="animation-delay:0.05s" {
            div class="card-title" { "Operators" }
            p class="card-desc" { "All operators have full admin access. The last operator cannot be deleted; deleting one revokes all their sessions." }
            div class="table-wrap" {
                table {
                    thead { tr { th { "Username" } th { "Created" } th {} } }
                    tbody id="ops-body" { (operator_rows(page)) }
                }
            }
            div class="card-title" style="margin-top:16px" { "Add Operator" }
            div class="login-error" id="op-error" data-testid="operator-add-error" style=(if page.operator_error.is_empty() { "display:none" } else { "display:block" }) { (page.operator_error) }
            form method="post" action="/account/operators" id="add-operator-form" {
                div class="input-row" { input type="text" id="op-user" name="username" autocomplete="off" data-testid="operator-username" placeholder="username" value=(page.operator_username) style="max-width:200px"; }
                div class="input-row" style="margin-top:8px" { input type="password" id="op-pw" name="password" autocomplete="new-password" data-testid="operator-password" placeholder={"password (min " (page.min_password_length) ")"} style="max-width:220px"; }
                div class="input-row" style="margin-top:8px" { input type="password" id="op-pw2" name="confirm" autocomplete="new-password" data-testid="operator-password-confirm" placeholder="confirm password" style="max-width:220px"; }
                div class="input-row" style="margin-top:8px" { input type="password" name="your_password" autocomplete="current-password" data-testid="operator-your-password" placeholder="your password" style="max-width:220px"; }
                button type="submit" class="btn btn-primary btn-sm" id="op-add" data-testid="operator-add" style="margin-top:12px" { "Add Operator" }
            }
        }
    }
}

fn session_rows(page: &AccountTemplate) -> Markup {
    html! {
        @for s in &page.sessions {
            tr data-testid="session-row" data-id=(s.id) {
                td class="mono text-primary" {
                    (s.username)
                    @if s.is_current { " " span class="badge badge-allowed" { "this device" } }
                }
                td class="mono" { (s.ip) }
                td { (s.user_agent) }
                td { (s.created_text) }
                td { (s.last_seen_text) }
                td style="text-align:right" {
                    form method="post" action={"/account/sessions/" (s.id) "/revoke"} class="inline-form" {
                        button type="submit" class="btn btn-danger btn-sm rev-sess" data-id=(s.id) data-current=(if s.is_current { "true" } else { "false" }) aria-label="Revoke session" { (trash_icon()) }
                    }
                }
            }
        }
    }
}

fn sessions_card(page: &AccountTemplate) -> Markup {
    html! {
        div class="card fade-in" style="animation-delay:0.1s" {
            div class="card-title" { "Active Sessions" }
            p class="card-desc" { "Tokens are never shown. Any operator can revoke any session. Sessions expire after 7 days, or 48 hours after a device last contacted the server." }
            div class="notice-banner info" id="sess-sso-note" role="status" style=(if page.via_sso { "margin-bottom:12px" } else { "display:none;margin-bottom:12px" }) {
                span class="icon" {}
                " "
                span class="msg" { "You're signed in via SSO, managed by your reverse proxy. Only password-login sessions are listed here; SSO access can't be revoked from noadd — sign out at your proxy instead." }
            }
            div class="table-wrap" {
                table {
                    thead { tr { th { "Operator" } th { "IP" } th { "Browser" } th { "Signed in" } th { "Last seen" } th {} } }
                    tbody id="sess-body" { (session_rows(page)) }
                }
            }
            form method="post" action="/account/sessions/revoke-others" {
                button type="submit" class="btn btn-danger" id="logout-others" data-testid="logout-other-sessions" style="margin-top:14px" { "Log Out Other Sessions" }
            }
        }
    }
}

fn api_key_rows(page: &AccountTemplate) -> Markup {
    html! {
        @if page.api_keys.is_empty() {
            tr { td class="text-dim" colspan="6" { "No API keys yet" } }
        } @else {
            @for k in &page.api_keys {
                tr data-testid="api-key-row" data-name=(k.name) {
                    td class="text-primary" { (k.name) }
                    td class="mono" { (k.prefix) }
                    td { (k.created_text) }
                    td { (k.last_used_text) }
                    td { (k.expires_text) }
                    td style="text-align:right" {
                        form method="post" action={"/account/api-keys/" (k.id) "/delete"} class="inline-form" {
                            button type="submit" class="btn btn-danger btn-sm del-api-key" data-id=(k.id) aria-label={"Revoke " (k.name)} { (trash_icon()) }
                        }
                    }
                }
            }
        }
    }
}

/// The token's only appearance — it is not stored, so this renders rather than
/// redirects.
fn api_key_reveal(page: &AccountTemplate) -> Markup {
    let has_token = !page.new_key_token.is_empty();
    html! {
        div id="api-key-reveal" data-testid="api-key-reveal" style=[(!has_token).then_some("display:none")] class=[has_token.then_some("api-key-reveal")] {
            @if has_token {
                div style="color:var(--text-primary);font-weight:600;margin-bottom:4px" { "API key created: " (page.new_key_name) }
                div style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:8px" { "Copy this token now — it won't be shown again." }
                div class="input-row" {
                    input type="text" id="api-key-token" data-testid="api-key-token" class="mono" value=(page.new_key_token) readonly style="flex:1";
                    " "
                    // Needs a clipboard, so ships hidden; app.js unhides it.
                    button type="button" class="btn btn-primary btn-sm js-only" id="api-key-copy" hidden { "Copy" }
                    " "
                    a href="/account" class="btn btn-sm" id="api-key-dismiss" { "Dismiss" }
                }
            }
        }
    }
}

fn api_keys_card(page: &AccountTemplate) -> Markup {
    html! {
        div class="card fade-in" style="animation-delay:0.15s" {
            div class="card-title" { "API Keys" }
            p class="card-desc" {
                "For programmatic access via " code style="color:var(--accent);font-size:0.8rem" { "Authorization: Bearer <token>" } ". "
                a class="text-accent" href="/api/docs" target="_blank" rel="noopener" { "Interactive API reference" }
            }
            div class="table-wrap" {
                table {
                    thead { tr { th { "Name" } th { "Prefix" } th { "Created" } th { "Last used" } th { "Expires" } th {} } }
                    tbody id="api-keys-body" { (api_key_rows(page)) }
                }
            }
            (api_key_reveal(page))
            div class="card-title" style="margin-top:16px" { "Create API Key" }
            div class="login-error" id="api-key-error" data-testid="api-key-error" style=(if page.api_key_error.is_empty() { "display:none" } else { "display:block" }) { (page.api_key_error) }
            form method="post" action="/account/api-keys" id="create-api-key-form" {
                div class="input-row" {
                    input type="text" id="api-key-name" name="name" data-testid="api-key-name" placeholder="name, e.g. home-assistant" value=(page.api_key_name) style="max-width:220px";
                    " "
                    input type="date" id="api-key-expires" name="expires" title="Expiry date (optional — leave blank for never)" value=(page.api_key_expires) style="max-width:160px";
                }
                div class="input-row" style="margin-top:8px" {
                    input type="password" name="your_password" autocomplete="current-password" data-testid="api-key-your-password" placeholder="your password" style="max-width:220px";
                    " "
                    button type="submit" class="btn btn-primary btn-sm" id="api-key-add" data-testid="api-key-create" { "Create" }
                }
            }
        }
    }
}

pub fn render(page: &AccountTemplate) -> Markup {
    let body = html! {
        account-page {
            div class="page-header fade-in" { h2 { "Account" } p { "Operator accounts and active sessions" } }
            @if page.account_saved {
                div class="rebuild-banner show done" data-testid="account-saved" {
                    div class="text" { span class="label" { "Saved" } }
                }
            }
            @if page.sessions_revoked {
                div class="rebuild-banner show done" data-testid="sessions-revoked" {
                    div class="text" {
                        span class="label" { "Signed out" }
                        " "
                        span class="meta" { "Those devices will have to sign in again." }
                    }
                }
            }
            (this_account_card(page))
            (operators_card(page))
            (sessions_card(page))
            (api_keys_card(page))
        }
    };
    super::layout::shell(&page.shell, &body)
}
