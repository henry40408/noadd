package views

import "strconv"

// OperatorRow is one operator, formatted the way the page shows it.
type OperatorRow struct {
	ID          int64
	Username    string
	CreatedText string
	IsYou       bool
	// Deletable is false for yourself and for the last operator.
	Deletable bool
}

// SessionRow is one live session.
type SessionRow struct {
	ID           int64
	Username     string
	IP           string
	UserAgent    string
	CreatedText  string
	LastSeenText string
	IsCurrent    bool
}

// APIKeyRow is one API key. The secret is never part of it.
type APIKeyRow struct {
	ID           int64
	Name         string
	Prefix       string
	CreatedText  string
	LastUsedText string
	ExpiresText  string
}

// AccountPage is the account page: this account, operators, sessions and keys.
type AccountPage struct {
	Shell             ShellData
	Username          string
	ViaSSO            bool
	MinPasswordLength int

	// PasswordError is the change-password form's message; nil for none.
	PasswordError   *string
	PasswordChanged bool

	Operators []OperatorRow
	Sessions  []SessionRow
	APIKeys   []APIKeyRow

	// Submitted values kept across a rejection. Never passwords.
	OperatorUsername string
	OperatorError    string

	// ConfirmOperatorID is the operator whose row expands into a delete
	// confirmation; 0 for none.
	ConfirmOperatorID    int64
	ConfirmOperatorName  string
	ConfirmOperatorError string

	APIKeyName    string
	APIKeyExpires string
	APIKeyError   string

	// NewKeyToken is set only on the response that minted the key.
	NewKeyName  string
	NewKeyToken string

	AccountSaved    bool
	SessionsRevoked bool
}

const passwordFieldStyle = "max-width:220px"

func passwordInput(attrs ...attr) node {
	all := append([]attr{a("type", "password")}, attrs...)
	return void("input", append(all, a("style", passwordFieldStyle))...)
}

func spacedRow(children ...node) node { return inputRow("margin-top:8px", children...) }

func thead(labels ...string) node {
	var cells []node
	for _, label := range labels {
		if label == "" {
			cells = append(cells, el("th", nil))
			continue
		}
		cells = append(cells, el("th", nil, text(label)))
	}
	return el("thead", nil, el("tr", nil, cells...))
}

func youBadge(show bool, label string) node {
	return when(show, func() node {
		return group(sp(), el("span", class("badge badge-allowed"), text(label)))
	})
}

func thisAccountCard(page AccountPage) node {
	errorAttrs := []attr{a("class", "login-error"), a("id", "pw-error")}
	var errorChildren []node
	if page.PasswordError != nil {
		errorAttrs = append(errorAttrs, a("style", "display:block"))
		errorChildren = append(errorChildren, text(*page.PasswordError))
	}
	return divClass("card fade-in",
		cardTitle("This Account"),
		el("p", []attr{a("id", "acct-whoami"), a("class", "card-desc")},
			text("Signed in as "), accentCodeSized("0.85rem", page.Username),
			when(page.ViaSSO, func() node { return group(sp(), el("span", class("text-dim"), text("· via SSO"))) })),
		el("div", []attr{a("class", "card-title"), a("style", "margin-top:4px")}, text("Change Password")),
		el("div", errorAttrs, errorChildren...),
		when(page.PasswordChanged, func() node {
			return el("p", []attr{a("class", "card-desc"), a("data-testid", "password-changed"), a("style", "color:var(--accent)")},
				text("✔ Password changed. Your other sessions were signed out."))
		}),
		el("form", []attr{a("method", "post"), a("action", "/account/password")},
			inputRow("", passwordInput(a("id", "pw-current"), a("name", "current_password"), a("autocomplete", "current-password"), a("data-testid", "password-current"), a("placeholder", "current password"))),
			spacedRow(passwordInput(a("id", "pw-new"), a("name", "new_password"), a("autocomplete", "new-password"), a("data-testid", "password-new"), a("placeholder", "new password (min "+strconv.Itoa(page.MinPasswordLength)+")"))),
			spacedRow(passwordInput(a("id", "pw-confirm"), a("name", "confirm_password"), a("autocomplete", "new-password"), a("data-testid", "password-confirm"), a("placeholder", "confirm new password"))),
			button([]attr{a("type", "submit"), a("class", "btn btn-primary btn-sm"), a("id", "pw-save"), a("data-testid", "password-save"), a("style", "margin-top:12px")}, text("Change Password"))))
}

func accentCodeSized(size, content string) node {
	return styled("code", "color:var(--accent);font-size:"+size, text(content))
}

func deleteOperatorCell(op OperatorRow) node {
	if !op.Deletable {
		return el("td", []attr{a("style", "text-align:right")},
			el("span", []attr{a("class", "btn btn-danger btn-sm"), a("aria-disabled", "true"), a("style", "opacity:.35")}, trashIcon()))
	}
	return el("td", []attr{a("style", "text-align:right")},
		el("a", []attr{
			a("href", "/account?confirm_delete="+id64(op.ID)), a("class", "btn btn-danger btn-sm del-op"),
			a("data-id", id64(op.ID)), a("aria-label", "Delete "+op.Username),
		}, trashIcon()))
}

func confirmDeleteRow(page AccountPage, op OperatorRow) node {
	return el("tr", []attr{a("class", "edit-row"), a("data-testid", "operator-confirm-row")},
		el("td", []attr{a("colspan", "3")},
			el("form", []attr{a("method", "post"), a("action", "/account/operators/"+id64(op.ID)+"/delete")},
				el("p", []attr{a("class", "card-desc"), a("style", "margin-bottom:8px")},
					text("Delete "), codeText(page.ConfirmOperatorName), text(" and revoke all their sessions? Confirm with your own password.")),
				divClass("input-row",
					passwordInput(a("name", "your_password"), a("autocomplete", "current-password"), a("data-testid", "operator-delete-password"), a("placeholder", "your password")), sp(),
					button([]attr{a("type", "submit"), a("class", "btn btn-danger btn-sm"), a("data-testid", "operator-delete-confirm")}, text("Delete operator")), sp(),
					el("a", []attr{a("href", "/account"), a("class", "btn btn-sm")}, text("Cancel"))),
				when(page.ConfirmOperatorError != "", func() node {
					return el("div", []attr{a("class", "field-msg error"), a("data-testid", "operator-delete-error")}, text(page.ConfirmOperatorError))
				}))))
}

func operatorRows(page AccountPage) []node {
	var rows []node
	for _, op := range page.Operators {
		rows = append(rows, el("tr", []attr{a("data-testid", "operator-row"), a("data-name", op.Username)},
			el("td", class("mono text-primary"), text(op.Username), youBadge(op.IsYou, "you")),
			el("td", nil, text(op.CreatedText)),
			deleteOperatorCell(op)))
		if page.ConfirmOperatorID == op.ID {
			rows = append(rows, confirmDeleteRow(page, op))
		}
	}
	return rows
}

func errorBanner(id, testID, message string) node {
	display := "display:none"
	if message != "" {
		display = "display:block"
	}
	attrs := []attr{a("class", "login-error"), a("id", id)}
	if testID != "" {
		attrs = append(attrs, a("data-testid", testID))
	}
	return el("div", append(attrs, a("style", display)), text(message))
}

func operatorsCard(page AccountPage) node {
	minLen := strconv.Itoa(page.MinPasswordLength)
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.05s")},
		cardTitle("Operators"),
		cardDesc(text("All operators have full admin access. The last operator cannot be deleted; deleting one revokes all their sessions.")),
		divClass("table-wrap", el("table", nil, thead("Username", "Created", ""), el("tbody", []attr{a("id", "ops-body")}, operatorRows(page)...))),
		spacedTitle("Add Operator"),
		errorBanner("op-error", "operator-add-error", page.OperatorError),
		el("form", []attr{a("method", "post"), a("action", "/account/operators"), a("id", "add-operator-form")},
			inputRow("", void("input", a("type", "text"), a("id", "op-user"), a("name", "username"), a("autocomplete", "off"),
				a("data-testid", "operator-username"), a("placeholder", "username"), a("value", page.OperatorUsername), a("style", "max-width:200px"))),
			spacedRow(passwordInput(a("id", "op-pw"), a("name", "password"), a("autocomplete", "new-password"), a("data-testid", "operator-password"), a("placeholder", "password (min "+minLen+")"))),
			spacedRow(passwordInput(a("id", "op-pw2"), a("name", "confirm"), a("autocomplete", "new-password"), a("data-testid", "operator-password-confirm"), a("placeholder", "confirm password"))),
			spacedRow(passwordInput(a("name", "your_password"), a("autocomplete", "current-password"), a("data-testid", "operator-your-password"), a("placeholder", "your password"))),
			button([]attr{a("type", "submit"), a("class", "btn btn-primary btn-sm"), a("id", "op-add"), a("data-testid", "operator-add"), a("style", "margin-top:12px")}, text("Add Operator"))))
}

func sessionRows(page AccountPage) []node {
	var rows []node
	for _, s := range page.Sessions {
		current := "false"
		if s.IsCurrent {
			current = "true"
		}
		rows = append(rows, el("tr", []attr{a("data-testid", "session-row"), a("data-id", id64(s.ID))},
			el("td", class("mono text-primary"), text(s.Username), youBadge(s.IsCurrent, "this device")),
			el("td", class("mono"), text(s.IP)),
			el("td", nil, text(s.UserAgent)),
			el("td", nil, text(s.CreatedText)),
			el("td", nil, text(s.LastSeenText)),
			el("td", []attr{a("style", "text-align:right")},
				el("form", []attr{a("method", "post"), a("action", "/account/sessions/"+id64(s.ID)+"/revoke"), a("class", "inline-form")},
					button([]attr{a("type", "submit"), a("class", "btn btn-danger btn-sm rev-sess"), a("data-id", id64(s.ID)), a("data-current", current), a("aria-label", "Revoke session")}, trashIcon())))))
	}
	return rows
}

func ssoNote(viaSSO bool) node {
	style := "display:none;margin-bottom:12px"
	if viaSSO {
		style = "margin-bottom:12px"
	}
	return el("div", []attr{a("class", "notice-banner info"), a("id", "sess-sso-note"), a("role", "status"), a("style", style)},
		el("span", class("icon")), sp(),
		el("span", class("msg"), text("You're signed in via SSO, managed by your reverse proxy. Only password-login sessions are listed here; SSO access can't be revoked from noadd — sign out at your proxy instead.")))
}

func sessionsCard(page AccountPage) node {
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.1s")},
		cardTitle("Active Sessions"),
		cardDesc(text("Tokens are never shown. Any operator can revoke any session. Sessions expire after 7 days, or 48 hours after a device last contacted the server.")),
		ssoNote(page.ViaSSO),
		divClass("table-wrap", el("table", nil, thead("Operator", "IP", "Browser", "Signed in", "Last seen", ""), el("tbody", []attr{a("id", "sess-body")}, sessionRows(page)...))),
		el("form", []attr{a("method", "post"), a("action", "/account/sessions/revoke-others")},
			button([]attr{a("type", "submit"), a("class", "btn btn-danger"), a("id", "logout-others"), a("data-testid", "logout-other-sessions"), a("style", "margin-top:14px")}, text("Log Out Other Sessions"))))
}

func apiKeyRows(page AccountPage) []node {
	if len(page.APIKeys) == 0 {
		return []node{el("tr", nil, el("td", []attr{a("class", "text-dim"), a("colspan", "6")}, text("No API keys yet")))}
	}
	var rows []node
	for _, k := range page.APIKeys {
		rows = append(rows, el("tr", []attr{a("data-testid", "api-key-row"), a("data-name", k.Name)},
			el("td", class("text-primary"), text(k.Name)),
			el("td", class("mono"), text(k.Prefix)),
			el("td", nil, text(k.CreatedText)),
			el("td", nil, text(k.LastUsedText)),
			el("td", nil, text(k.ExpiresText)),
			el("td", []attr{a("style", "text-align:right")},
				el("form", []attr{a("method", "post"), a("action", "/account/api-keys/"+id64(k.ID)+"/delete"), a("class", "inline-form")},
					button([]attr{a("type", "submit"), a("class", "btn btn-danger btn-sm del-api-key"), a("data-id", id64(k.ID)), a("aria-label", "Revoke "+k.Name)}, trashIcon())))))
	}
	return rows
}

// apiKeyReveal is the token's only appearance: it is not stored, so this
// renders rather than redirects.
func apiKeyReveal(page AccountPage) node {
	if page.NewKeyToken == "" {
		return el("div", []attr{a("id", "api-key-reveal"), a("data-testid", "api-key-reveal"), a("style", "display:none")})
	}
	return el("div", []attr{a("id", "api-key-reveal"), a("data-testid", "api-key-reveal"), a("class", "api-key-reveal")},
		styled("div", "color:var(--text-primary);font-weight:600;margin-bottom:4px", text("API key created: "+page.NewKeyName)),
		styled("div", "color:var(--text-secondary);font-size:0.9rem;margin-bottom:8px", text("Copy this token now — it won't be shown again.")),
		divClass("input-row",
			void("input", a("type", "text"), a("id", "api-key-token"), a("data-testid", "api-key-token"), a("class", "mono"),
				a("value", page.NewKeyToken), flag("readonly"), a("style", "flex:1")), sp(),
			// Needs a clipboard, so ships hidden; app.js unhides it.
			button([]attr{a("type", "button"), a("class", "btn btn-primary btn-sm js-only"), a("id", "api-key-copy"), flag("hidden")}, text("Copy")), sp(),
			el("a", []attr{a("href", "/account"), a("class", "btn btn-sm"), a("id", "api-key-dismiss")}, text("Dismiss"))))
}

func apiKeysCard(page AccountPage) node {
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.15s")},
		cardTitle("API Keys"),
		cardDesc(text("For programmatic access via "), accentCode("Authorization: Bearer <token>"), text(". "),
			el("a", []attr{a("class", "text-accent"), a("href", "/api/docs"), a("target", "_blank"), a("rel", "noopener")}, text("Interactive API reference"))),
		divClass("table-wrap", el("table", nil, thead("Name", "Prefix", "Created", "Last used", "Expires", ""), el("tbody", []attr{a("id", "api-keys-body")}, apiKeyRows(page)...))),
		apiKeyReveal(page),
		spacedTitle("Create API Key"),
		errorBanner("api-key-error", "api-key-error", page.APIKeyError),
		el("form", []attr{a("method", "post"), a("action", "/account/api-keys"), a("id", "create-api-key-form")},
			divClass("input-row",
				void("input", a("type", "text"), a("id", "api-key-name"), a("name", "name"), a("data-testid", "api-key-name"),
					a("placeholder", "name, e.g. home-assistant"), a("value", page.APIKeyName), a("style", "max-width:220px")), sp(),
				void("input", a("type", "date"), a("id", "api-key-expires"), a("name", "expires"),
					a("title", "Expiry date (optional — leave blank for never)"), a("value", page.APIKeyExpires), a("style", "max-width:160px"))),
			spacedRow(
				passwordInput(a("name", "your_password"), a("autocomplete", "current-password"), a("data-testid", "api-key-your-password"), a("placeholder", "your password")), sp(),
				button([]attr{a("type", "submit"), a("class", "btn btn-primary btn-sm"), a("id", "api-key-add"), a("data-testid", "api-key-create")}, text("Create")))))
}

func accountBanners(page AccountPage) node {
	return group(
		when(page.AccountSaved, func() node {
			return el("div", []attr{a("class", "rebuild-banner show done"), a("data-testid", "account-saved")},
				divClass("text", el("span", class("label"), text("Saved"))))
		}),
		when(page.SessionsRevoked, func() node {
			return el("div", []attr{a("class", "rebuild-banner show done"), a("data-testid", "sessions-revoked")},
				divClass("text", el("span", class("label"), text("Signed out")), sp(),
					el("span", class("meta"), text("Those devices will have to sign in again."))))
		}))
}

// Account renders the account page inside the signed-in shell.
func Account(page AccountPage) string {
	body := el("account-page", nil,
		divClass("page-header fade-in", el("h2", nil, text("Account")), el("p", nil, text("Operator accounts and active sessions"))),
		accountBanners(page), thisAccountCard(page), operatorsCard(page), sessionsCard(page), apiKeysCard(page))
	return Shell(page.Shell, body)
}
