package views

import (
	"strings"
	"testing"
)

const agoText = "2 minutes ago"

func accountShell() ShellData {
	return ShellData{Version: goldenVersion, Host: "127.0.0.1:19080", CurrentPath: "/account"}
}

func accountEmpty() AccountPage {
	return AccountPage{
		Shell: accountShell(), Username: "admin", MinPasswordLength: 12,
		Operators: []OperatorRow{{ID: 1, Username: "admin", CreatedText: agoText, IsYou: true}},
		Sessions:  []SessionRow{{ID: 1, Username: "admin", IP: "192.168.215.1", UserAgent: "—", CreatedText: agoText, LastSeenText: agoText, IsCurrent: true}},
	}
}

func accountData() AccountPage {
	page := accountEmpty()
	page.Operators = append(page.Operators,
		OperatorRow{ID: 2, Username: "second", CreatedText: agoText, Deletable: true},
		OperatorRow{ID: 3, Username: "cjk-user", CreatedText: agoText, Deletable: true})
	page.APIKeys = []APIKeyRow{
		{ID: 1, Name: "ci-expiring", Prefix: "noadd_abcd", CreatedText: agoText, LastUsedText: "—", ExpiresText: "in 26707 days"},
		{ID: 2, Name: "ci-forever", Prefix: "noadd_abcd", CreatedText: agoText, LastUsedText: agoText, ExpiresText: "never"},
	}
	return page
}

func TestAccountMatchesGoldens(t *testing.T) {
	empty := accountEmpty()
	empty.Shell.ShowNextStep, empty.Shell.NextStepAddr = true, "127.0.0.1:53"
	assertGolden(t, "account_empty", Account(empty))
	assertGolden(t, "account_data", Account(accountData()))

	confirm := accountData()
	confirm.ConfirmOperatorID, confirm.ConfirmOperatorName = 2, "second"
	assertGolden(t, "account_confirm_delete", Account(confirm))

	operatorError := accountData()
	operatorError.OperatorError = "password must be at least 12 characters"
	operatorError.OperatorUsername = "x"
	assertGolden(t, "account_operator_error", Account(operatorError))

	uiKey := APIKeyRow{ID: 3, Name: "ui-key", Prefix: "noadd_abcd", CreatedText: agoText, LastUsedText: "—", ExpiresText: "in 26708 days"}
	keyError := accountData()
	keyError.APIKeys = append(keyError.APIKeys, uiKey)
	keyError.APIKeyError = "Name is required, and at most 64 characters"
	assertGolden(t, "account_api_key_error", Account(keyError))

	created := accountData()
	created.APIKeys = append(created.APIKeys, uiKey)
	created.NewKeyName, created.NewKeyToken = "ui-key", "noadd_abcdefgh"
	assertGolden(t, "account_api_key_created", Account(created))
}

func TestAccountSavedBanners(t *testing.T) {
	page := accountEmpty()
	page.AccountSaved, page.SessionsRevoked, page.PasswordChanged = true, true, true
	html := Account(page)
	for _, marker := range []string{`data-testid="account-saved"`, `data-testid="sessions-revoked"`, `data-testid="password-changed"`} {
		if !strings.Contains(html, marker) {
			t.Fatalf("missing %s", marker)
		}
	}
}

// 待 Opus 審查: XSS. Usernames, user agents and key names are attacker
// controlled and land in text and attributes.
func TestAccountEscapesEveryString(t *testing.T) {
	const payload = `"><script>alert(1)</script>`
	page := accountData()
	page.Username, page.OperatorUsername, page.OperatorError = payload, payload, payload
	page.APIKeyName, page.APIKeyExpires, page.APIKeyError = payload, payload, payload
	page.NewKeyName, page.NewKeyToken = payload, payload
	page.ConfirmOperatorID, page.ConfirmOperatorName, page.ConfirmOperatorError = 2, payload, payload
	message := payload
	page.PasswordError = &message
	page.Operators[1].Username = payload
	page.Sessions[0].Username, page.Sessions[0].UserAgent, page.Sessions[0].IP = payload, payload, payload
	page.APIKeys[0].Name, page.APIKeys[0].Prefix = payload, payload
	if strings.Contains(Account(page), "<script>alert") {
		t.Fatal("unescaped payload in account output")
	}
}
