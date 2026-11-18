package e2e

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// The account actions that need a password proof (mint an API key, add an
// operator, delete one) carry a "your password" field in their own form, so
// the path is the same with or without JavaScript. POST /api/auth/reauth is
// covered in the Go API tests.
//
// Own instance: password confirmations share the five-per-minute login
// budget, which is why there are exactly three of them plus the one sign-in.
func TestSpecAccountSensitiveActions(t *testing.T) {
	server := specInstance(t, "account-sensitive-actions", accountPort)
	session := provision(t, server)

	runCases(t, server, desktop, []specCase{
		{"an API key is minted when the form carries the right password", func(p page) error {
			return sequence(
				func() error { return p.open(session, "/account") },
				func() error { return p.LocTestID("api-key-name").Fill("ci") },
				func() error { return p.LocTestID("api-key-your-password").Fill(harness.AdminPassword) },
				// Enter, not a click: on this long page the fixed status bar can
				// cover a button near the fold.
				p.LocTestID("api-key-your-password").PressEnter,
				// Rendered, not redirected: this response holds the only copy.
				p.LocTestID("api-key-reveal").ExpectVisible,
				func() error { return p.LocTestID("api-key-token").ExpectValueStartsWith("noadd_") },
				p.Loc(`[data-testid="api-key-row"][data-name="ci"]`).ExpectVisible,
				// No reauth dialog exists.
				func() error { return p.LocTestID("reauth-password").ExpectCount(0) },
			)
		}},
		{"a wrong password creates nothing and keeps what was typed", func(p page) error {
			return sequence(
				func() error { return p.open(session, "/account") },
				func() error { return p.LocTestID("api-key-name").Fill("rejected") },
				func() error { return p.LocTestID("api-key-your-password").Fill("not the password") },
				p.LocTestID("api-key-your-password").PressEnter,
				func() error { return p.LocTestID("api-key-error").ExpectTextContains("password is incorrect") },
				// The name survives so only the password has to be retyped.
				func() error { return p.LocTestID("api-key-name").ExpectValue("rejected") },
				p.LocTestID("api-key-reveal").ExpectHidden,
				func() error { return p.Loc(`[data-testid="api-key-row"][data-name="rejected"]`).ExpectCount(0) },
			)
		}},
		{"adding an operator needs the password, and deleting one asks by name", func(p page) error {
			row := p.Loc(`[data-testid="operator-row"][data-name="second-operator"]`)
			confirm := p.LocTestID("operator-confirm-row")
			return sequence(
				func() error { return p.open(session, "/account") },
				func() error { return p.LocTestID("operator-username").Fill("second-operator") },
				func() error { return p.LocTestID("operator-password").Fill("correct-horse-battery-staple-2") },
				func() error { return p.LocTestID("operator-password-confirm").Fill("correct-horse-battery-staple-2") },
				func() error { return p.LocTestID("operator-your-password").Fill(harness.AdminPassword) },
				p.LocTestID("operator-your-password").PressEnter,
				row.ExpectVisible,
				// Redirected, so a refresh cannot add a second one.
				func() error { return p.ExpectURLEndsWith("/account") },
				// Delete expands a confirmation naming the operator, with its own
				// password field. It is a GET, so no password is spent.
				row.Loc(".del-op").ClickJS,
				confirm.ExpectVisible,
				func() error { return confirm.ExpectTextContains("second-operator") },
				p.LocTestID("operator-delete-password").ExpectVisible,
				// Cancelling leaves the operator alone.
				confirm.Loc("a, button").HavingText("Cancel").ClickJS,
				func() error { return confirm.ExpectCount(0) },
				row.ExpectVisible,
			)
		}},
	})
}

// Regression: changing your own password revokes every other session and
// rotates this one, and the account page that comes back must list exactly
// that, with the operator still signed in.
//
// Own instance: the case is destructive, and needs its own five-per-minute
// login budget.
func TestSpecPasswordChangeSessionList(t *testing.T) {
	const newPassword = "an entirely different passphrase"
	server := specInstance(t, "password-change-session-list", passwordChangePort)
	api := harness.NewAPI(server)
	if err := api.Setup(harness.AdminUsername, harness.AdminPassword); err != nil {
		t.Fatal(err)
	}

	runCases(t, server, desktop, []specCase{
		{"changing my password revokes the others and rotates this one", func(p page) error {
			// A second, API-minted session, so there is another row to revoke.
			if _, err := api.Login(harness.AdminUsername, harness.AdminPassword); err != nil {
				return err
			}
			if err := p.signIn(); err != nil {
				return err
			}
			rows := p.LocTestID("session-row")
			if err := sequence(
				p.LocTestID("nav-account").Click,
				func() error { return rows.ExpectCount(2) },
			); err != nil {
				return err
			}
			idsBefore, err := sessionRowIDs(rows, 2)
			if err != nil {
				return err
			}
			if err := sequence(
				func() error { return p.LocTestID("password-current").Fill(harness.AdminPassword) },
				func() error { return p.LocTestID("password-new").Fill(newPassword) },
				func() error { return p.LocTestID("password-confirm").Fill(newPassword) },
				p.LocTestID("password-save").Click,
				// The confirmation is rendered after the redirect, so the table
				// below reflects the post-change state.
				p.LocTestID("password-changed").ExpectVisible,
				// The other session is gone; this one was rotated to a new id.
				func() error { return rows.ExpectCount(1) },
			); err != nil {
				return err
			}
			idAfter, err := sessionRowIDs(rows, 1)
			if err != nil {
				return err
			}
			if _, numeric := strconv.ParseUint(idAfter[0], 10, 64); numeric != nil {
				return fmt.Errorf("the surviving session id is not a number: %q", idAfter[0])
			}
			for _, before := range idsBefore {
				if before == idAfter[0] {
					return fmt.Errorf("the session id %s was not rotated", before)
				}
			}
			// Still signed in, not bounced to login by a stale cookie.
			return sequence(
				p.LocTestID("logout-other-sessions").ExpectVisible,
				func() error { return p.LocTestID("login-submit").ExpectCount(0) },
			)
		}},
	})
}

// sessionRowIDs is the data-id of each of the first count session rows.
func sessionRowIDs(rows harness.Locator, count int) ([]string, error) {
	ids := make([]string, 0, count)
	for i := range count {
		id, err := rows.Nth(i).Attr("data-id")
		if err != nil {
			return nil, err
		}
		if id == nil || *id == "" {
			return nil, fmt.Errorf("session row %d carried no id", i)
		}
		ids = append(ids, *id)
	}
	return ids, nil
}
