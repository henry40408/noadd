package e2e

import (
	"testing"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// The dashboard, settings and account with JavaScript off. None seeds or
// empties anything, so they share one instance.
//
//	dashboard: the readings arrive rendered; the chart says it needs a browser.
//	settings:  the no-JS save row posts and persists; a rejected value comes
//	           back in the field with a reason.
//	account:   password-proofed actions carry the password in their own form.
//
// Password confirmations share the five-per-minute login budget, so there is
// exactly one here plus the sign-in.
func TestSpecPagesNoJS(t *testing.T) {
	server := specInstance(t, "pages-no-js", pagesNoJSPort)
	session := provision(t, server)

	runCases(t, server, noJS, []specCase{
		{"the dashboard arrives with its readings, and says what needs a browser", func(p page) error {
			if err := p.open(session, "/"); err != nil {
				return err
			}
			// No traffic yet, so the rates are a real zero, not a blank.
			for _, step := range []func() error{
				p.LocTestID("stat-blocked-today").ExpectVisible,
				func() error { return p.LocTestID("stat-block-rate").ExpectTextContains("0.0%") },
				p.LocTestID("stat-throughput-value").ExpectVisible,
				// The top-N tables are rendered, not fetched.
				p.LocTestID("top-domains-card").ExpectVisible,
				// The client-only control ships hidden.
				p.LocTestID("live-toggle").ExpectHidden,
				// So does the status indicator: without the event stream it
				// cannot know the server is up, so it must not claim it.
				p.LocTestID("server-status").ExpectHidden,
				// No traffic: the empty state shows and the chart card is
				// hidden, so its "drawn in the browser" note is in the markup,
				// not on screen.
				p.LocTestID("dashboard-empty-state").ExpectVisible,
				func() error {
					return p.LocTestID("dashboard-empty-state").ExpectTextContains("Point a device at noadd")
				},
				p.Loc("#chart-card").ExpectHidden,
				func() error { return p.LocTestID("chart-needs-js").ExpectCount(1) },
			} {
				if err := step(); err != nil {
					return err
				}
			}
			return nil
		}},
		{"settings saves through its form and persists", func(p page) error {
			if err := p.open(session, "/settings"); err != nil {
				return err
			}
			// The no-JS save row ships visible; app.js would remove it.
			if err := p.LocTestID("save-settings").ExpectVisible(); err != nil {
				return err
			}
			// A browser posts the whole form, and a fresh appliance has no
			// upstream, so saving without one would be rejected outright.
			if err := p.Loc("#s-upstream").Fill("1.1.1.1:53"); err != nil {
				return err
			}
			if err := p.Loc("#s-retention").Fill("21"); err != nil {
				return err
			}
			if err := saveSettingsNoJS(p); err != nil {
				return err
			}
			// PRG: a flash on the redirected page, not a re-render.
			if err := p.LocTestID("settings-saved").ExpectVisible(); err != nil {
				return err
			}
			if err := p.ExpectURLEndsWith("/settings"); err != nil {
				return err
			}
			// And it is really stored: a fresh load shows it.
			if err := p.goTo("/settings"); err != nil {
				return err
			}
			if err := p.Loc("#s-retention").ExpectValue("21"); err != nil {
				return err
			}
			return p.Loc("#s-upstream").ExpectValue("1.1.1.1:53")
		}},
		{"a rejected setting comes back in the field with a reason", func(p page) error {
			if err := p.open(session, "/settings"); err != nil {
				return err
			}
			// Store a known-good state first, independent of earlier cases.
			if err := p.Loc("#s-upstream").Fill("9.9.9.9:53"); err != nil {
				return err
			}
			if err := p.Loc("#s-retention").Fill("14"); err != nil {
				return err
			}
			if err := saveSettingsNoJS(p); err != nil {
				return err
			}
			if err := p.LocTestID("settings-saved").ExpectVisible(); err != nil {
				return err
			}

			if err := p.Loc("#s-upstream").Fill("not a server"); err != nil {
				return err
			}
			if err := saveSettingsNoJS(p); err != nil {
				return err
			}
			// Re-rendered with the submitted value, reason next to the field.
			if err := p.Loc("#s-upstream").ExpectValue("not a server"); err != nil {
				return err
			}
			if err := p.ExpectPageText("Not a valid upstream"); err != nil {
				return err
			}
			if err := p.LocTestID("settings-saved").ExpectCount(0); err != nil {
				return err
			}
			// Nothing was written: the save is rejected whole, not half applied.
			if err := p.goTo("/settings"); err != nil {
				return err
			}
			if err := p.Loc("#s-upstream").ExpectValue("9.9.9.9:53"); err != nil {
				return err
			}
			return p.Loc("#s-retention").ExpectValue("14")
		}},
		{"the account page renders its tables and its delete confirmation", func(p page) error {
			if err := p.open(session, "/account"); err != nil {
				return err
			}
			// All three tables are in the first response.
			if err := p.LocTestID("operator-row").ExpectCount(1); err != nil {
				return err
			}
			if err := p.LocTestID("session-row").ExpectCountAtLeast(1); err != nil {
				return err
			}
			// The password field rides in the form that needs it.
			if err := p.LocTestID("operator-your-password").ExpectVisible(); err != nil {
				return err
			}
			if err := p.LocTestID("api-key-your-password").ExpectVisible(); err != nil {
				return err
			}
			// A destructive row action expands into a named confirmation via URL.
			if err := p.goTo("/account?confirm_delete=1"); err != nil {
				return err
			}
			if err := p.LocTestID("operator-confirm-row").ExpectVisible(); err != nil {
				return err
			}
			return p.LocTestID("operator-delete-password").ExpectVisible()
		}},
		{"minting an API key shows the token in the response that created it", func(p page) error {
			if err := p.open(session, "/account"); err != nil {
				return err
			}
			if err := p.LocTestID("api-key-name").Fill("nojs-key"); err != nil {
				return err
			}
			if err := p.LocTestID("api-key-your-password").Fill(harness.AdminPassword); err != nil {
				return err
			}
			if err := p.LocTestID("api-key-your-password").PressEnter(); err != nil {
				return err
			}
			// The one exception to PRG: this response holds the only copy.
			if err := p.LocTestID("api-key-token").ExpectVisible(); err != nil {
				return err
			}
			if err := p.LocTestID("api-key-token").ExpectValueNotEmpty(); err != nil {
				return err
			}
			if err := p.LocTestID("api-key-row").ExpectTextContains("nojs-key"); err != nil {
				return err
			}
			// And the password is never echoed back into the markup.
			return p.LocTestID("api-key-your-password").ExpectValue("")
		}},
		// Last: the dismissal is stored, removing the notice for good.
		{"the onboarding notice is rendered, and dismissing it is a form post", func(p page) error {
			if err := p.open(session, "/account"); err != nil {
				return err
			}
			// Server-rendered, so it exists with scripting off.
			if err := p.LocTestID("next-step-banner").ExpectVisible(); err != nil {
				return err
			}
			if err := p.LocTestID("next-step-banner-addr").ExpectTextContains(":"); err != nil {
				return err
			}
			if err := p.LocTestID("next-step-banner-dismiss").Click(); err != nil {
				return err
			}
			// The next field returns the operator to where they dismissed it.
			if err := p.ExpectURLEndsWith("/account"); err != nil {
				return err
			}
			if err := p.LocTestID("next-step-banner").ExpectCount(0); err != nil {
				return err
			}
			// And it stays dismissed.
			if err := p.goTo("/settings"); err != nil {
				return err
			}
			return p.LocTestID("next-step-banner").ExpectCount(0)
		}},
	})
}

// saveSettingsNoJS activates the real save button: settings does not submit
// on Enter (no default button for implicit submission). A script click,
// because the fixed status bar can cover it. The callers' assertions prove the
// POST landed.
func saveSettingsNoJS(p page) error {
	return p.LocTestID("save-settings").ClickJS()
}
