package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// settleAfterBlur is how long a wrong handler gets to fire before a case
// concludes none did.
const settleAfterBlur = 300 * time.Millisecond

// Regression: the settings page uses ONE "change = saved" model. Every control
// auto-saves on change/blur; there is no "Save Settings" button; mid-typing
// fires zero requests (onchange, not oninput); invalid or partial values never
// hit the network.
//
// The browser has no request stream here, so the profile records every fetch
// the page makes.
func TestSpecSettingsAutosave(t *testing.T) {
	server := specInstance(t, "settings-autosave", settingsPort)
	if err := harness.NewAPI(server).Setup(harness.AdminUsername, harness.AdminPassword); err != nil {
		t.Fatal(err)
	}

	openSettings := func(p page) error {
		return sequence(
			p.signIn,
			func() error { return p.goTo("/settings") },
			p.Loc("#s-block-mode").ExpectVisible,
		)
	}
	putCount := func(p page) (int, error) { return p.RequestCount("PUT", "/api/settings") }
	noNewPut := func(p page, before int, what string) error {
		now, err := putCount(p)
		if err != nil {
			return err
		}
		if now != before {
			return fmt.Errorf("%s", what)
		}
		return nil
	}

	runCases(t, server, recordingRequests, []specCase{
		{"there is no Save Settings button", func(p page) error {
			return sequence(
				func() error { return openSettings(p) },
				func() error { return p.Loc("#save-settings").ExpectCount(0) },
			)
		}},
		{"changing block mode persists across reload (no button click)", func(p page) error {
			if err := openSettings(p); err != nil {
				return err
			}
			before, err := putCount(p)
			if err != nil {
				return err
			}
			return sequence(
				func() error { return p.Loc("#s-block-mode").SelectValue("nxdomain") },
				func() error { return p.ExpectRequest("PUT", "/api/settings", before) },
				p.Reload,
				func() error { return p.Loc("#s-block-mode").ExpectValue("nxdomain") },
			)
		}},
		{"custom IP persists across reload", func(p page) error {
			if err := openSettings(p); err != nil {
				return err
			}
			if err := p.Loc("#s-block-mode").SelectValue("custom_ip"); err != nil {
				return err
			}
			if err := p.Loc("#s-block-custom").ExpectVisible(); err != nil {
				return err
			}
			before, err := putCount(p)
			if err != nil {
				return err
			}
			return sequence(
				func() error { return p.Loc("#s-block-ipv4").Fill("192.0.2.1") },
				p.Loc("#s-block-ipv4").Blur,
				func() error { return p.ExpectRequest("PUT", "/api/settings", before) },
				p.Reload,
				func() error { return p.Loc("#s-block-mode").ExpectValue("custom_ip") },
				func() error { return p.Loc("#s-block-ipv4").ExpectValue("192.0.2.1") },
			)
		}},
		{"typing a partial IP fires no request until blur, and invalid IP never PUTs", func(p page) error {
			if err := openSettings(p); err != nil {
				return err
			}
			if err := p.Loc("#s-block-mode").SelectValue("custom_ip"); err != nil {
				return err
			}
			before, err := putCount(p)
			if err != nil {
				return err
			}
			return sequence(
				// Type an incomplete IPv4 key by key. Not cleared first: clearing
				// is itself a change, and the result is invalid either way.
				p.Loc("#s-block-ipv4").Click,
				func() error { return p.Loc("#s-block-ipv4").TypeText("192.168.1") },
				func() error { return noNewPut(p, before, "a PUT went out mid-typing") },
				p.Loc("#s-block-ipv4").Blur,
				// Give a wrong handler a chance to fire, then assert none did.
				func() error { time.Sleep(settleAfterBlur); return nil },
				func() error { return noNewPut(p, before, "an invalid IPv4 was sent to the server") },
				// The error is inline next to the IPv4 field, not a shared line.
				func() error { return p.Loc("#msg-block-ipv4").ExpectTextContains("IPv4") },
			)
		}},
		{"log retention auto-saves on blur, accepts blank (default), rejects non-numeric", func(p page) error {
			retention := p.Loc("#s-retention")
			// saved fills the field, blurs it and waits for the PUT it triggers.
			saved := func(value string) error {
				before, err := putCount(p)
				if err != nil {
					return err
				}
				return sequence(
					func() error { return retention.Fill(value) },
					retention.Blur,
					func() error { return p.ExpectRequest("PUT", "/api/settings", before) },
					p.Reload,
				)
			}
			return sequence(
				func() error { return openSettings(p) },
				// Valid: persists.
				func() error { return saved("14") },
				func() error { return retention.ExpectValue("14") },
				// Blank means "use the default": saved, not rejected.
				func() error { return saved("") },
				func() error { return retention.ExpectValue("") },
				// Invalid non-numeric: no request.
				func() error {
					before, err := putCount(p)
					if err != nil {
						return err
					}
					return sequence(
						func() error { return retention.Fill("abc") },
						retention.Blur,
						func() error { time.Sleep(settleAfterBlur); return nil },
						func() error { return noNewPut(p, before, "a non-numeric retention was sent to the server") },
					)
				},
			)
		}},
	})
}
