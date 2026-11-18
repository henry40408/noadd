package e2e

import (
	"fmt"
	"strings"

	"github.com/cucumber/godog"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

func registerOnboardingSteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^I see the next-step banner explaining how to point a device at noadd$`, func() error {
		return w.browser.ExpectVisible("next-step-banner")
	})
	sc.Step(`^I dismiss the next-step banner$`, func() error { return w.browser.Click("next-step-banner-dismiss") })
	sc.Step(`^the next-step banner is no longer shown$`, func() error { return w.browser.ExpectAbsent("next-step-banner") })
	sc.Step(`^reloading the admin UI does not show the next-step banner again$`, w.bannerStaysGone)
	sc.Step(`^I see onboarding guidance explaining how to point a device at noadd$`, func() error {
		return w.browser.ExpectVisible("dashboard-empty-state")
	})
	sc.Step(`^the guidance shows this server's DNS address$`, func() error {
		// The HTTP origin's host is the address noadd serves DNS on.
		host := strings.TrimPrefix(w.instance.server.BaseURL, "http://")
		host, _, _ = strings.Cut(host, ":")
		return w.browser.ExpectText("dashboard-empty-state", host)
	})
	sc.Step(`^I see onboarding guidance explaining that no DNS queries have been logged yet$`, func() error {
		return w.browser.ExpectVisible("logs-empty-state")
	})
	sc.Step(`^noadd resolves a real DNS query$`, func() error {
		// No response needed: the following assertion polls past the logger's flush.
		return harness.SendDNSQuery(w.instance.server.DNSPort, "onboarding-probe.example")
	})
}

// bannerStaysGone waits for the dismissal to be saved before reloading:
// app.js removes the banner before its fire-and-forget POST lands, so a reload
// straight away can reach the server first and get the banner back.
func (w *world) bannerStaysGone() error {
	session, err := w.browser.SessionToken()
	if err != nil {
		return err
	}
	err = harness.Eventually("the dismissal to be saved", func() (bool, error) {
		settings, err := w.api().GetJSON(session, "/api/settings")
		if err != nil {
			return false, err
		}
		return fmt.Sprint(settings["onboarding_banner_dismissed"]) == "true", nil
	})
	if err != nil {
		return err
	}
	if err := w.browser.Reload(); err != nil {
		return err
	}
	return w.browser.ExpectAbsent("next-step-banner")
}
