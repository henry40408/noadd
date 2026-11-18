package e2e

import (
	"fmt"

	"github.com/cucumber/godog"
)

// navTabs maps the nav label used in the features to its data-testid. Only the
// desktop strip carries test ids (the mobile bar does not), so each matches one
// element.
var navTabs = []struct{ label, testID string }{
	{"Dashboard", "nav-dashboard"},
	{"Statistics", "nav-stats"},
	{"Query Log", "nav-logs"},
	{"Filters", "nav-filters"},
	{"Settings", "nav-settings"},
	{"Account", "nav-account"},
}

func registerNavigationSteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^I go to the `+quoted+` tab$`, w.goToTab)
	sc.Step(`^I am on the `+quoted+` tab$`, w.goToTab)
	// Shared by the dashboard ("Database Health") and filters ("Filter Lists").
	sc.Step(`^I see the `+quoted+` section$`, func(name string) error { return w.browser.ExpectTextSomewhere(name) })
}

func tabTestID(label string) (string, error) {
	for _, tab := range navTabs {
		if tab.label == label {
			return tab.testID, nil
		}
	}
	return "", fmt.Errorf("unknown tab: %s", label)
}

func (w *world) goToTab(label string) error {
	id, err := tabTestID(label)
	if err != nil {
		return err
	}
	if err := w.browser.Click(id); err != nil {
		return err
	}
	return w.browser.ExpectClass(`[data-testid="`+id+`"]`, "active")
}
