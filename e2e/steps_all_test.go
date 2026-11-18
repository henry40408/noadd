package e2e

import "github.com/cucumber/godog"

// quoted matches a Gherkin string argument. godog has no Cucumber
// Expressions, so every step is a regular expression.
const quoted = `"([^"]*)"`

func registerSteps(sc *godog.ScenarioContext, w *world) {
	registerAuthSteps(sc, w)
	registerNavigationSteps(sc, w)
	registerDashboardSteps(sc, w)
	registerFilterSteps(sc, w)
	registerRuleSteps(sc, w)
	registerOnboardingSteps(sc, w)
}
