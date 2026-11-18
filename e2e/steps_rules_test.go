package e2e

import (
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// rebuildTimeout is how long the filter-rebuild waits allow. A rebuild
// reparses the enabled lists, so it is the first thing to run late on a loaded
// machine; reusing the element wait keeps one number to reason about.
const rebuildTimeout = harness.WaitTimeout

const (
	ruleRows       = `[data-testid="rule-row"]`
	domainTestPoll = 300 * time.Millisecond
)

func registerRuleSteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^I (?:add|have added) the custom rule "(.*)"$`, w.addRule)
	sc.Step(`^the custom rules list shows an? "(allow|block)" rule for "(.*)"$`, func(kind, domain string) error {
		return w.browser.ExpectVisibleWithText(fmt.Sprintf(`%s[data-type=%q]`, ruleRows, kind), domain)
	})
	sc.Step(`^I delete the rule for `+quoted+`$`, func(domain string) error {
		return w.browser.ClickWithinTextRow(ruleRows, domain, `[data-testid="rule-delete"]`)
	})
	sc.Step(`^the custom rules list no longer shows `+quoted+`$`, func(domain string) error {
		return w.browser.ExpectNoneWithText(ruleRows, domain)
	})
	sc.Step(`^the filter engine has finished rebuilding$`, w.rebuildSettled)
	sc.Step(`^I run a domain test for `+quoted+`$`, w.runDomainTest)
	sc.Step(`^the domain test reports the domain as `+quoted+`$`, w.domainTestReports)
	sc.Step(`^the domain test result mentions `+quoted+`$`, func(text string) error {
		return w.browser.ExpectText("domain-test-result", text)
	})
}

func (w *world) addRule(rule string) error {
	if err := w.browser.Fill("rule-input", rule); err != nil {
		return err
	}
	return w.browser.Click("rule-submit")
}

// rebuildSettled waits out the async rebuild that adding a rule starts.
func (w *world) rebuildSettled() error {
	session, err := w.sessionToken()
	if err != nil {
		return err
	}
	return w.api().WaitUntilRebuilt(session, rebuildTimeout)
}

func (w *world) runDomainTest(domain string) error {
	if err := w.browser.Fill("domain-test-input", domain); err != nil {
		return err
	}
	return w.browser.Click("domain-test-submit")
}

// domainTestReports re-runs the check until the async rebuild swaps in an
// engine that has the rule.
func (w *world) domainTestReports(verdict string) error {
	var last string
	deadline := time.Now().Add(rebuildTimeout)
	for {
		if err := w.browser.Click("domain-test-submit"); err != nil {
			return err
		}
		text, err := w.browser.TextOfTestID("domain-test-result")
		if err == nil && text != nil {
			last = *text
		}
		if strings.Contains(last, verdict) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the domain test never reported %q; last read %q", verdict, last)
		}
		time.Sleep(domainTestPoll)
	}
}
