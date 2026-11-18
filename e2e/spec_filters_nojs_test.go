package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// The filters page with JavaScript off: every control is a real form, so
// adding, toggling, editing and deleting rules and lists, and testing a
// domain, must all work from the server's markup alone.
//
// Forms are submitted with Enter and row controls activated with a script
// click, because the fixed status bar can cover them in the short no-JS
// viewport.
func TestSpecFiltersNoJS(t *testing.T) {
	server := specInstance(t, "filters-no-js", filtersNoJSPort)
	session := provision(t, server)

	listRow := func(p page, name string) harness.Locator {
		return p.Loc(fmt.Sprintf(`[data-testid="filter-list-row"][data-name=%q]`, name))
	}

	runCases(t, server, noJS, []specCase{
		{"the page renders its lists, rules and controls from the server", func(p page) error {
			return sequence(
				func() error { return p.open(session, "/filters") },
				p.LocTestID("rules-list").ExpectVisible,
				func() error { return p.LocTestID("nav-filters").ExpectClass("active") },
				// The registry browser is a page of its own, reached by a link.
				p.Loc("#browse-registry").ExpectVisible,
				func() error { return p.Loc("#browse-registry").ExpectAttr("href", "/filters/registry") },
			)
		}},
		{"a custom rule can be added and deleted through the forms", func(p page) error {
			row := p.LocTestID("rule-row").HavingText("nojs-added.example.com")
			return sequence(
				func() error { return p.open(session, "/filters") },
				func() error { return p.LocTestID("rule-input").Fill("||nojs-added.example.com^") },
				p.LocTestID("rule-input").PressEnter,
				row.ExpectVisible,
				func() error { return row.ExpectAttr("data-type", "block") },
				// The POST redirected, so a refresh re-renders, not re-submits.
				func() error { return p.ExpectURLEndsWith("/filters") },
				row.TestID("rule-delete").ClickJS,
				func() error { return row.ExpectCount(0) },
			)
		}},
		{"a rule that does not parse comes back in the field with a reason", func(p page) error {
			return sequence(
				func() error { return p.open(session, "/filters") },
				func() error { return p.LocTestID("rule-input").Fill("   ") },
				p.LocTestID("rule-input").PressEnter,
				func() error {
					return p.LocTestID("rule-add-error").ExpectTextContains("Not a rule noadd understands")
				},
				// The nav still marks Filters, though the POST hit /filters/rules.
				func() error { return p.LocTestID("nav-filters").ExpectClass("active") },
			)
		}},
		{"a list can be added, toggled off, edited and deleted", func(p page) error {
			added := listRow(p, "No JS List")
			renamed := listRow(p, "Renamed Without JS")
			return sequence(
				func() error { return p.open(session, "/filters") },
				func() error { return p.LocTestID("list-name-input").Fill("No JS List") },
				func() error { return p.LocTestID("list-url-input").Fill("https://example.com/no-js.txt") },
				p.LocTestID("list-name-input").PressEnter,
				added.ExpectVisible,
				func() error { return added.TestID("filter-list-toggle").ExpectChecked(true) },
				// This list downloaded nothing: "No rules", distinct from "No impact".
				func() error { return added.TestID("filter-list-impact").ExpectTextEq("No rules") },
				// Untick, then submit via the .nojs-only button app.js removes.
				added.Loc("label.toggle").ClickJS,
				added.Loc(".nojs-only").ClickJS,
				func() error { return added.TestID("filter-list-toggle").ExpectChecked(false) },
				// A disabled list reports no impact figure.
				func() error { return added.TestID("filter-list-impact").ExpectTextEq("Disabled") },
				// Edit expands the row on the server rather than opening a dialog.
				added.Loc(".edit-list").ClickJS,
				p.LocTestID("filter-list-edit-row").ExpectVisible,
				func() error { return p.LocTestID("list-edit-name").ExpectValue("No JS List") },
				func() error { return p.LocTestID("list-edit-name").Fill("Renamed Without JS") },
				p.LocTestID("list-edit-name").PressEnter,
				renamed.ExpectVisible,
				renamed.Loc(".del-list").ClickJS,
				func() error { return renamed.ExpectCount(0) },
			)
		}},
		{"a list with no URL comes back with the name still typed", func(p page) error {
			return sequence(
				func() error { return p.open(session, "/filters") },
				func() error { return p.LocTestID("list-name-input").Fill("Missing URL") },
				p.LocTestID("list-name-input").PressEnter,
				func() error { return p.LocTestID("list-add-error").ExpectTextContains("URL is required") },
				func() error { return p.LocTestID("list-name-input").ExpectValue("Missing URL") },
				func() error { return listRow(p, "Missing URL").ExpectCount(0) },
			)
		}},
		{"a domain test is answered in the page and stays in the URL", func(p page) error {
			return sequence(
				func() error { return p.open(session, "/filters") },
				func() error { return p.LocTestID("rule-input").Fill("||nojs-tested.example.com^") },
				p.LocTestID("rule-input").PressEnter,
				// Wait for the redirect's row: Enter only dispatches the key, and
				// the navigation below would cancel a submission still in flight.
				p.LocTestID("rule-row").HavingText("nojs-tested.example.com").ExpectVisible,
				func() error { return waitForBlockedVerdict(p) },
				func() error { return p.ExpectURLContains("test=nojs-tested.example.com") },
				// Refreshable and linkable: the domain came back in the field too.
				func() error { return p.LocTestID("domain-test-input").ExpectValue("nojs-tested.example.com") },
			)
		}},
		{"Browse Registry is a link that reaches its page", func(p page) error {
			return sequence(
				func() error { return p.open(session, "/filters") },
				p.Loc("#browse-registry").ClickJS,
				func() error { return p.ExpectURLEndsWith("/filters/registry") },
				p.Loc("registry-page").ExpectVisible,
				// Either answer is the page working: entries, or (registry
				// unreachable) an explanation and a retry.
				p.Loc(`#registry-form, [data-testid="registry-unavailable"]`).First().ExpectVisible,
			)
		}},
	})
}

// waitForBlockedVerdict re-runs the domain test GET until the rule lands: the
// verdict comes from the live engine, refreshed by a background rebuild. It
// gets the full wait, since rebuilds run late on a busy machine.
func waitForBlockedVerdict(p page) error {
	deadline := time.Now().Add(harness.WaitTimeout)
	verdict := ""
	for time.Now().Before(deadline) {
		if err := p.goTo("/filters?test=nojs-tested.example.com"); err != nil {
			return err
		}
		verdict, _ = p.LocTestID("domain-test-result").Text()
		if strings.Contains(verdict, "Blocked") {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("the domain test never reported Blocked; last read %q", verdict)
}
