package e2e

import (
	"errors"
	"fmt"

	"github.com/cucumber/godog"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// A filter-list name whose double quote once escaped its own attribute. It is
// kept out of the .feature file because a quoted argument cannot carry a
// double quote reliably.
const (
	injectedName = `q" onmouseover="window.__xss=1`
	injectedURL  = "https://example.com/e2e-attr-injection.txt"

	listRows    = `[data-testid="filter-list-row"]`
	listToggles = `[data-testid="filter-list-toggle"]`
)

func registerFilterSteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^I see a filter list named `+quoted+`$`, w.seeList)
	sc.Step(`^the filter lists table shows a list named `+quoted+`$`, w.seeList)
	sc.Step(`^each filter list shows an enabled state and a rule count$`, w.listsHaveState)
	sc.Step(`^the filter list `+quoted+` is enabled$`, func(name string) error { return w.setListEnabled(name, true) })
	sc.Step(`^I disable the filter list `+quoted+`$`, func(name string) error { return w.setListEnabled(name, false) })
	sc.Step(`^I enable the filter list `+quoted+`$`, func(name string) error { return w.setListEnabled(name, true) })
	sc.Step(`^the filter list `+quoted+` is shown as disabled$`, func(name string) error {
		return w.browser.ExpectCheckedCSS(listToggleSelector(name), false)
	})
	sc.Step(`^the filter list `+quoted+` is shown as enabled$`, func(name string) error {
		return w.browser.ExpectCheckedCSS(listToggleSelector(name), true)
	})
	sc.Step(`^I add a custom filter list named `+quoted+` with URL `+quoted+`$`, w.addCustomList)
	sc.Step(`^I add a filter list whose name contains a double quote$`, w.addQuotedList)
	sc.Step(`^no filter list row carries an inline event handler$`, w.noInlineHandlers)
	sc.Step(`^the quoted filter list name is shown as text$`, func() error {
		// Matched as text: a [data-name="..."] selector would break on the quote.
		return w.browser.ExpectTextSomewhere(injectedName)
	})
	sc.Step(`^I open the registry browser$`, func() error { return w.browser.ClickCSS("#browse-registry") })
	sc.Step(`^the registry browser is a page of its own$`, w.registryIsAPage)
	sc.Step(`^I disable every filter list$`, w.disableEveryList)
	sc.Step(`^I see a warning that no filter list is enabled$`, func() error {
		return w.browser.ExpectVisible("filters-all-disabled-warning")
	})
	sc.Step(`^the warning offers a way to enable a recommended list$`, func() error {
		return w.browser.ExpectVisible("filters-enable-recommended")
	})
}

func listRowSelector(name string) string {
	return fmt.Sprintf(`%s[data-name=%q]`, listRows, name)
}

func listToggleSelector(name string) string {
	return listRowSelector(name) + " " + listToggles
}

func (w *world) seeList(name string) error {
	_, err := w.browser.CSS(listRowSelector(name))
	return err
}

func (w *world) listsHaveState() error {
	if _, err := w.browser.CSS(listRows); err != nil {
		return err
	}
	rows, err := w.browser.CountCSS(listRows)
	if err != nil {
		return err
	}
	return w.browser.ExpectCount(listRows+" "+listToggles, rows)
}

// setListEnabled clicks a row's toggle if it is not in the wanted state. It
// clicks the label because the checkbox itself is visually hidden.
func (w *world) setListEnabled(name string, enabled bool) error {
	if _, err := w.browser.CSS(listRowSelector(name)); err != nil {
		return err
	}
	current, err := w.browser.IsCheckedCSS(listToggleSelector(name))
	if err != nil {
		return err
	}
	if current != enabled {
		if err := w.browser.ClickCSS(listRowSelector(name) + " label.toggle"); err != nil {
			return err
		}
	}
	return w.browser.ExpectCheckedCSS(listToggleSelector(name), enabled)
}

func (w *world) addCustomList(name, url string) error {
	if err := w.browser.Fill("list-name-input", name); err != nil {
		return err
	}
	if err := w.browser.Fill("list-url-input", url); err != nil {
		return err
	}
	return w.browser.Click("list-add-submit")
}

func (w *world) addQuotedList() error {
	if err := w.addCustomList(injectedName, injectedURL); err != nil {
		return err
	}
	// Both inputs are cleared once the POST resolves and the table reloads.
	return w.browser.ExpectValue("list-url-input", "")
}

// noInlineHandlers: an on* attribute on a row means an interpolated value
// escaped its attribute, since nothing in the template writes one.
func (w *world) noInlineHandlers() error {
	handlers, err := harness.Eval[[]string](w.browser, `[...document.querySelectorAll('[data-testid="filter-list-row"]')]
		.flatMap((row) => [...row.attributes].map((a) => a.name))
		.filter((name) => name.startsWith('on'))`)
	if err != nil {
		return err
	}
	if len(handlers) > 0 {
		return fmt.Errorf("inline event handlers injected onto filter list rows: %q", handlers)
	}
	return nil
}

func (w *world) registryIsAPage() error {
	if err := w.browser.ExpectPathSuffix("/filters/registry"); err != nil {
		return err
	}
	if _, err := w.browser.CSS("registry-page"); err != nil {
		return err
	}
	// The nav still marks Filters; both bars do, so ask the one with a test id.
	return w.browser.ExpectClass(`[data-testid="nav-filters"]`, "active")
}

func (w *world) disableEveryList() error {
	count, err := w.browser.CountCSS(listToggles)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("expected at least one filter list to disable")
	}
	enabledLabel := listRows + ":has(" + listToggles + ":checked) label.toggle"
	for range count {
		remaining, err := w.browser.CountCSS(enabledLabel)
		if err != nil {
			return err
		}
		if remaining == 0 {
			return nil
		}
		// Click the label (the input is visually hidden); that fires the PUT,
		// and the unchecked state is what the wait is on.
		if err := w.browser.ClickCSS(enabledLabel); err != nil {
			return err
		}
		if err := w.browser.ExpectCount(listRows+":has("+listToggles+":checked) label.toggle", remaining-1); err != nil {
			return err
		}
	}
	return nil
}
