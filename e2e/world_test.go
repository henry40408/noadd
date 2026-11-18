package e2e

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// world is the state shared by the steps of one scenario.
type world struct {
	instance *instance
	browser  *harness.Browser
	// leakedMarkup is what the every-tab sweep found, for the assertion after it.
	leakedMarkup []string
}

// initializeScenario runs once per scenario, so each gets its own world.
func initializeScenario(sc *godog.ScenarioContext) {
	w := &world{}
	sc.Before(w.start)
	sc.After(w.cleanUp)
	registerSteps(sc, w)
}

func (w *world) start(ctx context.Context, scenario *godog.Scenario) (context.Context, error) {
	chosen, err := instanceFor(scenario)
	if err != nil {
		return ctx, err
	}
	w.instance = chosen
	w.browser, err = harness.Open()
	if err != nil {
		return ctx, err
	}
	if chosen.session == "" {
		return ctx, nil
	}
	return ctx, w.browser.AdoptSession(chosen.server.BaseURL, chosen.session)
}

// instanceFor picks the instance a feature's tag names.
func instanceFor(scenario *godog.Scenario) (*instance, error) {
	for _, tag := range scenario.Tags {
		if found, ok := instances[strings.TrimPrefix(tag.Name, "@")]; ok {
			return found, nil
		}
	}
	return nil, fmt.Errorf("no instance for the tags of %q: a feature forgot its tag", scenario.Name)
}

func (w *world) cleanUp(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
	if w.browser != nil {
		w.browser.Close()
	}
	return ctx, nil
}

func (w *world) api() *harness.API { return harness.NewAPI(w.instance.server) }

func (w *world) goTo(path string) error {
	return w.browser.Goto(w.instance.server.BaseURL + path)
}

// sessionToken is the session the scenario's requests are asked with.
func (w *world) sessionToken() (string, error) {
	if w.instance.session == "" {
		return "", errors.New("this instance has no session to ask with")
	}
	return w.instance.session, nil
}
