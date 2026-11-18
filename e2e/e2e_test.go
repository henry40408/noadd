package e2e

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

const defaultFeatures = "features"

// Ports are kept in one place so no step hardcodes one. The DNS port is the
// HTTP port plus 1000.
const (
	appPort        = 14100
	authPort       = 14101
	onboardingPort = 14102
)

// instance is one running noadd as the scenarios address it.
type instance struct {
	server *harness.Server
	// session is minted by the runner and replayed into the browser. Empty for
	// instances a feature configures itself.
	session string
}

// instances maps a feature tag to the instance that tag selects.
var instances map[string]*instance

// TestE2E runs the features one scenario at a time: @auth and @onboarding are
// each one narrative in file order, and the @app features share mutable
// filter state.
func TestE2E(t *testing.T) {
	started, err := startInstances()
	if err != nil {
		t.Fatal(err)
	}
	defer stopInstances(started)
	instances = started

	fmt.Fprintf(os.Stderr, "e2e: browser: %s\n", harness.BrowserChoice())
	suite := godog.TestSuite{
		Name:                "noadd",
		ScenarioInitializer: initializeScenario,
		Options: &godog.Options{
			Format: "pretty",
			// ANSI codes make CI logs unreadable.
			NoColors:    os.Getenv("CI") != "",
			Output:      os.Stdout,
			Paths:       featurePaths(),
			Concurrency: 1,
			// Undefined and pending steps fail rather than skip.
			Strict: true,
		},
	}
	if status := suite.Run(); status != 0 {
		t.Fatalf("the suite failed with status %d", status)
	}
}

func startInstances() (map[string]*instance, error) {
	started := map[string]*instance{}
	for tag, port := range map[string]int{"app": appPort, "auth": authPort, "onboarding": onboardingPort} {
		server, err := harness.NewServer(tag, port)
		if err != nil {
			stopInstances(started)
			return nil, fmt.Errorf("starting the %s instance: %w", tag, err)
		}
		started[tag] = &instance{server: server}
	}
	session, err := harness.NewAPI(started["app"].server).Provision()
	if err != nil {
		stopInstances(started)
		return nil, fmt.Errorf("provisioning the app instance: %w", err)
	}
	started["app"].session = session
	return started, nil
}

func stopInstances(started map[string]*instance) {
	for _, running := range started {
		running.server.Remove()
	}
}

// featurePaths is E2E_FEATURES, a comma-separated list of feature paths, for
// running one file locally. It defaults to every feature.
func featurePaths() []string {
	value := os.Getenv("E2E_FEATURES")
	if value == "" {
		return []string{defaultFeatures}
	}
	return strings.Split(value, ",")
}
