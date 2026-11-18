package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// The specs are regression tests that Gherkin does not suit: each owns an
// instance (so destructive cases and the five-per-minute login budget stay
// out of the features' way) and runs its cases in the order written, one
// browser per case. A no-JS case needs its own browser, because disabling
// scripts applies from the next document on.

// specPorts are one per spec file, kept in one place so none collides. The DNS
// port is the HTTP port plus 1000. 14100-14102 belong to the features.
const (
	chartTouchPort     = 14103
	settingsPort       = 14104
	passwordChangePort = 14105
	accountPort        = 14106
	filtersNoJSPort    = 14107
	logsNoJSPort       = 14108
	statsNoJSPort      = 14109
	pagesNoJSPort      = 14110
	logsLiveTailPort   = 14111
	statsChartsPort    = 14112
)

// profile says how a spec's browsers are emulated.
type profile struct {
	scripting harness.Scripting
	emulate   func(*harness.Browser) error
}

var (
	// desktop is the scripted default.
	desktop = profile{harness.ScriptsOn, func(*harness.Browser) error { return nil }}
	// phone is a touch-enabled Pixel 5, for the chart tap specs.
	phone = profile{harness.ScriptsOn, (*harness.Browser).EmulatePhone}
	// recordingRequests is the desktop with every fetch logged.
	recordingRequests = profile{harness.ScriptsOn, func(browser *harness.Browser) error {
		return browser.AddInitScript(harness.RecordRequests)
	}}
	// noJS is scripts off, reduced motion and a short window.
	noJS = profile{harness.ScriptsOff, func(browser *harness.Browser) error {
		if err := browser.SetViewport(harness.ShortWidth, harness.ShortHeight); err != nil {
			return err
		}
		return browser.ReduceMotion()
	}}
)

// page is a browser bound to the instance under test.
type page struct {
	*harness.Browser
	server *harness.Server
}

func (p page) goTo(path string) error {
	return p.Goto(p.server.BaseURL + path)
}

// goToAfterSubmit is goTo for a page that follows a form submit the browser
// may still be finishing: its pending navigation is cancelled by ours, which
// Chrome reports as ERR_ABORTED. The submitted request still reaches the
// server, so going again is safe.
func (p page) goToAfterSubmit(path string) error {
	var err error
	for range 5 {
		if err = p.goTo(path); err == nil || !strings.Contains(err.Error(), "ERR_ABORTED") {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return err
}

// open replays the spec's one login as a cookie, sparing the login budget,
// and lands on path inside the app shell.
func (p page) open(session, path string) error {
	if err := p.AdoptSession(p.server.BaseURL, session); err != nil {
		return err
	}
	if err := p.goTo(path); err != nil {
		return err
	}
	return p.LocTestID("app-shell").ExpectVisible()
}

// signIn goes through the login form, for the specs that test a page's own
// scripts from a signed-out start.
func (p page) signIn() error {
	if err := p.goTo("/"); err != nil {
		return err
	}
	if err := p.LocTestID("login-username").Fill(harness.AdminUsername); err != nil {
		return err
	}
	if err := p.LocTestID("login-password").Fill(harness.AdminPassword); err != nil {
		return err
	}
	if err := p.LocTestID("login-submit").Click(); err != nil {
		return err
	}
	return p.LocTestID("app-shell").ExpectVisible()
}

// specInstance starts a fresh instance, removed when the test ends.
func specInstance(t *testing.T, name string, port int) *harness.Server {
	t.Helper()
	server, err := harness.NewServer(name, port)
	if err != nil {
		t.Fatalf("starting the %s instance: %v", name, err)
	}
	t.Cleanup(server.Remove)
	return server
}

// provision creates the operator and signs in through the API.
func provision(t *testing.T, server *harness.Server) string {
	t.Helper()
	session, err := harness.NewAPI(server).Provision()
	if err != nil {
		t.Fatalf("provisioning %d: %v", server.HTTPPort, err)
	}
	return session
}

// seeded creates the schema and the operator, then stops the instance, loads
// the fixture, and boots it again with data the page can show. It returns the
// session of a login made after the reboot.
func seeded(t *testing.T, server *harness.Server, fixture string) string {
	t.Helper()
	api := harness.NewAPI(server)
	if err := api.Setup(harness.AdminUsername, harness.AdminPassword); err != nil {
		t.Fatal(err)
	}
	server.Stop()
	if err := server.Seed(fixture); err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	session, err := api.Login(harness.AdminUsername, harness.AdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

// specCase is one named case; it runs in a browser of its own.
type specCase struct {
	name string
	run  func(page) error
}

// runCases runs the cases in order. A failing case does not stop the rest,
// which is what t.Run gives.
func runCases(t *testing.T, server *harness.Server, shaped profile, cases []specCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			browser, err := harness.OpenWith(shaped.scripting)
			if err != nil {
				t.Fatal(err)
			}
			defer browser.Close()
			if err := shaped.emulate(browser); err != nil {
				t.Fatalf("emulating the profile: %v", err)
			}
			if err := c.run(page{Browser: browser, server: server}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// sequence runs the steps in order and stops at the first failure, so a case
// reads as a list of what it checks.
func sequence(steps ...func() error) error {
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}
