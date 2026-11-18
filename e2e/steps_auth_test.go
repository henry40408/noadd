package e2e

import (
	"errors"
	"fmt"

	"github.com/cucumber/godog"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

func registerAuthSteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^I am signed in to the admin UI$`, w.signedIn)
	sc.Step(`^the admin UI has never been configured$`, w.neverConfigured)
	sc.Step(`^I open the admin UI$`, func() error { return w.goTo("/") })
	sc.Step(`^I am shown the first-run setup screen$`, func() error { return w.browser.ExpectVisible("setup-username") })
	sc.Step(`^I enter `+quoted+` as the username$`, func(value string) error { return w.browser.Fill("setup-username", value) })
	sc.Step(`^I enter `+quoted+` as the new password$`, func(value string) error { return w.browser.Fill("setup-password", value) })
	sc.Step(`^I enter `+quoted+` as the confirmation$`, func(value string) error { return w.browser.Fill("setup-password-confirm", value) })
	sc.Step(`^I enter the setup token printed to the server stderr$`, w.enterSetupToken)
	sc.Step(`^I submit the setup form$`, func() error { return w.browser.Click("setup-submit") })
	sc.Step(`^I see a setup error about the passwords not matching$`, func() error {
		return w.browser.ExpectText("setup-error", "do not match")
	})
	sc.Step(`^I see a setup error about the password being too short$`, func() error {
		// Deliberately not the figure: only that the setup form rejects a
		// short password with a reason.
		return w.browser.ExpectText("setup-error", "at least")
	})
	sc.Step(`^the admin password has still not been set$`, w.stillNotSet)
	sc.Step(`^I land on the dashboard$`, func() error {
		if err := w.browser.ExpectVisible("app-shell"); err != nil {
			return err
		}
		return w.browser.ExpectVisible("nav-dashboard")
	})
	sc.Step(`^the admin password has been set to `+quoted+`$`, func(password string) error {
		return w.api().Setup(harness.AdminUsername, password)
	})
	sc.Step(`^I sign in with the password `+quoted+`$`, w.signInWith)
	sc.Step(`^I remain on the sign-in screen$`, func() error { return w.browser.ExpectVisible("login-submit") })
	sc.Step(`^I see a sign-in error telling me the password is incorrect$`, func() error {
		return w.browser.ExpectText("login-error", "incorrect password")
	})
	sc.Step(`^I log out all other sessions$`, func() error {
		return w.browser.ConfirmAndSubmit("logout-other-sessions")
	})
	sc.Step(`^I stay signed in on the account page$`, w.staySignedIn)
	sc.Step(`^reloading the admin UI keeps me signed in$`, w.reloadKeepsSignedIn)
	sc.Step(`^I see a welcome message confirming the setup is complete$`, func() error {
		return w.browser.ExpectVisible("setup-welcome")
	})
}

// signedIn drives the boot screen to a signed-in shell, whichever state the
// instance is in: unconfigured (setup), signed out (login), or authenticated
// (a session the runner replayed).
func (w *world) signedIn() error {
	if err := w.goTo("/"); err != nil {
		return err
	}
	err := harness.Eventually("one of the shell, setup or sign-in screens", func() (bool, error) {
		for _, id := range []string{"app-shell", "setup-password", "login-password"} {
			shown, err := w.browser.IsVisible(id)
			if err != nil || shown {
				return shown, err
			}
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	switch {
	case w.visible("setup-password"):
		if err := w.completeSetup(); err != nil {
			return err
		}
	case w.visible("login-password"):
		if err := w.signInWith(harness.AdminPassword); err != nil {
			return err
		}
	}
	return w.browser.ExpectVisible("app-shell")
}

func (w *world) visible(id string) bool {
	shown, _ := w.browser.IsVisible(id)
	return shown
}

func (w *world) completeSetup() error {
	fields := [][2]string{
		{"setup-username", harness.AdminUsername},
		{"setup-password", harness.AdminPassword},
		{"setup-password-confirm", harness.AdminPassword},
		{"setup-token", w.instance.server.SetupToken()},
	}
	for _, field := range fields {
		if err := w.browser.Fill(field[0], field[1]); err != nil {
			return err
		}
	}
	return w.browser.Click("setup-submit")
}

func (w *world) neverConfigured() error {
	needs, err := w.api().NeedsSetup()
	if err != nil {
		return err
	}
	if !needs {
		return errors.New("expected a fresh, unconfigured instance")
	}
	return nil
}

func (w *world) stillNotSet() error {
	needs, err := w.api().NeedsSetup()
	if err != nil {
		return err
	}
	if !needs {
		return errors.New("the instance reports it has been configured")
	}
	return nil
}

func (w *world) enterSetupToken() error {
	token := w.instance.server.SetupToken()
	if token == "" {
		return errors.New("the server printed no setup token")
	}
	return w.browser.Fill("setup-token", token)
}

func (w *world) signInWith(password string) error {
	if err := w.browser.Fill("login-username", harness.AdminUsername); err != nil {
		return err
	}
	if err := w.browser.Fill("login-password", password); err != nil {
		return err
	}
	return w.browser.Click("login-submit")
}

func (w *world) staySignedIn() error {
	// The current session is kept, so no bounce to the sign-in screen.
	if err := w.browser.ExpectVisible("logout-other-sessions"); err != nil {
		return err
	}
	return w.expectNoSignIn()
}

func (w *world) reloadKeepsSignedIn() error {
	if err := w.browser.Reload(); err != nil {
		return err
	}
	if err := w.browser.ExpectVisible("app-shell"); err != nil {
		return err
	}
	return w.expectNoSignIn()
}

func (w *world) expectNoSignIn() error {
	if shown, err := w.browser.IsVisible("login-submit"); err != nil || shown {
		return fmt.Errorf("the sign-in screen is showing (err: %v)", err)
	}
	return nil
}
