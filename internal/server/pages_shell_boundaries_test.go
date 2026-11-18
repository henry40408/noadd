package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/henry40408/noadd/internal/auth"
)

func TestEachFlashShowsItsOwnNoticeOnceAndNoOtherOne(t *testing.T) {
	cases := []struct {
		flash, page string
		markers     []string
	}{
		{"filters_saved", "/filters", []string{`data-testid="filters-saved"`, `data-testid="lists-updated"`}},
		{"lists_updating", "/filters", []string{`data-testid="lists-updated"`, `data-testid="filters-saved"`}},
		{"password_changed", "/account", []string{`data-testid="password-changed"`, `data-testid="account-saved"`, `data-testid="sessions-revoked"`}},
		{"account_saved", "/account", []string{`data-testid="account-saved"`, `data-testid="password-changed"`, `data-testid="sessions-revoked"`}},
		{"sessions_revoked", "/account", []string{`data-testid="sessions-revoked"`, `data-testid="password-changed"`, `data-testid="account-saved"`}},
		{"logs_cleared", "/logs", []string{`data-testid="logs-cleared"`}},
		{"welcome", "/stats", []string{`data-testid="setup-welcome"`, `data-testid="proxy-logout-notice"`}},
		{"proxy_logout", "/stats", []string{`data-testid="proxy-logout-notice"`, `data-testid="setup-welcome"`}},
	}
	for _, c := range cases {
		t.Run(c.flash, func(t *testing.T) {
			h := newAPIHarness(t, harnessOptions{})
			withFlash := h.page(pageRequest{path: c.page, cookies: []string{"session=" + h.token, "noadd_flash=" + c.flash}})
			wantStatus(t, withFlash, http.StatusOK)
			wantContains(t, withFlash.Body.String(), c.markers[0])
			for _, other := range c.markers[1:] {
				wantAbsent(t, withFlash.Body.String(), other)
			}
			wantContains(t, strings.Join(withFlash.Header().Values("Set-Cookie"), ";"), "noadd_flash=;")
			wantAbsent(t, h.pageBody(c.page), c.markers[0])
		})
	}
}

func TestSettingsSavedFlashChangesTheSettingsPage(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	plain := h.pageBody("/settings")
	flashed := h.page(pageRequest{path: "/settings", cookies: []string{"session=" + h.token, "noadd_flash=settings_saved"}})
	if flashed.Body.String() == plain {
		t.Error("the settings_saved flash left no trace on the page")
	}
	for _, unrelated := range []string{"password_changed", "account_saved", "filters_saved"} {
		page := h.page(pageRequest{path: "/settings", cookies: []string{"session=" + h.token, "noadd_flash=" + unrelated}})
		if page.Body.String() != plain {
			t.Errorf("flash %s changed the settings page", unrelated)
		}
	}
}

const nextStepBanner = `data-testid="next-step-banner"`

func TestNextStepBannerShowsOnAFreshInstallExceptOnTheDashboard(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantContains(t, h.pageBody("/settings"), nextStepBanner)
	wantAbsent(t, h.pageBody("/"), nextStepBanner)
}

func TestNextStepBannerStaysAwayOnceTrafficWasSeen(t *testing.T) {
	latched := newAPIHarness(t, harnessOptions{})
	latched.deps.Events.NoteTraffic()
	wantAbsent(t, latched.pageBody("/settings"), nextStepBanner)

	logged := newAPIHarness(t, harnessOptions{})
	logged.seedQueries("a.example", "10.0.0.5", 1, false)
	wantAbsent(t, logged.pageBody("/settings"), nextStepBanner)
	if !logged.deps.Events.HasTraffic() {
		t.Error("a database hit should latch the hub so later pages skip the read")
	}
}

func TestNextStepBannerHonoursOnlyAnExactDismissal(t *testing.T) {
	cases := map[string]bool{"true": false, "false": true, "": true}
	for stored, wantShown := range cases {
		h := newAPIHarness(t, harnessOptions{})
		if err := h.db.SetSetting(ctxBackground(), onboardingDismissedKey, stored); err != nil {
			t.Fatal(err)
		}
		shown := strings.Contains(h.pageBody("/settings"), nextStepBanner)
		if shown != wantShown {
			t.Errorf("dismissed=%q: shown = %v, want %v", stored, shown, wantShown)
		}
	}
}

func TestFormPostsAreBoundedAndMustDecode(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	atLimit := "next=" + strings.Repeat("a", maxFormBody-len("next="))
	wantStatus(t, h.signedIn(http.MethodPost, "/onboarding/dismiss", atLimit), http.StatusSeeOther)
	wantStatus(t, h.signedIn(http.MethodPost, "/onboarding/dismiss", atLimit+"a"), http.StatusRequestEntityTooLarge)
	wantStatus(t, h.signedIn(http.MethodPost, "/onboarding/dismiss", "next=%zz"), http.StatusBadRequest)
}

func TestLogoutHandsAProxyManagedSessionToItsLogoutURL(t *testing.T) {
	forward, err := auth.NewForwardAuth("X-Remote-User", "127.0.0.0/8", "https://sso.example/out")
	if err != nil {
		t.Fatal(err)
	}
	h := newAPIHarness(t, harnessOptions{forwardAuth: forward})
	response := pagesFormAs(h, "/logout", "", map[string]string{"X-Remote-User": "admin"})
	wantRedirect(t, response, "https://sso.example/out")
	if response.Header().Get("Clear-Site-Data") == "" {
		t.Error("no Clear-Site-Data on the hand-off")
	}
}

func TestLogoutOfAProxyManagedSessionWithoutALogoutURLExplainsWhy(t *testing.T) {
	h := pagesForwardAuthHarness(t)
	response := pagesFormAs(h, "/logout", "", map[string]string{"X-Remote-User": "admin"})
	wantRedirect(t, response, "/")
	if got := response.Header().Get("Clear-Site-Data"); got != "" {
		t.Errorf("Clear-Site-Data = %q would wipe the explaining flash", got)
	}
	wantContains(t, strings.Join(response.Header().Values("Set-Cookie"), ";"), "noadd_flash=proxy_logout")
}

func TestLogoutOfAPasswordSessionClearsSiteDataAndReturnsToLogin(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	response := h.signedIn(http.MethodPost, "/logout", "")
	wantRedirect(t, response, "/login")
	if response.Header().Get("Clear-Site-Data") == "" {
		t.Error("no Clear-Site-Data on logout")
	}
}
