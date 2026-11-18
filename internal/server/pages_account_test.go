package server

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func formBody(pairs ...string) string {
	values := url.Values{}
	for i := 0; i < len(pairs); i += 2 {
		values.Set(pairs[i], pairs[i+1])
	}
	return values.Encode()
}

func wantExpiry(t *testing.T, raw string, want int64) {
	t.Helper()
	got, valid := parseExpiryDate(raw)
	if !valid || got == nil || *got != want {
		t.Errorf("parseExpiryDate(%q) = %v, %v; want %d", raw, got, valid, want)
	}
}

func wantExpiryRejected(t *testing.T, bad ...string) {
	t.Helper()
	for _, raw := range bad {
		if _, valid := parseExpiryDate(raw); valid {
			t.Errorf("%q was accepted", raw)
		}
	}
}

func TestAnExpiryDateLastsUntilThatDayIsOver(t *testing.T) {
	// Blank means a key that never expires, not one expiring at the epoch.
	for _, blank := range []string{"", "   "} {
		if got, valid := parseExpiryDate(blank); !valid || got != nil {
			t.Errorf("%q = %v, %v", blank, got, valid)
		}
	}
	wantExpiry(t, "1970-01-01", 86_399)
	wantExpiry(t, "1970-01-02", 86_400+86_399)
	// Before the epoch counts backwards.
	wantExpiry(t, "1969-12-31", -1)
	// 2000 is a leap year (the 400 rule), 2100 is not (the 100 rule).
	wantExpiry(t, "2000-03-01", 11_017*86_400+86_399)
	wantExpiry(t, "2100-03-01", 47_541*86_400+86_399)
	wantExpiry(t, " 2024-02-29 ", 1709251199)
	wantExpiryRejected(t, "not-a-date", "2027-13-01", "2027-01-32", "2027-01", "2027-01-01-01", "2024--01")
}

func TestAnExpiryDateMustExistOnTheCalendar(t *testing.T) {
	// Days that overflow their month used to roll into the next one.
	wantExpiryRejected(t, "2027-02-29", "2027-02-30", "2027-02-31", "2027-04-31", "2100-02-29", "2027-00-10", "2027-01-00")
	// Leap days are real in leap years (the 4 and 400 rules).
	wantExpiry(t, "2028-02-29", 21_243*86_400+86_399)
	wantExpiry(t, "2000-02-29", 11_016*86_400+86_399)
}

func TestAnExpiryYearOutOfRangeIsRejectedNotWrapped(t *testing.T) {
	wantExpiryRejected(t, "9223372036854775807-12-31", "10000-01-01", "2147483648-01-01", "2147483647-01-01")
}

func TestSettingsPageRendersDefaultsAndStoredValues(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	body := h.pageBody("/settings")
	wantContains(t, body, "Server configuration")
	if err := h.db.SetSetting(ctxBackground(), "public_url", "https://dns.example"); err != nil {
		t.Fatal(err)
	}
	wantContains(t, h.pageBody("/settings"), "https://dns.example")
}

func settingsForm(overrides map[string]string) string {
	fields := map[string]string{
		"upstream_servers": "1.1.1.1:53", "upstream_strategy": "sequential", "dnssec": "on",
		"block_mode": "null_ip", "block_custom_ipv4": "", "block_custom_ipv6": "",
		"log_retention_days": "7", "public_url": "", "doh_access_policy": "allow",
	}
	for key, value := range overrides {
		fields[key] = value
	}
	var pairs []string
	for key, value := range fields {
		pairs = append(pairs, key, value)
	}
	return formBody(pairs...)
}

func TestSettingsFormSavesAndRedirectsWithAFlash(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.signedIn(http.MethodPost, "/settings", settingsForm(map[string]string{"dnssec": "off", "log_retention_days": "30"}))
	wantRedirect(t, recorder, "/settings")
	if value, _, _ := h.db.GetSetting(ctxBackground(), "dnssec_disabled"); value != "true" {
		t.Fatalf("dnssec_disabled = %q", value)
	}
	if value, _, _ := h.db.GetSetting(ctxBackground(), "log_retention_days"); value != "30" {
		t.Fatalf("log_retention_days = %q", value)
	}
	page := h.page(pageRequest{path: "/settings", cookies: append(cookiePairs(recorder), "session="+h.token)})
	wantContains(t, page.Body.String(), `data-testid="settings-saved"`)
}

func TestSettingsFormRejectionKeepsWhatWasSubmittedAndSavesNothing(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.signedIn(http.MethodPost, "/settings",
		settingsForm(map[string]string{"block_custom_ipv4": "not-an-ip", "public_url": "https://kept.example"}))
	wantStatus(t, recorder, http.StatusBadRequest)
	body := recorder.Body.String()
	wantContains(t, body, "Not a valid IPv4 address")
	wantContains(t, body, "https://kept.example")
	if _, found, _ := h.db.GetSetting(ctxBackground(), "public_url"); found {
		t.Fatal("a rejected save wrote a setting")
	}
}

func TestSettingsFormNeedsEveryField(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.signedIn(http.MethodPost, "/settings", formBody("upstream_servers", "1.1.1.1:53"))
	wantStatus(t, recorder, http.StatusUnprocessableEntity)
}

func TestAPISettingsStillAnswersABareStatus(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.authed(http.MethodPut, "/api/settings", `{"block_mode":"bogus"}`)
	wantStatus(t, recorder, http.StatusBadRequest)
	if recorder.Body.Len() != 0 {
		t.Fatalf("body = %q", recorder.Body.String())
	}
}

func TestAccountPageListsTheOperatorSessionsAndKeys(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	body := h.pageBody("/account")
	wantContains(t, body, "Signed in as")
	wantContains(t, body, "admin")
}

func TestAccountPageExpandsOnlyAnOperatorThatExists(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	other := h.seedOperator("second", "second")
	wantContains(t, h.pageBody("/account?confirm_delete="+itoa(other)), "second")
	// A junk or unknown id is a plain page, never a 400.
	h.pageBody("/account?confirm_delete=abc")
	h.pageBody("/account?confirm_delete=999999")
}

func TestAccountPasswordMismatchAnswers400(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.signedIn(http.MethodPost, "/account/password",
		formBody("current_password", "admin", "new_password", "a-long-unrelated-passphrase-1", "confirm_password", "different"))
	wantStatus(t, recorder, http.StatusBadRequest)
	wantContains(t, recorder.Body.String(), "Passwords do not match")
}

func TestAccountPasswordChangeRotatesTheSessionAndRedirects(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	const newPassword = "a-long-unrelated-passphrase-1"
	recorder := h.signedIn(http.MethodPost, "/account/password",
		formBody("current_password", "admin", "new_password", newPassword, "confirm_password", newPassword))
	wantRedirect(t, recorder, "/account")
	if token, ok := sessionTokenFromSetCookie(recorder); !ok || token == h.token {
		t.Fatal("the session cookie was not rotated")
	}
}

func TestAccountPasswordWrongCurrentAnswers401(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	const newPassword = "a-long-unrelated-passphrase-1"
	recorder := h.signedIn(http.MethodPost, "/account/password",
		formBody("current_password", "nope", "new_password", newPassword, "confirm_password", newPassword))
	wantStatus(t, recorder, http.StatusUnauthorized)
	wantContains(t, recorder.Body.String(), "Current password is incorrect")
}

func TestAccountAddOperatorNeedsThePasswordAndKeepsTheUsernameOnRejection(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	const password = "a-long-unrelated-passphrase-1"
	recorder := h.signedIn(http.MethodPost, "/account/operators",
		formBody("username", "carol", "password", password, "confirm", password, "your_password", "wrong"))
	wantStatus(t, recorder, http.StatusUnauthorized)
	wantContains(t, recorder.Body.String(), "Your password is incorrect")
	wantContains(t, recorder.Body.String(), "carol")
	wantAbsent(t, recorder.Body.String(), password)

	recorder = h.signedIn(http.MethodPost, "/account/operators",
		formBody("username", "carol", "password", password, "confirm", password, "your_password", "admin"))
	wantRedirect(t, recorder, "/account")
	if users, _ := h.db.ListUsers(ctxBackground()); len(users) != 2 {
		t.Fatalf("users = %d", len(users))
	}
}

func TestAccountAddOperatorRefusesATakenUsernameWith409(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	const password = "a-long-unrelated-passphrase-1"
	recorder := h.signedIn(http.MethodPost, "/account/operators",
		formBody("username", "admin", "password", password, "confirm", password, "your_password", "admin"))
	wantStatus(t, recorder, http.StatusConflict)
	wantContains(t, recorder.Body.String(), "That username is already taken")
}

func TestAccountDeleteOperatorRefusesYourselfAsTheLastOne(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.signedIn(http.MethodPost, "/account/operators/"+itoa(h.userID)+"/delete", formBody("your_password", "admin"))
	wantStatus(t, recorder, http.StatusConflict)
	wantContains(t, recorder.Body.String(), "last operator")
}

func TestAccountDeleteOperatorRemovesAnotherOne(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	other := h.seedOperator("second", "second")
	// A third operator keeps the last-operator guard out of the second delete.
	h.seedOperator("third", "third")
	recorder := h.signedIn(http.MethodPost, "/account/operators/"+itoa(other)+"/delete", formBody("your_password", "admin"))
	wantRedirect(t, recorder, "/account")
	missing := h.signedIn(http.MethodPost, "/account/operators/"+itoa(other)+"/delete", formBody("your_password", "admin"))
	wantStatus(t, missing, http.StatusNotFound)
}

func TestAccountRevokingYourOwnSessionSignsYouOut(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	sessions, _ := h.db.ListSessions(ctxBackground())
	recorder := h.signedIn(http.MethodPost, "/account/sessions/"+itoa(sessions[0].ID)+"/revoke", "")
	wantRedirect(t, recorder, "/login")
	if recorder.Header().Get("Clear-Site-Data") == "" {
		t.Fatal("Clear-Site-Data missing")
	}
	wantRedirect(t, h.signedIn(http.MethodGet, "/account", ""), "/login?next=/account")
}

func TestAccountRevokingAnAbsentSessionStillReportsRevoked(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantRedirect(t, h.signedIn(http.MethodPost, "/account/sessions/999999/revoke", ""), "/account")
}

func TestAccountRevokeOthersKeepsTheCurrentSession(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.bindSession(h.seedOperator("second", "second"))
	wantRedirect(t, h.signedIn(http.MethodPost, "/account/sessions/revoke-others", ""), "/account")
	if sessions, _ := h.db.ListSessions(ctxBackground()); len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	wantStatus(t, h.signedIn(http.MethodGet, "/account", ""), http.StatusOK)
}

func TestAccountAPIKeyIsShownOnceAndNotRedirected(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.signedIn(http.MethodPost, "/account/api-keys",
		formBody("name", "ci", "expires", "", "your_password", "admin"))
	wantStatus(t, recorder, http.StatusOK)
	wantContains(t, recorder.Body.String(), apiKeyPrefix)
	keys, _ := h.db.ListAPIKeysForUser(ctxBackground(), h.userID)
	if len(keys) != 1 {
		t.Fatalf("keys = %d", len(keys))
	}
	// The reload lists the key without the secret.
	wantRedirect(t, h.signedIn(http.MethodPost, "/account/api-keys/"+itoa(keys[0].ID)+"/delete", ""), "/account")
	if keys, _ := h.db.ListAPIKeysForUser(ctxBackground(), h.userID); len(keys) != 0 {
		t.Fatal("key not deleted")
	}
}

func TestAccountAPIKeyRejectionsKeepTheInput(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	bad := h.signedIn(http.MethodPost, "/account/api-keys", formBody("name", "ci", "expires", "soon", "your_password", "admin"))
	wantStatus(t, bad, http.StatusBadRequest)
	wantContains(t, bad.Body.String(), "Expiry must be a date")
	wrong := h.signedIn(http.MethodPost, "/account/api-keys", formBody("name", "ci", "expires", "", "your_password", "x"))
	wantStatus(t, wrong, http.StatusUnauthorized)
	blank := h.signedIn(http.MethodPost, "/account/api-keys", formBody("name", "  ", "expires", "", "your_password", "admin"))
	wantStatus(t, blank, http.StatusBadRequest)
}

func TestAccountAndSettingsPostsRefuseAnAnonymousBrowser(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, path := range []string{
		"/settings", "/account/password", "/account/operators", "/account/operators/1/delete",
		"/account/sessions/1/revoke", "/account/sessions/revoke-others", "/account/api-keys", "/account/api-keys/1/delete",
	} {
		wantRedirect(t, h.page(pageRequest{method: http.MethodPost, path: path, body: "x=y"}), "/login?next="+encodeQueryValue(path))
	}
}
