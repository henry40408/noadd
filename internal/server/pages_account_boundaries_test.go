package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/db"
)

func TestAnExpiryYearAtTheEdgesOfTheFourDigitRangeIsAccepted(t *testing.T) {
	wantExpiry(t, "0000-01-01", -62_167_219_200+86_399)
	wantExpiry(t, "9999-12-31", 253_402_214_400+86_399)
}

// pagesBearerKey stores an API key for the harness operator and returns the
// header value that authenticates with it.
func pagesBearerKey(t *testing.T, h *apiHarness) string {
	t.Helper()
	full, prefix, hash := auth.NewAPIKey()
	if _, err := h.db.InsertAPIKey(ctxBackground(), db.NewAPIKey{
		UserID: h.userID, Name: "ci", TokenHash: hash, Prefix: prefix, CreatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	return "Bearer " + full
}

// pagesFormAs posts a form with arbitrary request headers.
func pagesFormAs(h *apiHarness, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	return recorder
}

func pagesForwardAuthHarness(t *testing.T) *apiHarness {
	t.Helper()
	forward, err := auth.NewForwardAuth("X-Remote-User", "127.0.0.0/8", "")
	if err != nil {
		t.Fatal(err)
	}
	return newAPIHarness(t, harnessOptions{forwardAuth: forward})
}

func TestAccountPageOffersDeletionOnlyForOtherOperatorsWhileSeveralExist(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	only := h.pageBody("/account")
	wantAbsent(t, only, "del-op")

	other := h.seedOperator("second", "second")
	body := h.pageBody("/account")
	wantContains(t, body, `href="/account?confirm_delete=`+itoa(other)+`"`)
	wantAbsent(t, body, `href="/account?confirm_delete=`+itoa(h.userID)+`"`)
	wantContains(t, body, `admin <span class="badge badge-allowed">you</span>`)
	wantAbsent(t, body, `second <span class="badge badge-allowed">you</span>`)
}

func TestAccountPageExpandsTheDeleteFormOfTheOperatorNamed(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	second := h.seedOperator("second", "second")
	third := h.seedOperator("third", "third")

	body := h.pageBody("/account?confirm_delete=" + itoa(third))
	wantContains(t, body, `action="/account/operators/`+itoa(third)+`/delete"`)
	wantContains(t, body, "<code")
	wantContains(t, body, ">third</code> and revoke all their sessions")
	wantAbsent(t, body, `action="/account/operators/`+itoa(second)+`/delete"`)

	for _, query := range []string{"", "?confirm_delete=999999", "?confirm_delete=0"} {
		wantAbsent(t, h.pageBody("/account"+query), `data-testid="operator-confirm-row"`)
	}
}

func TestAccountPageMarksOnlyTheCurrentBrowserSessionAsThisDevice(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.bindSession(h.seedOperator("second", "second"))

	body := h.pageBody("/account")
	if got := strings.Count(body, `data-current="true"`); got != 1 {
		t.Errorf("current sessions = %d, want 1", got)
	}
	if got := strings.Count(body, `data-current="false"`); got != 1 {
		t.Errorf("other sessions = %d, want 1", got)
	}
	if got := strings.Count(body, `<span class="badge badge-allowed">this device</span>`); got != 1 {
		t.Errorf("this-device badges = %d, want 1", got)
	}
}

func TestAccountPageMarksNoSessionAsCurrentForAnAPIKeyCaller(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.Header.Set("Authorization", pagesBearerKey(t, h))
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	wantStatus(t, recorder, http.StatusOK)
	wantAbsent(t, recorder.Body.String(), `data-current="true"`)
	wantContains(t, recorder.Body.String(), `data-current="false"`)
}

func TestAccountPageShowsTheAddressAndBrowserASessionWasOpenedFrom(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	signIn := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=admin&password=admin"))
	signIn.RemoteAddr = "127.0.0.1:50000"
	signIn.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	signIn.Header.Set("User-Agent", "PagesTestBrowser/1.0")
	signIn.Header.Set("X-Forwarded-For", "203.0.113.9")
	reply := httptest.NewRecorder()
	h.handler.ServeHTTP(reply, signIn)
	wantStatus(t, reply, http.StatusSeeOther)

	body := h.pageBody("/account")
	wantContains(t, body, "PagesTestBrowser/1.0")
	wantContains(t, body, "203.0.113.9")
	// The harness session carries neither, so it falls back to the dash.
	wantContains(t, body, `<td class="mono">—</td><td>—</td>`)
}

func TestAccountPasswordChangeNeedsABrowserSession(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	const newPassword = "a-long-unrelated-passphrase-1"
	recorder := pagesFormAs(h, "/account/password",
		formBody("current_password", "admin", "new_password", newPassword, "confirm_password", newPassword),
		map[string]string{"Authorization": pagesBearerKey(t, h)})
	wantStatus(t, recorder, http.StatusUnauthorized)
	wantContains(t, recorder.Body.String(), "Changing a password needs a browser session")
}

func TestAccountPasswordChangeRefusesAWeakPasswordAndIsRateLimited(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	weak := h.signedIn(http.MethodPost, "/account/password",
		formBody("current_password", "admin", "new_password", "short", "confirm_password", "short"))
	wantStatus(t, weak, http.StatusBadRequest)
	wantAbsent(t, weak.Body.String(), "Current password is incorrect")

	var last *httptest.ResponseRecorder
	for range 6 {
		last = h.signedIn(http.MethodPost, "/account/password",
			formBody("current_password", "nope", "new_password", "a-long-unrelated-passphrase-1", "confirm_password", "a-long-unrelated-passphrase-1"))
	}
	wantStatus(t, last, http.StatusTooManyRequests)
	wantContains(t, last.Body.String(), rateLimitedText)
}

func TestAccountFormsThatConfirmAPasswordNeedASessionOrTheProxy(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	const password = "a-long-unrelated-passphrase-1"
	recorder := pagesFormAs(h, "/account/operators",
		formBody("username", "carol", "password", password, "confirm", password, "your_password", "admin"),
		map[string]string{"Authorization": pagesBearerKey(t, h)})
	wantStatus(t, recorder, http.StatusUnauthorized)
	wantContains(t, recorder.Body.String(), needsSessionAction)

	proxied := pagesForwardAuthHarness(t)
	added := pagesFormAs(proxied, "/account/operators",
		formBody("username", "carol", "password", password, "confirm", password, "your_password", ""),
		map[string]string{"X-Remote-User": "proxied"})
	wantRedirect(t, added, "/account")
	if _, found, _ := proxied.db.GetUserAuth(ctxBackground(), "carol"); !found {
		t.Fatal("the proxied operator could not add an operator")
	}
}

func TestAccountFormsThatConfirmAPasswordAreRateLimited(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	const password = "a-long-unrelated-passphrase-1"
	var last *httptest.ResponseRecorder
	for range 6 {
		last = h.signedIn(http.MethodPost, "/account/operators",
			formBody("username", "carol", "password", password, "confirm", password, "your_password", "wrong"))
	}
	wantStatus(t, last, http.StatusTooManyRequests)
	wantContains(t, last.Body.String(), rateLimitedText)
}

func TestAccountAddOperatorRefusesAMismatchAndAWeakPassword(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	mismatch := h.signedIn(http.MethodPost, "/account/operators",
		formBody("username", "carol", "password", "one-long-passphrase-123", "confirm", "other", "your_password", "admin"))
	wantStatus(t, mismatch, http.StatusBadRequest)
	wantContains(t, mismatch.Body.String(), passwordMismatch)

	weak := h.signedIn(http.MethodPost, "/account/operators",
		formBody("username", "carol", "password", "short", "confirm", "short", "your_password", "admin"))
	wantStatus(t, weak, http.StatusBadRequest)
	wantContains(t, weak.Body.String(), "carol")
	if users, _ := h.db.ListUsers(ctxBackground()); len(users) != 1 {
		t.Fatalf("users = %d", len(users))
	}
}

func TestAccountDeleteOperatorChecksYourPasswordFirst(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	other := h.seedOperator("second", "second")
	h.seedOperator("third", "third")
	wrong := h.signedIn(http.MethodPost, "/account/operators/"+itoa(other)+"/delete", formBody("your_password", "wrong"))
	wantStatus(t, wrong, http.StatusUnauthorized)
	wantContains(t, wrong.Body.String(), "Your password is incorrect")
	wantContains(t, wrong.Body.String(), `data-testid="operator-delete-error"`)
	if users, _ := h.db.ListUsers(ctxBackground()); len(users) != 3 {
		t.Fatalf("users = %d", len(users))
	}
}

func TestAccountAPIKeyCreationRefusesAnOverlongNameAndAcceptsALimitLengthOne(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	long := h.signedIn(http.MethodPost, "/account/api-keys",
		formBody("name", strings.Repeat("n", apiKeyNameMaxChars+1), "expires", "", "your_password", "admin"))
	wantStatus(t, long, http.StatusBadRequest)
	wantContains(t, long.Body.String(), "Name is required, and at most 64 characters")

	exact := h.signedIn(http.MethodPost, "/account/api-keys",
		formBody("name", strings.Repeat("n", apiKeyNameMaxChars), "expires", "2999-01-01", "your_password", "admin"))
	wantStatus(t, exact, http.StatusOK)
}

func TestAccountAPIKeyListShowsWhenEachKeyExpires(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.signedIn(http.MethodPost, "/account/api-keys",
		formBody("name", "soon", "expires", "2999-01-01", "your_password", "admin")), http.StatusOK)
	wantStatus(t, h.signedIn(http.MethodPost, "/account/api-keys",
		formBody("name", "forever", "expires", "", "your_password", "admin")), http.StatusOK)
	body := h.pageBody("/account")
	wantContains(t, body, "never")
	wantContains(t, body, "days")
}
