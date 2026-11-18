package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/henry40408/noadd/internal/db"
)

// pageRequest is one browser request: a form body when body is set.
type pageRequest struct {
	method string
	path   string
	body   string
	// cookies are sent as given, name=value pairs.
	cookies []string
	host    string
}

func (h *apiHarness) page(r pageRequest) *httptest.ResponseRecorder {
	h.t.Helper()
	method := r.method
	if method == "" {
		method = http.MethodGet
	}
	req := httptest.NewRequest(method, r.path, strings.NewReader(r.body))
	req.RemoteAddr = "127.0.0.1:50000"
	if r.body != "" || method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if len(r.cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(r.cookies, "; "))
	}
	if r.host != "" {
		req.Host = r.host
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	return recorder
}

// signedIn is a request carrying the harness session.
func (h *apiHarness) signedIn(method, path, body string) *httptest.ResponseRecorder {
	return h.page(pageRequest{method: method, path: path, body: body, cookies: []string{"session=" + h.token}})
}

// pageBody GETs a path as the signed-in operator and requires 200.
func (h *apiHarness) pageBody(path string) string {
	h.t.Helper()
	recorder := h.signedIn(http.MethodGet, path, "")
	wantStatus(h.t, recorder, http.StatusOK)
	return recorder.Body.String()
}

func wantRedirect(t *testing.T, recorder *httptest.ResponseRecorder, location string) {
	t.Helper()
	wantStatus(t, recorder, http.StatusSeeOther)
	if got := recorder.Header().Get("Location"); got != location {
		t.Fatalf("Location = %q, want %q", got, location)
	}
}

func wantContains(t *testing.T, body, fragment string) {
	t.Helper()
	if !strings.Contains(body, fragment) {
		t.Fatalf("body lacks %q", fragment)
	}
}

func wantAbsent(t *testing.T, body, fragment string) {
	t.Helper()
	if strings.Contains(body, fragment) {
		t.Fatalf("body has unexpected %q", fragment)
	}
}

// cookiePairs turns a response's Set-Cookie headers into request cookies.
func cookiePairs(recorder *httptest.ResponseRecorder) []string {
	var pairs []string
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.MaxAge < 0 {
			continue
		}
		pairs = append(pairs, cookie.Name+"="+cookie.Value)
	}
	return pairs
}

const bannerTestID = `data-testid="next-step-banner"`

func TestPageRequestWithoutASessionRedirectsToSignIn(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantRedirect(t, h.page(pageRequest{path: "/stats"}), "/login?next=/stats")
	// The query survives, encoded as one value.
	wantRedirect(t, h.page(pageRequest{path: "/logs?page=2&q=a"}), "/login?next=/logs%3Fpage%3D2%26q%3Da")
}

func TestPageRequestBeforeSetupRedirectsToTheWizard(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{noOperator: true})
	wantRedirect(t, h.page(pageRequest{path: "/"}), "/setup")
}

func TestEveryPageMethodRefusesAnAnonymousBrowser(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	posts := []string{"/logs/rules", "/logs/clear", "/onboarding/dismiss", "/logout"}
	for _, path := range posts {
		recorder := h.page(pageRequest{method: http.MethodPost, path: path, body: "rule=x&next=/"})
		wantRedirect(t, recorder, "/login?next="+encodeQueryValue(path))
	}
}

func TestEveryPagePathIsServedToAnAuthenticatedBrowser(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, path := range []string{"/", "/stats", "/logs"} {
		body := h.pageBody(path)
		if !strings.Contains(body, `id="app"`) || !strings.Contains(body, "/app.js") {
			t.Errorf("%s did not render the shell", path)
		}
	}
}

func TestAServerRenderedPageIsNeverStored(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.signedIn(http.MethodGet, "/", "")
	if cc := recorder.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q", cc)
	}
	if ct := recorder.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
}

func TestShellMarksTheNavigationItemForThePathItServes(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	body := h.pageBody("/logs")
	wantContains(t, body, `class="nav-item active" href="/logs"`)
	wantAbsent(t, body, `class="nav-item active" href="/stats"`)
	wantContains(t, body, `action="/logout"`)
	wantContains(t, body, "statusbar")
	wantContains(t, body, "<server-status")
}

func TestOnboardingNoticeIsRenderedOnAFreshAppliance(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	body := h.pageBody("/logs")
	wantContains(t, body, bannerTestID)
	wantContains(t, body, `action="/onboarding/dismiss"`)
	wantContains(t, body, `name="next" value="/logs"`)
}

func TestOnboardingNoticeShowsTheHostWithTheDNSPort(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.page(pageRequest{path: "/logs", cookies: []string{"session=" + h.token}, host: "noadd.lan:8080"})
	wantStatus(t, recorder, http.StatusOK)
	wantContains(t, recorder.Body.String(), "noadd.lan:53")
}

func TestOnboardingNoticeStaysOffTheDashboard(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	body := h.pageBody("/")
	wantAbsent(t, body, bannerTestID)
	wantContains(t, body, `data-testid="dashboard-empty-state"`)
}

func TestOnboardingNoticeGoesAwayOnceAQueryHasBeenAnswered(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	err := h.db.InsertQueryLogs(ctxBackground(), []db.QueryLogEntry{{
		Timestamp: 1_000_000, Domain: "example.com", QueryType: "A", ClientIP: "192.168.1.1", ResponseMs: 5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	wantAbsent(t, h.pageBody("/logs"), bannerTestID)
	if !h.deps.Events.HasTraffic() {
		t.Fatal("rendering the page did not set the traffic latch")
	}
}

func TestDismissingTheOnboardingNoticePersistsAndReturnsToThePage(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantRedirect(t, h.signedIn(http.MethodPost, "/onboarding/dismiss", "next=/logs"), "/logs")
	wantAbsent(t, h.pageBody("/stats"), bannerTestID)
}

func TestDismissingTheOnboardingNoticeRefusesAnOffOriginReturn(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, target := range []string{"https://evil.example/", "//evil.example", `/\evil.example`} {
		recorder := h.signedIn(http.MethodPost, "/onboarding/dismiss", "next="+url.QueryEscape(target))
		wantRedirect(t, recorder, "/")
	}
}

func TestSignInRefusesToCarryAnOffOriginDestination(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, target := range []string{"https://evil.example", "//evil.example", `/\evil.example`} {
		recorder := h.page(pageRequest{path: "/login?next=" + url.QueryEscape(target)})
		wantStatus(t, recorder, http.StatusOK)
		wantAbsent(t, recorder.Body.String(), "evil.example")
	}
	// A path survives.
	recorder := h.page(pageRequest{path: "/login?next=/logs"})
	wantContains(t, recorder.Body.String(), `value="/logs"`)
}

func TestFormSignInMintsASessionAndRedirects(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.page(pageRequest{method: http.MethodPost, path: "/login", body: "username=admin&password=admin&next=/logs"})
	wantRedirect(t, recorder, "/logs")
	if _, ok := sessionTokenFromSetCookie(recorder); !ok {
		t.Fatal("no session cookie was issued")
	}
}

func TestFormSignInDropsAnOffOriginNext(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.page(pageRequest{method: http.MethodPost, path: "/login", body: "username=admin&password=admin&next=https://evil.example"})
	wantRedirect(t, recorder, "/")
}

func TestRefusedFormSignInAnswers401AndKeepsTheUsername(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.page(pageRequest{method: http.MethodPost, path: "/login", body: "username=admin&password=wrong-password"})
	wantStatus(t, recorder, http.StatusUnauthorized)
	wantContains(t, recorder.Body.String(), `data-testid="login-error"`)
	wantContains(t, recorder.Body.String(), `value="admin"`)
}

func TestFormSignInIsRateLimitedWith429(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	var recorder *httptest.ResponseRecorder
	for range 6 {
		recorder = h.page(pageRequest{method: http.MethodPost, path: "/login", body: "username=admin&password=wrong-password"})
	}
	wantStatus(t, recorder, http.StatusTooManyRequests)
}

func TestFormRejectsAWrongContentTypeAndAMissingField(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"username":"a"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	wantStatus(t, recorder, http.StatusUnsupportedMediaType)

	missing := h.page(pageRequest{method: http.MethodPost, path: "/login", body: "username=admin"})
	wantStatus(t, missing, http.StatusUnprocessableEntity)
}

func TestSignInPageRendersForAnAnonymousBrowserAndSendsASignedInOneOnward(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.page(pageRequest{path: "/login"})
	wantStatus(t, recorder, http.StatusOK)
	wantContains(t, recorder.Body.String(), `data-testid="login-submit"`)
	wantContains(t, recorder.Body.String(), `action="/login"`)

	wantRedirect(t, h.signedIn(http.MethodGet, "/login", ""), "/")
	wantRedirect(t, h.signedIn(http.MethodGet, "/login?next=/logs", ""), "/logs")
	wantRedirect(t, h.signedIn(http.MethodGet, "/login?next=//evil.example", ""), "/")
}

func TestSignInPageSendsAnUnconfiguredApplianceToTheWizard(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{noOperator: true})
	wantRedirect(t, h.page(pageRequest{path: "/login"}), "/setup")
}

func TestWizardRendersBeforeTheFirstOperatorAndRedirectsAfter(t *testing.T) {
	empty := newAPIHarness(t, harnessOptions{noOperator: true})
	recorder := empty.page(pageRequest{path: "/setup"})
	wantStatus(t, recorder, http.StatusOK)
	wantContains(t, recorder.Body.String(), `data-testid="setup-submit"`)

	configured := newAPIHarness(t, harnessOptions{})
	wantRedirect(t, configured.page(pageRequest{path: "/setup"}), "/login")
}

const setupForm = "username=admin&password=correct-horse-battery&confirm=correct-horse-battery&setup_token=ABCDE-FGHJK"

func TestWizardCreatesTheFirstOperatorAndSignsThemIn(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{noOperator: true})
	recorder := h.page(pageRequest{method: http.MethodPost, path: "/setup", body: setupForm})
	wantRedirect(t, recorder, "/")
	if _, ok := sessionTokenFromSetCookie(recorder); !ok {
		t.Fatal("no session cookie")
	}
	var flashSet bool
	for _, cookie := range recorder.Result().Cookies() {
		flashSet = flashSet || (cookie.Name == flashCookieName && cookie.Value == "welcome")
	}
	if !flashSet {
		t.Fatal("no welcome flash")
	}
}

func TestWizardSignsInAnOperatorWhoseUsernameWasPadded(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{noOperator: true})
	body := strings.Replace(setupForm, "username=admin", "username=%20admin%20", 1)
	recorder := h.page(pageRequest{method: http.MethodPost, path: "/setup", body: body})
	wantRedirect(t, recorder, "/")
}

func TestWizardFailuresReRenderWithTheRightStatus(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		text       string
	}{
		{"mismatch", "username=admin&password=correct-horse-battery&confirm=other&setup_token=ABCDE-FGHJK", 400, "do not match"},
		{"bad token", strings.Replace(setupForm, "ABCDE-FGHJK", "WRONG", 1), 403, "setup token"},
		{"short password", "username=admin&password=short&confirm=short&setup_token=ABCDE-FGHJK", 400, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newAPIHarness(t, harnessOptions{noOperator: true})
			recorder := h.page(pageRequest{method: http.MethodPost, path: "/setup", body: c.body})
			wantStatus(t, recorder, c.status)
			wantContains(t, recorder.Body.String(), `value="admin"`)
			wantContains(t, recorder.Body.String(), c.text)
		})
	}
}

func TestWizardSetupTokenGuessesAreRateLimited(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{noOperator: true})
	wrong := strings.Replace(setupForm, "ABCDE-FGHJK", "WRONG", 1)
	for range 5 {
		wantStatus(t, h.page(pageRequest{method: http.MethodPost, path: "/setup", body: wrong}), http.StatusForbidden)
	}
	wantStatus(t, h.page(pageRequest{method: http.MethodPost, path: "/setup", body: setupForm}), http.StatusTooManyRequests)
}

func TestWizardRefusesAConfiguredApplianceWith409(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.page(pageRequest{method: http.MethodPost, path: "/setup", body: setupForm}), http.StatusConflict)
}

func TestLogoutFormRevokesTheSessionAndRedirects(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.signedIn(http.MethodPost, "/logout", "")
	wantRedirect(t, recorder, "/login")
	if recorder.Header().Get("Clear-Site-Data") == "" {
		t.Error("no Clear-Site-Data")
	}
	// The same cookie must no longer authenticate anything.
	wantRedirect(t, h.signedIn(http.MethodGet, "/logs", ""), "/login?next=/logs")
}

// TestFlashConsumedByAnyShellPage pins the flash contract: whichever page
// renders first consumes the notice, once.
func TestFlashConsumedByAnyShellPage(t *testing.T) {
	for _, path := range []string{"/", "/stats", "/logs"} {
		t.Run(path, func(t *testing.T) {
			h := newAPIHarness(t, harnessOptions{noOperator: true})
			created := h.page(pageRequest{method: http.MethodPost, path: "/setup", body: setupForm})
			cookies := cookiePairs(created)

			first := h.page(pageRequest{path: path, cookies: cookies})
			wantStatus(t, first, http.StatusOK)
			wantContains(t, first.Body.String(), "setup-welcome")
			var cleared bool
			for _, cookie := range first.Result().Cookies() {
				cleared = cleared || (cookie.Name == flashCookieName && cookie.MaxAge < 0)
			}
			if !cleared {
				t.Fatal("the rendering response did not clear the flash")
			}

			var sessionOnly []string
			for _, pair := range cookies {
				if !strings.HasPrefix(pair, flashCookieName+"=") {
					sessionOnly = append(sessionOnly, pair)
				}
			}
			second := h.page(pageRequest{path: path, cookies: sessionOnly})
			wantAbsent(t, second.Body.String(), "setup-welcome")
		})
	}
}

func TestAStaleOrForgedFlashShowsNothing(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.page(pageRequest{path: "/", cookies: []string{"session=" + h.token, flashCookieName + "=<script>"}})
	wantStatus(t, recorder, http.StatusOK)
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == flashCookieName {
			t.Fatal("a forged flash was acted on")
		}
	}
}
