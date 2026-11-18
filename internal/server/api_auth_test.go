package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/henry40408/noadd/internal/auth"
)

func loginBody(username, password string) string {
	return fmt.Sprintf(`{"username":%q,"password":%q}`, username, password)
}

func (h *apiHarness) loginFrom(ip, username, password string) int {
	return h.do(request{method: "POST", path: "/api/auth/login", body: loginBody(username, password), from: ip}).Code
}

// lockAccount spends the free allowance from distinct addresses, leaving the
// account locked; it returns how many addresses it used.
func (h *apiHarness) lockAccount(username string) int {
	h.t.Helper()
	attempts := auth.LockoutFreeAttempts + 1
	for i := 0; i < attempts; i++ {
		if got := h.loginFrom(fmt.Sprintf("10.0.0.%d", i), username, "not-the-password"); got != http.StatusUnauthorized {
			h.t.Fatalf("attempt %d: status %d, want 401 from the password, not the IP limiter", i, got)
		}
	}
	return attempts
}

func TestUnauthenticatedRoutesAnswer401(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/auth/me"},
		{"GET", "/api/users"},
		{"GET", "/api/sessions"},
		{"GET", "/api/api-keys"},
		{"GET", "/api/doh-tokens"},
		{"POST", "/api/auth/logout"},
	} {
		recorder := h.do(request{method: route.method, path: route.path})
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", route.method, route.path, recorder.Code)
		}
	}
}

func TestWrongMethodAnswers405WithAllow(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.do(request{method: "DELETE", path: "/api/auth/login"})
	wantStatus(t, recorder, http.StatusMethodNotAllowed)
	if recorder.Header().Get("Allow") == "" {
		t.Fatal("missing Allow header")
	}
}

func TestLoginSetsCookieAndMeWorks(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.do(request{method: "POST", path: "/api/auth/login", body: loginBody("admin", "admin")})
	wantStatus(t, recorder, http.StatusOK)
	token, ok := sessionTokenFromSetCookie(recorder)
	if !ok {
		t.Fatal("no session cookie")
	}
	cookie := recorder.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Secure {
		t.Fatalf("cookie attributes: %+v", cookie)
	}
	me := h.do(request{method: "GET", path: "/api/auth/me", cookie: token})
	wantStatus(t, me, http.StatusOK)
	if strings.Contains(me.Body.String(), "hash") {
		t.Fatalf("me leaks a hash: %s", me.Body.String())
	}
}

func TestLoginCookieIsSecureWhenConfigured(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{cookieSecure: true})
	recorder := h.do(request{method: "POST", path: "/api/auth/login", body: loginBody("admin", "admin")})
	wantStatus(t, recorder, http.StatusOK)
	if cookie := recorder.Result().Cookies()[0]; !cookie.Secure {
		t.Fatalf("cookie not Secure: %+v", cookie)
	}
}

func TestLoginRejectsWrongCredentials(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, creds := range [][2]string{{"admin", "nope"}, {"ghost", "admin"}} {
		if got := h.loginFrom("", creds[0], creds[1]); got != http.StatusUnauthorized {
			t.Errorf("%v = %d, want 401", creds, got)
		}
	}
}

func TestLoginIsRateLimitedPerAddress(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for i := 0; i < 5; i++ {
		if got := h.loginFrom("192.0.2.9", "admin", "wrong"); got != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d", i, got)
		}
	}
	if got := h.loginFrom("192.0.2.9", "admin", "admin"); got != http.StatusTooManyRequests {
		t.Fatalf("sixth attempt = %d, want 429", got)
	}
}

func TestDistributedGuessingLocksTheAccount(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	used := h.lockAccount("admin")
	if got := h.loginFrom(fmt.Sprintf("10.0.0.%d", used), "admin", "admin"); got != http.StatusUnauthorized {
		t.Fatalf("correct password on a locked account = %d, want 401", got)
	}
}

func TestLockedAccountLooksLikeUnknownAccount(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	used := h.lockAccount("admin")
	locked := h.do(request{method: "POST", path: "/api/auth/login", body: loginBody("admin", "whatever-long"), from: fmt.Sprintf("10.0.1.%d", used)})
	unknown := h.do(request{method: "POST", path: "/api/auth/login", body: loginBody("nobody", "whatever-long"), from: fmt.Sprintf("10.0.2.%d", used)})
	wantStatus(t, locked, http.StatusUnauthorized)
	wantStatus(t, unknown, http.StatusUnauthorized)
	if fmt.Sprint(locked.Header()) != fmt.Sprint(unknown.Header()) || locked.Body.String() != unknown.Body.String() {
		t.Fatalf("locked %v %q differs from unknown %v %q", locked.Header(), locked.Body, unknown.Header(), unknown.Body)
	}
}

func TestSuccessfulLoginClearsAccountBudget(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	free := auth.LockoutFreeAttempts
	for round := 0; round < 2; round++ {
		for i := 0; i < free; i++ {
			if got := h.loginFrom(fmt.Sprintf("10.1.%d.%d", round, i), "admin", "wrong-one"); got != http.StatusUnauthorized {
				t.Fatalf("round %d attempt %d = %d", round, i, got)
			}
		}
		if got := h.loginFrom(fmt.Sprintf("10.1.%d.200", round), "admin", "admin"); got != http.StatusOK {
			t.Fatalf("round %d: login = %d, want 200; the counter must restart", round, got)
		}
	}
}

func TestLockoutCoversEveryPasswordCheck(t *testing.T) {
	for _, route := range []struct{ path, body string }{
		{"/api/auth/reauth", `{"password":"admin"}`},
		{"/api/users/me/password", `{"current_password":"admin","new_password":"` + strongPassword + `"}`},
	} {
		h := newAPIHarness(t, harnessOptions{})
		used := h.lockAccount("admin")
		recorder := h.do(request{method: "POST", path: route.path, body: route.body, cookie: h.token, from: fmt.Sprintf("10.0.3.%d", used)})
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401 under lockout", route.path, recorder.Code)
		}
	}
}

func TestSensitiveActionsNeedRecentPasswordProof(t *testing.T) {
	for _, route := range []struct{ method, path, body string }{
		{"POST", "/api/api-keys", `{"name":"ci"}`},
		{"POST", "/api/users", `{"username":"bob","password":"` + strongPassword + `"}`},
		{"DELETE", "/api/users/2", ""},
	} {
		h := newAPIHarness(t, harnessOptions{})
		if got := h.authed(route.method, route.path, route.body).Code; got == http.StatusForbidden {
			t.Errorf("%s %s forbidden straight after login", route.method, route.path)
		}
		h.ageReauth(h.token)
		recorder := h.authed(route.method, route.path, route.body)
		wantStatus(t, recorder, http.StatusForbidden)
		var body map[string]any
		decodeBody(t, recorder, &body)
		if body["code"] != "reauth_required" {
			t.Errorf("%s %s code = %v", route.method, route.path, body["code"])
		}
	}
}

func TestReauthReopensTheWindow(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.ageReauth(h.token)
	wantStatus(t, h.authed("POST", "/api/api-keys", `{"name":"ci"}`), http.StatusForbidden)
	wantStatus(t, h.authed("POST", "/api/auth/reauth", `{"password":"admin"}`), http.StatusNoContent)
	wantStatus(t, h.authed("POST", "/api/api-keys", `{"name":"ci"}`), http.StatusCreated)
}

func TestReauthWrongPasswordLeavesWindowShut(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.ageReauth(h.token)
	wantStatus(t, h.authed("POST", "/api/auth/reauth", `{"password":"not-the-password"}`), http.StatusUnauthorized)
	wantStatus(t, h.authed("POST", "/api/api-keys", `{"name":"ci"}`), http.StatusForbidden)
}

func TestReauthIsRateLimited(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for i := 0; i < 5; i++ {
		wantStatus(t, h.authed("POST", "/api/auth/reauth", `{"password":"wrong"}`), http.StatusUnauthorized)
	}
	wantStatus(t, h.authed("POST", "/api/auth/reauth", `{"password":"wrong"}`), http.StatusTooManyRequests)
}

// Counting is detect-only: a stale tab must not lock the operator out.
func TestInvalidSessionCookiesAreCountedPerIPAndNeverBlock(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	warnings := func() int {
		count := 0
		for _, event := range h.logs.events(t) {
			if event["reason"] == "unknown_token_burst" {
				count++
			}
		}
		return count
	}
	for i := 0; i < invalidSessionMaxAttempts-1; i++ {
		wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", cookie: "bogus", from: "198.51.100.1"}), http.StatusUnauthorized)
	}
	if got := warnings(); got != 0 {
		t.Fatalf("warned %d times before the threshold", got)
	}
	wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", cookie: "bogus", from: "198.51.100.1"}), http.StatusUnauthorized)
	if got := warnings(); got != 1 {
		t.Fatalf("warnings at the threshold = %d, want 1", got)
	}
	for i := 0; i < invalidSessionMaxAttempts+2; i++ {
		wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", from: "198.51.100.3"}), http.StatusUnauthorized)
	}
	if got := warnings(); got != 1 {
		t.Fatalf("cookie-less requests were counted: %d warnings", got)
	}
}

func TestLogoutRevokesSessionAndClearsCookies(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.authed("POST", "/api/auth/logout", "")
	wantStatus(t, recorder, http.StatusOK)
	if recorder.Header().Get("Clear-Site-Data") != `"cache", "cookies", "storage"` {
		t.Fatalf("Clear-Site-Data = %q", recorder.Header().Get("Clear-Site-Data"))
	}
	wantStatus(t, h.authed("GET", "/api/auth/me", ""), http.StatusUnauthorized)
}

func TestHostPrefixedCookieIsAccepted(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.do(request{method: "GET", path: "/api/auth/me", headers: map[string]string{"Cookie": "__Host-session=" + h.token}})
	wantStatus(t, recorder, http.StatusOK)
}

func TestStaleCookieDoesNotShadowValidOne(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.do(request{method: "GET", path: "/api/auth/me", headers: map[string]string{"Cookie": "__Host-session=stale; session=" + h.token}})
	wantStatus(t, recorder, http.StatusOK)
}

func TestBearerAPIKeyAuthenticates(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	created := h.authed("POST", "/api/api-keys", `{"name":"ci"}`)
	wantStatus(t, created, http.StatusCreated)
	var body struct {
		Key string `json:"token"`
	}
	decodeBody(t, created, &body)
	if !strings.HasPrefix(body.Key, "noadd_") {
		t.Fatalf("key = %q", body.Key)
	}
	wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", headers: map[string]string{"Authorization": "Bearer " + body.Key}}), http.StatusOK)
	wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", headers: map[string]string{"Authorization": "Bearer noadd_" + strings.Repeat("a", 40)}}), http.StatusUnauthorized)
}
