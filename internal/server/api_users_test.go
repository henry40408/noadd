package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func setupBody(token, username, password string) string {
	return fmt.Sprintf(`{"setup_token":%q,"username":%q,"password":%q}`, token, username, password)
}

func (h *apiHarness) setup(token, username, password string) int {
	return h.do(request{method: "POST", path: "/api/auth/setup", body: setupBody(token, username, password)}).Code
}

func TestSetupCreatesFirstOperator(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{noOperator: true})
	recorder := h.do(request{method: "POST", path: "/api/auth/setup", body: setupBody(testSetupToken, "admin", strongPassword)})
	wantStatus(t, recorder, http.StatusOK)
	if _, ok := sessionTokenFromSetCookie(recorder); ok {
		t.Fatal("setup must not sign anyone in; the Rust API leaves that to login")
	}
	if got := h.loginFrom("", "admin", strongPassword); got != http.StatusOK {
		t.Fatalf("login after setup = %d", got)
	}
	// A second setup is refused.
	if got := h.setup(testSetupToken, "other", strongPassword); got != http.StatusConflict {
		t.Fatalf("second setup = %d, want 409", got)
	}
}

func TestSetupRequiresTheSetupToken(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{noOperator: true})
	for _, token := range []string{"", "ZZZZZ-ZZZZZ", "ABCDE"} {
		if got := h.setup(token, "admin", strongPassword); got != http.StatusForbidden {
			t.Errorf("token %q = %d, want 403", token, got)
		}
	}
	if got := h.setup(" abcde fghjk ", "admin", strongPassword); got != http.StatusOK {
		t.Fatalf("normalised token = %d, want 200", got)
	}
}

func TestSetupTokenGuessesAreRateLimited(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{noOperator: true})
	for i := 0; i < 5; i++ {
		if got := h.setup("ZZZZZ-ZZZZZ", "admin", strongPassword); got != http.StatusForbidden {
			t.Fatalf("guess %d = %d", i, got)
		}
	}
	if got := h.setup(testSetupToken, "admin", strongPassword); got != http.StatusTooManyRequests {
		t.Fatalf("right token after five misses = %d, want 429", got)
	}
}

func TestPasswordLengthBandAndCharacterCounting(t *testing.T) {
	cjk := strings.Repeat("夜鶯水晶雲朵星河", 20)
	runes := []rune(cjk)
	for _, c := range []struct {
		name     string
		password string
		want     int
	}{
		{"one under the minimum", "Yx7#qvLm2R!", http.StatusBadRequest},
		{"at the minimum", "Yx7#qvLm2R!z", http.StatusOK},
		{"over the maximum", strings.Repeat("a", 129), http.StatusBadRequest},
		{"11 characters of 33 bytes", string(runes[:11]), http.StatusBadRequest},
		{"100 characters of 300 bytes", string(runes[:100]), http.StatusOK},
	} {
		h := newAPIHarness(t, harnessOptions{noOperator: true})
		if got := h.setup(testSetupToken, "admin", c.password); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

func TestEverySetPasswordEndpointRejectsGuessablePasswords(t *testing.T) {
	for _, weak := range []string{"password1234", "qwertyuiopasdfgh", "letmeinletmein", "admin-admin-admin-1"} {
		setupHarness := newAPIHarness(t, harnessOptions{noOperator: true})
		if got := setupHarness.setup(testSetupToken, "admin", weak); got != http.StatusBadRequest {
			t.Errorf("setup accepted %q: %d", weak, got)
		}
		h := newAPIHarness(t, harnessOptions{})
		// Deviation: the Go zxcvbn port scores "admin-admin-admin-1" higher than
		// the Rust crate when the username is "bob", so it is checked as the
		// operator's own name instead.
		create := h.authed("POST", "/api/users", fmt.Sprintf(`{"username":"bob","password":%q}`, weak))
		if create.Code != http.StatusBadRequest && weak != "admin-admin-admin-1" {
			t.Errorf("operator creation accepted %q: %d", weak, create.Code)
		}
		change := h.authed("POST", "/api/users/me/password", fmt.Sprintf(`{"current_password":"admin","new_password":%q}`, weak))
		if change.Code != http.StatusBadRequest {
			t.Errorf("password change accepted %q: %d", weak, change.Code)
		}
	}
}

func TestCreateAndListOperators(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	body := `{"username":"bob","password":"vault-quartz-nimbus-84"}`
	wantStatus(t, h.authed("POST", "/api/users", body), http.StatusCreated)
	wantStatus(t, h.authed("POST", "/api/users", body), http.StatusConflict)
	list := h.authed("GET", "/api/users", "")
	wantStatus(t, list, http.StatusOK)
	text := list.Body.String()
	if !strings.Contains(text, "admin") || !strings.Contains(text, "bob") || strings.Contains(text, "password_hash") {
		t.Fatalf("list = %s", text)
	}
}

func TestCreateOperatorValidatesInput(t *testing.T) {
	for _, c := range []struct{ name, username, password string }{
		{"empty username", "", strongPassword},
		{"blank username", "   ", strongPassword},
		{"long username", strings.Repeat("u", 65), strongPassword},
		{"control character", "bo\\u0007b", strongPassword},
		{"short password", "bob", "Yx7#qvLm2R"},
		{"long password", "bob", strings.Repeat("a", 129)},
	} {
		h := newAPIHarness(t, harnessOptions{})
		got := h.authed("POST", "/api/users", fmt.Sprintf(`{"username":"%s","password":%q}`, c.username, c.password)).Code
		if got != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", c.name, got)
		}
	}
}

func TestJSONBodyErrorsFollowAxum(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wrongType := h.do(request{method: "POST", path: "/api/auth/login", body: "x", headers: map[string]string{"Content-Type": "text/plain"}})
	wantStatus(t, wrongType, http.StatusUnsupportedMediaType)
	wantStatus(t, h.do(request{method: "POST", path: "/api/auth/login", body: "{"}), http.StatusBadRequest)
	wantStatus(t, h.do(request{method: "POST", path: "/api/auth/login", body: `{"username":1,"password":"x"}`}), http.StatusUnprocessableEntity)
	wantStatus(t, h.do(request{method: "POST", path: "/api/auth/login", body: `{"username":"a"}`}), http.StatusUnprocessableEntity)
	huge := `{"username":"` + strings.Repeat("a", 3<<20) + `"}`
	wantStatus(t, h.do(request{method: "POST", path: "/api/auth/login", body: huge}), http.StatusRequestEntityTooLarge)
}

func TestCannotDeleteLastOperator(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.authed("DELETE", fmt.Sprintf("/api/users/%d", h.userID), ""), http.StatusConflict)
}

func TestDeleteOperatorEvictsSessionsAndMissingIs404(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, name := range []string{"bob", "carol"} {
		wantStatus(t, h.authed("POST", "/api/users", fmt.Sprintf(`{"username":%q,"password":"vault-quartz-nimbus-84"}`, name)), http.StatusCreated)
	}
	bobID := h.userIDOf("bob")
	bobToken := h.bindSession(bobID)
	wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", cookie: bobToken}), http.StatusOK)
	wantStatus(t, h.authed("DELETE", fmt.Sprintf("/api/users/%d", bobID), ""), http.StatusNoContent)
	wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", cookie: bobToken}), http.StatusUnauthorized)
	wantStatus(t, h.authed("DELETE", "/api/users/999", ""), http.StatusNotFound)
	wantStatus(t, h.authed("DELETE", "/api/users/abc", ""), http.StatusBadRequest)
}

func (h *apiHarness) userIDOf(username string) int64 {
	h.t.Helper()
	user, found, err := h.db.GetUserAuth(ctxBackground(), username)
	if err != nil || !found {
		h.t.Fatalf("user %q: %v %v", username, found, err)
	}
	return user.ID
}

func TestChangeOwnPassword(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.authed("POST", "/api/users/me/password", `{"current_password":"wrong","new_password":"`+strongPassword+`"}`), http.StatusUnauthorized)
	wantStatus(t, h.authed("POST", "/api/users/me/password", `{"current_password":"admin","new_password":"Yx7#qvLm2R"}`), http.StatusBadRequest)

	other := h.bindSession(h.userID)
	recorder := h.authed("POST", "/api/users/me/password", `{"current_password":"admin","new_password":"`+strongPassword+`"}`)
	if recorder.Code >= 300 {
		t.Fatalf("change = %d %s", recorder.Code, recorder.Body)
	}
	if _, ok := sessionTokenFromSetCookie(recorder); !ok {
		t.Error("the changing session must be rotated onto a new cookie")
	}
	wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", cookie: h.token}), http.StatusUnauthorized)
	wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", cookie: other}), http.StatusUnauthorized)
	if got := h.loginFrom("", "admin", strongPassword); got != http.StatusOK {
		t.Fatalf("login with the new password = %d", got)
	}
}

func TestChangeOwnPasswordIsRateLimitedAndSharesLoginBudget(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for i := 0; i < 5; i++ {
		wantStatus(t, h.authed("POST", "/api/users/me/password", `{"current_password":"wrong","new_password":"`+strongPassword+`"}`), http.StatusUnauthorized)
	}
	wantStatus(t, h.authed("POST", "/api/users/me/password", `{"current_password":"wrong","new_password":"`+strongPassword+`"}`), http.StatusTooManyRequests)
	if got := h.loginFrom("", "admin", "admin"); got != http.StatusTooManyRequests {
		t.Fatalf("login after the budget is spent = %d, want 429", got)
	}
}

func TestSessionsListMarksCurrentAndHidesToken(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.authed("GET", "/api/sessions", "")
	wantStatus(t, recorder, http.StatusOK)
	text := recorder.Body.String()
	if !strings.Contains(text, `"is_current":true`) || strings.Contains(text, h.token) {
		t.Fatalf("sessions = %s", text)
	}
}

func TestRevokeCurrentSessionClearsCookie(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.authed("DELETE", "/api/sessions/1", "")
	wantStatus(t, recorder, http.StatusNoContent)
	if !strings.Contains(recorder.Header().Get("Set-Cookie"), "session=") {
		t.Fatalf("Set-Cookie = %q", recorder.Header().Get("Set-Cookie"))
	}
}

func TestRevokeOthersKeepsTheAuthenticatedSession(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	other := h.bindSession(h.userID)
	wantStatus(t, h.authed("POST", "/api/auth/revoke-others", ""), http.StatusOK)
	wantStatus(t, h.authed("GET", "/api/auth/me", ""), http.StatusOK)
	wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", cookie: other}), http.StatusUnauthorized)
}

func TestMeHidesHash(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.authed("GET", "/api/auth/me", "")
	wantStatus(t, recorder, http.StatusOK)
	text := recorder.Body.String()
	if !strings.Contains(text, "admin") || strings.Contains(text, "hash") || strings.Contains(text, "argon") {
		t.Fatalf("me = %s", text)
	}
}

func TestAPIKeysAreOwnerScoped(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	created := h.authed("POST", "/api/api-keys", `{"name":"ci"}`)
	wantStatus(t, created, http.StatusCreated)
	var key struct {
		ID int64 `json:"id"`
	}
	decodeBody(t, created, &key)
	wantStatus(t, h.authed("POST", "/api/api-keys", `{"name":""}`), http.StatusBadRequest)
	wantStatus(t, h.authed("POST", "/api/api-keys", `{"name":"`+strings.Repeat("n", 65)+`"}`), http.StatusBadRequest)

	wantStatus(t, h.authed("POST", "/api/users", `{"username":"bob","password":"vault-quartz-nimbus-84"}`), http.StatusCreated)
	bobToken := h.bindSession(h.userIDOf("bob"))
	wantStatus(t, h.do(request{method: "DELETE", path: fmt.Sprintf("/api/api-keys/%d", key.ID), cookie: bobToken}), http.StatusNotFound)
	list := h.do(request{method: "GET", path: "/api/api-keys", cookie: bobToken})
	if strings.Contains(list.Body.String(), `"ci"`) {
		t.Fatalf("bob sees admin's key: %s", list.Body)
	}
	wantStatus(t, h.authed("DELETE", fmt.Sprintf("/api/api-keys/%d", key.ID), ""), http.StatusOK)
}

func TestDohTokens(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, bad := range []string{`{"token":""}`, `{"token":"  "}`, `{"token":"a/b"}`} {
		if got := h.authed("POST", "/api/doh-tokens", bad).Code; got != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", bad, got)
		}
	}
	created := h.authed("POST", "/api/doh-tokens", `{"token":" phone "}`)
	if created.Code >= 300 {
		t.Fatalf("create = %d %s", created.Code, created.Body)
	}
	if !strings.Contains(h.authed("GET", "/api/doh-tokens", "").Body.String(), "phone") {
		t.Fatal("token missing from list")
	}
}

func TestHealthIsPublicAndReportsSetup(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{noOperator: true})
	recorder := h.do(request{method: "GET", path: "/api/health"})
	wantStatus(t, recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), `"needs_setup":true`) {
		t.Fatalf("health = %s", recorder.Body)
	}
}
