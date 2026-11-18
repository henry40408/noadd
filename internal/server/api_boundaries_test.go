package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/events"
)

func TestLogSafeTextBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, value string
		max         int
		want        string
	}{
		{"exactly max bytes is kept", "abcd", 4, "abcd"},
		{"one over max is cut", "abcde", 4, "abcd"},
		{"a rune straddling max is dropped whole", "abcé", 4, "abc"},
		{"a rune ending at max is kept", "abé", 4, "abé"},
		{"only continuation bytes leave nothing", strings.Repeat("\x80", 6), 4, ""},
	}
	for _, c := range cases {
		if got := logSafeText(c.value, c.max); got != c.want {
			t.Errorf("%s: logSafeText(%q, %d) = %q, want %q", c.name, c.value, c.max, got, c.want)
		}
	}
}

func TestLogSafeBoundaries(t *testing.T) {
	t.Parallel()
	exact := strings.Repeat("a", logSafeMax)
	if got := logSafe(exact); got != exact {
		t.Errorf("a value of exactly logSafeMax bytes was changed: %d bytes", len(got))
	}
	if got := logSafe(exact + "a"); got != exact {
		t.Errorf("one byte over logSafeMax = %d bytes, want %d", len(got), logSafeMax)
	}
	if got := logSafe(strings.Repeat("\x80", logSafeMax+1)); got != "" {
		t.Errorf("continuation bytes only = %q, want empty", got)
	}
	// A two-byte rune ending exactly at the limit survives; one starting on it does not.
	endsAtLimit := strings.Repeat("a", logSafeMax-2) + "é" + "a"
	if got := logSafe(endsAtLimit); got != strings.Repeat("a", logSafeMax-2)+"é" {
		t.Errorf("rune ending at the limit: got %d bytes", len(got))
	}
}

func TestHeaderLogValueByteBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		value string
		want  string
	}{
		{"~", "~"},
		{"\x7f", "<non-ascii>"},
		{" ", " "},
		{"\x1f", "<non-ascii>"},
		{"\t", "\t"},
		{"\x01", "<non-ascii>"},
		{"a\x00b", "<non-ascii>"},
		{"café", "<non-ascii>"},
	}
	for _, c := range cases {
		header := http.Header{"X-Probe": []string{c.value}}
		if got := headerLogValue(header, "X-Probe"); got != c.want {
			t.Errorf("headerLogValue(%q) = %q, want %q", c.value, got, c.want)
		}
	}
	if got := headerLogValue(http.Header{}, "X-Probe"); got != "<none>" {
		t.Errorf("absent header = %q", got)
	}
}

func TestFloorDivRoundsTowardNegativeInfinity(t *testing.T) {
	t.Parallel()
	cases := []struct{ value, divisor, want int64 }{
		{-15, 15, -1}, // divisible: no correction
		{-16, 15, -2},
		{-1, 15, -1},
		{0, 15, 0},
		{14, 15, 0},
		{15, 15, 1},
	}
	for _, c := range cases {
		if got := floorDiv(c.value, c.divisor); got != c.want {
			t.Errorf("floorDiv(%d, %d) = %d, want %d", c.value, c.divisor, got, c.want)
		}
	}
}

func TestMethodNotAllowedListsExactlyTheHandledMethods(t *testing.T) {
	t.Parallel()
	h := newAPIHarness(t, harnessOptions{})
	cases := []struct{ method, path, wantAllow string }{
		{"DELETE", "/api/auth/me", "GET, HEAD"},
		{"GET", "/api/auth/login", "POST"},
	}
	for _, c := range cases {
		recorder := h.do(request{method: c.method, path: c.path})
		wantStatus(t, recorder, http.StatusMethodNotAllowed)
		if got := recorder.Header().Get("Allow"); got != c.wantAllow {
			t.Errorf("%s %s: Allow = %q, want %q", c.method, c.path, got, c.wantAllow)
		}
	}
}

func TestLowestLatencyTiePrefersTheFirstServerByLabel(t *testing.T) {
	t.Parallel()
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.authed("PUT", "/api/settings",
		`{"upstream_servers":"127.0.0.1:1,127.0.0.1:2","upstream_strategy":"lowest-latency"}`), http.StatusOK)
	h.deps.Forwarder.UpdateLatency(0, 10)
	h.deps.Forwarder.UpdateLatency(1, 10)
	var entries []upstreamLatencyEntry
	decodeBody(t, h.authed("GET", "/api/upstream/latency", ""), &entries)
	if len(entries) != 2 || !entries[0].Preferred || entries[1].Preferred {
		t.Fatalf("a tie must keep the first server: %+v", entries)
	}
}

func TestAccountLockoutIsLoggedOnlyOnceThePenaltyStarts(t *testing.T) {
	t.Parallel()
	logs := &capturedLogs{}
	a := newAPI(APIDeps{Lockout: auth.NewLockout(nil)}, logs.logger())
	ip := netip.MustParseAddr("192.0.2.7")
	for range auth.LockoutFreeAttempts {
		a.noteAccountFailure(1, ip, "login")
	}
	if got := logs.events(t); len(got) != 0 {
		t.Fatalf("the free allowance logged %d events", len(got))
	}
	a.noteAccountFailure(1, ip, "login")
	got := logs.events(t)
	if len(got) != 1 || got[0]["event"] != "auth.account_locked" || got[0]["locked_secs"] != float64(1) {
		t.Fatalf("events = %v, want one lock of 1s", got)
	}
}

func TestClearSessionCookiesExpiresOnlyTheCookiesCarried(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		carried    string
		wantSecure bool
	}{
		{"session", "session", false},
		{"__Host-session", "__Host-session", true},
	}
	for _, c := range cases {
		request := httptest.NewRequest("POST", "/logout", nil)
		request.AddCookie(&http.Cookie{Name: c.carried, Value: "x"})
		recorder := httptest.NewRecorder()
		clearSessionCookies(recorder, request)
		setCookies := recorder.Header().Values("Set-Cookie")
		if len(setCookies) != 1 {
			t.Fatalf("%s: %d Set-Cookie headers, want 1: %q", c.name, len(setCookies), setCookies)
		}
		cleared := recorder.Result().Cookies()[0]
		if cleared.Name != c.carried || cleared.Secure != c.wantSecure || cleared.MaxAge != -1 || cleared.Value != "" {
			t.Errorf("%s: cleared = %+v", c.name, cleared)
		}
		if !strings.Contains(setCookies[0], "Max-Age=0") {
			t.Errorf("%s: %q does not expire the cookie immediately", c.name, setCookies[0])
		}
	}
}

func TestLoginAcceptsPasswordOfExactlyTheMaximumLength(t *testing.T) {
	t.Parallel()
	h := newAPIHarness(t, harnessOptions{})
	longest := strings.Repeat("p", auth.MaxLoginPasswordLength)
	h.seedOperator("longest", longest)
	body := fmt.Sprintf(`{"username":"longest","password":%q}`, longest)
	wantStatus(t, h.do(request{method: "POST", path: "/api/auth/login", body: body}), http.StatusOK)
}

func TestReauthAcceptsPasswordOfExactlyTheMaximumLength(t *testing.T) {
	t.Parallel()
	h := newAPIHarness(t, harnessOptions{})
	longest := strings.Repeat("p", auth.MaxLoginPasswordLength)
	token := h.bindSession(h.seedOperator("longest", longest))
	body := fmt.Sprintf(`{"password":%q}`, longest)
	wantStatus(t, h.do(request{method: "POST", path: "/api/auth/reauth", body: body, cookie: token}), http.StatusNoContent)
}

func (h *apiHarness) storedUserAgents() []*string {
	h.t.Helper()
	rows, err := h.db.ListSessions(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	agents := make([]*string, 0, len(rows))
	for _, row := range rows {
		agents = append(agents, row.UserAgent)
	}
	return agents
}

func TestLoginStoresTheUserAgentOnlyWhenOneWasSent(t *testing.T) {
	t.Parallel()
	const login = `{"username":"admin","password":"admin"}`
	t.Run("sent", func(t *testing.T) {
		t.Parallel()
		h := newAPIHarness(t, harnessOptions{})
		headers := map[string]string{"User-Agent": "probe/1"}
		wantStatus(t, h.do(request{method: "POST", path: "/api/auth/login", body: login, headers: headers}), http.StatusOK)
		stored := 0
		for _, agent := range h.storedUserAgents() {
			if agent != nil && *agent == "probe/1" {
				stored++
			}
		}
		if stored != 1 {
			t.Fatalf("%d sessions carry the user agent, want 1", stored)
		}
	})
	t.Run("header present but empty", func(t *testing.T) {
		t.Parallel()
		h := newAPIHarness(t, harnessOptions{})
		req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(login))
		req.RemoteAddr = "127.0.0.1:50000"
		req.Header.Set("Content-Type", "application/json")
		req.Header["User-Agent"] = []string{}
		recorder := httptest.NewRecorder()
		h.handler.ServeHTTP(recorder, req)
		wantStatus(t, recorder, http.StatusOK)
		for _, agent := range h.storedUserAgents() {
			if agent != nil {
				t.Fatalf("stored user agent %q, want none", *agent)
			}
		}
	})
}

func TestSessionCreatedLogCarriesAReasonOnlyWhenGiven(t *testing.T) {
	t.Parallel()
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.do(request{method: "POST", path: "/api/auth/login", body: `{"username":"admin","password":"admin"}`}), http.StatusOK)
	change := fmt.Sprintf(`{"current_password":"admin","new_password":%q}`, strongPassword)
	wantStatus(t, h.authed("POST", "/api/users/me/password", change), http.StatusNoContent)

	reasons := map[string]any{}
	created := 0
	for _, event := range h.logs.events(t) {
		if event["event"] != "session.created" {
			continue
		}
		created++
		if reason, present := event["reason"]; present {
			reasons[fmt.Sprint(event["msg"])] = reason
		}
	}
	if created != 2 {
		t.Fatalf("%d session.created events, want 2: %v", created, reasons)
	}
	if reason, present := reasons["login successful"]; present {
		t.Errorf("login logged reason %v, want none", reason)
	}
	if reasons["rotated session after password change"] != "password_change" {
		t.Errorf("rotation reason = %v", reasons["rotated session after password change"])
	}
}

func TestLogoutOfAForwardAuthOperatorRedirectsToTheProxy(t *testing.T) {
	t.Parallel()
	forward, err := auth.NewForwardAuth("X-Remote-User", "127.0.0.0/8", "https://sso.example/logout")
	if err != nil {
		t.Fatal(err)
	}
	h := newAPIHarness(t, harnessOptions{forwardAuth: forward})
	recorder := h.do(request{method: "POST", path: "/api/auth/logout", headers: map[string]string{"X-Remote-User": "proxied"}})
	wantStatus(t, recorder, http.StatusOK)
	var body logoutResponse
	decodeBody(t, recorder, &body)
	if !body.ViaForwardAuth || body.RedirectTo == nil || *body.RedirectTo != "https://sso.example/logout" {
		t.Fatalf("logout = %+v", body)
	}
}

func TestCheckListURLJudgesTheStatusRange(t *testing.T) {
	t.Parallel()
	h := newAPIHarness(t, harnessOptions{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var status int
		if _, err := fmt.Sscanf(r.URL.Path, "/status/%d", &status); err != nil {
			status = http.StatusNotFound
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	for status, wantOK := range map[int]bool{200: true, 204: true, 299: true, 300: false, 404: false} {
		body := fmt.Sprintf(`{"url":%q}`, fmt.Sprintf("%s/status/%d", server.URL, status))
		var result map[string]any
		decodeBody(t, h.authed("POST", "/api/lists/999/check", body), &result)
		if result["ok"] != wantOK || result["status"] != float64(status) {
			t.Errorf("status %d: result = %v, want ok=%v", status, result, wantOK)
		}
	}
}

func TestBatchAddAcceptsExactlyTheLimitAndStoresRuleCounts(t *testing.T) {
	t.Parallel()
	h := newAPIHarness(t, harnessOptions{})
	item := `{"name":"a","url":"http://127.0.0.1:1/x"}`
	atLimit := `{"items":[` + strings.Repeat(item+",", batchAddLimit-1) + item + `]}`
	recorder := h.authed("POST", "/api/lists/batch", atLimit)
	wantStatus(t, recorder, http.StatusOK)
	var response batchAddResponse
	decodeBody(t, recorder, &response)
	if len(response.Failed) != batchAddLimit {
		t.Fatalf("%d failures, want all %d unreachable items reported", len(response.Failed), batchAddLimit)
	}
}

func TestBatchAddRecordsTheDownloadedRuleCount(t *testing.T) {
	t.Parallel()
	h := newAPIHarness(t, harnessOptions{})
	server := listServer(t)
	body := fmt.Sprintf(`{"items":[{"name":"one","url":%q}]}`, server.URL+"/one.txt")
	wantStatus(t, h.authed("POST", "/api/lists/batch", body), http.StatusOK)
	lists := h.listsJSON()
	if len(lists) != 1 || lists[0].RuleCount != 3 || lists[0].LastUpdated == 0 {
		t.Fatalf("stored lists = %+v, want one with 3 rules and a download time", lists)
	}
	h.settleRebuilds()
}

func TestAPIKeyNameLengthIsCountedInRunes(t *testing.T) {
	t.Parallel()
	h := newAPIHarness(t, harnessOptions{})
	for _, name := range []string{strings.Repeat("n", apiKeyNameMaxChars), strings.Repeat("é", apiKeyNameMaxChars)} {
		body := fmt.Sprintf(`{"name":%q}`, name)
		wantStatus(t, h.authed("POST", "/api/api-keys", body), http.StatusCreated)
	}
}

func TestPumpEventsEndsOnceEverySourceIsClosed(t *testing.T) {
	t.Parallel()
	logs := &capturedLogs{}
	a := newAPI(APIDeps{}, logs.logger())
	recorder := httptest.NewRecorder()
	stream := &eventStream{w: recorder, flush: http.NewResponseController(recorder)}
	ticks := make(chan *events.Tick, 1)
	feed := make(chan *db.QueryLogEntry)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan struct{})
	go func() {
		defer close(done)
		a.pumpEvents(ctx, stream, eventSources{ticks: ticks, logs: feed})
	}()

	ticks <- &events.Tick{Seq: 1, At: 42}
	close(feed) // the tail ends first; the heartbeat must keep going
	close(ticks)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pumpEvents kept running after every source closed")
	}
	if !strings.Contains(recorder.Body.String(), "event: ping") {
		t.Fatalf("the tick was not forwarded: %q", recorder.Body.String())
	}
}
