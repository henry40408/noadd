package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// realAdmin is the whole admin handler over the real API routes, so a request
// the guard lets through reaches the auth layer and gets its 401, as in the
// Rust tests.
func realAdmin(t *testing.T, logs *capturedLogs) http.Handler {
	t.Helper()
	return newAPIHarness(t, harnessOptions{logs: logs}).handler
}

type capturedLogs struct{ buffer bytes.Buffer }

func (c *capturedLogs) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&c.buffer, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// events returns each logged JSON object.
func (c *capturedLogs) events(t *testing.T) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(c.buffer.String()), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}

func postLogout(t *testing.T, logs *capturedLogs, headers map[string]string) *httptest.ResponseRecorder {
	chain := realAdmin(t, logs)
	request := httptest.NewRequest("POST", "/api/auth/logout", nil)
	request.Host = ""
	for name, value := range headers {
		if strings.EqualFold(name, "Host") {
			request.Host = value
			continue
		}
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	chain.ServeHTTP(recorder, request)
	return recorder
}

// Rust: csrf_test.rs sec_fetch_site_cross_site_is_rejected
func TestCrossSiteFetchIsRejected(t *testing.T) {
	response := postLogout(t, &capturedLogs{}, map[string]string{"Sec-Fetch-Site": "cross-site"})
	if response.Code != http.StatusForbidden || response.Body.Len() != 0 {
		t.Fatalf("status = %d, body = %q (want an empty 403)", response.Code, response.Body.String())
	}
}

// Rust: csrf_test.rs origin_host_mismatch_is_rejected
func TestOriginHostMismatchIsRejected(t *testing.T) {
	response := postLogout(t, &capturedLogs{}, map[string]string{"Origin": "https://evil.test", "Host": "app.test"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
}

// Rust: csrf_test.rs same_origin_request_reaches_handler
func TestSameOriginRequestReachesTheHandler(t *testing.T) {
	response := postLogout(t, &capturedLogs{}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want the handler's 401", response.Code)
	}
	// "none" is a user-initiated navigation such as the address bar.
	if got := postLogout(t, &capturedLogs{}, map[string]string{"Sec-Fetch-Site": "none"}).Code; got != http.StatusUnauthorized {
		t.Fatalf("Sec-Fetch-Site: none = %d", got)
	}
}

// Rust: csrf_test.rs csrf_rejection_is_not_stored
func TestCSRFRejectionIsNotStored(t *testing.T) {
	response := postLogout(t, &capturedLogs{}, map[string]string{"Sec-Fetch-Site": "cross-site"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
	if got := response.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Fatalf("expected no-store, got %q", got)
	}
	if response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("the guard's 403 lacks the security headers")
	}
}

// Rust: csrf_test.rs header_less_client_reaches_handler
func TestHeaderLessClientReachesTheHandler(t *testing.T) {
	if got := postLogout(t, &capturedLogs{}, nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 from the handler", got)
	}
}

// Rust: csrf_test.rs rejection_records_the_classification_inputs
func TestRejectionRecordsTheClassificationInputs(t *testing.T) {
	logs := &capturedLogs{}
	response := postLogout(t, logs, map[string]string{"Origin": "https://evil.test", "Host": "app.test"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
	events := logs.events(t)
	if len(events) != 1 {
		t.Fatalf("got %d log events: %s", len(events), logs.buffer.String())
	}
	for field, want := range map[string]string{
		"event":  "csrf.rejected",
		"reason": "origin_mismatch",
		"method": "POST",
		"path":   "/api/auth/logout",
		"origin": "https://evil.test",
		"host":   "app.test",
		// Recorded as absent rather than omitted: "not sent" and
		// "same-origin" must not read the same.
		"sec_fetch_site": "<none>",
		"level":          "WARN",
	} {
		if events[0][field] != want {
			t.Errorf("%s = %v, want %q", field, events[0][field], want)
		}
	}
}

// Rust: csrf_test.rs a_browser_stated_cross_site_rejection_is_logged_under_its_own_reason
func TestBrowserStatedCrossSiteIsLoggedAsCrossSite(t *testing.T) {
	logs := &capturedLogs{}
	postLogout(t, logs, map[string]string{
		"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.test", "Host": "app.test",
	})
	event := logs.events(t)[0]
	if event["reason"] != "cross_site" || event["sec_fetch_site"] != "cross-site" {
		t.Fatalf("event = %v", event)
	}
}

// Rust: csrf_test.rs a_same_site_post_from_a_sibling_subdomain_is_refused
func TestSameSitePostFromASiblingSubdomainIsRefused(t *testing.T) {
	logs := &capturedLogs{}
	response := postLogout(t, logs, map[string]string{
		"Sec-Fetch-Site": "same-site", "Origin": "https://evil.app.test", "Host": "app.test",
	})
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
	if reason := logs.events(t)[0]["reason"]; reason != "same_site_cross_origin" {
		t.Fatalf("reason = %v", reason)
	}
}

// Rust: csrf_test.rs a_same_site_post_is_refused_even_when_its_origin_matches_host
func TestSameSitePostIsRefusedEvenWhenOriginMatchesHost(t *testing.T) {
	response := postLogout(t, &capturedLogs{}, map[string]string{
		"Sec-Fetch-Site": "same-site", "Origin": "https://app.test", "Host": "app.test",
	})
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
}

// Rust: csrf_test.rs the_origin_fallback_rejects_an_authority_that_differs_from_host
func TestOriginFallbackRejectsAnAuthorityThatDiffersFromHost(t *testing.T) {
	for _, c := range []struct{ origin, host, why string }{
		{"http://app.test:9000", "app.test:8080", "another port is another origin, and cookies ignore ports"},
		{"https://app.test:8443", "app.test", "a proxy forwarding Host without the port looks the same"},
		{"http://[::1]:9000", "[::1]:8080", "an IPv6 literal is compared the same way"},
		{"https://other.app.test", "app.test", "a sibling subdomain is another origin"},
	} {
		response := postLogout(t, &capturedLogs{}, map[string]string{"Origin": c.origin, "Host": c.host})
		if response.Code != http.StatusForbidden {
			t.Errorf("Origin %s / Host %s must be rejected: %s (got %d)", c.origin, c.host, c.why, response.Code)
		}
	}
}

// Rust: csrf_test.rs the_origin_fallback_passes_an_authority_that_matches_host
func TestOriginFallbackPassesAnAuthorityThatMatchesHost(t *testing.T) {
	for _, c := range []struct{ origin, host string }{
		{"http://app.test:8080", "app.test:8080"},
		{"http://[::1]:8080", "[::1]:8080"},
		// A TLS-terminating proxy: the comparison ignores the scheme.
		{"https://app.test", "app.test"},
	} {
		response := postLogout(t, &capturedLogs{}, map[string]string{"Origin": c.origin, "Host": c.host})
		if response.Code == http.StatusForbidden {
			t.Errorf("Origin %s / Host %s must reach the handler", c.origin, c.host)
		}
	}
}

// Rust: csrf_test.rs each_rejection_is_logged_under_the_reason_that_decided_it
func TestEachRejectionIsLoggedUnderTheReasonThatDecidedIt(t *testing.T) {
	for _, c := range []struct {
		headers map[string]string
		reason  string
	}{
		{map[string]string{"Sec-Fetch-Site": "cross-site"}, "cross_site"},
		{map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://evil.app.test", "Host": "app.test"}, "same_site_cross_origin"},
		// A browser that said same-site is not a header-less client.
		{map[string]string{"Sec-Fetch-Site": "same-site"}, "same_site_cross_origin"},
		{map[string]string{"Origin": "null", "Host": "app.test"}, "opaque_origin"},
		{map[string]string{"Origin": "https://evil.test", "Host": "app.test"}, "origin_mismatch"},
	} {
		logs := &capturedLogs{}
		response := postLogout(t, logs, c.headers)
		if response.Code != http.StatusForbidden {
			t.Errorf("%v: status = %d", c.headers, response.Code)
			continue
		}
		if reason := logs.events(t)[0]["reason"]; reason != c.reason {
			t.Errorf("%v: reason = %v, want %s", c.headers, reason, c.reason)
		}
	}
}

// Rust: csrf_test.rs a_request_the_guard_allows_logs_nothing
func TestAllowedRequestLogsNothing(t *testing.T) {
	logs := &capturedLogs{}
	postLogout(t, logs, nil)
	postLogout(t, logs, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if logs.buffer.Len() != 0 {
		t.Fatalf("the guard logged on requests it passed: %s", logs.buffer.String())
	}
}

func TestSafeMethodsAreNeverChecked(t *testing.T) {
	chain := realAdmin(t, &capturedLogs{})
	for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
		request := httptest.NewRequest(method, "/api/health", nil)
		request.Header.Set("Sec-Fetch-Site", "cross-site")
		recorder := httptest.NewRecorder()
		chain.ServeHTTP(recorder, request)
		if recorder.Code == http.StatusForbidden {
			t.Errorf("%s was rejected", method)
		}
	}
}

func TestEveryStateChangingMethodIsChecked(t *testing.T) {
	chain := realAdmin(t, &capturedLogs{})
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		request := httptest.NewRequest(method, "/api/rules/1", nil)
		request.Header.Set("Sec-Fetch-Site", "cross-site")
		recorder := httptest.NewRecorder()
		chain.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", method, recorder.Code)
		}
	}
}

func TestLoggedValuesAreTruncatedAndFlagNonASCII(t *testing.T) {
	logs := &capturedLogs{}
	postLogout(t, logs, map[string]string{"Origin": strings.Repeat("a", 400), "Host": "app.test"})
	origin, _ := logs.events(t)[0]["origin"].(string)
	if len(origin) != logSafeMax {
		t.Fatalf("origin = %d bytes, want %d", len(origin), logSafeMax)
	}
	// 255 one-byte runes then a two-byte one: the cut must not split it.
	if got := logSafe(strings.Repeat("a", logSafeMax-1) + "é"); got != strings.Repeat("a", logSafeMax-1) {
		t.Fatalf("logSafe split a rune: %d bytes", len(got))
	}

	header := http.Header{"Origin": {"caf\xe9"}}
	if got := headerLogValue(header, "Origin"); got != "<non-ascii>" {
		t.Fatalf("non-ASCII header logged as %q", got)
	}
	if got := headerLogValue(header, "X-Absent"); got != "<none>" {
		t.Fatalf("absent header logged as %q", got)
	}
}
