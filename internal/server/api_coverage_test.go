package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/db"
)

func newForwardAuthHarness(t *testing.T) *apiHarness {
	t.Helper()
	forward, err := auth.NewForwardAuth("X-Remote-User", "127.0.0.0/8", "")
	if err != nil {
		t.Fatal(err)
	}
	return newAPIHarness(t, harnessOptions{forwardAuth: forward})
}

func TestForwardAuthProvisionsOperatorOnFirstSight(t *testing.T) {
	h := newForwardAuthHarness(t)
	headers := map[string]string{"X-Remote-User": "proxied"}
	wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", headers: headers}), http.StatusOK)

	row, found, err := h.db.GetUserAuth(t.Context(), "proxied")
	if err != nil || !found {
		t.Fatalf("operator not provisioned: found=%v err=%v", found, err)
	}
	// A second request resolves the same operator instead of creating another.
	wantStatus(t, h.do(request{method: "GET", path: "/api/auth/me", headers: headers}), http.StatusOK)
	if count, _ := h.db.CountUsers(t.Context()); count != 2 {
		t.Fatalf("users = %d, want admin + proxied", count)
	}
	if again, _, _ := h.db.GetUserAuth(t.Context(), "proxied"); again.ID != row.ID {
		t.Fatalf("operator id changed: %d -> %d", row.ID, again.ID)
	}
}

func TestForwardAuthRefusesUntrustedPeerAndRepeatedHeader(t *testing.T) {
	h := newForwardAuthHarness(t)
	untrusted := httptest.NewRequest("GET", "/api/auth/me", nil)
	untrusted.RemoteAddr = "203.0.113.9:4000"
	untrusted.Header.Set("X-Remote-User", "intruder")
	untrustedReply := httptest.NewRecorder()
	h.handler.ServeHTTP(untrustedReply, untrusted)
	wantStatus(t, untrustedReply, http.StatusUnauthorized)

	repeated := httptest.NewRequest("GET", "/api/auth/me", nil)
	repeated.RemoteAddr = "127.0.0.1:4000"
	repeated.Header.Add("X-Remote-User", "one")
	repeated.Header.Add("X-Remote-User", "two")
	repeatedReply := httptest.NewRecorder()
	h.handler.ServeHTTP(repeatedReply, repeated)
	wantStatus(t, repeatedReply, http.StatusUnauthorized)

	if _, found, _ := h.db.GetUserAuth(t.Context(), "intruder"); found {
		t.Fatal("an untrusted peer provisioned an operator")
	}
}

func TestForwardAuthReportsLookupFailureAs500(t *testing.T) {
	h := newForwardAuthHarness(t)
	if err := h.db.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	recorder := h.do(request{method: "GET", path: "/api/auth/me", headers: map[string]string{"X-Remote-User": "proxied"}})
	wantStatus(t, recorder, http.StatusInternalServerError)
}

func TestServerInfoReturnsConfiguredAddresses(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.authed("GET", "/api/server-info", "")
	wantStatus(t, recorder, http.StatusOK)
	var info ServerInfo
	decodeBody(t, recorder, &info)
	if info.DNSAddr != "127.0.0.1:53" || info.HTTPAddr != "127.0.0.1:3000" {
		t.Fatalf("info = %+v", info)
	}
}

func TestDohTokenLifecycle(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	created := h.authed("POST", "/api/doh-tokens", `{"token":"  laptop  "}`)
	wantStatus(t, created, http.StatusOK)
	var row db.DohTokenRow
	decodeBody(t, created, &row)
	if row.Token != "laptop" {
		t.Fatalf("token = %q, want it trimmed", row.Token)
	}

	var listed []db.DohTokenRow
	list := h.authed("GET", "/api/doh-tokens", "")
	wantStatus(t, list, http.StatusOK)
	decodeBody(t, list, &listed)
	if len(listed) != 1 || listed[0].ID != row.ID {
		t.Fatalf("listed = %+v", listed)
	}

	wantStatus(t, h.authed("DELETE", "/api/doh-tokens/"+itoa(row.ID), ""), http.StatusOK)
	if body := h.authed("GET", "/api/doh-tokens", "").Body.String(); body != "[]" {
		t.Fatalf("after delete: %s", body)
	}
}

func TestDohTokenRejectsUnusableValues(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, body := range []string{`{"token":""}`, `{"token":"   "}`, `{"token":"a/b"}`} {
		wantStatus(t, h.authed("POST", "/api/doh-tokens", body), http.StatusBadRequest)
	}
	wantStatus(t, h.authed("POST", "/api/doh-tokens", `{}`), http.StatusUnprocessableEntity)
	wantStatus(t, h.authed("DELETE", "/api/doh-tokens/not-a-number", ""), http.StatusBadRequest)
}

// The session lives in memory, so a closed database leaves the caller signed
// in and every read or write behind the session fails.
func TestAuthedRoutesAnswer500WhenTheDatabaseFails(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	if err := h.db.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	routes := []struct{ method, path, body string }{
		{"GET", "/api/users", ""},
		{"GET", "/api/sessions", ""},
		{"GET", "/api/doh-tokens", ""},
		{"POST", "/api/doh-tokens", `{"token":"t"}`},
		{"DELETE", "/api/doh-tokens/1", ""},
		{"GET", "/api/api-keys", ""},
		{"GET", "/api/rules", ""},
		{"DELETE", "/api/rules/1", ""},
		{"GET", "/api/logs", ""},
		{"DELETE", "/api/logs", ""},
		{"GET", "/api/auth/me", ""},
		{"GET", "/api/lists", ""},
		{"DELETE", "/api/lists/1", ""},
		{"POST", "/api/lists/update", ""},
		{"GET", "/api/stats/summary", ""},
		{"GET", "/api/stats/timeline", ""},
		{"GET", "/api/stats/top-domains", ""},
		{"GET", "/api/stats/top-clients", ""},
		{"GET", "/api/stats/top-upstreams", ""},
		{"GET", "/api/stats/v2/timeline", ""},
		{"GET", "/api/stats/v2/heatmap", ""},
		{"GET", "/api/stats/v2/breakdown", ""},
		{"GET", "/api/stats/v2/health", ""},
		{"GET", "/api/stats/v2/highlights", ""},
		{"GET", "/api/stats/v2/top-domains", ""},
		{"GET", "/api/stats/v2/top-clients", ""},
	}
	for _, route := range routes {
		recorder := h.authed(route.method, route.path, route.body)
		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("%s %s = %d, want 500", route.method, route.path, recorder.Code)
		}
	}
}

func TestWriteInternalErrorAnswersJSON(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeInternalError(recorder)
	wantStatus(t, recorder, http.StatusInternalServerError)
	if got := strings.TrimSpace(recorder.Body.String()); got != `{"error":"internal error"}` {
		t.Fatalf("body = %s", got)
	}
}

func TestMissingItemFieldNamesTheAbsentField(t *testing.T) {
	name, url := "n", "u"
	if got := missingItemField(batchAddItem{URL: &url}); got != "name" {
		t.Fatalf("got %q, want name", got)
	}
	if got := missingItemField(batchAddItem{Name: &name}); got != "url" {
		t.Fatalf("got %q, want url", got)
	}
}

func TestNewInvalidSessionLimiterAllowsThenRefuses(t *testing.T) {
	limiter := NewInvalidSessionLimiter()
	ip := netip.MustParseAddr("198.51.100.7")
	for i := 0; i < invalidSessionMaxAttempts; i++ {
		if !limiter.Check(ip) {
			t.Fatalf("refused after %d attempts, before the threshold", i)
		}
		limiter.Record(ip)
	}
	if limiter.Check(ip) {
		t.Fatal("still allowed past the threshold")
	}
}
