package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/henry40408/noadd/internal/db"
)

func ptr[T any](value T) *T { return &value }

func (h *apiHarness) seedLogs(entries ...db.QueryLogEntry) {
	h.t.Helper()
	if err := h.db.InsertQueryLogs(ctxBackground(), entries); err != nil {
		h.t.Fatal(err)
	}
}

func TestLogsPagingFilteringAndTotal(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	var empty logsResponseForTest
	decodeBody(t, h.authed("GET", "/api/logs", ""), &empty)
	if empty.Total != 0 || empty.Logs == nil || len(empty.Logs) != 0 {
		t.Fatalf("empty = %+v", empty)
	}
	h.seedLogs(
		db.QueryLogEntry{Timestamp: 100, Domain: "ads.example.com", QueryType: "A", ClientIP: "10.0.0.1", Blocked: true},
		db.QueryLogEntry{Timestamp: 200, Domain: "ok.example.com", QueryType: "AAAA", ClientIP: "10.0.0.2", DohToken: ptr("tok")},
		db.QueryLogEntry{Timestamp: 300, Domain: "other.test", QueryType: "A", ClientIP: "10.0.0.2"},
	)
	cases := map[string]struct {
		total int64
		first string
	}{
		"/api/logs":                      {3, "other.test"},
		"/api/logs?limit=1&offset=1":     {3, "ok.example.com"},
		"/api/logs?blocked=true":         {1, "ads.example.com"},
		"/api/logs?search=ok.":           {1, "ok.example.com"},
		"/api/logs?search=*.example.com": {2, "ok.example.com"},
		"/api/logs?query_type=AAAA":      {1, "ok.example.com"},
		"/api/logs?token=tok":            {1, "ok.example.com"},
		"/api/logs?unknown=1&limit=100":  {3, "other.test"},
	}
	for path, want := range cases {
		var got logsResponseForTest
		decodeBody(t, h.authed("GET", path, ""), &got)
		if got.Total != want.total || len(got.Logs) == 0 || got.Logs[0].Domain != want.first {
			t.Errorf("%s = total %d first %v, want %d %s", path, got.Total, got.Logs, want.total, want.first)
		}
	}
}

type logsResponseForTest struct {
	Logs  []db.QueryLogEntry `json:"logs"`
	Total int64              `json:"total"`
}

func TestLogsRejectBadQueryParameters(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for path, want := range map[string]string{
		"/api/logs?limit=abc":                  "Failed to deserialize query string: limit: invalid digit found in string",
		"/api/logs?offset=":                    "Failed to deserialize query string: offset: cannot parse integer from empty string",
		"/api/logs?blocked=maybe":              "Failed to deserialize query string: blocked: provided string was not `true` or `false`",
		"/api/logs?limit=99999999999999999999": "Failed to deserialize query string: limit: number too large to fit in target type",
	} {
		recorder := h.authed("GET", path, "")
		wantStatus(t, recorder, http.StatusBadRequest)
		if recorder.Body.String() != want {
			t.Errorf("%s body %q, want %q", path, recorder.Body.String(), want)
		}
	}
}

func TestDeleteLogsClearsEverything(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedLogs(db.QueryLogEntry{Timestamp: 100, Domain: "a.test", QueryType: "A", ClientIP: "10.0.0.1"})
	wantStatus(t, h.authed("DELETE", "/api/logs", ""), http.StatusOK)
	var got logsResponseForTest
	decodeBody(t, h.authed("GET", "/api/logs", ""), &got)
	if got.Total != 0 {
		t.Fatalf("total = %d", got.Total)
	}
}

func TestMobileConfigMatchesTheRustProfileByteForByte(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	raw, err := os.ReadFile("testdata/rust/api_mobileconfig.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Headers [][2]string `json:"headers"`
		BodyB64 string      `json:"body_b64"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	want, err := base64.StdEncoding.DecodeString(golden.BodyB64)
	if err != nil {
		t.Fatal(err)
	}

	if err := h.db.SetSetting(ctxBackground(), "public_url", "https://dns.example.test/"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, h.authed("POST", "/api/doh-tokens", `{"token":"alpha-token"}`), http.StatusOK)
	// No cookie: the token is the credential.
	recorder := h.do(request{method: "GET", path: "/api/mobileconfig/alpha-token"})
	wantStatus(t, recorder, http.StatusOK)
	if recorder.Body.String() != string(want) {
		t.Fatalf("body differs:\n%s\nwant:\n%s", recorder.Body.String(), want)
	}
	for _, header := range golden.Headers[:2] {
		if got := recorder.Header().Get(header[0]); got != header[1] {
			t.Errorf("%s = %q, want %q", header[0], got, header[1])
		}
	}
}

func TestMobileConfigErrors(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.do(request{method: "GET", path: "/api/mobileconfig/unknown"}), http.StatusNotFound)
	wantStatus(t, h.authed("POST", "/api/doh-tokens", `{"token":"t1"}`), http.StatusOK)
	wantStatus(t, h.do(request{method: "GET", path: "/api/mobileconfig/t1"}), http.StatusBadRequest)
	if err := h.db.SetSetting(ctxBackground(), "public_url", ""); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, h.do(request{method: "GET", path: "/api/mobileconfig/t1"}), http.StatusBadRequest)
}
