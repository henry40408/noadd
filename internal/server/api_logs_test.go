package server

import (
	"net/http"
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

// rustMobileConfig is the profile the Rust server answered with for the token
// "alpha-token" and the public URL below. It is never regenerated from Go output.
const rustMobileConfig = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>https://dns.example.test/dns-query/alpha-token</string>
			</dict>
			<key>PayloadDisplayName</key>
			<string>noadd DNS (alpha-token)</string>
			<key>PayloadIdentifier</key>
			<string>com.noadd.dns.alpha-token.dns</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>db7aea8a-a3be-57cc-a0d5-ce5b44136e11</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>noadd DNS (alpha-token)</string>
	<key>PayloadIdentifier</key>
	<string>com.noadd.dns.alpha-token</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>388a618e-d08e-5b04-ba88-7ad7e400475a</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadDescription</key>
	<string>Configures DNS-over-HTTPS to use noadd ad-blocking DNS server.</string>
	<key>PayloadScope</key>
	<string>System</string>
</dict>
</plist>`

func TestMobileConfigMatchesTheRustProfileByteForByte(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	if err := h.db.SetSetting(ctxBackground(), "public_url", "https://dns.example.test/"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, h.authed("POST", "/api/doh-tokens", `{"token":"alpha-token"}`), http.StatusOK)
	// No cookie: the token is the credential.
	recorder := h.do(request{method: "GET", path: "/api/mobileconfig/alpha-token"})
	wantStatus(t, recorder, http.StatusOK)
	if recorder.Body.String() != rustMobileConfig {
		t.Fatalf("body differs:\n%s\nwant:\n%s", recorder.Body.String(), rustMobileConfig)
	}
	for header, want := range map[string]string{
		"Content-Type":        "application/x-apple-aspen-config; charset=utf-8",
		"Content-Disposition": `attachment; filename="noadd-alpha-token.mobileconfig"`,
	} {
		if got := recorder.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
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
