package dnsserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/netx"
)

type dohFixture struct {
	mux      http.Handler
	database *db.DB
}

func newDoHFixture(t *testing.T, options handlerOptions) *dohFixture {
	t.Helper()
	database, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(context.Background()) })
	mux := http.NewServeMux()
	NewDoH(DoHConfig{
		Handler: newTestHandler(t, options).Handler,
		Store:   database,
		Trusted: netx.TrustedProxies{},
		Slog:    quietLogger(),
	}).Register(mux)
	return &dohFixture{mux: mux, database: database}
}

func (f *dohFixture) do(method, target, contentType string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	f.mux.ServeHTTP(recorder, request)
	return recorder
}

func encodeQuery(wire []byte) string { return base64.RawURLEncoding.EncodeToString(wire) }

// Rust: doh_test.rs test_doh_get_no_token
func TestDoHGetWithoutTokenIsOpenByDefault(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{blocked: []string{blockedDomain}})
	wire := queryBytes(t, 1234, blockedDomain+".", mdns.TypeA)

	response := fixture.do("GET", "/dns-query?dns="+encodeQuery(wire), "", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "application/dns-message" {
		t.Fatalf("content-type = %q", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "max-age=300" {
		t.Fatalf("cache-control = %q, want the blocked answer's TTL", got)
	}
}

// Rust: doh_test.rs test_doh_post_no_token
func TestDoHPostWithoutTokenIsOpenByDefault(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{blocked: []string{blockedDomain}})
	wire := queryBytes(t, 1234, blockedDomain+".", mdns.TypeA)

	response := fixture.do("POST", "/dns-query", "application/dns-message", wire)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if unpack(t, response.Body.Bytes()).Id != 1234 {
		t.Fatal("response ID does not echo the query")
	}
}

// Rust: doh_test.rs test_doh_upstream_failure_returns_servfail_not_500
func TestDoHUpstreamFailureReturnsServfailNot500(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{upstreamAddr: "127.0.0.1:9", upstreamTimeout: 500 * time.Millisecond})
	wire := queryBytes(t, 1234, "example.com.", mdns.TypeA)

	response := fixture.do("POST", "/dns-query", "application/dns-message", wire)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, RFC 8484 wants 200 with SERVFAIL", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "application/dns-message" {
		t.Fatalf("content-type = %q", got)
	}
	message := unpack(t, response.Body.Bytes())
	if message.Rcode != mdns.RcodeServerFailure || message.Id != 1234 {
		t.Fatalf("rcode = %d, id = %d", message.Rcode, message.Id)
	}
	if got := response.Header().Get("Cache-Control"); got != "max-age=0" {
		t.Fatalf("cache-control = %q", got)
	}
}

// Rust: doh_test.rs test_doh_post_wrong_content_type_returns_415
func TestDoHPostWrongContentTypeIs415(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{})
	wire := queryBytes(t, 1, "example.com.", mdns.TypeA)

	response := fixture.do("POST", "/dns-query", "application/json", wire)

	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d", response.Code)
	}
	if got := response.Body.String(); got != "expected Content-Type: application/dns-message" {
		t.Fatalf("body = %q", got)
	}
}

func TestDoHPostContentTypeRules(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{blocked: []string{blockedDomain}})
	wire := queryBytes(t, 1, blockedDomain+".", mdns.TypeA)
	cases := map[string]string{
		"absent header is accepted":      "",
		"parameters are ignored":         "application/dns-message; charset=utf-8",
		"the match ignores case":         "Application/DNS-Message",
		"surrounding space is tolerated": " application/dns-message ",
	}
	for name, contentType := range cases {
		request := httptest.NewRequest("POST", "/dns-query", bytes.NewReader(wire))
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		recorder := httptest.NewRecorder()
		fixture.mux.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Errorf("%s: status = %d", name, recorder.Code)
		}
	}
}

// Rust: doh_test.rs test_doh_post_malformed_body_returns_400
func TestDoHPostMalformedBodyIs400(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{})

	response := fixture.do("POST", "/dns-query", "application/dns-message", []byte{0xde, 0xad, 0xbe, 0xef})

	if response.Code != http.StatusBadRequest || response.Body.String() != "malformed DNS message" {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

// Rust: doh_test.rs test_doh_get_malformed_body_returns_400
func TestDoHGetMalformedBodyIs400(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{})

	response := fixture.do("GET", "/dns-query?dns="+encodeQuery([]byte{0xde, 0xad, 0xbe, 0xef}), "", nil)

	if response.Code != http.StatusBadRequest || response.Body.String() != "malformed DNS message" {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

// Rust: doh_test.rs test_doh_token_required_when_configured
func TestDoHTokenRequiredWhenPolicyIsDeny(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{blocked: []string{blockedDomain}})
	ctx := context.Background()
	if _, err := fixture.database.AddDohToken(ctx, "my-secret-token"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.SetSetting(ctx, "doh_access_policy", "deny"); err != nil {
		t.Fatal(err)
	}
	encoded := encodeQuery(queryBytes(t, 1234, blockedDomain+".", mdns.TypeA))

	for target, want := range map[string]int{
		"/dns-query?dns=" + encoded:                     http.StatusForbidden,
		"/dns-query/wrong-token?dns=" + encoded:         http.StatusForbidden,
		"/dns-query/my-secret-token?dns=" + encoded:     http.StatusOK,
		"/dns-query/my-secret-token?x=1&dns=" + encoded: http.StatusOK,
	} {
		if got := fixture.do("GET", target, "", nil).Code; got != want {
			t.Errorf("GET %s = %d, want %d", target, got, want)
		}
	}
}

func TestDoHPolicyValueIsTrimmedAndOnlyDenyDenies(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{})
	encoded := encodeQuery(queryBytes(t, 1, blockedDomain+".", mdns.TypeA))
	for policy, want := range map[string]int{
		" deny\n": http.StatusForbidden,
		"allow":   http.StatusOK,
		"DENY":    http.StatusOK,
		"":        http.StatusOK,
	} {
		if err := fixture.database.SetSetting(context.Background(), "doh_access_policy", policy); err != nil {
			t.Fatal(err)
		}
		if got := fixture.do("GET", "/dns-query?dns="+encoded, "", nil).Code; got != want {
			t.Errorf("policy %q: status = %d, want %d", policy, got, want)
		}
	}
}

func TestDoHPostChecksTokenAndPolicy(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{blocked: []string{blockedDomain}})
	ctx := context.Background()
	if _, err := fixture.database.AddDohToken(ctx, "tok"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.SetSetting(ctx, "doh_access_policy", "deny"); err != nil {
		t.Fatal(err)
	}
	wire := queryBytes(t, 1, blockedDomain+".", mdns.TypeA)
	for target, want := range map[string]int{
		"/dns-query":         http.StatusForbidden,
		"/dns-query/nope":    http.StatusForbidden,
		"/dns-query/tok":     http.StatusOK,
		"/dns-query/tok%20x": http.StatusForbidden,
	} {
		got := fixture.do("POST", target, "application/dns-message", wire).Code
		if got != want {
			t.Errorf("POST %s = %d, want %d", target, got, want)
		}
	}
}

// Rust: the extractors run before authorisation, so a request that fails to
// parse is answered 400 or 413 even when its token is wrong.
func TestDoHRequestIsParsedBeforeItIsAuthorised(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{})
	if err := fixture.database.SetSetting(context.Background(), "doh_access_policy", "deny"); err != nil {
		t.Fatal(err)
	}

	missing := fixture.do("GET", "/dns-query/wrong", "", nil)
	if missing.Code != http.StatusBadRequest ||
		missing.Body.String() != "Failed to deserialize query string: missing field `dns`" {
		t.Fatalf("missing dns: %d %q", missing.Code, missing.Body.String())
	}
	duplicate := fixture.do("GET", "/dns-query?dns=AA&dns=AA", "", nil)
	if duplicate.Code != http.StatusBadRequest ||
		duplicate.Body.String() != "Failed to deserialize query string: duplicate field `dns`" {
		t.Fatalf("duplicate dns: %d %q", duplicate.Code, duplicate.Body.String())
	}
	oversized := fixture.do("POST", "/dns-query/wrong", "application/json", make([]byte, maxDoHBodyBytes+1))
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", oversized.Code)
	}
}

func TestDoHBadBase64Is400(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{})
	for _, bad := range []string{"!!!", "AAAA=", "AB%20"} {
		response := fixture.do("GET", "/dns-query?dns="+bad, "", nil)
		if response.Code != http.StatusBadRequest || response.Body.String() != "invalid base64url encoding" {
			t.Errorf("dns=%s: %d %q", bad, response.Code, response.Body.String())
		}
	}
	// Non-canonical trailing bits are refused as the Rust decoder did.
	if got := fixture.do("GET", "/dns-query?dns=AB", "", nil).Body.String(); got != "invalid base64url encoding" {
		t.Errorf("trailing bits: %q", got)
	}
}

func TestDoHBodyAtTheLimitIsReadAndOneOverIsRefused(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{})

	garbage := bytes.Repeat([]byte{0xff}, maxDoHBodyBytes)
	atLimit := fixture.do("POST", "/dns-query", "application/dns-message", garbage)
	if atLimit.Code != http.StatusBadRequest {
		t.Fatalf("at limit: %d, want 400 (read fully, then not a DNS message)", atLimit.Code)
	}
	over := fixture.do("POST", "/dns-query", "application/dns-message", make([]byte, maxDoHBodyBytes+1))
	if over.Code != http.StatusRequestEntityTooLarge ||
		over.Body.String() != "Failed to buffer the request body: length limit exceeded" {
		t.Fatalf("over limit: %d %q", over.Code, over.Body.String())
	}
}

func TestDoHOtherMethodsAre405(t *testing.T) {
	fixture := newDoHFixture(t, handlerOptions{})
	for _, path := range []string{"/dns-query", "/dns-query/tok"} {
		response := fixture.do("PUT", path, "", nil)
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET,HEAD,POST" {
			t.Errorf("PUT %s: %d allow=%q", path, response.Code, response.Header().Get("Allow"))
		}
	}
}

func TestDoHClientIPFollowsTrustedProxies(t *testing.T) {
	trusted, err := netx.ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(context.Background()) })
	handler := newTestHandler(t, handlerOptions{blocked: []string{blockedDomain}})
	mux := http.NewServeMux()
	NewDoH(DoHConfig{Handler: handler.Handler, Store: database, Trusted: trusted, Slog: quietLogger()}).Register(mux)
	encoded := encodeQuery(queryBytes(t, 1, blockedDomain+".", mdns.TypeA))

	for remote, wantClient := range map[string]string{
		"10.1.1.1:5000":    "198.51.100.7", // trusted proxy: the forwarded address
		"203.0.113.9:5000": "203.0.113.9",  // untrusted peer: the header is ignored
	} {
		request := httptest.NewRequest("GET", "/dns-query?dns="+encoded, nil)
		request.RemoteAddr = remote
		request.Header.Set("X-Forwarded-For", "198.51.100.7")
		mux.ServeHTTP(httptest.NewRecorder(), request)
		waitFor(t, "log entry for "+remote, func() bool {
			for _, entry := range handler.logger.snapshot() {
				if entry.ClientIP == wantClient {
					return true
				}
			}
			return false
		})
	}
}

func TestDoHRecordsTheTokenNameInTheLog(t *testing.T) {
	database, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(context.Background()) })
	if _, err := database.AddDohToken(context.Background(), "laptop"); err != nil {
		t.Fatal(err)
	}
	handler := newTestHandler(t, handlerOptions{blocked: []string{blockedDomain}})
	mux := http.NewServeMux()
	NewDoH(DoHConfig{Handler: handler.Handler, Store: database, Slog: quietLogger()}).Register(mux)
	encoded := encodeQuery(queryBytes(t, 1, blockedDomain+".", mdns.TypeA))

	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest("GET", "/dns-query/laptop?dns="+encoded, nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	waitFor(t, "log entry", func() bool {
		entries := handler.logger.snapshot()
		return len(entries) == 1 && entries[0].DohToken != nil && *entries[0].DohToken == "laptop"
	})
}

func TestFormDecode(t *testing.T) {
	for input, want := range map[string]string{
		"plain":   "plain",
		"a+b":     "a b",
		"a%20b":   "a b",
		"100%":    "100%",
		"%zz":     "%zz",
		"%4":      "%4",
		"%41%42":  "AB",
		"x%2Fy":   "x/y",
		"%e4%bd":  "�",
		"trail%2": "trail%2",
	} {
		if got := formDecode(input); got != want {
			t.Errorf("formDecode(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPostContentTypeRejectsNonASCII(t *testing.T) {
	header := http.Header{"Content-Type": {"application/dns-message\xff"}}
	if postContentTypeOK(header) {
		t.Fatal("non-ASCII value accepted")
	}
}
