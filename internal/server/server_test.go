package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/henry40408/noadd/internal/assets"
	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/dnsserver"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestServer(t *testing.T, deps Deps) http.Handler {
	t.Helper()
	if deps.Slog == nil {
		deps.Slog = quietLogger()
	}
	handler, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func serve(handler http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// golden is a response captured from the Rust server. Status and headers are
// compared as captured; the body is the text in Body, or only its SHA-256 in
// BodySHA256 when the document is large, or absent when the test compares the
// body with something else.
type golden struct {
	Status     int
	Headers    [][]string
	Body       string
	BodySHA256 string
}

// rustGoldens were recorded from the Rust image ghcr.io/henry40408/noadd:0.41.1
// (date dropped). They are never regenerated from Go output.
var rustGoldens = map[string]golden{
	"api_apple_touch_icon": {
		Status: 200,
		Headers: [][]string{
			{"content-type", "image/png"},
			{"etag", "\"9b6f217c4c01188d\""},
			{"cache-control", "no-cache"},
			{"content-security-policy", "frame-ancestors 'none'"},
			{"x-frame-options", "DENY"},
			{"x-content-type-options", "nosniff"},
			{"content-length", "3809"},
		},
	},
	"api_doh_get_missing_param": {
		Status: 400,
		Headers: [][]string{
			{"content-type", "text/plain; charset=utf-8"},
			{"content-length", "55"},
		},
		Body: "Failed to deserialize query string: missing field `dns`",
	},
	"api_static_app_css": {
		Status: 200,
		Headers: [][]string{
			{"content-type", "text/css"},
			{"etag", "\"5cfec8610c318452\""},
			{"cache-control", "no-cache"},
			{"content-security-policy", "frame-ancestors 'none'"},
			{"x-frame-options", "DENY"},
			{"x-content-type-options", "nosniff"},
			{"content-length", "40621"},
		},
	},
	"api_static_app_css_304": {
		Status: 304,
		Headers: [][]string{
			{"etag", "\"5cfec8610c318452\""},
			{"cache-control", "no-cache"},
			{"content-security-policy", "frame-ancestors 'none'"},
			{"x-frame-options", "DENY"},
			{"x-content-type-options", "nosniff"},
		},
	},
	"api_static_app_js": {
		Status: 200,
		Headers: [][]string{
			{"content-type", "text/javascript"},
			{"etag", "\"ed445fb322955ecf\""},
			{"cache-control", "no-cache"},
			{"content-security-policy", "frame-ancestors 'none'"},
			{"x-frame-options", "DENY"},
			{"x-content-type-options", "nosniff"},
			{"content-length", "95767"},
		},
	},
	"api_static_favicon_svg": {
		Status: 200,
		Headers: [][]string{
			{"content-type", "image/svg+xml"},
			{"etag", "\"a33ba3d96655196b\""},
			{"cache-control", "no-cache"},
			{"content-security-policy", "frame-ancestors 'none'"},
			{"x-frame-options", "DENY"},
			{"x-content-type-options", "nosniff"},
			{"content-length", "566"},
		},
	},
	"api_stats_v2_bad_range": {
		Status: 400,
		Headers: [][]string{
			{"cache-control", "no-cache, no-store, must-revalidate, max-age=0"},
			{"pragma", "no-cache"},
			{"expires", "0"},
			{"content-security-policy", "frame-ancestors 'none'"},
			{"x-frame-options", "DENY"},
			{"x-content-type-options", "nosniff"},
			{"content-length", "0"},
		},
		Body: "",
	},
	"api_stats_v2_unknown_param": {
		Status: 400,
		Headers: [][]string{
			{"content-type", "text/plain; charset=utf-8"},
			{"cache-control", "no-cache, no-store, must-revalidate, max-age=0"},
			{"pragma", "no-cache"},
			{"expires", "0"},
			{"content-security-policy", "frame-ancestors 'none'"},
			{"x-frame-options", "DENY"},
			{"x-content-type-options", "nosniff"},
			{"content-length", "97"},
		},
		Body: "Failed to deserialize query string: bogus: unknown field `bogus`, expected `range` or `tz_offset`",
	},
	"api_docs": {
		Status: 200,
		Headers: [][]string{
			{"content-type", "text/html; charset=utf-8"},
			{"cache-control", "no-cache, no-store, must-revalidate, max-age=0"},
			{"pragma", "no-cache"},
			{"expires", "0"},
			{"content-security-policy", "frame-ancestors 'none'"},
			{"x-frame-options", "DENY"},
			{"x-content-type-options", "nosniff"},
			{"content-length", "18992"},
		},
		BodySHA256: "9d4ed5d4a15be477afe91e6467af02a856beb3fbc1ede651428fcd11776a929c",
	},
}

func loadGolden(t *testing.T, name string) golden {
	t.Helper()
	captured, found := rustGoldens[name]
	if !found {
		t.Fatalf("no Rust golden named %q", name)
	}
	return captured
}

func (g golden) header(name string) string {
	for _, pair := range g.Headers {
		if pair[0] == name {
			return pair[1]
		}
	}
	return ""
}

// assertMatchesGolden compares status, every captured header except the
// transport-computed ones, and the body.
func assertMatchesGolden(t *testing.T, got *httptest.ResponseRecorder, want golden) {
	t.Helper()
	assertHeadersMatchGolden(t, got, want)
	if want.BodySHA256 != "" {
		if digest := sha256.Sum256(got.Body.Bytes()); hex.EncodeToString(digest[:]) != want.BodySHA256 {
			t.Errorf("body digest differs from the Rust response (%d bytes)", got.Body.Len())
		}
		return
	}
	if got.Body.String() != want.Body {
		t.Errorf("body = %q, want %q", got.Body.String(), want.Body)
	}
}

// assertHeadersMatchGolden is assertMatchesGolden without the body, for the
// goldens whose text bodies were normalised (numbers replaced by placeholders).
func assertHeadersMatchGolden(t *testing.T, got *httptest.ResponseRecorder, want golden) {
	t.Helper()
	if got.Code != want.Status {
		t.Errorf("status = %d, want %d", got.Code, want.Status)
	}
	for _, pair := range want.Headers {
		if pair[0] == "content-length" {
			continue
		}
		if value := got.Header().Get(pair[0]); value != pair[1] {
			t.Errorf("header %s = %q, want %q", pair[0], value, pair[1])
		}
	}
}

// Rust: api_static_* and api_apple_touch_icon goldens.
func TestStaticFilesMatchTheRustGoldens(t *testing.T) {
	handler := newTestServer(t, Deps{})
	for path, name := range map[string]string{
		"/app.css":              "api_static_app_css",
		"/app.js":               "api_static_app_js",
		"/favicon.svg":          "api_static_favicon_svg",
		"/apple-touch-icon.png": "api_apple_touch_icon",
	} {
		t.Run(name, func(t *testing.T) {
			want := loadGolden(t, name)
			got := serve(handler, "GET", path, nil)
			// The text goldens are normalised, so the body is compared with the
			// file; the matching ETag shows the bytes equal the Rust build's.
			assertHeadersMatchGolden(t, got, want)
			file, err := fs.ReadFile(assets.Static(), strings.TrimPrefix(path, "/"))
			if err != nil || !bytes.Equal(got.Body.Bytes(), file) {
				t.Errorf("body is not the embedded file (err %v)", err)
			}

			revalidated := serve(handler, "GET", path, map[string]string{"If-None-Match": want.header("etag")})
			if revalidated.Code != http.StatusNotModified || revalidated.Body.Len() != 0 {
				t.Errorf("revalidation: %d with %d body bytes", revalidated.Code, revalidated.Body.Len())
			}
			for header, wantValue := range map[string]string{
				"ETag":            want.header("etag"),
				"Cache-Control":   "no-cache",
				"X-Frame-Options": "DENY",
			} {
				if got := revalidated.Header().Get(header); got != wantValue {
					t.Errorf("304 header %s = %q, want %q", header, got, wantValue)
				}
			}
		})
	}
}

func TestStaticFile304MatchesTheRustGolden(t *testing.T) {
	handler := newTestServer(t, Deps{})
	want := loadGolden(t, "api_static_app_css_304")
	got := serve(handler, "GET", "/app.css", map[string]string{"If-None-Match": want.header("etag")})
	assertMatchesGolden(t, got, want)
}

func TestIfNoneMatchAcceptsAListAndRejectsOtherTags(t *testing.T) {
	handler := newTestServer(t, Deps{})
	etag := loadGolden(t, "api_static_app_css").header("etag")
	for value, want := range map[string]int{
		`"nope", ` + etag: http.StatusNotModified,
		`"nope"`:          http.StatusOK,
		`W/` + etag:       http.StatusOK,
		`*`:               http.StatusOK,
	} {
		got := serve(handler, "GET", "/app.css", map[string]string{"If-None-Match": value}).Code
		if got != want {
			t.Errorf("If-None-Match %q = %d, want %d", value, got, want)
		}
	}
}

func TestUnknownPathIs404NotFoundWithAdminHeaders(t *testing.T) {
	handler := newTestServer(t, Deps{})
	for _, path := range []string{"/nope", "/", "/app.js/", "/static/app.js", "/../app.js", "//nope"} {
		response := serve(handler, "GET", path, nil)
		if response.Code != http.StatusNotFound && response.Code != http.StatusTemporaryRedirect {
			t.Errorf("%s: status = %d", path, response.Code)
		}
		if response.Code == http.StatusNotFound && response.Body.String() != "not found" {
			t.Errorf("%s: body = %q", path, response.Body.String())
		}
	}
	response := serve(handler, "GET", "/nope", nil)
	if got := response.Header().Get("Cache-Control"); got != noStoreCacheControl {
		t.Errorf("404 cache-control = %q", got)
	}
	if got := response.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("404 content-type = %q", got)
	}
}

func TestAppleTouchIconOnlyAnswersGetAndHead(t *testing.T) {
	handler := newTestServer(t, Deps{})
	if got := serve(handler, "HEAD", "/apple-touch-icon.png", nil).Code; got != http.StatusOK {
		t.Errorf("HEAD = %d", got)
	}
	response := serve(handler, "DELETE", "/apple-touch-icon.png", nil)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET,HEAD" {
		t.Errorf("DELETE = %d allow=%q", response.Code, response.Header().Get("Allow"))
	}
}

func TestServerNeedsTheAppleTouchIcon(t *testing.T) {
	if _, err := New(Deps{StaticFiles: fstest.MapFS{"app.js": {Data: []byte("x")}}}); err == nil {
		t.Fatal("New succeeded without apple-touch-icon.png")
	}
}

func TestContentETagMatchesRustDefaultHasher(t *testing.T) {
	static := assets.Static()
	for name, want := range map[string]string{
		"app.css":     loadGolden(t, "api_static_app_css").header("etag"),
		"app.js":      loadGolden(t, "api_static_app_js").header("etag"),
		"favicon.svg": loadGolden(t, "api_static_favicon_svg").header("etag"),
	} {
		body, err := fs.ReadFile(static, name)
		if err != nil {
			t.Fatal(err)
		}
		if got := contentETag(body); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
}

func TestSecurityHeadersAndNoStoreOnAdminResponses(t *testing.T) {
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/declared":
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		case "/streamed":
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "data")
			_ = http.NewResponseController(w).Flush()
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
	chain := adminChain(stub, quietLogger())

	plain := serve(chain, "GET", "/", nil)
	for header, want := range map[string]string{
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Cache-Control":           noStoreCacheControl,
		"Pragma":                  "no-cache",
		"Expires":                 "0",
	} {
		if got := plain.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	declared := serve(chain, "GET", "/declared", nil)
	if got := declared.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("declared policy overwritten: %q", got)
	}
	if got := declared.Header().Get("Pragma"); got != "" {
		t.Errorf("Pragma added next to a declared policy: %q", got)
	}
	if got := declared.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("security headers must overwrite: X-Frame-Options = %q", got)
	}

	streamed := serve(chain, "GET", "/streamed", nil)
	if streamed.Header().Get("X-Frame-Options") != "DENY" || !streamed.Flushed {
		t.Errorf("flush through the wrappers: headers=%v flushed=%v", streamed.Header(), streamed.Flushed)
	}
}

func TestHSTSCoversDoHAndAdminOnlyWhenEnabled(t *testing.T) {
	enabled := newTestServer(t, Deps{HSTS: true, HSTSMaxAgeSeconds: 600})
	if got := serve(enabled, "GET", "/app.css", nil).Header().Get("Strict-Transport-Security"); got != "max-age=600" {
		t.Errorf("HSTS = %q", got)
	}
	if got := serve(enabled, "GET", "/nope", nil).Header().Get("Strict-Transport-Security"); got != "max-age=600" {
		t.Errorf("HSTS on 404 = %q", got)
	}
	disabled := newTestServer(t, Deps{HSTSMaxAgeSeconds: 600})
	if got := serve(disabled, "GET", "/app.css", nil).Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS = %q while disabled", got)
	}
	if got := hstsHeaderValue(0); got != "max-age=0" {
		t.Errorf("max-age 0 must be sent to retract a pin: %q", got)
	}
}

func TestDoHRoutesGetNeitherAdminHeadersNorTheCSRFGuard(t *testing.T) {
	database, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	handler := newTestServer(t, Deps{
		DoH: dnsserver.NewDoH(dnsserver.DoHConfig{Store: database, Slog: quietLogger()}),
	})

	// Rust golden api_doh_bad_token: no admin headers on DoH responses.
	missing := serve(handler, "GET", "/dns-query/bad", nil)
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", missing.Code)
	}
	for _, header := range []string{"X-Frame-Options", "Content-Security-Policy", "Cache-Control"} {
		if got := missing.Header().Get(header); got != "" {
			t.Errorf("DoH response carries %s = %q", header, got)
		}
	}
	golden := loadGolden(t, "api_doh_get_missing_param")
	assertMatchesGolden(t, missing, golden)

	// A cross-site POST is not CSRF-checked on DoH (RFC 8484 clients are not browsers).
	cross := serve(handler, "POST", "/dns-query", map[string]string{
		"Sec-Fetch-Site": "cross-site", "Content-Type": "application/json",
	})
	if cross.Code != http.StatusUnsupportedMediaType {
		t.Errorf("cross-site DoH POST = %d, want the handler's 415", cross.Code)
	}
}

func TestHTTPServerBoundsHeadersButNotResponses(t *testing.T) {
	server := NewHTTPServer(":0", http.NotFoundHandler())
	if server.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout must be set")
	}
	if server.WriteTimeout != 0 || server.ReadTimeout != 0 {
		t.Errorf("WriteTimeout %v / ReadTimeout %v would cut the SSE stream", server.WriteTimeout, server.ReadTimeout)
	}
}
