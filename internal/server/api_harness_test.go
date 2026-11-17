package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/cache"
	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/dnsserver"
	"github.com/henry40408/noadd/internal/filter"
	"github.com/henry40408/noadd/internal/registry"
	"github.com/henry40408/noadd/internal/upstream"
	"github.com/henry40408/noadd/internal/version"
)

const testSetupToken = "ABCDE-FGHJK"

// apiHarness is the admin router over a real database, with an operator
// "admin" (password "admin") and one signed-in session.
type apiHarness struct {
	t        *testing.T
	handler  http.Handler
	db       *db.DB
	sessions *auth.Manager
	invalid  *auth.Limiter
	token    string
	userID   int64
	logs     *capturedLogs
	deps     APIDeps
}

type harnessOptions struct {
	noOperator   bool
	cookieSecure bool
	forwardAuth  *auth.ForwardAuth
	// logs, when set, receives the server log instead of a private buffer.
	logs *capturedLogs
}

func newAPIHarness(t *testing.T, options harnessOptions) *apiHarness {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(ctx) })

	logs := options.logs
	if logs == nil {
		logs = &capturedLogs{}
	}
	sessions := auth.NewManager(auth.ManagerConfig{DB: database, Logger: logs.logger()})
	harness := &apiHarness{t: t, db: database, sessions: sessions, logs: logs}
	harness.invalid = auth.NewLimiter(invalidSessionMaxAttempts, invalidSessionWindowSecs*time.Second, nil)
	harness.deps = APIDeps{
		DB:                    database,
		Sessions:              sessions,
		Work:                  auth.NewPasswordWork(2),
		LoginLimiter:          auth.NewLimiter(5, 60*time.Second, nil),
		InvalidSessionLimiter: harness.invalid,
		Lockout:               auth.NewLockout(nil),
		SetupToken:            auth.FixedSetupToken(testSetupToken, nil),
		ForwardAuth:           options.forwardAuth,
		CookieSecure:          options.cookieSecure,
		ServerInfo:            ServerInfo{DNSAddr: "127.0.0.1:53", HTTPAddr: "127.0.0.1:3000"},
		Version:               "test",
	}
	harness.wireFilterSide(ctx, database)
	t.Cleanup(harness.settleRebuilds)
	handler, err := New(Deps{API: &harness.deps, Slog: logs.logger()})
	if err != nil {
		t.Fatal(err)
	}
	harness.handler = handler
	if !options.noOperator {
		harness.seedOperator("admin", "admin")
	}
	return harness
}

// wireFilterSide gives the API a real engine, list manager, forwarder, cache
// and DNS handler. The forwarder's only upstream is unroutable, so nothing
// leaves the machine.
func (h *apiHarness) wireFilterSide(ctx context.Context, database *db.DB) {
	holder := filter.NewHolder(filter.NewFromNamed(nil, nil))
	h.deps.Filter = holder
	h.deps.ListManager = &filter.Manager{DB: database, Holder: holder, Downloader: filter.NewDownloader(version.UserAgent())}
	h.deps.Rebuild = filter.NewCoordinator()
	h.deps.Registry = registry.NewClient("http://127.0.0.1:1/filters.json", time.Minute, version.UserAgent())
	h.deps.Forwarder = upstream.New(ctx, upstream.Config{Servers: []string{"0.250.250.254:15353"}})
	h.deps.Cache = cache.New(cache.Config{CapacityBytes: 1 << 20, StaleWindow: time.Minute})
	h.deps.Handler = dnsserver.New(dnsserver.Config{Filter: holder, Cache: h.deps.Cache, Forwarder: h.deps.Forwarder})
}

// eventually polls until condition holds; rebuilds run in the background, so
// a test waits for their visible effect.
func (h *apiHarness) eventually(condition func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			h.t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// settleRebuilds waits until background rebuilds go quiet, so none outlives
// the database.
func (h *apiHarness) settleRebuilds() {
	for quiet := 0; quiet < 5; {
		if h.deps.Rebuild.Status().Rebuilding {
			quiet = 0
		} else {
			quiet++
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// seedOperator inserts an operator directly (bypassing the password policy,
// like the Rust fixtures) and, for the first one, a bound session.
func (h *apiHarness) seedOperator(username, password string) int64 {
	h.t.Helper()
	ctx := context.Background()
	hash, err := auth.HashPassword(password)
	if err != nil {
		h.t.Fatal(err)
	}
	userID, err := h.db.CreateUser(ctx, username, hash, time.Now().Unix())
	if err != nil {
		h.t.Fatal(err)
	}
	if h.token == "" {
		h.userID = userID
		h.token = h.bindSession(userID)
	}
	return userID
}

// bindSession stores a fresh session for userID and returns its raw token.
func (h *apiHarness) bindSession(userID int64) string {
	h.t.Helper()
	token := auth.NewSessionToken()
	tokenHash := auth.HashToken(token)
	now := time.Now().Unix()
	sessionID, err := h.db.InsertSession(context.Background(), db.NewSession{
		TokenHash: tokenHash, UserID: userID, CreatedAt: now, LastSeen: now,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.sessions.Store(tokenHash, auth.SessionInfo{
		SessionID: sessionID, UserID: userID, CreatedAt: now, LastSeen: now, LastReauthAt: now,
	})
	return token
}

// ageReauth makes the session's password proof stale, leaving it valid.
func (h *apiHarness) ageReauth(token string) {
	h.t.Helper()
	hash := auth.HashToken(token)
	info, found := h.sessions.Get(hash)
	if !found {
		h.t.Fatal("no such session")
	}
	info.LastReauthAt = time.Now().Unix() - auth.ReauthWindow - 1
	h.sessions.Store(hash, info)
}

// request describes one call.
type request struct {
	method  string
	path    string
	body    string
	cookie  string
	headers map[string]string
	// from is the X-Forwarded-For address; the peer is loopback, which is
	// trusted, as in the Rust tests that had no connection info.
	from string
}

func (h *apiHarness) do(r request) *httptest.ResponseRecorder {
	h.t.Helper()
	var body *strings.Reader
	if r.body != "" {
		body = strings.NewReader(r.body)
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(r.method, r.path, body)
	req.RemoteAddr = "127.0.0.1:50000"
	if r.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.cookie != "" {
		req.Header.Set("Cookie", "session="+r.cookie)
	}
	if r.from != "" {
		req.Header.Set("X-Forwarded-For", r.from)
	}
	for name, value := range r.headers {
		req.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, req)
	return recorder
}

// authed is a request signed in with the harness session.
func (h *apiHarness) authed(method, path, body string) *httptest.ResponseRecorder {
	return h.do(request{method: method, path: path, body: body, cookie: h.token})
}

func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder, into any) {
	t.Helper()
	if err := json.Unmarshal(recorder.Body.Bytes(), into); err != nil {
		t.Fatalf("body %q: %v", recorder.Body.String(), err)
	}
}

func wantStatus(t *testing.T, recorder *httptest.ResponseRecorder, want int) {
	t.Helper()
	if recorder.Code != want {
		t.Fatalf("status = %d, want %d (body %q)", recorder.Code, want, recorder.Body.String())
	}
}

// sessionTokenFromSetCookie returns the value of the first session cookie a
// response sets.
func sessionTokenFromSetCookie(recorder *httptest.ResponseRecorder) (string, bool) {
	for _, cookie := range recorder.Result().Cookies() {
		if (cookie.Name == "session" || cookie.Name == "__Host-session") && cookie.MaxAge >= 0 {
			return cookie.Value, true
		}
	}
	return "", false
}

const strongPassword = "vault-quartz-nimbus-84"

func ctxBackground() context.Context { return context.Background() }
