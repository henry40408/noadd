package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/cache"
	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/dnsserver"
	"github.com/henry40408/noadd/internal/events"
	"github.com/henry40408/noadd/internal/filter"
	"github.com/henry40408/noadd/internal/netx"
	"github.com/henry40408/noadd/internal/querylog"
	"github.com/henry40408/noadd/internal/registry"
	"github.com/henry40408/noadd/internal/upstream"
)

const (
	// maxJSONBody matches axum's default body limit for the Json extractor.
	maxJSONBody = 2 << 20
	// failedKeyPrefixLen is how much of a rejected API key reaches the log:
	// "noadd_" plus four characters, the part shown at creation.
	failedKeyPrefixLen = 10
)

// APIDeps is what the admin JSON API is built from. A nil APIDeps in Deps
// leaves the API routes unmounted.
type APIDeps struct {
	DB       *db.DB
	Sessions *auth.Manager
	Work     *auth.PasswordWork
	// LoginLimiter bounds password attempts per source address;
	// InvalidSessionLimiter counts unknown session cookies separately so
	// cookie guessing cannot spend an operator's login budget.
	LoginLimiter          *auth.Limiter
	InvalidSessionLimiter *auth.Limiter
	Lockout               *auth.Lockout
	SetupToken            *auth.SetupToken
	ForwardAuth           *auth.ForwardAuth
	Trusted               netx.TrustedProxies
	// CookieSecure sets Secure on the session cookie.
	CookieSecure bool
	ServerInfo   ServerInfo
	// Version is the build version reported by /api/health.
	Version string
	// Filter is the live rule engine; ListManager downloads lists and rebuilds
	// it; Rebuild serializes those rebuilds.
	Filter      *filter.Holder
	ListManager *filter.Manager
	Rebuild     *filter.Coordinator
	Registry    *registry.Client
	// Forwarder, Cache and Handler are the DNS side that runtime settings
	// reconfigure.
	Forwarder *upstream.Forwarder
	Cache     *cache.Cache
	Handler   *dnsserver.Handler
	// Events is the tick source behind /api/events; LogEvents feeds its log
	// events. A nil Events leaves the stream unmounted.
	Events    *events.Hub
	LogEvents *querylog.Logger
	// StopStreams is closed when the HTTP server starts shutting down, which
	// ends every open event stream; Shutdown would otherwise wait on them.
	// Wire it with http.Server.RegisterOnShutdown.
	StopStreams <-chan struct{}
	// Now is the clock for expiry and reauth stamps; nil means time.Now.
	Now func() time.Time
}

// api holds the dependencies shared by every admin handler.
type api struct {
	APIDeps
	log *slog.Logger
}

func newAPI(deps APIDeps, logger *slog.Logger) *api {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	return &api{APIDeps: deps, log: logger}
}

func (a *api) clientIP(r *http.Request) netip.Addr {
	return netx.RequestClientIP(r, a.Trusted)
}

// writeCtx keeps a write running after the client disconnects, so a request
// cannot leave a half-applied change behind.
func writeCtx(r *http.Request) context.Context {
	return context.WithoutCancel(r.Context())
}

// errorBody is the JSON shape of an error that carries a reason.
type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorBody{Error: message})
}

func writeInternalError(w http.ResponseWriter) {
	writeAPIError(w, http.StatusInternalServerError, "internal error")
}

// writeStatus answers with an empty body, like an axum StatusCode rejection.
func writeStatus(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}

// decodeJSON reads a JSON request body into dst, answering like axum's Json
// extractor: 415 for a wrong content type, 400 for syntax errors, 413 for an
// oversized body and 422 for well-formed JSON of the wrong shape. It reports
// whether decoding succeeded.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeText(w, http.StatusUnsupportedMediaType,
			"Expected request with `Content-Type: application/json`")
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeText(w, http.StatusRequestEntityTooLarge, "length limit exceeded")
			return false
		}
		writeText(w, http.StatusBadRequest, "Failed to buffer the request body")
		return false
	}
	if err := json.Unmarshal(body, dst); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			writeText(w, http.StatusUnprocessableEntity, "Failed to deserialize the JSON body into the target type")
			return false
		}
		writeText(w, http.StatusBadRequest, "Failed to parse the request body as JSON")
		return false
	}
	return true
}

// isJSONContentType accepts application/json and any +json subtype.
func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	return mediaType == "application/json" ||
		(strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json"))
}

// missingField answers 422 as serde does for an absent required field.
func missingField(w http.ResponseWriter, name string) {
	writeText(w, http.StatusUnprocessableEntity,
		"Failed to deserialize the JSON body into the target type: missing field `"+name+"`")
}

// logSafeText bounds client-controlled text written to a log line.
func logSafeText(value string, max int) string {
	if len(value) <= max {
		return value
	}
	end := max
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}
