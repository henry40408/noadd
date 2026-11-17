package server

import (
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"
)

// logSafeMax bounds a client-chosen value written to a log field.
const logSafeMax = 256

// crossOriginGuard rejects state-changing requests a browser reports, or
// reveals, to be cross-origin. It is header-only, stateless and has no token.
//
// On every method but GET, HEAD and OPTIONS:
//   - Sec-Fetch-Site decides when present: same-origin and none pass, anything
//     else is rejected, including same-site (a sibling subdomain or another
//     port), exactly the request SameSite=Lax lets through with the cookie.
//   - Origin is the fallback for browsers without Sec-Fetch-Site: its host and
//     port must match the request's Host. A mismatch or "null" is rejected.
//   - Neither header means a non-browser client, which carries no ambient
//     cookie and is allowed through.
//
// The 403 has no body: the gap was that the operator saw no trace, not that
// the caller got no explanation. Each rejection is logged as csrf.rejected.
func crossOriginGuard(next http.Handler, logger *slog.Logger) http.Handler {
	protection := http.NewCrossOriginProtection()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if protection.Check(r) == nil {
			next.ServeHTTP(w, r)
			return
		}
		logCSRFRejection(logger, r)
		w.WriteHeader(http.StatusForbidden)
	})
}

// csrfReason names the check that refused the request. A browser that said the
// request was cross-origin is an attempted CSRF; an old browser whose Origin
// merely failed to match Host is as likely a proxy rewriting Host. Those want
// different fixes.
//
//   - cross_site: Sec-Fetch-Site said so (spelling kept for existing queries).
//   - same_site_cross_origin: Sec-Fetch-Site: same-site, the one shape a
//     current browser both labels and sends the session cookie with.
//   - opaque_origin: Origin: null, a sandboxed iframe or cross-origin redirect.
//   - origin_mismatch: the Origin fallback disagreed.
func csrfReason(r *http.Request) string {
	// Check's errors are unexported, but its decision is a function of these
	// headers: a rejection with Sec-Fetch-Site present is the cross-origin
	// branch, one without is the Origin fallback.
	switch fetchSite := r.Header.Get("Sec-Fetch-Site"); {
	case strings.EqualFold(fetchSite, "same-site"):
		return "same_site_cross_origin"
	case fetchSite != "":
		return "cross_site"
	case r.Header.Get("Origin") == "null":
		return "opaque_origin"
	default:
		return "origin_mismatch"
	}
}

// logCSRFRejection emits the one csrf.rejected event. Origin, Host and
// Sec-Fetch-Site are logged together because telling a cross-site POST from a
// proxy rewrite needs all three.
func logCSRFRejection(logger *slog.Logger, r *http.Request) {
	host := r.Host
	if host == "" {
		host = "<none>"
	}
	logger.Warn("state-changing request rejected as cross-origin",
		"event", "csrf.rejected",
		"reason", csrfReason(r),
		"method", r.Method,
		"path", logSafe(r.URL.Path),
		"sec_fetch_site", logSafe(headerLogValue(r.Header, "Sec-Fetch-Site")),
		"origin", logSafe(headerLogValue(r.Header, "Origin")),
		"host", logSafe(host),
	)
}

// logSafe truncates a client-controlled value to logSafeMax bytes on a rune
// boundary.
func logSafe(value string) string {
	if len(value) <= logSafeMax {
		return value
	}
	end := logSafeMax
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}

// headerLogValue is the header to log, telling an absent header ("<none>")
// from a non-ASCII one ("<non-ascii>"). It is still caller-controlled: pass it
// through logSafe.
func headerLogValue(header http.Header, name string) string {
	values := header.Values(name)
	if len(values) == 0 {
		return "<none>"
	}
	for i := 0; i < len(values[0]); i++ {
		if c := values[0][i]; c > 0x7e || (c < 0x20 && c != '\t') {
			return "<non-ascii>"
		}
	}
	return values[0]
}
