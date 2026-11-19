package server

import (
	"fmt"
	"net/http"
)

// noStoreCacheControl is what admin responses carry. no-store is what matters;
// the rest cover caches that mishandle it alone.
const noStoreCacheControl = "no-cache, no-store, must-revalidate, max-age=0"

// beforeHeaders runs hook on the response header just before the status line
// is written, so it sees what the handler chose and can overwrite it.
func beforeHeaders(next http.Handler, hook func(http.Header)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&hookedWriter{ResponseWriter: w, hook: hook}, r)
	})
}

type hookedWriter struct {
	http.ResponseWriter
	hook        func(http.Header)
	wroteHeader bool
}

func (w *hookedWriter) runHook() {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.hook(w.Header())
}

func (w *hookedWriter) WriteHeader(status int) {
	// 1xx responses are interim; the final status line has not been sent.
	if status >= 200 || status == http.StatusSwitchingProtocols {
		w.runHook()
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *hookedWriter) Write(body []byte) (int, error) {
	w.runHook()
	return w.ResponseWriter.Write(body)
}

// Flush keeps server-sent events working through the wrapper.
func (w *hookedWriter) Flush() {
	w.runHook()
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *hookedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// noStore stamps Cache-Control: no-store (plus Pragma and Expires for
// HTTP/1.0) on every response that does not already declare a caching policy.
//
// It keys on an existing Cache-Control rather than the path: the embedded
// assets set no-cache and an ETag and must keep their 304 revalidation, and
// the event stream keeps its own no-cache.
func noStore(next http.Handler) http.Handler {
	return beforeHeaders(next, func(header http.Header) {
		if _, declared := header["Cache-Control"]; declared {
			return
		}
		header.Set("Cache-Control", noStoreCacheControl)
		header.Set("Pragma", "no-cache")
		header.Set("Expires", "0")
	})
}

// securityHeaders stamps the browser-hardening headers on every admin
// response, overwriting any value the handler set.
//
// frame-ancestors and X-Frame-Options overlap on purpose, for browsers lacking
// the former. A full CSP is out of scope: inline style attributes would still
// need style-src 'unsafe-inline'. The headers are not TLS-conditional: a
// plain-HTTP LAN appliance can be framed just the same.
func securityHeaders(next http.Handler) http.Handler {
	return beforeHeaders(next, func(header http.Header) {
		header.Set("Content-Security-Policy", "frame-ancestors 'none'")
		header.Set("X-Frame-Options", "DENY")
		header.Set("X-Content-Type-Options", "nosniff")
	})
}

// hstsHeaderValue is max-age only. includeSubDomains and preload are omitted
// on purpose: noadd cannot know whether the operator serves other things on
// sibling subdomains, and preload is effectively irreversible.
func hstsHeaderValue(maxAgeSeconds uint64) string {
	return fmt.Sprintf("max-age=%d", maxAgeSeconds)
}

// hsts stamps Strict-Transport-Security on every response, DoH included: the
// scheme is the same, and DoH is HTTPS-only anyway.
func hsts(next http.Handler, value string) http.Handler {
	return beforeHeaders(next, func(header http.Header) {
		header.Set("Strict-Transport-Security", value)
	})
}
