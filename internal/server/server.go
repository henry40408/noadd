// Package server assembles the HTTP listener's handler: DoH, the admin UI
// assets and, in later steps, the admin API and pages.
package server

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/henry40408/noadd/internal/assets"
	"github.com/henry40408/noadd/internal/dnsserver"
)

// Deps is what the HTTP handler is built from.
type Deps struct {
	DoH *dnsserver.DoH
	// StaticFiles are the admin UI files, including apple-touch-icon.png; nil
	// means the embedded ones.
	StaticFiles fs.FS
	// HSTS stamps Strict-Transport-Security: max-age=HSTSMaxAgeSeconds on
	// every response.
	HSTS              bool
	HSTSMaxAgeSeconds uint64
	Slog              *slog.Logger
}

// New builds the handler for the single HTTP listener. DoH sits beside the
// admin routes on purpose: one listener, no admin-only address. Only the admin
// routes get the cache, framing and CSRF protections.
func New(deps Deps) (http.Handler, error) {
	logger := deps.Slog
	if logger == nil {
		logger = slog.Default()
	}
	admin, err := newAdminHandler(deps, logger)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	if deps.DoH != nil {
		deps.DoH.Register(mux)
	}
	mux.Handle("/", admin)

	var root http.Handler = mux
	if deps.HSTS {
		root = hsts(root, hstsHeaderValue(deps.HSTSMaxAgeSeconds))
	}
	return root, nil
}

// newAdminHandler serves the admin UI assets under the admin middleware.
func newAdminHandler(deps Deps, logger *slog.Logger) (http.Handler, error) {
	files := deps.StaticFiles
	if files == nil {
		files = assets.Static()
	}
	static, err := newStaticFiles(files)
	if err != nil {
		return nil, fmt.Errorf("load static files: %w", err)
	}
	icon, ok := static.files[appleTouchIconFile]
	if !ok {
		return nil, fmt.Errorf("static files lack %s", appleTouchIconFile)
	}

	mux := http.NewServeMux()
	mux.Handle("/"+appleTouchIconFile, appleTouchIconHandler(icon))
	mux.Handle("/", static)
	return adminChain(mux, logger), nil
}

// adminChain wraps h in the admin middleware, outermost first: security
// headers, no-store, then the CSRF guard. The no-store layer wraps the guard,
// so the guard's own 403 carries it.
func adminChain(h http.Handler, logger *slog.Logger) http.Handler {
	return securityHeaders(noStore(crossOriginGuard(h, logger)))
}
