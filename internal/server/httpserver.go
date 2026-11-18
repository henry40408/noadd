package server

import (
	"net/http"
	"time"
)

const (
	// readHeaderTimeout stops a client holding a connection open by trickling
	// its request line and headers (slowloris).
	readHeaderTimeout = 10 * time.Second
	// idleTimeout closes keep-alive connections nobody is using.
	idleTimeout = 120 * time.Second
)

// NewHTTPServer wraps handler in the http.Server the listener runs.
//
// There is deliberately no WriteTimeout and no ReadTimeout: both are
// connection deadlines that would cut the /api/events stream (SSE) after a
// fixed time. A slow reader of ordinary responses costs one goroutine, as it
// did in the Rust server.
func NewHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
}
