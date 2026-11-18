package main

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// httpDrainTimeout is how long open HTTP requests get once shutdown starts.
const httpDrainTimeout = 5 * time.Second

// closeOnShutdown closes stop when srv starts shutting down. Event streams end
// on it (APIDeps.StopStreams): http.Server.Shutdown waits for every connection to
// go idle and would otherwise wait out the drain timeout on them. The close is
// once-guarded because RegisterOnShutdown callbacks run on every Shutdown call.
func closeOnShutdown(srv *http.Server, stop chan struct{}) {
	var once sync.Once
	srv.RegisterOnShutdown(func() { once.Do(func() { close(stop) }) })
}

// listenerFailures records a fatal DNS listener failure and ends the run, so
// HTTP and DoH do not keep serving without plain DNS.
type listenerFailures struct {
	failed atomic.Bool
	end    context.CancelFunc
}

// supervise runs serve and treats any return as fatal unless ctx ended first.
func (f *listenerFailures) supervise(ctx context.Context, serve func(context.Context) error, report func(error)) {
	err := serve(ctx)
	if err == nil || errors.Is(err, context.Canceled) || ctx.Err() != nil {
		return
	}
	report(err)
	f.failed.Store(true)
	f.end()
}
