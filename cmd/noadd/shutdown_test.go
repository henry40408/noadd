package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestShutdownClosesTheStreamStopChannelOnce(t *testing.T) {
	srv := &http.Server{}
	stop := make(chan struct{})
	closeOnShutdown(srv, stop)
	select {
	case <-stop:
		t.Fatal("closed before shutdown")
	default:
	}
	// Shutdown runs its callbacks on every call; a second close would panic.
	for range 2 {
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// Shutdown starts the callbacks in their own goroutines.
	select {
	case <-stop:
	case <-time.After(waitFor):
		t.Fatal("not closed by shutdown")
	}
}

func TestAListenerFailureEndsTheRunAndIsRemembered(t *testing.T) {
	ended := false
	failures := &listenerFailures{end: func() { ended = true }}
	var reported error
	failures.supervise(context.Background(), func(context.Context) error { return errors.New("boom") }, func(err error) { reported = err })
	if !ended || !failures.failed.Load() || reported == nil {
		t.Fatalf("ended %v failed %v reported %v", ended, failures.failed.Load(), reported)
	}
}

func TestAListenerReturningAfterCancelIsNotAFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	failures := &listenerFailures{end: func() { t.Fatal("ended the run") }}
	failures.supervise(ctx, func(context.Context) error { return errors.New("closed") }, func(error) { t.Fatal("reported") })
	failures.supervise(context.Background(), func(context.Context) error { return nil }, func(error) { t.Fatal("reported") })
	if failures.failed.Load() {
		t.Fatal("marked failed")
	}
}

func TestResolveTLSDefault(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		override *bool
		tls      bool
		want     bool
	}{{nil, true, true}, {nil, false, false}, {&yes, false, true}, {&no, true, false}}
	for _, c := range cases {
		if got := resolveTLSDefault(c.override, c.tls); got != c.want {
			t.Errorf("%v %v = %v", c.override, c.tls, got)
		}
	}
}

// waitForLog polls a buffer shared with a running serve.
func waitForLog(t *testing.T, buffer *syncBuffer, fragment string) {
	t.Helper()
	deadline := time.Now().Add(waitFor)
	for !strings.Contains(buffer.String(), fragment) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in %q", fragment, buffer.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Serving and shutting down in-process must leave no goroutine behind. This
// stands in for goleak, which the project does not depend on.
func TestServeLeavesNoGoroutinesBehindAfterSIGTERM(t *testing.T) {
	dir := t.TempDir()
	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	opts := newOptions()
	dbPath := filepath.Join(dir, "n.sqlite3")
	opts.dbPath = &dbPath
	opts.dnsAddr, opts.httpAddr = "127.0.0.1:0", "127.0.0.1:0"
	// The first signal.Notify starts a runtime goroutine that never exits.
	warmup := make(chan os.Signal, 1)
	signal.Notify(warmup, syscall.SIGUSR2)
	signal.Stop(warmup)
	before := runtime.NumGoroutine()

	result := make(chan error, 1)
	go func() { result <- serve(process{stdout: stdout, stderr: stderr}, opts) }()
	waitForLog(t, stdout, "event=server.started")
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(waitFor):
		t.Fatal("serve ignored SIGTERM")
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		buffer := make([]byte, 1<<16)
		t.Fatalf("goroutines %d -> %d\n%s", before, after, buffer[:runtime.Stack(buffer, true)])
	}
}
