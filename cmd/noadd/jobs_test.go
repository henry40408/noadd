package main

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/dnsserver"
	"github.com/henry40408/noadd/internal/filter"
	"github.com/henry40408/noadd/internal/upstream"
)

func newSyncLogger(buffer *syncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// runJob starts job and returns a stop that cancels it and waits for it to
// return, so a leaked goroutine cannot outlive the test.
func runJob(t *testing.T, job func(ctx context.Context)) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		job(ctx)
		close(done)
	}()
	stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(waitFor):
			t.Error("job ignored cancel")
		}
	}
	t.Cleanup(stop)
	return stop
}

func TestPruneLogsJobRemovesOldRowsOnEachTick(t *testing.T) {
	ctx := context.Background()
	database := openTestDB(t)
	old := (time.Now().Unix() - 30*86400) * 1000
	if err := database.InsertQueryLogs(ctx, []db.QueryLogEntry{{Timestamp: old, Domain: "old.example", QueryType: "A", ClientIP: "10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	runJob(t, func(jobCtx context.Context) { pruneLogs(jobCtx, time.Millisecond, database, newSyncLogger(&out)) })
	waitForLog(t, &out, "event=db.logs_pruned")
	if has, err := database.HasAnyQueryLogs(ctx); err != nil || has {
		t.Fatalf("old log survived the prune: has=%v err=%v", has, err)
	}
}

func TestUpdateListsJobKeepsTheFilterWhenNothingChanged(t *testing.T) {
	database := openTestDB(t)
	manager := &filter.Manager{DB: database, Holder: filter.NewHolder(filter.NewFromNamed(nil, nil)), Downloader: filter.NewDownloader("test")}
	var out syncBuffer
	runJob(t, func(ctx context.Context) {
		updateLists(ctx, time.Millisecond, manager, filter.NewCoordinator(), newSyncLogger(&out))
	})
	waitForLog(t, &out, "event=filter.rebuild_skipped")
}

func TestUpdateListsJobStillRebuildsAfterAFailedRefresh(t *testing.T) {
	database := openTestDB(t)
	manager := &filter.Manager{DB: database, Holder: filter.NewHolder(filter.NewFromNamed(nil, nil)), Downloader: filter.NewDownloader("test")}
	if err := database.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	rebuild := filter.NewCoordinator()
	runJob(t, func(ctx context.Context) { updateLists(ctx, time.Millisecond, manager, rebuild, newSyncLogger(&out)) })
	waitForLog(t, &out, "event=filter.list_refresh_failed")
	deadline := time.Now().Add(waitFor)
	for !rebuild.LastFailed() {
		if time.Now().After(deadline) {
			t.Fatal("a refresh failure did not trigger a rebuild")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestPruneRateLimitsJobEvictsIdleBuckets(t *testing.T) {
	targets := pruneTargets{
		dns:            dnsserver.NewLimiter(10, 10),
		login:          auth.NewLimiter(5, time.Minute, nil),
		invalidSession: auth.NewLimiter(5, time.Minute, nil),
		setupToken:     auth.FixedSetupToken("ABCDE-FGHJK", nil),
	}
	targets.dns.Allow(netip.MustParseAddr("192.0.2.1"), time.Now().Add(-time.Hour))
	var out syncBuffer
	runJob(t, func(ctx context.Context) { pruneRateLimits(ctx, time.Millisecond, targets, newSyncLogger(&out)) })
	waitForLog(t, &out, "scope=dns removed=1")
}

func TestProbeUpstreamsJobProbesOnlyUnderLowestLatency(t *testing.T) {
	forwarder := upstream.New(context.Background(), upstream.Config{Servers: []string{"127.0.0.1:1"}, Timeout: 200 * time.Millisecond})

	var idle syncBuffer
	stop := runJob(t, func(ctx context.Context) { probeUpstreams(ctx, time.Millisecond, forwarder, newSyncLogger(&idle)) })
	time.Sleep(50 * time.Millisecond)
	stop()
	if strings.Contains(idle.String(), "upstream.probe_completed") {
		t.Fatalf("probed under the sequential strategy:\n%s", idle.String())
	}

	forwarder.SetStrategy(upstream.LowestLatency)
	var active syncBuffer
	runJob(t, func(ctx context.Context) { probeUpstreams(ctx, time.Millisecond, forwarder, newSyncLogger(&active)) })
	waitForLog(t, &active, "event=upstream.probe_completed")
}
