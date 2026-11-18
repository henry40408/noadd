package main

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/stats"
)

func testLogger(buffer *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "t.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	return database
}

func TestRetentionDaysFallsBackToTheDefault(t *testing.T) {
	ctx := context.Background()
	database := openTestDB(t)
	// The stats package seeds a default on first use; remove any seeded row by
	// overwriting, so each case is explicit.
	for value, want := range map[string]int64{"7": 7, "bogus": stats.DefaultLogRetentionDays, "": stats.DefaultLogRetentionDays} {
		if err := database.SetSetting(ctx, "log_retention_days", value); err != nil {
			t.Fatal(err)
		}
		if got := retentionDays(ctx, database); got != want {
			t.Errorf("value %q: got %d, want %d", value, got, want)
		}
	}
}

func TestRetentionDaysFallsBackWhenTheDatabaseFails(t *testing.T) {
	database := openTestDB(t)
	if err := database.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := retentionDays(context.Background(), database); got != stats.DefaultLogRetentionDays {
		t.Fatalf("got %d", got)
	}
}

func TestPruneLogsOnceReportsADatabaseFailureAndKeepsGoing(t *testing.T) {
	database := openTestDB(t)
	if err := database.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	pruneLogsOnce(context.Background(), database, testLogger(&out))
	if !strings.Contains(out.String(), "event=db.prune_failed") {
		t.Fatalf("no failure logged:\n%s", out.String())
	}
}

func TestPruneLogsOnceRemovesOldRowsAndLogsTheCount(t *testing.T) {
	ctx := context.Background()
	database := openTestDB(t)
	old := time.Now().Add(-400 * 24 * time.Hour).UnixMilli()
	fresh := time.Now().UnixMilli()
	err := database.InsertQueryLogs(ctx, []db.QueryLogEntry{
		{Timestamp: old, Domain: "old.example", ClientIP: "127.0.0.1"},
		{Timestamp: fresh, Domain: "new.example", ClientIP: "127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	pruneLogsOnce(ctx, database, testLogger(&out))
	if !strings.Contains(out.String(), "event=db.logs_pruned") || !strings.Contains(out.String(), "count=1") {
		t.Fatalf("unexpected log:\n%s", out.String())
	}
}

func TestTickerRunsWorkAndStopsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ran := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		ticker(ctx, time.Millisecond, func() {
			select {
			case ran <- struct{}{}:
			default:
			}
		})
		close(done)
	}()
	select {
	case <-ran:
	case <-time.After(waitFor):
		t.Fatal("work never ran")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(waitFor):
		t.Fatal("ticker ignored cancel")
	}
}

// The hub hands the source a millisecond clock. Reading it as seconds empties
// every window, which blanked the dashboard on the first tick.
func TestDashboardSourceReadsTheHubClockAsMilliseconds(t *testing.T) {
	ctx := context.Background()
	database := openTestDB(t)
	nowMs := time.Now().UnixMilli()
	err := database.InsertQueryLogs(ctx, []db.QueryLogEntry{{Timestamp: nowMs - 1000, Domain: "example.com", QueryType: "A", ClientIP: "10.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := dashboardSource(database).Snapshot(ctx, nowMs)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, ok := got.(*stats.DashboardSnapshot)
	if !ok {
		t.Fatalf("snapshot type %T", got)
	}
	if snapshot.Summary.TotalToday != 1 || len(snapshot.TopDomains) != 1 {
		t.Fatalf("total_today=%d top_domains=%d, want 1 and 1", snapshot.Summary.TotalToday, len(snapshot.TopDomains))
	}
}
