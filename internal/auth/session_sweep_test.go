package auth

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/henry40408/noadd/internal/db"
)

func newLoggedManager(t *testing.T, logs *bytes.Buffer) (*Manager, *fakeClock, *db.DB) {
	t.Helper()
	clock := newFakeClock()
	database := openDB(t)
	logger := slog.New(slog.NewTextHandler(logs, nil))
	return NewManager(ManagerConfig{DB: database, Now: clock.Now, Logger: logger}), clock, database
}

func TestSweepAndLogReportsWhatItDestroyed(t *testing.T) {
	var logs bytes.Buffer
	manager, clock, _ := newLoggedManager(t, &logs)
	now := unixOf(clock)
	manager.Store("idle", infoAt(1, now-1000, now-SessionIdleTimeout-1))

	manager.sweepAndLog(context.Background())
	if !strings.Contains(logs.String(), "event=session.destroyed") || !strings.Contains(logs.String(), "evicted=1") {
		t.Fatalf("log = %q", logs.String())
	}
}

func TestSweepAndLogStaysQuietWhenNothingExpired(t *testing.T) {
	var logs bytes.Buffer
	manager, clock, _ := newLoggedManager(t, &logs)
	now := unixOf(clock)
	manager.Store("fresh", infoAt(1, now, now))

	manager.sweepAndLog(context.Background())
	if logs.Len() != 0 {
		t.Fatalf("unexpected log %q", logs.String())
	}
}

func TestSweepAndLogWarnsWhenThePurgeFails(t *testing.T) {
	var logs bytes.Buffer
	manager, _, database := newLoggedManager(t, &logs)
	if err := database.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager.sweepAndLog(context.Background())
	if !strings.Contains(logs.String(), "event=session.sweep_failed") {
		t.Fatalf("log = %q", logs.String())
	}
}

func TestManagerKeepsTheConfiguredSalt(t *testing.T) {
	var salt [SessionLogSaltLen]byte
	salt[0], salt[SessionLogSaltLen-1] = 7, 9
	manager := NewManager(ManagerConfig{DB: openDB(t), Salt: salt})
	if manager.Salt() != salt {
		t.Fatalf("Salt() = %v, want %v", manager.Salt(), salt)
	}
}

func TestLoadOrCreateSessionLogSaltReportsDatabaseFailure(t *testing.T) {
	database := openDB(t)
	if err := database.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateSessionLogSalt(context.Background(), database); err == nil {
		t.Fatal("no error from a closed database")
	}
}
