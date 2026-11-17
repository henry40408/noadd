package events

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/db"
)

const (
	fast = 20 * time.Millisecond
	wait = 5 * time.Second
)

func openDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(context.Background()) })
	return database
}

func startRun(t *testing.T, hub *Hub, source Source) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		hub.Run(ctx, Config{Interval: fast, Source: source, Now: func() int64 { return 1234 }})
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func plainSource() Source {
	return Source{
		HasAnyQueryLogs: func(context.Context) (bool, error) { return false, nil },
		Snapshot:        func(context.Context, int64) (any, error) { return "snapshot", nil },
	}
}

func nextTick(t *testing.T, subscription *Subscription) *Tick {
	t.Helper()
	select {
	case tick, open := <-subscription.C:
		if !open {
			t.Fatal("the subscription was closed")
		}
		return tick
	case <-time.After(wait):
		t.Fatal("no tick within 5s")
		return nil
	}
}

// Rust: a_hub_with_no_connections_reports_none
func TestHubWithNoConnectionsReportsNone(t *testing.T) {
	hub := New(8)
	if hub.ConnectionCount() != 0 || hub.WantsStats() {
		t.Fatal("a new hub has no connections")
	}
}

// Rust: a_dropped_stats_guard_releases_its_claim
func TestClosedSubscriptionReleasesItsClaim(t *testing.T) {
	hub := New(8)
	first := hub.Subscribe(true)
	second := hub.Subscribe(true)
	if !hub.WantsStats() {
		t.Fatal("stats were asked for")
	}
	second.Close()
	if !hub.WantsStats() {
		t.Fatal("one connection leaving must not cancel another's snapshots")
	}
	first.Close()
	first.Close()
	if hub.WantsStats() || hub.ConnectionCount() != 0 {
		t.Fatal("the claims must be released, once each")
	}
}

// Rust: the_ticker_does_nothing_while_nobody_is_connected
func TestTickerDoesNothingWhileNobodyIsConnected(t *testing.T) {
	hub := New(8)
	startRun(t, hub, plainSource())
	time.Sleep(fast * 5)

	subscription := hub.Subscribe(false)
	defer subscription.Close()

	if tick := nextTick(t, subscription); tick.Seq != 1 {
		t.Fatalf("seq = %d: ticks were numbered while no one was connected", tick.Seq)
	}
}

// Rust: a_tick_carries_a_snapshot_only_when_one_was_asked_for
func TestTickCarriesSnapshotOnlyWhenAskedFor(t *testing.T) {
	hub := New(64)
	var snapshots atomic.Int32
	source := plainSource()
	source.Snapshot = func(context.Context, int64) (any, error) {
		snapshots.Add(1)
		return "snapshot", nil
	}
	plain := hub.Subscribe(false)
	startRun(t, hub, source)

	if nextTick(t, plain).Snapshot != nil || snapshots.Load() != 0 {
		t.Fatal("a stats-free connection must not cost a snapshot")
	}

	asking := hub.Subscribe(true)
	waitFor(t, "a snapshot", func() bool { return nextTick(t, plain).Snapshot == "snapshot" })
	asking.Close()
	waitFor(t, "snapshots to stop", func() bool { return nextTick(t, plain).Snapshot == nil })
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
	}
	t.Fatalf("never saw %s", what)
}

// Rust: a_tick_reaches_every_subscriber
func TestTickReachesEverySubscriber(t *testing.T) {
	hub := New(8)
	a, b := hub.Subscribe(false), hub.Subscribe(false)
	if hub.ConnectionCount() != 2 {
		t.Fatal("two connections")
	}

	hub.Send(&Tick{Seq: 7, At: 1234})

	for _, subscription := range []*Subscription{a, b} {
		if tick := nextTick(t, subscription); tick.Seq != 7 || tick.At != 1234 || tick.Snapshot != nil {
			t.Fatalf("tick = %+v", tick)
		}
	}
}

func TestSlowConnectionIsDroppedWithoutBlocking(t *testing.T) {
	hub := New(2)
	slow := hub.Subscribe(true)
	for seq := range 3 {
		hub.Send(&Tick{Seq: uint64(seq)})
	}
	if hub.ConnectionCount() != 0 || hub.WantsStats() {
		t.Fatal("the slow connection must be dropped and its stats claim released")
	}
	for range 2 {
		<-slow.C
	}
	if _, open := <-slow.C; open {
		t.Fatal("its channel must end")
	}
	slow.Close()
}

// Rust (tests/event_hub_test.rs): the_tick_reports_traffic_once_the_appliance_has_answered_something
func TestTickReportsTrafficOnceTheApplianceHasAnsweredSomething(t *testing.T) {
	database := openDB(t)
	hub := New(64)
	subscription := hub.Subscribe(false)
	startRun(t, hub, Source{
		HasAnyQueryLogs: database.HasAnyQueryLogs,
		Snapshot:        func(context.Context, int64) (any, error) { return nil, nil },
	})

	if nextTick(t, subscription).Traffic {
		t.Fatal("a fresh appliance has answered nothing")
	}
	if err := database.InsertQueryLogs(context.Background(), []db.QueryLogEntry{{Timestamp: 1_000_000, Domain: "example.com", QueryType: "A", ClientIP: "192.168.1.1", ResponseMs: 5}}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "the first query to latch", func() bool { return nextTick(t, subscription).Traffic })
}

// Rust (tests/event_hub_test.rs): the_traffic_latch_does_not_clear_when_the_logs_are_emptied
func TestTrafficLatchDoesNotClearWhenLogsAreEmptied(t *testing.T) {
	database := openDB(t)
	hub := New(8)
	if hub.HasTraffic() {
		t.Fatal("not latched yet")
	}
	hub.NoteTraffic()
	if err := database.DeleteAllLogs(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !hub.HasTraffic() {
		t.Fatal("an appliance that has served traffic is not a fresh one again")
	}
}

func TestFailedSnapshotStillSendsTheHeartbeat(t *testing.T) {
	hub := New(8)
	source := plainSource()
	source.Snapshot = func(context.Context, int64) (any, error) { return nil, errors.New("db down") }
	subscription := hub.Subscribe(true)
	startRun(t, hub, source)

	if tick := nextTick(t, subscription); tick.Snapshot != nil {
		t.Fatal("no snapshot on failure")
	}
}

func TestTrafficProbeIsSkippedOnceLatched(t *testing.T) {
	hub := New(64)
	hub.NoteTraffic()
	var probes atomic.Int32
	source := plainSource()
	source.HasAnyQueryLogs = func(context.Context) (bool, error) { probes.Add(1); return true, nil }
	subscription := hub.Subscribe(false)
	startRun(t, hub, source)

	for range 3 {
		if !nextTick(t, subscription).Traffic {
			t.Fatal("latched")
		}
	}
	if probes.Load() != 0 {
		t.Fatal("a latched hub must not pay for the question")
	}
}
