package filter

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func spawnSleeping(coordinator *Coordinator, duration time.Duration) <-chan struct{} {
	return coordinator.Spawn(func() error {
		time.Sleep(duration)
		return nil
	})
}

// Rust: rebuild_state_transitions
func TestRebuildStateTransitions(t *testing.T) {
	coordinator := NewCoordinator()
	if status := coordinator.Status(); status.Rebuilding || status.StartedAt != 0 || status.LastDurationMs != 0 {
		t.Fatalf("initial status = %+v", status)
	}
	done := spawnSleeping(coordinator, 30*time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if status := coordinator.Status(); !status.Rebuilding || status.StartedAt <= 0 {
		t.Fatalf("running status = %+v", status)
	}
	<-done
	if status := coordinator.Status(); status.Rebuilding || status.LastDurationMs < 30 {
		t.Fatalf("finished status = %+v", status)
	}
}

// Rust: concurrent_spawns_serialised
func TestConcurrentSpawnsSerialised(t *testing.T) {
	coordinator := NewCoordinator()
	start := time.Now()
	first := spawnSleeping(coordinator, 50*time.Millisecond)
	second := spawnSleeping(coordinator, 50*time.Millisecond)
	<-first
	<-second
	if elapsed := time.Since(start); elapsed < 95*time.Millisecond {
		t.Fatalf("tasks overlapped: %v", elapsed)
	}
}

// Rust: subscribers_see_both_edges_of_a_rebuild
func TestSubscribersSeeBothEdgesOfARebuild(t *testing.T) {
	coordinator := NewCoordinator()
	updates, unsubscribe := coordinator.Subscribe()
	defer unsubscribe()

	<-spawnSleeping(coordinator, 30*time.Millisecond)

	started := <-updates
	if !started.Rebuilding || started.StartedAt <= 0 {
		t.Fatalf("start edge = %+v", started)
	}
	finished := <-updates
	if finished.Rebuilding || finished.LastDurationMs < 30 || finished.StartedAt != started.StartedAt {
		t.Fatalf("finish edge = %+v (start %+v)", finished, started)
	}
	select {
	case extra := <-updates:
		t.Fatalf("a rebuild published more than its two edges: %+v", extra)
	default:
	}
}

// Rust: status_reports_the_current_state_to_a_caller_that_missed_the_edges
func TestStatusReportsTheCurrentState(t *testing.T) {
	coordinator := NewCoordinator()
	if idle := coordinator.Status(); idle.Rebuilding || idle.StartedAt != 0 {
		t.Fatalf("idle = %+v", idle)
	}
	<-coordinator.Spawn(func() error { return nil })
	if after := coordinator.Status(); after.Rebuilding || after.StartedAt <= 0 {
		t.Fatalf("after = %+v", after)
	}
}

// Rust: failed_rebuild_clears_flag
func TestFailedRebuildClearsFlag(t *testing.T) {
	coordinator := NewCoordinator()
	<-coordinator.Spawn(func() error { return errors.New("boom") })
	if coordinator.Status().Rebuilding {
		t.Fatal("a failed rebuild left the coordinator rebuilding")
	}
	if !coordinator.LastFailed() {
		t.Fatal("failure not remembered")
	}
	<-coordinator.Spawn(func() error { return nil })
	if coordinator.LastFailed() {
		t.Fatal("success did not clear the failure")
	}
}

// Rust: coalesced_requests_collapse_into_one_follow_up
func TestCoalescedRequestsCollapseIntoOneFollowUp(t *testing.T) {
	var runs atomic.Int32
	coordinator := NewCoordinator()
	spawn := func() (<-chan struct{}, bool) {
		return coordinator.SpawnCoalesced(func() error {
			runs.Add(1)
			time.Sleep(30 * time.Millisecond)
			return nil
		})
	}

	first, ok := spawn()
	if !ok {
		t.Fatal("the first request always runs")
	}
	time.Sleep(5 * time.Millisecond)
	second, ok := spawn()
	if !ok {
		t.Fatal("a request during a run queues a follow-up")
	}
	if _, ok := spawn(); ok {
		t.Fatal("third request should coalesce")
	}
	if _, ok := spawn(); ok {
		t.Fatal("fourth request should coalesce")
	}
	<-first
	<-second
	if got := runs.Load(); got != 2 {
		t.Fatalf("runs = %d, want 2", got)
	}

	third, ok := spawn()
	if !ok {
		t.Fatal("the flag is cleared once the follow-up ran")
	}
	<-third
	if got := runs.Load(); got != 3 {
		t.Fatalf("runs = %d, want 3", got)
	}
}
