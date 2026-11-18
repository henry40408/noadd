package auth

import (
	"net/netip"
	"testing"
	"time"
)

// Rust: test_rate_limiter_allows_under_limit
func TestLimiterAllowsUnderLimit(t *testing.T) {
	limiter := NewLimiter(3, time.Minute, nil)
	ip := netip.MustParseAddr("192.168.1.1")
	for i := 0; i < 3; i++ {
		if !limiter.Check(ip) {
			t.Fatalf("attempt %d refused", i+1)
		}
		limiter.Record(ip)
	}
}

// Rust: test_rate_limiter_blocks_over_limit
func TestLimiterBlocksOverLimit(t *testing.T) {
	limiter := NewLimiter(3, time.Minute, nil)
	ip, other := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	for i := 0; i < 3; i++ {
		limiter.Record(ip)
	}
	if limiter.Check(ip) {
		t.Fatal("over-limit IP allowed")
	}
	if !limiter.Check(other) {
		t.Fatal("limit leaked to another IP")
	}
}

func TestLimiterWindowExpires(t *testing.T) {
	clock := newFakeClock()
	limiter := NewLimiter(1, time.Minute, clock.Now)
	ip := netip.MustParseAddr("10.0.0.1")
	limiter.Record(ip)
	clock.Advance(59 * time.Second)
	if limiter.Check(ip) {
		t.Fatal("allowed inside the window")
	}
	clock.Advance(time.Second)
	if !limiter.Check(ip) {
		t.Fatal("refused after the window")
	}
}

// Rust: record_crossing_fires_exactly_once_per_window
func TestRecordCrossingFiresExactlyOncePerWindow(t *testing.T) {
	limiter := NewLimiter(3, time.Minute, nil)
	ip := netip.MustParseAddr("10.0.0.1")
	got := []bool{}
	for i := 0; i < 5; i++ {
		got = append(got, limiter.RecordCrossing(ip))
	}
	want := []bool{false, false, true, false, false}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("crossings = %v, want %v", got, want)
		}
	}
	if limiter.RecordCrossing(netip.MustParseAddr("10.0.0.2")) {
		t.Fatal("a different IP has its own window")
	}
}

// Rust: prune_drops_entries_whose_window_elapsed
func TestPruneDropsEntriesWhoseWindowElapsed(t *testing.T) {
	limiter := NewLimiter(5, 0, nil)
	limiter.Record(netip.MustParseAddr("10.0.0.1"))
	limiter.Record(netip.MustParseAddr("10.0.0.2"))
	if limiter.TrackedIPs() != 2 || limiter.Prune() != 2 || limiter.TrackedIPs() != 0 {
		t.Fatal("prune did not drop elapsed entries")
	}
}

// Rust: prune_keeps_entries_whose_window_is_still_live
func TestPruneKeepsLiveEntries(t *testing.T) {
	limiter := NewLimiter(5, time.Hour, nil)
	limiter.Record(netip.MustParseAddr("10.0.0.1"))
	if limiter.Prune() != 0 || limiter.TrackedIPs() != 1 {
		t.Fatal("prune dropped a live entry")
	}
}
