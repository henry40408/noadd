package dnsserver

import (
	"net/netip"
	"testing"
	"time"
)

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func ipN(n byte) netip.Addr { return netip.AddrFrom4([4]byte{10, 0, 0, n}) }

// Rust: ratelimit.rs disabled_limiter_always_allows
func TestDisabledLimiterAlwaysAllows(t *testing.T) {
	limiter := NewLimiter(0, 0)
	for range 10_000 {
		if !limiter.Allow(ipN(1), epoch) {
			t.Fatal("a limiter with qps 0 refused a query")
		}
	}
	if limiter.TrackedIPs() != 0 {
		t.Fatal("a disabled limiter should track nothing")
	}
}

// Rust: burst_allows_initial_spike_then_blocks
func TestBurstAllowsInitialSpikeThenBlocks(t *testing.T) {
	limiter := NewLimiter(1, 5)
	for i := range 5 {
		if !limiter.Allow(ipN(1), epoch) {
			t.Fatalf("burst token %d refused", i)
		}
	}
	if limiter.Allow(ipN(1), epoch) {
		t.Fatal("6th query should be refused")
	}
}

// Rust: per_ip_isolation
func TestPerIPIsolation(t *testing.T) {
	limiter := NewLimiter(1, 2)
	limiter.Allow(ipN(1), epoch)
	limiter.Allow(ipN(1), epoch)
	if limiter.Allow(ipN(1), epoch) {
		t.Fatal("ip 1 should be drained")
	}
	for i := range 2 {
		if !limiter.Allow(ipN(2), epoch) {
			t.Fatalf("ip 2 query %d refused; its bucket should be untouched", i)
		}
	}
}

// Rust: refill_after_wait
func TestRefillAfterWait(t *testing.T) {
	limiter := NewLimiter(1000, 1)
	limiter.Allow(ipN(1), epoch)
	if limiter.Allow(ipN(1), epoch) {
		t.Fatal("bucket should be empty")
	}
	if !limiter.Allow(ipN(1), epoch.Add(5*time.Millisecond)) {
		t.Fatal("5 ms at 1000 qps should refill a token")
	}
}

func TestRefillIsCappedAtBurst(t *testing.T) {
	limiter := NewLimiter(1000, 2)
	limiter.Allow(ipN(1), epoch)
	later := epoch.Add(time.Hour)
	limiter.Allow(ipN(1), later)
	limiter.Allow(ipN(1), later)
	if limiter.Allow(ipN(1), later) {
		t.Fatal("an idle hour must not bank more than burst tokens")
	}
}

func TestClockGoingBackwardsDoesNotMintTokens(t *testing.T) {
	limiter := NewLimiter(1000, 1)
	limiter.Allow(ipN(1), epoch)
	if limiter.Allow(ipN(1), epoch.Add(-time.Hour)) {
		t.Fatal("a backwards clock refilled the bucket")
	}
}

// Rust: prune_drops_inactive_ips
func TestPruneDropsInactiveIPs(t *testing.T) {
	limiter := NewLimiter(10, 10)
	limiter.Allow(ipN(1), epoch)
	limiter.Allow(ipN(2), epoch)
	if limiter.TrackedIPs() != 2 {
		t.Fatalf("tracked = %d, want 2", limiter.TrackedIPs())
	}
	if removed := limiter.Prune(0, epoch); removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}
	if limiter.TrackedIPs() != 0 {
		t.Fatalf("tracked = %d, want 0", limiter.TrackedIPs())
	}
}

func TestPruneKeepsRecentIPs(t *testing.T) {
	limiter := NewLimiter(10, 10)
	limiter.Allow(ipN(1), epoch)
	limiter.Allow(ipN(2), epoch.Add(9*time.Minute))
	if removed := limiter.Prune(10*time.Minute, epoch.Add(11*time.Minute)); removed != 1 {
		t.Fatalf("removed = %d, want only the idle IP", removed)
	}
}
