package auth

import (
	"math"
	"testing"
	"time"
)

// Rust: lockout_leaves_ordinary_mistyping_alone
func TestLockoutLeavesOrdinaryMistypingAlone(t *testing.T) {
	lockout := NewLockout(nil)
	for i := 1; i <= LockoutFreeAttempts; i++ {
		if lockout.RecordFailure(1) != 0 || lockout.IsLocked(1) {
			t.Fatalf("failure %d is inside the free allowance and must not lock", i)
		}
	}
}

// Rust: lockout_doubles_and_then_stops_doubling. The shape is the security
// property: doubling, then capped.
func TestLockoutDoublesAndThenStopsDoubling(t *testing.T) {
	cases := map[uint32]time.Duration{
		LockoutFreeAttempts:      0,
		LockoutFreeAttempts + 1:  1 * time.Second,
		LockoutFreeAttempts + 2:  2 * time.Second,
		LockoutFreeAttempts + 3:  4 * time.Second,
		LockoutFreeAttempts + 10: 512 * time.Second,
		LockoutFreeAttempts + 11: LockoutMax,
		LockoutFreeAttempts + 40: LockoutMax,
		// An oversized shift saturates to the cap rather than wrapping.
		math.MaxUint32: LockoutMax,
	}
	for failures, want := range cases {
		if got := lockoutPenalty(failures); got != want {
			t.Errorf("penalty(%d) = %v, want %v", failures, got, want)
		}
	}
}

// Rust: lockout_actually_locks_once_the_allowance_is_spent
func TestLockoutLocksOnceTheAllowanceIsSpent(t *testing.T) {
	clock := newFakeClock()
	lockout := NewLockout(clock.Now)
	for i := 0; i < LockoutFreeAttempts; i++ {
		lockout.RecordFailure(7)
	}
	if lockout.IsLocked(7) {
		t.Fatal("locked inside the allowance")
	}
	if got := lockout.RecordFailure(7); got != time.Second {
		t.Fatalf("first failure past the allowance locks for %v, want 1s", got)
	}
	if !lockout.IsLocked(7) {
		t.Fatal("not locked")
	}
	clock.Advance(time.Second)
	if lockout.IsLocked(7) {
		t.Fatal("still locked after the penalty elapsed")
	}
}

func TestLockoutForgetsAfterAQuietHour(t *testing.T) {
	clock := newFakeClock()
	lockout := NewLockout(clock.Now)
	for i := 0; i < LockoutFreeAttempts+12; i++ {
		lockout.RecordFailure(1)
	}
	clock.Advance(LockoutReset - time.Second)
	if lockout.RecordFailure(1) != LockoutMax {
		t.Fatal("backoff reset too early")
	}
	clock.Advance(LockoutReset)
	if lockout.IsLocked(1) {
		t.Fatal("locked after the reset window")
	}
	if lockout.RecordFailure(1) != 0 {
		t.Fatal("count not restarted after the quiet period")
	}
}

// Rust: lockout_is_per_account
func TestLockoutIsPerAccount(t *testing.T) {
	lockout := NewLockout(nil)
	for i := 0; i <= LockoutFreeAttempts; i++ {
		lockout.RecordFailure(1)
	}
	if !lockout.IsLocked(1) || lockout.IsLocked(2) {
		t.Fatal("one account under attack must not lock another")
	}
}

// Rust: a_correct_password_clears_the_history
func TestACorrectPasswordClearsTheHistory(t *testing.T) {
	lockout := NewLockout(nil)
	for i := 0; i <= LockoutFreeAttempts; i++ {
		lockout.RecordFailure(1)
	}
	lockout.RecordSuccess(1)
	if lockout.IsLocked(1) || lockout.TrackedAccounts() != 0 {
		t.Fatal("history not cleared")
	}
	if lockout.RecordFailure(1) != 0 {
		t.Fatal("backoff resumed instead of starting over")
	}
}

// Rust: an_untouched_account_is_never_locked
func TestAnUntouchedAccountIsNeverLocked(t *testing.T) {
	lockout := NewLockout(nil)
	if lockout.IsLocked(42) || lockout.TrackedAccounts() != 0 {
		t.Fatal("untouched account tracked or locked")
	}
}
