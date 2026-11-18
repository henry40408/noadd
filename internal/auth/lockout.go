package auth

import (
	"sync"
	"time"
)

const (
	// LockoutFreeAttempts is how many consecutive password failures are allowed
	// before any delay (ordinary mistyping).
	LockoutFreeAttempts = 3
	// LockoutMax caps the exponential backoff; a ceiling rather than a permanent
	// lock, because a hard lock would be an on-demand denial of service with no
	// password-reset flow to escape it.
	LockoutMax = 900 * time.Second
	// LockoutReset is the quiet period after which an account's failure count is
	// forgotten, so old typos do not carry a backoff months later.
	LockoutReset = 3600 * time.Second
)

// Lockout is a per-account exponential backoff on password failures. The IP
// limiter bounds one source address; this bounds one account, so a botnet gets
// many IP budgets but one account budget.
//
// It is keyed by user id, and only ever by one that resolved, so the map is
// bounded by the number of accounts. The state is in memory on purpose: a
// restart clears it.
type Lockout struct {
	mu       sync.Mutex
	failures map[int64]lockoutEntry
	now      func() time.Time
}

type lockoutEntry struct {
	failures uint32
	last     time.Time
}

// NewLockout returns an empty Lockout. now may be nil.
func NewLockout(now func() time.Time) *Lockout {
	if now == nil {
		now = time.Now
	}
	return &Lockout{failures: make(map[int64]lockoutEntry), now: now}
}

// lockoutPenalty is how long failures consecutive failures lock an account:
// 1s, 2s, 4s, ... capped, and zero inside the free allowance.
func lockoutPenalty(failures uint32) time.Duration {
	if failures <= LockoutFreeAttempts {
		return 0
	}
	over := failures - LockoutFreeAttempts
	// `over` is attacker-driven, so an oversized shift must not wrap.
	if over-1 >= 32 {
		return LockoutMax
	}
	return min(time.Duration(1<<(over-1))*time.Second, LockoutMax)
}

// IsLocked reports whether the account currently refuses password attempts.
func (l *Lockout) IsLocked(userID int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, found := l.failures[userID]
	if !found {
		return false
	}
	elapsed := l.now().Sub(entry.last)
	if elapsed >= LockoutReset {
		return false
	}
	return elapsed < lockoutPenalty(entry.failures)
}

// RecordFailure counts one password failure and returns the lock now in
// force, or zero while the account is inside its free allowance.
func (l *Lockout) RecordFailure(userID int64) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry, found := l.failures[userID]
	if !found || now.Sub(entry.last) >= LockoutReset {
		entry = lockoutEntry{}
	}
	if entry.failures < ^uint32(0) {
		entry.failures++
	}
	entry.last = now
	l.failures[userID] = entry
	return lockoutPenalty(entry.failures)
}

// RecordSuccess forgets an account's failures after a correct password.
func (l *Lockout) RecordSuccess(userID int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, userID)
}

// TrackedAccounts is the number of accounts currently carrying failures.
func (l *Lockout) TrackedAccounts() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.failures)
}
