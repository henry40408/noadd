package auth

import (
	"net/netip"
	"sync"
	"time"
)

// Limiter is a per-IP windowed attempt counter, used to rate-limit logins and
// to detect bursts of unknown session tokens. One instance per signal:
// sharing one would let a cookie guesser spend an operator's login budget from
// the same NAT address.
type Limiter struct {
	mu          sync.Mutex
	attempts    map[netip.Addr]limiterEntry
	maxAttempts int
	window      time.Duration
	now         func() time.Time
}

type limiterEntry struct {
	count   int
	started time.Time
}

// NewLimiter allows maxAttempts per window per IP. now may be nil.
func NewLimiter(maxAttempts int, window time.Duration, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		attempts:    make(map[netip.Addr]limiterEntry),
		maxAttempts: maxAttempts,
		window:      window,
		now:         now,
	}
}

func (l *Limiter) windowElapsed(entry limiterEntry, now time.Time) bool {
	return now.Sub(entry.started) >= l.window
}

// Check reports whether ip may make another attempt (false means limited).
func (l *Limiter) Check(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, found := l.attempts[ip]
	if !found || l.windowElapsed(entry, l.now()) {
		return true
	}
	return entry.count < l.maxAttempts
}

// Record counts an attempt from ip.
func (l *Limiter) Record(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recordLocked(ip)
}

// RecordCrossing counts an attempt and reports true only for the one that
// reaches maxAttempts in this window, so it can drive a single log line.
func (l *Limiter) RecordCrossing(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.recordLocked(ip) == l.maxAttempts
}

func (l *Limiter) recordLocked(ip netip.Addr) int {
	now := l.now()
	entry, found := l.attempts[ip]
	if !found || l.windowElapsed(entry, now) {
		entry = limiterEntry{count: 0, started: now}
	}
	entry.count++
	l.attempts[ip] = entry
	return entry.count
}

// Prune drops entries whose window elapsed and returns how many. Without it a
// scanner cycling addresses (trivial across an IPv6 /64) grows the map
// without bound.
func (l *Limiter) Prune() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	removed := 0
	for ip, entry := range l.attempts {
		if l.windowElapsed(entry, now) {
			delete(l.attempts, ip)
			removed++
		}
	}
	return removed
}

// TrackedIPs is the number of IPs currently tracked.
func (l *Limiter) TrackedIPs() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.attempts)
}
