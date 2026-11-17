package dnsserver

import (
	"net/netip"
	"sync"
	"time"
)

type bucket struct {
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
}

// Limiter is a per-client-IP token bucket. Each IP's bucket refills at qps
// tokens per second up to burst; a query that finds no token is refused. It
// keeps one noisy device from starving the shared cache and upstream quota.
type Limiter struct {
	qps     float64
	burst   float64
	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
}

// NewLimiter creates a Limiter. A qps of 0 allows every query.
func NewLimiter(qps, burst uint32) *Limiter {
	return &Limiter{qps: float64(qps), burst: float64(burst), buckets: make(map[netip.Addr]*bucket)}
}

// Allow takes a token for ip at time now. It reports false when the bucket is
// empty.
func (l *Limiter) Allow(ip netip.Addr, now time.Time) bool {
	if l.qps == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: l.burst, lastRefill: now}
		l.buckets[ip] = b
	}
	elapsed := max(now.Sub(b.lastRefill).Seconds(), 0)
	b.tokens = min(b.tokens+elapsed*l.qps, l.burst)
	b.lastRefill = now
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Prune drops buckets unseen for maxAge and returns how many it dropped. Call
// it periodically to bound the map.
func (l *Limiter) Prune(maxAge time.Duration, now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	before := len(l.buckets)
	for ip, b := range l.buckets {
		if now.Sub(b.lastSeen) >= maxAge {
			delete(l.buckets, ip)
		}
	}
	return before - len(l.buckets)
}

// TrackedIPs returns the number of IPs with a bucket.
func (l *Limiter) TrackedIPs() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
