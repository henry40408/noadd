package dns

import (
	"context"
	"sync"
	"time"
)

// DefaultInflightWait caps how long a waiter blocks on a fetcher that may be
// wedged. After it the waiter forwards the query itself.
const DefaultInflightWait = 3 * time.Second

// Group coalesces concurrent cache misses: N misses on one key make one
// upstream query. The first caller fetches; the rest wait for it to finish and
// re-check the cache. It is generic over the key so this package does not
// import the cache, which imports this package.
//
// It is not golang.org/x/sync/singleflight because a waiter must give up after
// a timeout and fetch for itself, and must re-read the cache, not share a
// result value.
type Group[K comparable] struct {
	wait    time.Duration
	mu      sync.Mutex
	pending map[K]chan struct{}
}

// NewGroup creates a Group. A zero wait takes DefaultInflightWait.
func NewGroup[K comparable](wait time.Duration) *Group[K] {
	if wait == 0 {
		wait = DefaultInflightWait
	}
	return &Group[K]{wait: wait, pending: make(map[K]chan struct{})}
}

// Fetch is held by the one caller fetching a key.
type Fetch[K comparable] struct {
	group *Group[K]
	key   K
	done  chan struct{}
	once  sync.Once
}

// Begin registers interest in key. Exactly one caller gets a non-nil Fetch;
// the others get the channel that closes when the fetcher finishes.
func (g *Group[K]) Begin(key K) (*Fetch[K], <-chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if done, ok := g.pending[key]; ok {
		return nil, done
	}
	done := make(chan struct{})
	g.pending[key] = done
	return &Fetch[K]{group: g, key: key, done: done}, nil
}

// Finish removes the key and wakes the waiters. Call it after the response is
// in the cache, and defer it so a panic or early return cannot wedge the key.
// Calling it again does nothing.
func (f *Fetch[K]) Finish() {
	f.once.Do(func() {
		f.group.mu.Lock()
		delete(f.group.pending, f.key)
		f.group.mu.Unlock()
		close(f.done)
	})
}

// Wait blocks until the fetcher finishes, the group's wait cap passes or ctx
// ends. The caller re-checks the cache either way.
func (g *Group[K]) Wait(ctx context.Context, done <-chan struct{}) {
	timer := time.NewTimer(g.wait)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	case <-ctx.Done():
	}
}

// Len returns the number of keys being fetched.
func (g *Group[K]) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.pending)
}

// RefreshSet makes sure each key has at most one background stale refresh.
type RefreshSet[K comparable] struct {
	mu   sync.Mutex
	keys map[K]struct{}
}

// NewRefreshSet creates an empty set.
func NewRefreshSet[K comparable]() *RefreshSet[K] {
	return &RefreshSet[K]{keys: make(map[K]struct{})}
}

// TryStart claims key. It returns false when a refresh is already running.
// The caller that gets true must call End, deferred, when the refresh ends.
func (r *RefreshSet[K]) TryStart(key K) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, running := r.keys[key]; running {
		return false
	}
	r.keys[key] = struct{}{}
	return true
}

// End releases key so a later stale read can refresh again.
func (r *RefreshSet[K]) End(key K) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.keys, key)
}
