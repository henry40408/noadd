// Package events is the tick source behind the admin UI's single SSE stream:
// the ping heartbeat and the dashboard's stats snapshot.
//
// One connection per page, because the status indicator is on every page. A
// ping goes out every tick; a snapshot only when a connection asked for one, so
// an idle settings page costs no aggregate queries. The snapshot is computed
// once per tick and shared.
package events

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// TickInterval is how often a tick fires in production.
const TickInterval = 10 * time.Second

// Tick is one beat of the stream. Snapshot is nil when no connection asked for
// stats.
type Tick struct {
	Seq uint64
	At  int64
	// Traffic is whether the appliance has ever answered a query: a state bit for
	// the onboarding notice, so it rides the heartbeat.
	Traffic  bool
	Snapshot any
}

// Hub broadcasts Ticks and counts the connections that want a snapshot.
type Hub struct {
	capacity int

	mu            sync.Mutex
	subscriptions map[*Subscription]struct{}
	statsWanted   int

	// trafficSeen is a one-way latch: a machine that served traffic is not a
	// fresh one again.
	trafficSeen atomic.Bool
}

// Subscription is one connection's feed. C is closed on Close, or when the
// connection falls behind by the hub's capacity and is dropped.
type Subscription struct {
	C         <-chan *Tick
	feed      chan *Tick
	hub       *Hub
	wantStats bool
	// ended is guarded by hub.mu.
	ended bool
}

// New creates a Hub whose subscribers buffer capacity ticks.
func New(capacity int) *Hub {
	return &Hub{capacity: capacity, subscriptions: make(map[*Subscription]struct{})}
}

// Subscribe registers a connection. wantStats makes ticks carry a snapshot
// until Close.
func (h *Hub) Subscribe(wantStats bool) *Subscription {
	feed := make(chan *Tick, h.capacity)
	subscription := &Subscription{C: feed, feed: feed, hub: h, wantStats: wantStats}
	h.mu.Lock()
	h.subscriptions[subscription] = struct{}{}
	if wantStats {
		h.statsWanted++
	}
	h.mu.Unlock()
	return subscription
}

// Close releases the connection's claim. It is safe to call more than once, and
// must be called when the client goes away.
func (s *Subscription) Close() {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	s.hub.remove(s)
}

// remove forgets a subscription and closes its feed once; the caller holds h.mu.
func (h *Hub) remove(s *Subscription) {
	if s.ended {
		return
	}
	s.ended = true
	delete(h.subscriptions, s)
	if s.wantStats {
		h.statsWanted--
	}
	close(s.feed)
}

// ConnectionCount is the number of live connections, stats-wanting or not.
func (h *Hub) ConnectionCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscriptions)
}

// WantsStats reports whether any connection wants a snapshot.
func (h *Hub) WantsStats() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.statsWanted > 0
}

// HasTraffic reports whether the appliance has answered a query, as far as
// anything has looked.
func (h *Hub) HasTraffic() bool { return h.trafficSeen.Load() }

// NoteTraffic records that it has. The ticker probes for it; a page render that
// learns the same fact sets it too.
func (h *Hub) NoteTraffic() { h.trafficSeen.Store(true) }

// Send delivers a tick to every connection. One that has capacity ticks pending
// is dropped rather than allowed to block the ticker.
func (h *Hub) Send(tick *Tick) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for subscription := range h.subscriptions {
		select {
		case subscription.feed <- tick:
		default:
			h.remove(subscription)
		}
	}
}

// Source supplies what a tick reports. Both calls hit the database.
type Source struct {
	// HasAnyQueryLogs answers the onboarding question.
	HasAnyQueryLogs func(ctx context.Context) (bool, error)
	// Snapshot computes the dashboard payload.
	Snapshot func(ctx context.Context, now int64) (any, error)
}

// Config configures Run.
type Config struct {
	Interval time.Duration
	Source   Source
	Now      func() int64
	Logger   *slog.Logger
}

// Run drives the stream until ctx ends: one tick per interval, skipped whole
// while no connection is open.
func (h *Hub) Run(ctx context.Context, cfg Config) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if h.ConnectionCount() == 0 {
			continue
		}
		seq++
		h.Send(h.buildTick(ctx, cfg, seq))
	}
}

func (h *Hub) buildTick(ctx context.Context, cfg Config, seq uint64) *Tick {
	now := cfg.Now()
	h.probeTraffic(ctx, cfg)
	tick := &Tick{Seq: seq, At: now, Traffic: h.HasTraffic()}
	if !h.WantsStats() {
		return tick
	}
	snapshot, err := cfg.Source.Snapshot(ctx, now)
	if err != nil {
		// The heartbeat still goes out: the server is still up.
		cfg.Logger.Warn("failed to compute the dashboard snapshot for the event stream",
			"event", "events.snapshot_failed", "error", err)
		return tick
	}
	tick.Snapshot = snapshot
	return tick
}

// probeTraffic asks once per tick, only until the latch is set.
func (h *Hub) probeTraffic(ctx context.Context, cfg Config) {
	if h.HasTraffic() {
		return
	}
	seen, err := cfg.Source.HasAnyQueryLogs(ctx)
	if err != nil {
		cfg.Logger.Warn("failed to check whether the appliance has served any queries",
			"event", "events.traffic_probe_failed", "error", err)
		return
	}
	if seen {
		h.NoteTraffic()
	}
}
