package filter

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// statusBacklog is the buffer of each subscriber: two messages per rebuild, so
// it covers several rebuilds. A subscriber further behind loses messages and
// can read the live state with Status.
const statusBacklog = 16

// Status is what a rebuild is doing at one instant, as pushed to the admin
// event stream.
type Status struct {
	Rebuilding     bool   `json:"rebuilding"`
	StartedAt      int64  `json:"started_at"`
	LastDurationMs uint64 `json:"last_duration_ms"`
}

// Coordinator runs rebuild-like tasks one at a time and publishes both edges
// of each run.
type Coordinator struct {
	running sync.Mutex
	// queued is set while a coalescable task waits for the lock and has not
	// read any state yet.
	queued atomic.Bool

	rebuilding     atomic.Bool
	startedAt      atomic.Int64
	lastDurationMs atomic.Uint64
	lastFailed     atomic.Bool

	subscribersMu sync.Mutex
	subscribers   map[chan Status]struct{}
}

// NewCoordinator returns an idle coordinator.
func NewCoordinator() *Coordinator {
	return &Coordinator{subscribers: map[chan Status]struct{}{}}
}

// Status is the current state, for a caller that just connected.
func (c *Coordinator) Status() Status {
	return Status{
		Rebuilding:     c.rebuilding.Load(),
		StartedAt:      c.startedAt.Load(),
		LastDurationMs: c.lastDurationMs.Load(),
	}
}

// LastFailed reports whether the latest run failed, so the live engine may be
// stale and a refresh that changed nothing should still retry.
func (c *Coordinator) LastFailed() bool { return c.lastFailed.Load() }

// Subscribe returns a channel that gets both edges of every run, and a
// function that ends the subscription.
func (c *Coordinator) Subscribe() (<-chan Status, func()) {
	updates := make(chan Status, statusBacklog)
	c.subscribersMu.Lock()
	c.subscribers[updates] = struct{}{}
	c.subscribersMu.Unlock()
	return updates, func() {
		c.subscribersMu.Lock()
		delete(c.subscribers, updates)
		c.subscribersMu.Unlock()
	}
}

// publish never blocks: a slow subscriber loses its oldest messages, so the
// newest one, such as a rebuild finishing, always arrives.
func (c *Coordinator) publish() {
	status := c.Status()
	c.subscribersMu.Lock()
	defer c.subscribersMu.Unlock()
	for updates := range c.subscribers {
		offer(updates, status)
	}
}

// Spawn runs task after any task already running. The returned channel closes
// when the task has finished. A failed task is logged and still resets the
// state.
func (c *Coordinator) Spawn(task func() error) <-chan struct{} {
	return c.spawn(false, task)
}

// SpawnCoalesced is Spawn for a task that reads the latest state when it runs.
// While one such task still waits for its turn another request adds nothing,
// so it returns false.
//
// The waiting task clears the flag before it reads state, so a request made
// after that point queues a new task and is never lost.
func (c *Coordinator) SpawnCoalesced(task func() error) (<-chan struct{}, bool) {
	if c.queued.Swap(true) {
		return nil, false
	}
	return c.spawn(true, task), true
}

func (c *Coordinator) spawn(coalesced bool, task func() error) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.running.Lock()
		defer c.running.Unlock()
		if coalesced {
			c.queued.Store(false)
		}
		c.run(task)
	}()
	return done
}

func (c *Coordinator) run(task func() error) {
	c.startedAt.Store(time.Now().Unix())
	c.rebuilding.Store(true)
	c.publish()

	start := time.Now()
	err := CatchPanic(task)
	c.lastDurationMs.Store(uint64(time.Since(start).Milliseconds()))
	c.rebuilding.Store(false)
	// After the flag and the duration, so a completion never carries the
	// previous run's numbers.
	c.lastFailed.Store(err != nil)
	c.publish()
	if err != nil {
		slog.Warn("rebuild task failed; keeping previous filter", "event", "filter.rebuild_failed", "error", err)
	}
}

// CatchPanic runs task and turns a panic into an error. A background
// goroutine has no caller to recover, so without this a panic ends the process.
func CatchPanic(task func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("panic: %v", recovered)
		}
	}()
	return task()
}

// offer makes room by dropping the oldest message when the buffer is full.
// publish holds subscribersMu, so it is the only sender and the retry fits.
func offer(updates chan Status, status Status) {
	select {
	case updates <- status:
		return
	default:
	}
	select {
	case <-updates:
	default:
	}
	select {
	case updates <- status:
	default:
	}
}
