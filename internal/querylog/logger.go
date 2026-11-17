// Package querylog buffers query log entries and writes them to the database in
// batches, and publishes each entry live to the admin UI tail.
package querylog

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/henry40408/noadd/internal/db"
)

const (
	// QueueCapacity is the entries the queue holds before Log drops.
	QueueCapacity = 10_000
	// SubscriberCapacity is the live entries buffered per subscriber.
	SubscriberCapacity = 256
)

// ErrCloseTimeout means the final flush did not finish in time.
var ErrCloseTimeout = errors.New("query logger did not stop in time")

// Sink stores a batch of entries; *db.DB satisfies it.
type Sink interface {
	InsertQueryLogs(ctx context.Context, entries []db.QueryLogEntry) error
}

// Config configures a Logger.
type Config struct {
	Sink           Sink
	FlushThreshold int
	FlushInterval  time.Duration
	Logger         *slog.Logger
}

// Logger is the async query logger.
type Logger struct {
	cfg     Config
	queue   chan db.QueryLogEntry
	stop    chan struct{}
	done    chan struct{}
	closing sync.Once
	closed  atomic.Bool

	subscribersMu sync.Mutex
	subscribers   map[*Subscription]struct{}
}

// Subscription is a live feed of entries. C is closed when the subscriber is
// dropped for falling behind, or after Cancel.
type Subscription struct {
	C      <-chan *db.QueryLogEntry
	feed   chan *db.QueryLogEntry
	logger *Logger
	// ended is guarded by logger.subscribersMu.
	ended bool
}

// New creates a Logger. Call Run in a goroutine.
func New(cfg Config) *Logger {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Logger{
		cfg:         cfg,
		queue:       make(chan db.QueryLogEntry, QueueCapacity),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		subscribers: make(map[*Subscription]struct{}),
	}
}

// Log queues an entry without blocking the query path. It reports false when
// the queue is full or the logger is closed, and the entry is dropped.
func (l *Logger) Log(entry db.QueryLogEntry) bool {
	if l.closed.Load() {
		return false
	}
	select {
	case l.queue <- entry:
		return true
	default:
		return false
	}
}

// Subscribe returns a live feed of entries, published before the database flush.
// A subscriber that lets SubscriberCapacity entries pile up is dropped and its
// channel closed, so a stalled admin tab cannot slow the logger.
func (l *Logger) Subscribe() *Subscription {
	feed := make(chan *db.QueryLogEntry, SubscriberCapacity)
	subscription := &Subscription{C: feed, feed: feed, logger: l}
	l.subscribersMu.Lock()
	l.subscribers[subscription] = struct{}{}
	l.subscribersMu.Unlock()
	return subscription
}

// Cancel ends the subscription. It is safe to call more than once.
func (s *Subscription) Cancel() {
	s.logger.subscribersMu.Lock()
	defer s.logger.subscribersMu.Unlock()
	s.logger.end(s)
}

// end removes a subscription and closes its feed once; the caller holds
// subscribersMu.
func (l *Logger) end(s *Subscription) {
	if s.ended {
		return
	}
	s.ended = true
	delete(l.subscribers, s)
	close(s.feed)
}

func (l *Logger) publish(entry *db.QueryLogEntry) {
	l.subscribersMu.Lock()
	defer l.subscribersMu.Unlock()
	for subscription := range l.subscribers {
		select {
		case subscription.feed <- entry:
		default:
			l.end(subscription)
		}
	}
}

func (l *Logger) hasSubscribers() bool {
	l.subscribersMu.Lock()
	defer l.subscribersMu.Unlock()
	return len(l.subscribers) > 0
}

// Run writes entries until Close is called or ctx ends, then flushes what is
// left. It returns once the final flush is done.
func (l *Logger) Run(ctx context.Context) {
	defer close(l.done)
	buffer := make([]db.QueryLogEntry, 0, l.cfg.FlushThreshold)
	ticker := time.NewTicker(l.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case entry := <-l.queue:
			buffer = l.accept(ctx, buffer, entry)
		case <-ticker.C:
			buffer = l.flush(ctx, buffer)
		case <-l.stop:
			l.shutdown(buffer)
			return
		case <-ctx.Done():
			l.closed.Store(true)
			l.shutdown(buffer)
			return
		}
	}
}

func (l *Logger) accept(ctx context.Context, buffer []db.QueryLogEntry, entry db.QueryLogEntry) []db.QueryLogEntry {
	// No copy when nobody is watching.
	if l.hasSubscribers() {
		published := entry
		l.publish(&published)
	}
	buffer = append(buffer, entry)
	if len(buffer) >= l.cfg.FlushThreshold {
		return l.flush(ctx, buffer)
	}
	return buffer
}

// shutdown drains the queue and writes the remainder. It uses a fresh context:
// the one that stopped Run is already done.
func (l *Logger) shutdown(buffer []db.QueryLogEntry) {
	for {
		select {
		case entry := <-l.queue:
			buffer = append(buffer, entry)
			continue
		default:
		}
		break
	}
	l.flush(context.Background(), buffer)
	l.cfg.Logger.Info("query logger shutting down", "event", "querylog.worker_stopped")
}

// flush writes the buffer and always empties it: a failed batch is dropped, not
// retried forever.
func (l *Logger) flush(ctx context.Context, buffer []db.QueryLogEntry) []db.QueryLogEntry {
	if len(buffer) == 0 {
		return buffer
	}
	if err := l.cfg.Sink.InsertQueryLogs(ctx, buffer); err != nil {
		l.cfg.Logger.Warn("failed to flush query logs to database", "event", "querylog.flush_failed",
			"entries", len(buffer), "error", err)
	}
	return buffer[:0]
}

// Close stops accepting entries, then waits up to timeout for the remainder to
// be written.
func (l *Logger) Close(timeout time.Duration) error {
	l.closing.Do(func() {
		l.closed.Store(true)
		close(l.stop)
	})
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-l.done:
		return nil
	case <-timer.C:
		return ErrCloseTimeout
	}
}
