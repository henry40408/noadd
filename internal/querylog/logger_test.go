package querylog

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/db"
)

func openDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close(context.Background()) })
	return database
}

func entry(domain string, blocked bool, queryType string) db.QueryLogEntry {
	return db.QueryLogEntry{Timestamp: 1000, Domain: domain, QueryType: queryType, ClientIP: "127.0.0.1", Blocked: blocked}
}

func startLogger(t *testing.T, sink Sink, threshold int, interval time.Duration) *Logger {
	t.Helper()
	logger := New(Config{Sink: sink, FlushThreshold: threshold, FlushInterval: interval})
	go logger.Run(context.Background())
	return logger
}

func countLogs(t *testing.T, database *db.DB) int {
	t.Helper()
	rows, err := database.QueryLogs(context.Background(), db.QueryLogFilter{}, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Rust: test_logger_flushes_on_threshold
func TestFlushesOnThreshold(t *testing.T) {
	database := openDB(t)
	logger := startLogger(t, database, 5, time.Hour)
	for i := range 5 {
		logger.Log(entry("example"+strconv.Itoa(i)+".com", false, "A"))
	}

	eventually(t, "the threshold flush", func() bool { return countLogs(t, database) == 5 })

	if err := logger.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}
}

// Rust: test_logger_flushes_on_channel_close
func TestFlushesRemainderOnClose(t *testing.T) {
	database := openDB(t)
	logger := startLogger(t, database, 1000, time.Hour)
	for i := range 3 {
		logger.Log(entry("test"+strconv.Itoa(i)+".org", true, "AAAA"))
	}

	if err := logger.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	rows, err := database.QueryLogs(context.Background(), db.QueryLogFilter{}, 100, 0)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	for _, row := range rows {
		if !row.Blocked || row.QueryType != "AAAA" {
			t.Fatalf("row = %+v", row)
		}
	}
}

// Rust: test_logger_flushes_on_interval
func TestFlushesOnInterval(t *testing.T) {
	database := openDB(t)
	logger := startLogger(t, database, 10000, 50*time.Millisecond)
	defer logger.Close(5 * time.Second)
	logger.Log(entry("interval0.com", false, "A"))
	logger.Log(entry("interval1.com", false, "A"))

	eventually(t, "the timer flush", func() bool { return countLogs(t, database) == 2 })
}

// Rust: test_logger_publishes_to_event_broadcast
func TestPublishesToSubscribersBeforeTheFlush(t *testing.T) {
	database := openDB(t)
	logger := startLogger(t, database, 1000, time.Hour)
	defer logger.Close(5 * time.Second)
	subscription := logger.Subscribe()
	defer subscription.Cancel()

	logger.Log(entry("live.example.com", false, "A"))

	select {
	case got := <-subscription.C:
		if got.Domain != "live.example.com" || got.QueryType != "A" || got.Blocked {
			t.Fatalf("entry = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no live entry")
	}
	if countLogs(t, database) != 0 {
		t.Fatal("the live entry must not wait for the flush")
	}
}

type blockingSink struct {
	release chan struct{}
	mu      sync.Mutex
	got     int
}

func (s *blockingSink) InsertQueryLogs(_ context.Context, entries []db.QueryLogEntry) error {
	<-s.release
	s.mu.Lock()
	s.got += len(entries)
	s.mu.Unlock()
	return nil
}

// tokio broadcast lagged a receiver; the plan drops it. Either way the logger
// must not block on a stalled subscriber.
func TestSlowSubscriberIsDroppedAndDoesNotBlock(t *testing.T) {
	database := openDB(t)
	logger := startLogger(t, database, 100000, time.Hour)
	defer logger.Close(5 * time.Second)
	slow := logger.Subscribe()
	fast := logger.Subscribe()
	defer fast.Cancel()

	go func() {
		for range fast.C {
		}
	}()
	for i := range SubscriberCapacity + 50 {
		logger.Log(entry("d"+strconv.Itoa(i)+".test", false, "A"))
	}

	eventually(t, "the slow subscriber being dropped", func() bool {
		select {
		case _, open := <-slow.C:
			return !open && len(slow.C) == 0
		default:
			return false
		}
	})
	slow.Cancel() // after a drop it must be a no-op, not a double close
}

func TestLogDropsWhenQueueIsFullOrClosed(t *testing.T) {
	logger := New(Config{Sink: &blockingSink{release: make(chan struct{})}, FlushThreshold: 1, FlushInterval: time.Hour})
	for range QueueCapacity {
		if !logger.Log(entry("a.test", false, "A")) {
			t.Fatal("the queue has room")
		}
	}
	if logger.Log(entry("a.test", false, "A")) {
		t.Fatal("a full queue must drop, not block")
	}
	logger.closed.Store(true)
	if logger.Log(entry("a.test", false, "A")) {
		t.Fatal("a closed logger must refuse entries")
	}
}

type failingSink struct{ calls int }

func (s *failingSink) InsertQueryLogs(context.Context, []db.QueryLogEntry) error {
	s.calls++
	return errors.New("disk full")
}

func TestFailedFlushDropsTheBatch(t *testing.T) {
	sink := &failingSink{}
	logger := startLogger(t, sink, 2, time.Hour)
	logger.Log(entry("a.test", false, "A"))
	logger.Log(entry("b.test", false, "A"))
	if err := logger.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if sink.calls != 1 {
		t.Fatalf("flush calls = %d: a failed batch must be dropped, not retried on close", sink.calls)
	}
}

func TestCloseTimesOutWhenTheSinkIsStuck(t *testing.T) {
	sink := &blockingSink{release: make(chan struct{})}
	logger := startLogger(t, sink, 1, time.Hour)
	logger.Log(entry("a.test", false, "A"))
	defer close(sink.release)

	if err := logger.Close(50 * time.Millisecond); !errors.Is(err, ErrCloseTimeout) {
		t.Fatalf("err = %v", err)
	}
}

func TestCloseTwiceAndRunStopsOnContext(t *testing.T) {
	logger := New(Config{Sink: &failingSink{}, FlushThreshold: 10, FlushInterval: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	go logger.Run(ctx)
	cancel()
	if err := logger.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := logger.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}
}

type batchRecordingSink struct {
	mu      sync.Mutex
	batches []int
}

func (s *batchRecordingSink) InsertQueryLogs(_ context.Context, entries []db.QueryLogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, len(entries))
	return nil
}

func (s *batchRecordingSink) batchSizes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int(nil), s.batches...)
}

// Entries below the threshold wait for the timer or Close; reaching it flushes
// them as one batch.
func TestThresholdFlushWritesOneFullBatch(t *testing.T) {
	sink := &batchRecordingSink{}
	logger := startLogger(t, sink, 3, time.Hour)
	for i := range 3 {
		logger.Log(entry("batch"+strconv.Itoa(i)+".test", false, "A"))
	}

	eventually(t, "the threshold flush", func() bool { return len(sink.batchSizes()) > 0 })
	if err := logger.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}

	if got := sink.batchSizes(); len(got) != 1 || got[0] != 3 {
		t.Fatalf("batches = %v, want [3]", got)
	}
}

// syncBuffer lets the logger goroutine write while the test reads.
type syncBuffer struct {
	mu   sync.Mutex
	data strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}

func flushAndCollectLog(t *testing.T, sink Sink) string {
	t.Helper()
	var output syncBuffer
	logger := New(Config{
		Sink:           sink,
		FlushThreshold: 1000,
		FlushInterval:  time.Hour,
		Logger:         slog.New(slog.NewTextHandler(&output, nil)),
	})
	go logger.Run(context.Background())
	logger.Log(entry("a.test", false, "A"))
	if err := logger.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func TestFlushFailureIsLoggedAndSuccessIsNot(t *testing.T) {
	if got := flushAndCollectLog(t, &failingSink{}); !strings.Contains(got, "querylog.flush_failed") {
		t.Fatalf("a failed flush must be logged, got %q", got)
	}
	if got := flushAndCollectLog(t, &batchRecordingSink{}); strings.Contains(got, "flush_failed") {
		t.Fatalf("a successful flush must not log a failure, got %q", got)
	}
}
