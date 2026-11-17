package db

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Ports of tests/db_concurrency_test.rs.

func concurrencyEntry(i int64) QueryLogEntry {
	upstream := "1.1.1.1"
	return QueryLogEntry{
		Timestamp:  1_700_000_000_000 + i,
		Domain:     fmt.Sprintf("host-%d.example.com", i%1024),
		QueryType:  "A",
		ClientIP:   fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256),
		Blocked:    i%7 == 0,
		Cached:     i%3 == 0,
		ResponseMs: i%50 + 1,
		Upstream:   &upstream,
	}
}

// A reader and a streaming writer run concurrently under WAL on their own
// connections; both must finish. Only a generous 5 s ceiling, as in Rust.
func TestReaderAndWriterRunConcurrentlyWithoutError(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	seed := make([]QueryLogEntry, 10_000)
	for i := range seed {
		seed[i] = concurrencyEntry(int64(i))
	}
	must(t, database.InsertQueryLogs(ctx, seed))

	errs := make(chan error, 2)
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		for round := range int64(10) {
			batch := make([]QueryLogEntry, 500)
			for i := range batch {
				batch[i] = concurrencyEntry(100_000 + round*500 + int64(i))
			}
			if err := database.InsertQueryLogs(ctx, batch); err != nil {
				errs <- err
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	go func() {
		defer group.Done()
		const sinceSeconds = 1_000_000_000 // epoch seconds; well before any row
		for range 10 {
			summary, err := database.LatencySummarySince(ctx, sinceSeconds)
			if err != nil {
				errs <- err
				return
			}
			if summary.SampleCount == 0 {
				errs <- fmt.Errorf("no samples")
				return
			}
		}
	}()
	finished := make(chan struct{})
	go func() { group.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("writer + reader must both complete within 5s")
	}
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if total, _ := database.TotalLogCount(ctx); total != 10_000+10*500 {
		t.Fatalf("total %d", total)
	}
}

// Readers are read-only, so a write routed to one would fail: a write then a
// read succeeding shows each went to the right connection.
func TestReadOnlyRoutingDoesNotBreakWrites(t *testing.T) {
	database := fileDB(t)
	insertLogs(t, database, concurrencyEntry(1))
	if rows, err := database.QueryLogs(context.Background(), QueryLogFilter{}, 10, 0); err != nil || len(rows) != 1 {
		t.Fatalf("%d %v", len(rows), err)
	}
}
