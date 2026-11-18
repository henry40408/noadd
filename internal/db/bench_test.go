package db

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const (
	syntheticLogRows = 200_000
	syntheticSpanMs  = 30 * 24 * hourMs
)

// benchDB opens BENCH_DB (a production copy: Open migrates in place) or, when
// unset, builds a synthetic 30-day database. BENCH_NOW pins "now" in Unix
// seconds.
func benchDB(b *testing.B) (database *DB, nowSecs int64) {
	b.Helper()
	ctx := context.Background()
	nowSecs = time.Now().Unix()
	if pinned := os.Getenv("BENCH_NOW"); pinned != "" {
		parsed, err := strconv.ParseInt(pinned, 10, 64)
		if err != nil {
			b.Fatalf("BENCH_NOW must be Unix seconds: %v", err)
		}
		nowSecs = parsed
	}
	if path := os.Getenv("BENCH_DB"); path != "" {
		opened, err := Open(ctx, path)
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { _ = opened.Close(ctx) })
		return opened, nowSecs
	}
	opened, err := Open(ctx, filepath.Join(b.TempDir(), "bench.sqlite3"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = opened.Close(ctx) })
	startMs := nowSecs*1000 - syntheticSpanMs
	for batchStart := int64(0); batchStart < syntheticLogRows; batchStart += 500 {
		batch := make([]QueryLogEntry, 0, 500)
		for i := batchStart; i < batchStart+500; i++ {
			entry := logAt(startMs+i*(syntheticSpanMs/syntheticLogRows), "d"+strconv.FormatInt(i%5000, 10)+".example")
			entry.Blocked = i%5 == 0
			entry.Cached = i%3 == 0
			entry.ClientIP = "10.0.0." + strconv.FormatInt(i%50, 10)
			batch = append(batch, entry)
		}
		if err := opened.InsertQueryLogs(ctx, batch); err != nil {
			b.Fatal(err)
		}
	}
	return opened, nowSecs
}

func BenchmarkStatsSummary(b *testing.B) {
	ctx := context.Background()
	database, now := benchDB(b)
	b.ResetTimer()
	for range b.N {
		if _, err := database.SummaryMultiSince(ctx, now-86400, now-7*86400, now-30*86400); err != nil {
			b.Fatal(err)
		}
		if _, err := database.StatsScanSince(ctx, now-30*86400, now-7*86400); err != nil {
			b.Fatal(err)
		}
		if _, err := database.TrafficListsSince(ctx, now-30*86400, 10); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryLogsPage(b *testing.B) {
	ctx := context.Background()
	database, _ := benchDB(b)
	filters := map[string]QueryLogFilter{
		"unfiltered": {},
		"blocked":    {Blocked: ptr(true)},
		"type":       {QueryType: ptr("A")},
		"search":     {Search: ptr("d12")},
	}
	for name, filter := range filters {
		b.Run(name, func(b *testing.B) {
			for range b.N {
				if _, err := database.QueryLogs(ctx, filter, 50, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkInsertBatch500(b *testing.B) {
	ctx := context.Background()
	database, err := Open(ctx, filepath.Join(b.TempDir(), "insert.sqlite3"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = database.Close(ctx) })
	batch := make([]QueryLogEntry, 500)
	for i := range batch {
		batch[i] = logAt(int64(i)*1000, "bench"+strconv.Itoa(i%100)+".example")
	}
	b.ResetTimer()
	for range b.N {
		if err := database.InsertQueryLogs(ctx, batch); err != nil {
			b.Fatal(err)
		}
	}
}
