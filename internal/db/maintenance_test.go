package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pragmaInt(t *testing.T, pool *sql.DB, name string) int64 {
	t.Helper()
	var value int64
	if err := pool.QueryRow("PRAGMA " + name).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

// freelistOfAFifth adds one-page tables until the page count divides by five,
// then drops them until the freelist is exactly a fifth of the pages, less
// shortfall. A dropped table returns its page to the freelist and the file
// does not shrink, so both numbers are exact. It returns the page count and
// the freelist it reached.
func freelistOfAFifth(t *testing.T, database *DB, shortfall int64) (pages, freelist int64) {
	t.Helper()
	exec := func(query string) {
		t.Helper()
		if _, err := database.writer.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	tables := 0
	for pages = pragmaInt(t, database.writer, "page_count"); pages < 100 || pages%5 != 0; pages = pragmaInt(t, database.writer, "page_count") {
		tables++
		// A 3000-byte row fills a 4 KiB page by itself.
		exec(fmt.Sprintf("CREATE TABLE scratch%d (payload BLOB)", tables))
		exec(fmt.Sprintf("INSERT INTO scratch%d VALUES (zeroblob(3000))", tables))
	}
	want := pages/5 - shortfall
	for dropped := 1; dropped <= tables && pragmaInt(t, database.writer, "freelist_count") < want; dropped++ {
		exec(fmt.Sprintf("DROP TABLE scratch%d", dropped))
	}
	freelist = pragmaInt(t, database.writer, "freelist_count")
	if freelist != want || pragmaInt(t, database.writer, "page_count") != pages {
		t.Fatalf("setup: freelist %d of %d pages, want %d", freelist, pages, want)
	}
	return pages, freelist
}

func TestMaintenanceVacuumsFromTheFreelistRatio(t *testing.T) {
	for _, c := range []struct {
		name       string
		shortfall  int64
		wantVacuum bool
	}{
		{"exactly at the ratio", 0, true},
		{"one page below the ratio", 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			database := fileDB(t)
			_, freelist := freelistOfAFifth(t, database, c.shortfall)

			if err := database.RunMaintenance(context.Background()); err != nil {
				t.Fatal(err)
			}

			want := freelist
			if c.wantVacuum {
				want = 0
			}
			if got := pragmaInt(t, database.writer, "freelist_count"); got != want {
				t.Fatalf("freelist after maintenance = %d, want %d", got, want)
			}
		})
	}
}

func TestStorageStatsReportBytesNotPages(t *testing.T) {
	database := fileDB(t)
	pages, freelist := freelistOfAFifth(t, database, 0)
	pageSize := pragmaInt(t, database.writer, "page_size")

	stats, err := database.DBStorageStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if stats.MainBytes != pages*pageSize || stats.ReclaimableBytes != freelist*pageSize {
		t.Fatalf("stats = %+v, want main %d reclaimable %d", stats, pages*pageSize, freelist*pageSize)
	}
}

// rowsAsText renders every row of query as "a|b|c" so two result sets compare
// with slices.Equal.
func rowsAsText(t *testing.T, pool *sql.DB, query string) []string {
	t.Helper()
	rows, err := pool.Query(query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		values := make([]any, len(columns))
		targets := make([]any, len(columns))
		for i := range values {
			targets[i] = &values[i]
		}
		if err := rows.Scan(targets...); err != nil {
			t.Fatal(err)
		}
		cells := make([]string, len(values))
		for i, value := range values {
			cells[i] = fmt.Sprint(value)
		}
		out = append(out, strings.Join(cells, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// rollupChecks pair each rollup table with the query that recomputes it from
// query_logs. Equal output means no residue: no zero-count rows, no rows for
// pruned units, no missing rows.
var rollupChecks = []struct{ name, rollup, recomputed string }{
	{
		"quarter",
		"SELECT quarter, blocked, cached, count, sum_ms FROM query_stats_quarter ORDER BY 1, 2, 3",
		"SELECT timestamp / 900000, blocked, cached, COUNT(*), SUM(response_ms) FROM query_logs GROUP BY 1, 2, 3 ORDER BY 1, 2, 3",
	},
	{
		"domain hour",
		"SELECT hour, domain, count FROM query_stats_domain_hour ORDER BY 1, 2",
		"SELECT timestamp / 3600000, domain, COUNT(*) FROM query_logs GROUP BY 1, 2 ORDER BY 1, 2",
	},
	{
		"client hour",
		"SELECT hour, client_ip, doh_token, count FROM query_stats_client_hour ORDER BY 1, 2, 3",
		"SELECT timestamp / 3600000, client_ip, COALESCE(doh_token, ''), COUNT(*) FROM query_logs GROUP BY 1, 2, 3 ORDER BY 1, 2, 3",
	},
	{
		"upstream hour",
		"SELECT hour, upstream, count, sum_ms FROM query_stats_upstream_hour ORDER BY 1, 2",
		"SELECT timestamp / 3600000, upstream, COUNT(*), SUM(response_ms) FROM query_logs WHERE upstream IS NOT NULL GROUP BY 1, 2 ORDER BY 1, 2",
	},
	{
		"metrics hour",
		"SELECT hour, blocked, cached, has_result, query_type, response_ms, count FROM query_stats_metrics_hour ORDER BY 1, 2, 3, 4, 5, 6",
		`SELECT timestamp / 3600000, blocked, cached, result IS NOT NULL AND result != '', query_type, response_ms, COUNT(*)
			FROM query_logs GROUP BY 1, 2, 3, 4, 5, 6 ORDER BY 1, 2, 3, 4, 5, 6`,
	},
}

func assertRollupsMatchLogs(t *testing.T, database *DB) {
	t.Helper()
	for _, check := range rollupChecks {
		got := rowsAsText(t, database.reader, check.rollup)
		want := rowsAsText(t, database.reader, check.recomputed)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s rollup differs from the logs\n got: %q\nwant: %q", check.name, got, want)
		}
	}
}

func TestPruneLeavesRollupsEqualToTheRemainingLogs(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	const hourMs = int64(3_600_000)
	baseMs := 1_700_000_000_000 / hourMs * hourMs
	upstream, token, result := "1.1.1.1", "tok", "NOERROR"
	var entries []QueryLogEntry
	for i := range int64(40) {
		entry := logAt(baseMs+i*400_000, fmt.Sprintf("d%d.test", i%7))
		entry.Blocked, entry.Cached = i%3 == 0, i%4 == 0
		entry.ClientIP = fmt.Sprintf("10.0.0.%d", i%3)
		entry.ResponseMs = i % 5
		if i%2 == 0 {
			entry.Upstream, entry.DohToken, entry.Result = &upstream, &token, &result
		}
		entries = append(entries, entry)
	}
	must(t, database.InsertQueryLogs(ctx, entries))
	assertRollupsMatchLogs(t, database)

	// 2 h 7 min 30 s in: inside both an hour and a quarter hour.
	cutoffSecs := (baseMs + 2*hourMs + 7*60_000 + 30_000) / 1000
	if _, err := database.PruneLogsBefore(ctx, cutoffSecs); err != nil {
		t.Fatal(err)
	}

	assertRollupsMatchLogs(t, database)
}

// VACUUM rewrites the database through the WAL, so the truncating checkpoint
// after it is what gives that space back; returning early would leave it.
func TestMaintenanceTruncatesTheWALAfterAVacuum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.sqlite3")
	database := openDB(t, path)
	freelistOfAFifth(t, database, 0)

	if err := database.RunMaintenance(context.Background()); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("WAL is %d bytes after maintenance, want 0 (truncated)", info.Size())
	}
}
