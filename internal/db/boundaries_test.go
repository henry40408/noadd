package db

import (
	"context"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDSNUsesAnAbsolutePath(t *testing.T) {
	if got := dsn("relative.sqlite3", nil, ""); !strings.HasPrefix(got, "file:///") {
		t.Fatalf("dsn = %q, want an absolute file URI", got)
	}
}

// A step whose version equals the stored one has already run and must not run
// again; step 13 overwrites the counter, so a re-run shows.
func TestMigrationAtTheStoredVersionIsNotReapplied(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "reopen.sqlite3")
	first, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.writer.Exec("UPDATE settings SET value = '999' WHERE key = ?1", queryLogCountKey); err != nil {
		t.Fatal(err)
	}
	if _, err := first.writer.Exec("PRAGMA user_version = 13"); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(ctx); err != nil {
		t.Fatal(err)
	}

	database := openDB(t, path)

	if got, err := database.TotalLogCount(ctx); err != nil || got != 999 {
		t.Fatalf("count = %d, err %v: step 13 ran again", got, err)
	}
}

func TestLogCountFallsBackToCountingOnlyWhenUnreadable(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	must(t, database.InsertQueryLogs(ctx, []QueryLogEntry{logAt(1, "a"), logAt(2, "b")}))
	setCounter := func(value string) {
		t.Helper()
		if _, err := database.writer.Exec("UPDATE settings SET value = ?1 WHERE key = ?2", value, queryLogCountKey); err != nil {
			t.Fatal(err)
		}
	}

	setCounter("7")
	if got, _ := database.TotalLogCount(ctx); got != 7 {
		t.Fatalf("a readable counter must be trusted, got %d", got)
	}
	setCounter("not a number")
	if got, _ := database.TotalLogCount(ctx); got != 2 {
		t.Fatalf("an unreadable counter must fall back to COUNT(*), got %d", got)
	}
}

func TestSaturatingAdd(t *testing.T) {
	for _, c := range []struct{ a, b, want int64 }{
		{1, 1, 2},
		{0, 5, 5},
		{5, 0, 5},
		{-3, 2, -1},
		{math.MaxInt64, 1, math.MaxInt64},
		{1, math.MaxInt64, math.MaxInt64},
		{math.MaxInt64, math.MaxInt64, math.MaxInt64},
	} {
		if got := saturatingAdd(c.a, c.b); got != c.want {
			t.Errorf("saturatingAdd(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func domainsOf(entries []QueryLogEntry) []string {
	var domains []string
	for _, entry := range entries {
		domains = append(domains, entry.Domain)
	}
	return domains
}

func TestQueryLogsTypeFilterCombinesWithOtherFilters(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	var entries []QueryLogEntry
	for i, domain := range []string{"a1", "a2", "a3", "a4", "a5"} {
		entry := logAt(int64(100+i), domain)
		entry.Blocked = i%2 == 0
		entries = append(entries, entry)
	}
	aaaa := logAt(200, "v6")
	aaaa.QueryType = "AAAA"
	aaaa.Blocked = true
	must(t, database.InsertQueryLogs(ctx, append(entries, aaaa)))

	typeOnly, err := database.QueryLogs(ctx, QueryLogFilter{QueryType: ptr("A")}, 2, 1)
	must(t, err)
	if got := domainsOf(typeOnly); !slices.Equal(got, []string{"a4", "a3"}) {
		t.Fatalf("type-only page = %v, want [a4 a3]", got)
	}
	unlimited, err := database.QueryLogs(ctx, QueryLogFilter{QueryType: ptr("A")}, -1, 0)
	must(t, err)
	if len(unlimited) != 5 {
		t.Fatalf("unlimited type-only page has %d rows, want 5", len(unlimited))
	}

	combined, err := database.QueryLogs(ctx, QueryLogFilter{QueryType: ptr("A"), Blocked: ptr(true)}, 10, 0)
	must(t, err)
	if got := domainsOf(combined); !slices.Equal(got, []string{"a5", "a3", "a1"}) {
		t.Fatalf("type and blocked = %v, want [a5 a3 a1]", got)
	}
}

func TestFlushSessionsLastSeenWritesEveryEntry(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	user, err := database.CreateUser(ctx, "alice", "h", 1)
	must(t, err)
	for _, hash := range []string{"s1", "s2", "s3"} {
		_, err := database.InsertSession(ctx, NewSession{TokenHash: hash, UserID: user, CreatedAt: 1, LastSeen: 1})
		must(t, err)
	}

	must(t, database.FlushSessionsLastSeen(ctx, []SessionLastSeen{{"s1", 10}, {"s2", 20}, {"s3", 30}}))

	listed, err := database.ListSessions(ctx)
	must(t, err)
	lastSeen := map[string]int64{}
	for _, session := range listed {
		lastSeen[session.TokenHash] = session.LastSeen
	}
	if lastSeen["s1"] != 10 || lastSeen["s2"] != 20 || lastSeen["s3"] != 30 {
		t.Fatalf("last seen = %v", lastSeen)
	}
}

func TestQueryTypesAreOrderedByCountThenName(t *testing.T) {
	rows := []WindowMetricsRow{
		{QueryType: "TXT", Count: 3},
		{QueryType: "B", Count: 5},
		{QueryType: "A", Count: 5},
		{QueryType: "MX", Count: 9},
	}

	got := queryTypesFromWindow(rows)

	want := []NameCount{{"MX", 9}, {"A", 5}, {"B", 5}, {"TXT", 3}}
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestOrderingHelpers(t *testing.T) {
	for _, c := range []struct {
		a, b int64
		want int
	}{{1, 2, -1}, {2, 2, 0}, {3, 2, 1}} {
		if got := cmpInt(c.a, c.b); got != c.want {
			t.Errorf("cmpInt(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	a, b := "a", "b"
	for _, c := range []struct {
		x, y *string
		want int
	}{{nil, nil, 0}, {nil, &a, -1}, {&a, nil, 1}, {&a, &a, 0}, {&a, &b, -1}, {&b, &a, 1}} {
		if got := compareOptionalString(c.x, c.y); got != c.want {
			t.Errorf("compareOptionalString(%v, %v) = %d, want %d", c.x, c.y, got, c.want)
		}
	}
}

// An hour-aligned instant in 2023, in milliseconds.
const alignedBaseMs = 1_699_999_200_000

// poisonedStatsDB holds twelve logs in the first hour after alignedBaseMs, then
// adds rollupSkew to every quarter rollup row. A read that folds the rollup
// shows the skew; a read that counts query_logs does not.
func poisonedStatsDB(t *testing.T) (database *DB, rollupSkew int64) {
	t.Helper()
	database = fileDB(t)
	var entries []QueryLogEntry
	for i := range int64(12) {
		entries = append(entries, logAt(alignedBaseMs+i*300_000, "p.test"))
	}
	must(t, database.InsertQueryLogs(context.Background(), entries))
	const skew = 1000
	if _, err := database.writer.Exec("UPDATE query_stats_quarter SET count = count + ?1", skew); err != nil {
		t.Fatal(err)
	}
	return database, skew
}

func TestStatsReadsChooseTheRollupOnlyForWholeQuarterShapes(t *testing.T) {
	ctx := context.Background()
	database, skew := poisonedStatsDB(t)
	sinceSecs := int64(alignedBaseMs / 1000)

	timelineTotal := func(bucketSecs, tzOffsetSecs int64) int64 {
		t.Helper()
		points, err := database.TimelineMultiSince(ctx, sinceSecs, bucketSecs, tzOffsetSecs)
		must(t, err)
		var total int64
		for _, point := range points {
			total += point.Total
		}
		return total
	}
	heatmapTotal := func(tzOffsetSecs int64) int64 {
		t.Helper()
		cells, err := database.HourlyHeatmapSince(ctx, sinceSecs, tzOffsetSecs)
		must(t, err)
		var total int64
		for _, cell := range cells {
			total += cell.Count
		}
		return total
	}
	simpleTimelineTotal := func(bucketSecs int64) int64 {
		t.Helper()
		points, err := database.TimelineSince(ctx, sinceSecs, bucketSecs)
		must(t, err)
		var total int64
		for _, point := range points {
			total += point.Total
		}
		return total
	}

	for name, c := range map[string]struct {
		total   int64
		fromLog bool
	}{
		"timeline, whole-quarter bucket and zero offset":    {timelineTotal(3600, 0), false},
		"timeline, whole-quarter bucket and quarter offset": {timelineTotal(3600, 900), false},
		"timeline, bucket off the quarter grid":             {timelineTotal(1000, 0), true},
		"timeline, offset off the quarter grid":             {timelineTotal(3600, 1), true},
		"heatmap, whole-quarter offset":                     {heatmapTotal(3600), false},
		"heatmap, offset off the quarter grid":              {heatmapTotal(1), true},
		"simple timeline, whole-quarter bucket":             {simpleTimelineTotal(3600), false},
		"simple timeline, bucket off the quarter grid":      {simpleTimelineTotal(1000), true},
	} {
		want := int64(12)
		if !c.fromLog {
			want += 4 * skew // twelve logs at five-minute steps span four quarters
		}
		if c.total != want {
			t.Errorf("%s: total = %d, want %d", name, c.total, want)
		}
	}
}

// A log exactly on the first whole quarter of the window is counted by the
// rollup arm; the table arm must not count it again.
func TestStatsScanCountsARowOnTheFirstWholeQuarterOnce(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	const firstQuarterMs = alignedBaseMs + 900_000
	must(t, database.InsertQueryLogs(ctx, []QueryLogEntry{logAt(firstQuarterMs, "edge.test")}))

	scan, err := database.StatsScanSince(ctx, firstQuarterMs/1000, firstQuarterMs/1000)
	must(t, err)

	var total int64
	for _, count := range scan.Series.Total {
		total += count
	}
	if total != 1 {
		t.Fatalf("series total = %d, want 1", total)
	}
}
