package db

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"
)

// Ports of tests/stats_db_test.rs, in file order.

func statsEntry(tsSecs int64, queryType string, blocked, cached bool, result *string) QueryLogEntry {
	return QueryLogEntry{
		Timestamp: tsSecs * 1000, Domain: "example.com", QueryType: queryType, ClientIP: "1.2.3.4",
		Blocked: blocked, Cached: cached, Result: result, ResponseMs: 5,
	}
}

func statsEntryWith(tsSecs int64, domain string, responseMs int64) QueryLogEntry {
	return QueryLogEntry{Timestamp: tsSecs * 1000, Domain: domain, QueryType: "A", ClientIP: "1.2.3.4", ResponseMs: responseMs}
}

func nameCounts(rows []NameCount) map[string]int64 {
	counts := make(map[string]int64, len(rows))
	for _, row := range rows {
		counts[row.Name] = row.Count
	}
	return counts
}

func sortedNameCounts(rows []NameCount) []NameCount {
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b NameCount) int {
		if a.Name != b.Name {
			return cmpString(a.Name, b.Name)
		}
		return cmpInt(a.Count, b.Count)
	})
	return sorted
}

func cmpString(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func TestTimelineMultiBucketsTotalBlockedCached(t *testing.T) {
	database := rustTestDB(t)
	insertLogs(t, database,
		statsEntry(600, "A", false, false, ptr("NOERROR")),
		statsEntry(610, "A", true, false, ptr("NXDOMAIN")),
		statsEntry(620, "A", false, true, ptr("NOERROR")),
		statsEntry(700, "AAAA", false, false, ptr("NOERROR")))
	points, err := database.TimelineMultiSince(context.Background(), 0, 60, 0)
	must(t, err)
	want := []TimelineMultiPoint{{Timestamp: 600, Total: 3, Blocked: 1, Cached: 1}, {Timestamp: 660, Total: 1}}
	if !slices.Equal(points, want) {
		t.Fatalf("%+v", points)
	}
}

func TestTimelineMultiEmptyDB(t *testing.T) {
	points, err := rustTestDB(t).TimelineMultiSince(context.Background(), 0, 60, 0)
	must(t, err)
	if len(points) != 0 {
		t.Fatalf("%+v", points)
	}
}

// UTC+8 viewer: a query at 2026-06-13 00:00 UTC is local 08:00, so its day
// bucket starts at the prior local midnight (2026-06-12 16:00 UTC).
func TestTimelineMultiOffsetAlignsDayBucketsToLocalMidnight(t *testing.T) {
	database := rustTestDB(t)
	const utcMidnight = 1_781_280_000 + 8*3600
	insertLogs(t, database,
		statsEntry(utcMidnight, "A", false, false, nil),
		statsEntry(utcMidnight+9*3600, "A", true, false, nil),
		statsEntry(utcMidnight+16*3600, "A", false, true, nil))
	points, err := database.TimelineMultiSince(context.Background(), 0, 86400, 8*3600)
	must(t, err)
	want := []TimelineMultiPoint{{Timestamp: 1_781_280_000, Total: 2, Blocked: 1}, {Timestamp: 1_781_280_000 + 86400, Total: 1, Cached: 1}}
	if !slices.Equal(points, want) {
		t.Fatalf("%+v", points)
	}
}

func TestHeatmapGroupsByWeekdayAndHour(t *testing.T) {
	database := rustTestDB(t)
	const mondayMidnight = 1_704_067_200 // 2024-01-01 00:00:00 UTC
	insertLogs(t, database,
		statsEntry(mondayMidnight+10, "A", false, false, nil),
		statsEntry(mondayMidnight+20, "A", false, false, nil),
		statsEntry(mondayMidnight+3600+5, "A", false, false, nil))
	cells, err := database.HourlyHeatmapSince(context.Background(), 0, 0)
	must(t, err)
	got := map[[2]int64]int64{}
	for _, cell := range cells {
		got[[2]int64{cell.Weekday, cell.Hour}] = cell.Count
	}
	if got[[2]int64{1, 0}] != 2 || got[[2]int64{1, 1}] != 1 {
		t.Fatalf("%v", got)
	}
}

func TestHeatmapShiftsCellsByTzOffset(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	insertLogs(t, database, statsEntry(1_704_067_200+10, "A", false, false, nil))

	cells, _ := database.HourlyHeatmapSince(ctx, 0, 8*3600)
	if len(cells) != 1 || cells[0].Weekday != 1 || cells[0].Hour != 8 {
		t.Fatalf("UTC+8: %+v", cells)
	}
	// UTC-5 rolls it back over midnight to Sunday 19:00 local.
	cells, _ = database.HourlyHeatmapSince(ctx, 0, -5*3600)
	if len(cells) != 1 || cells[0].Weekday != 0 || cells[0].Hour != 19 {
		t.Fatalf("UTC-5: %+v", cells)
	}
}

// Weekday and hour come from integer arithmetic, not strftime; pin it across a
// week and several offsets (flooring vs truncation, the Thursday anchor).
func TestHeatmapMatchesStrftimeAcrossAFullWeek(t *testing.T) {
	database := rustTestDB(t)
	const start = 1_704_067_200
	entries := make([]QueryLogEntry, 40)
	for i := range entries {
		entries[i] = statsEntry(start+int64(i)*5*3600, "A", false, false, nil)
	}
	insertLogs(t, database, entries...)

	for _, offsetHours := range []int64{0, 8, -5, 13, -11} {
		offset := offsetHours * 3600
		cells, err := database.HourlyHeatmapSince(context.Background(), 0, offset)
		must(t, err)
		expected := map[[2]int64]int64{}
		for i := range int64(40) {
			local := start + i*5*3600 + offset
			expected[[2]int64{(floorDiv(local, 86400) + 4) % 7, floorMod(local, 86400) / 3600}]++
		}
		got := map[[2]int64]int64{}
		for _, cell := range cells {
			got[[2]int64{cell.Weekday, cell.Hour}] = cell.Count
			if cell.Weekday < 0 || cell.Weekday > 6 || cell.Hour < 0 || cell.Hour > 23 {
				t.Fatalf("cell outside the grid: %+v", cell)
			}
		}
		if !maps.Equal(got, expected) {
			t.Fatalf("offset %dh: got %v want %v", offsetHours, got, expected)
		}
	}
}

// floorMod is the Euclidean remainder, rem_euclid in the Rust tests.
func floorMod(dividend, divisor int64) int64 {
	return dividend - floorDiv(dividend, divisor)*divisor
}

func TestHeatmapEmptyDB(t *testing.T) {
	cells, err := rustTestDB(t).HourlyHeatmapSince(context.Background(), 0, 0)
	must(t, err)
	if len(cells) != 0 {
		t.Fatalf("%+v", cells)
	}
}

func TestQueryTypeBreakdownSortsDesc(t *testing.T) {
	database := rustTestDB(t)
	insertLogs(t, database,
		statsEntry(1000, "A", false, false, ptr("NOERROR")),
		statsEntry(1001, "A", false, false, ptr("NOERROR")),
		statsEntry(1002, "AAAA", false, false, ptr("NOERROR")),
		statsEntry(1003, "HTTPS", false, false, ptr("NOERROR")),
		statsEntry(1004, "A", false, false, ptr("NOERROR")))
	rows, err := database.QueryTypeBreakdownSince(context.Background(), 0)
	must(t, err)
	if len(rows) != 3 || rows[0] != (NameCount{"A", 3}) || rows[1].Count != 1 || rows[2].Count != 1 {
		t.Fatalf("%+v", rows)
	}
}

func TestOutcomeBreakdownCategorizesByAction(t *testing.T) {
	database := rustTestDB(t)
	insertLogs(t, database,
		statsEntry(1000, "A", false, false, ptr("142.250.196.142")),
		statsEntry(1001, "A", false, false, ptr("8.8.8.8")),
		statsEntry(1002, "A", true, false, nil),
		statsEntry(1003, "A", false, true, ptr("1.1.1.1")),
		statsEntry(1004, "A", false, false, nil))
	rows, err := database.OutcomeBreakdownSince(context.Background(), 0)
	must(t, err)
	got := nameCounts(rows)
	if got["Resolved"] != 2 || got["Blocked"] != 1 || got["Cached"] != 1 || got["Empty"] != 1 {
		t.Fatalf("%v", got)
	}
}

func TestDBStorageStatsAreSane(t *testing.T) {
	stats, err := rustTestDB(t).DBStorageStats(context.Background())
	must(t, err)
	if stats.MainBytes <= 0 || stats.ReclaimableBytes < 0 || stats.ReclaimableBytes > stats.MainBytes {
		t.Fatalf("%+v", stats)
	}
}

func TestTotalLogCountMatchesInserts(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	if n, _ := database.TotalLogCount(ctx); n != 0 {
		t.Fatalf("%d", n)
	}
	insertLogs(t, database, statsEntry(1000, "A", false, false, nil))
	if n, _ := database.TotalLogCount(ctx); n != 1 {
		t.Fatalf("%d", n)
	}
}

func TestUniqueDomainsCountsDistinct(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	insertLogs(t, database, statsEntryWith(1000, "a.com", 1), statsEntryWith(1001, "a.com", 2),
		statsEntryWith(1002, "b.com", 3), statsEntryWith(1003, "c.com", 4))
	if n, _ := database.UniqueDomainsSince(ctx, 0); n != 3 {
		t.Fatalf("%d", n)
	}
	if n, _ := database.UniqueDomainsSince(ctx, 1002); n != 2 {
		t.Fatalf("%d", n)
	}
}

func TestUniqueDomainsEmptyDBIsZero(t *testing.T) {
	if n, err := rustTestDB(t).UniqueDomainsSince(context.Background(), 0); err != nil || n != 0 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestLatencySummaryComputesPercentiles(t *testing.T) {
	database := rustTestDB(t)
	entries := make([]QueryLogEntry, 100)
	for i := range entries {
		entries[i] = statsEntryWith(1000+int64(i)+1, "x.com", int64(i)+1)
	}
	insertLogs(t, database, entries...)
	summary, err := database.LatencySummarySince(context.Background(), 0)
	must(t, err)
	if summary != (LatencySummary{SampleCount: 100, P50Ms: 50, P95Ms: 95, P99Ms: 99}) {
		t.Fatalf("%+v", summary)
	}
}

func TestLatencySummaryEmptyDBIsZero(t *testing.T) {
	summary, err := rustTestDB(t).LatencySummarySince(context.Background(), 0)
	must(t, err)
	if summary != (LatencySummary{}) {
		t.Fatalf("%+v", summary)
	}
}

func near(got, want float64) bool { return got-want < 1e-9 && want-got < 1e-9 }

// compute_summary lives in internal/stats (a later step); its ratios are
// restated here from the SummaryMultiSince fields it divides. The stats step
// must port the compute_summary call itself.
func TestComputeSummaryPopulates7dAnd30dRates(t *testing.T) {
	database := rustTestDB(t)
	const now, oneDay = 40 * 86400, 86400
	insertLogs(t, database,
		statsEntry(now-100, "A", true, false, ptr("NXDOMAIN")),
		statsEntry(now-200, "A", false, true, ptr("NOERROR")),
		statsEntry(now-3*oneDay, "A", false, false, ptr("NOERROR")),
		statsEntry(now-20*oneDay, "A", true, false, ptr("NXDOMAIN")))
	windows, err := database.SummaryMultiSince(context.Background(), now-oneDay, now-7*oneDay, now-30*oneDay)
	must(t, err)
	wantBlock := []float64{0.5, 1.0 / 3.0, 0.5}
	wantCache := []float64{1.0, 0.5, 0.5}
	for i, w := range windows {
		if !near(float64(w.Blocked)/float64(w.Total), wantBlock[i]) ||
			!near(float64(w.CacheHits)/float64(w.Allowed), wantCache[i]) || !near(w.AvgResponseMs, 5.0) {
			t.Fatalf("window %d: %+v", i, w)
		}
	}
}

// Totals and blocks count every query; cache hits and latency only allowed
// ones. Blocked rows get a response time no allowed row has.
func TestSummaryMultiSinceComputesEachWindow(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	const now, oneDay = 40 * 86400, 86400
	blocked := func(ts int64) QueryLogEntry {
		entry := statsEntry(ts, "A", true, false, ptr("NXDOMAIN"))
		entry.ResponseMs = 900
		return entry
	}
	insertLogs(t, database, blocked(now-100), statsEntry(now-200, "A", false, true, ptr("NOERROR")),
		statsEntry(now-3*oneDay, "A", false, false, ptr("NOERROR")), blocked(now-20*oneDay))
	windows, err := database.SummaryMultiSince(ctx, now-oneDay, now-7*oneDay, now-30*oneDay)
	must(t, err)
	if today, _ := database.CountQueriesSince(ctx, now-oneDay); windows[0].Total != today {
		t.Fatalf("today total %d vs %d", windows[0].Total, today)
	}
	if d30, _ := database.CountQueriesSince(ctx, now-30*oneDay); windows[2].Total != d30 {
		t.Fatalf("30d total %d vs %d", windows[2].Total, d30)
	}
	want := [][4]int64{{2, 1, 1, 1}, {3, 1, 2, 1}, {4, 2, 2, 1}}
	for i, w := range windows {
		if got := [4]int64{w.Total, w.Blocked, w.Allowed, w.CacheHits}; got != want[i] || !near(w.AvgResponseMs, 5.0) {
			t.Fatalf("window %d: %+v (blocked rows leaked into the average?)", i, w)
		}
	}
}

func TestSummaryMultiSinceOnAnEmptyWindowReportsZeroes(t *testing.T) {
	windows, err := rustTestDB(t).SummaryMultiSince(context.Background(), 0, 0, 0)
	must(t, err)
	for _, w := range windows {
		if w != (WindowSummary{}) {
			t.Fatalf("%+v", w)
		}
	}
}

// The Throughput card divides queries_1m by 60; older rows must not leak in.
// compute_summary is the stats step's; CountQueriesSince(now-60) is its source.
func TestComputeSummaryQueries1mCountsOnlyTheLast60Seconds(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	const now = 40 * 86400
	insertLogs(t, database,
		statsEntry(now-5, "A", false, false, ptr("NOERROR")),
		statsEntry(now-59, "A", true, false, ptr("NXDOMAIN")),
		statsEntry(now-61, "A", false, false, ptr("NOERROR")),
		statsEntry(now-3600, "A", false, false, ptr("NOERROR")))
	if n, _ := database.CountQueriesSince(ctx, now-60); n != 2 {
		t.Fatalf("1m %d", n)
	}
	windows, _ := database.SummaryMultiSince(ctx, now-86400, now-7*86400, now-30*86400)
	if windows[0].Total != 4 {
		t.Fatalf("today %d", windows[0].Total)
	}
}

func TestBothTimelineTypesReportBucketStartsInTheSameUnit(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	insertLogs(t, database,
		statsEntry(600, "A", false, false, ptr("NOERROR")),
		statsEntry(610, "A", true, false, ptr("NXDOMAIN")),
		statsEntry(700, "AAAA", false, false, ptr("NOERROR")))
	single, err := database.TimelineSince(ctx, 0, 60)
	must(t, err)
	multi, err := database.TimelineMultiSince(ctx, 0, 60, 0)
	must(t, err)
	if len(single) != 2 || len(multi) != 2 || single[0].Timestamp != 600 || single[1].Timestamp != 660 {
		t.Fatalf("%+v %+v", single, multi)
	}
	for i := range single {
		if single[i].Timestamp != multi[i].Timestamp || single[i].Total != multi[i].Total || single[i].Blocked != multi[i].Blocked {
			t.Fatalf("%+v vs %+v", single[i], multi[i])
		}
	}
}

func TestWindowMetricsAgreesWithTheSinglePurposeQueries(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	insertLogs(t, database,
		statsEntry(600, "A", false, false, ptr("1.1.1.1")),
		statsEntry(610, "A", true, false, nil),
		statsEntry(620, "AAAA", false, true, ptr("2606::1")),
		statsEntry(700, "HTTPS", false, false, nil),
		statsEntry(710, "A", false, false, ptr("")),
		statsEntry(720, "AAAA", false, false, ptr("2606::2")))
	combined, err := database.WindowMetricsSince(ctx, 0)
	must(t, err)
	latency, _ := database.LatencySummarySince(ctx, 0)
	types, _ := database.QueryTypeBreakdownSince(ctx, 0)
	outcomes, _ := database.OutcomeBreakdownSince(ctx, 0)
	if combined.Latency != latency ||
		!slices.Equal(sortedNameCounts(combined.QueryTypes), sortedNameCounts(types)) ||
		!slices.Equal(sortedNameCounts(combined.Outcomes), sortedNameCounts(outcomes)) {
		t.Fatalf("%+v", combined)
	}
}

// An empty result is not an answer, just as a NULL one is not.
func TestAnEmptyResultCountsAsEmptyNotResolved(t *testing.T) {
	database := rustTestDB(t)
	insertLogs(t, database,
		statsEntry(600, "A", false, false, ptr("")),
		statsEntry(610, "A", false, false, nil),
		statsEntry(620, "A", false, false, ptr("1.1.1.1")))
	rows, _ := database.OutcomeBreakdownSince(context.Background(), 0)
	if got := nameCounts(rows); got["Empty"] != 2 || got["Resolved"] != 1 {
		t.Fatalf("%v", got)
	}
}

// Blocked wins over cached, cached over answered, so each query counts once.
func TestOutcomePrecedenceCountsEachQueryOnce(t *testing.T) {
	database := rustTestDB(t)
	insertLogs(t, database,
		statsEntry(600, "A", true, true, ptr("1.1.1.1")),
		statsEntry(610, "A", false, true, ptr("1.1.1.1")))
	rows, _ := database.OutcomeBreakdownSince(context.Background(), 0)
	var sum int64
	for _, row := range rows {
		sum += row.Count
	}
	if got := nameCounts(rows); sum != 2 || got["Blocked"] != 1 || got["Cached"] != 1 {
		t.Fatalf("%v", got)
	}
}

func TestDomainStatsReportsTheTopListAndTheDistinctCountTogether(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	var entries []QueryLogEntry
	for i, domain := range []string{"a.test", "b.test", "c.test"} {
		for n := 0; n <= i; n++ {
			entry := statsEntry(600+int64(n), "A", false, false, ptr("1.1.1.1"))
			entry.Domain = domain
			entries = append(entries, entry)
		}
	}
	insertLogs(t, database, entries...)
	stats, err := database.DomainStatsSince(ctx, 0, 2)
	must(t, err)
	if stats.Unique != 3 || len(stats.Top) != 2 || stats.Top[0] != (TopDomain{"c.test", 3}) {
		t.Fatalf("%+v", stats)
	}
	if n, _ := database.UniqueDomainsSince(ctx, 0); n != 3 {
		t.Fatalf("unique %d", n)
	}
	if top, _ := database.TopDomainsSince(ctx, 0, 2); len(top) != 2 {
		t.Fatalf("top %+v", top)
	}
}

func TestDomainStatsOnAnEmptyWindowReportsNothing(t *testing.T) {
	stats, err := rustTestDB(t).DomainStatsSince(context.Background(), 0, 5)
	must(t, err)
	if stats.Unique != 0 || len(stats.Top) != 0 {
		t.Fatalf("%+v", stats)
	}
}

// Both lists fold one grouping of (domain, client_ip, doh_token); counts tie,
// so the tie-break order is asserted.
func TestTrafficListsAnswerWhatTheSeparateListsDid(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	const since = 10_000
	var entries []QueryLogEntry
	for i := range int64(600) {
		entry := statsEntry(since+i, "A", false, false, ptr("1.1.1.1"))
		entry.Domain = fmt.Sprintf("d%d.test", i%7)
		entry.ClientIP = fmt.Sprintf("10.0.0.%d", i%5)
		if i%3 == 0 {
			entry.DohToken = ptr("phone")
		}
		entries = append(entries, entry)
	}
	early := statsEntry(since-1, "A", false, false, ptr("1.1.1.1"))
	early.Domain, early.ClientIP = "d0.test", "10.0.0.9"
	entries = append(entries, early)
	insertLogs(t, database, entries...)

	lists, err := database.TrafficListsSince(ctx, since, 4)
	must(t, err)
	domains, _ := database.DomainStatsSince(ctx, since, 4)
	if lists.Domains.Unique != domains.Unique || lists.Domains.Unique != 7 || !slices.Equal(lists.Domains.Top, domains.Top) {
		t.Fatalf("the two spellings disagree: %+v vs %+v", lists.Domains, domains)
	}

	type clientKey struct{ ip, token string }
	expectedCounts := map[clientKey]int64{}
	for _, entry := range entries {
		if entry.Timestamp < since*1000 {
			continue
		}
		key := clientKey{ip: entry.ClientIP}
		if entry.DohToken != nil {
			key.token = "\x00" + *entry.DohToken // NULL sorts before any token
		}
		expectedCounts[key]++
	}
	expected := slices.Collect(maps.Keys(expectedCounts))
	slices.SortFunc(expected, func(a, b clientKey) int {
		if c := cmpInt(expectedCounts[b], expectedCounts[a]); c != 0 {
			return c
		}
		if c := cmpString(a.ip, b.ip); c != 0 {
			return c
		}
		return cmpString(a.token, b.token)
	})
	expected = expected[:4]
	for i, client := range lists.Clients {
		key := clientKey{ip: client.ClientIP}
		if client.DohToken != nil {
			key.token = "\x00" + *client.DohToken
		}
		if key != expected[i] || client.Count != expectedCounts[key] || client.ClientIP == "10.0.0.9" {
			t.Fatalf("client %d: %+v, want %+v", i, client, expected[i])
		}
	}
	if len(lists.Clients) != 4 {
		t.Fatalf("clients %d", len(lists.Clients))
	}
	if top, _ := database.TopClientsSince(ctx, since, 4); len(top) != 4 {
		t.Fatalf("top clients %d", len(top))
	}
}

func TestTrafficListsOnAnEmptyWindowReportNothing(t *testing.T) {
	lists, err := rustTestDB(t).TrafficListsSince(context.Background(), 0, 5)
	must(t, err)
	if lists.Domains.Unique != 0 || len(lists.Domains.Top) != 0 || len(lists.Clients) != 0 {
		t.Fatalf("%+v", lists)
	}
}

func sortedPairs(rows []NameCount) []NameCount { return sortedNameCounts(rows) }

// spreadEntries is several days of mixed queries at a non-whole-minute
// interval, so rows land on both sides of every boundary the tests draw.
func spreadEntries() []QueryLogEntry {
	const start = 1_704_067_200 // 2024-01-01 00:00:00 UTC, a Monday
	entries := make([]QueryLogEntry, 900)
	for i := range entries {
		n := int64(i)
		var result *string
		if n%11 != 0 {
			result = ptr("1.1.1.1")
		}
		entry := statsEntry(start+n*437, []string{"A", "AAAA", "HTTPS"}[n%3], n%7 == 0, n%5 == 0, result)
		entry.Timestamp += n % 1000 // milliseconds off the whole second
		entry.ResponseMs = (n * 13) % 90
		entries[i] = entry
	}
	return entries
}

// foldTimeline and foldHeatmap are the browser's folds restated; the JS ones
// are held to the API by the e2e charts spec.
func foldTimeline(series QuarterSeries, bucket, offset int64) []TimelineMultiPoint {
	var out []TimelineMultiPoint
	for i, total := range series.Total {
		if total == 0 {
			continue
		}
		at := floorDiv(series.Start+int64(i)*QuarterSecs+offset, bucket)*bucket - offset
		if len(out) == 0 || out[len(out)-1].Timestamp != at {
			out = append(out, TimelineMultiPoint{Timestamp: at})
		}
		point := &out[len(out)-1]
		point.Total += total
		point.Blocked += series.Blocked[i]
		point.Cached += series.Cached[i]
	}
	return out
}

func foldHeatmap(series QuarterSeries, offset int64) map[[2]int64]int64 {
	cells := map[[2]int64]int64{}
	for i, count := range series.Heatmap {
		if count == 0 {
			continue
		}
		local := series.Start + int64(i)*QuarterSecs + offset
		cells[[2]int64{(floorDiv(local, 86400) + 4) % 7, floorMod(local, 86400) / 3600}] += count
	}
	return cells
}

func heatmapMap(cells []HeatmapCell) map[[2]int64]int64 {
	got := map[[2]int64]int64{}
	for _, cell := range cells {
		got[[2]int64{cell.Weekday, cell.Hour}] = cell.Count
	}
	return got
}

// The scan must match the window readings and, folded into a viewer's
// calendar, the API's timeline and heatmap for that offset, including half-
// and three-quarter-hour zones (India, Nepal, the Marquesas).
func TestTheStatsScanAnswersWhatTheSeparateQueriesDo(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	insertLogs(t, database, spreadEntries()...)
	const rangeSince, heatmapSince = 1_704_067_200 + 86_400 + 1_234, 1_704_067_200 + 40_000
	scan, err := database.StatsScanSince(ctx, rangeSince, heatmapSince)
	must(t, err)
	window, err := database.WindowMetricsSince(ctx, rangeSince)
	must(t, err)
	if scan.Metrics.Latency != window.Latency ||
		!slices.Equal(sortedPairs(scan.Metrics.QueryTypes), sortedPairs(window.QueryTypes)) ||
		!slices.Equal(sortedPairs(scan.Metrics.Outcomes), sortedPairs(window.Outcomes)) {
		t.Fatalf("scan metrics %+v vs window %+v", scan.Metrics, window)
	}
	for _, offsetMinutes := range []int64{0, 480, -300, 330, 345, -570, 840, -720} {
		offset := offsetMinutes * 60
		for _, bucket := range []int64{3600, 6 * 3600, 86400} {
			want, err := database.TimelineMultiSince(ctx, rangeSince, bucket, offset)
			must(t, err)
			if got := foldTimeline(scan.Series, bucket, offset); !slices.Equal(got, want) {
				t.Fatalf("timeline, offset %d min, bucket %d s:\n got %+v\nwant %+v", offsetMinutes, bucket, got, want)
			}
		}
		cells, err := database.HourlyHeatmapSince(ctx, heatmapSince, offset)
		must(t, err)
		if got := foldHeatmap(scan.Series, offset); !maps.Equal(got, heatmapMap(cells)) {
			t.Fatalf("heatmap, offset %d min", offsetMinutes)
		}
	}
}

// Each window keeps its own edge to the millisecond, even inside a shared
// quarter; the series starts at the first non-empty quarter.
func TestTheStatsScanDrawsEachWindowToTheMillisecond(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	const rangeSince = 1_704_067_200 + 450 // mid-quarter
	atMs := func(ms int64) QueryLogEntry {
		entry := statsEntry(0, "A", false, false, ptr("1.1.1.1"))
		entry.Timestamp = ms
		return entry
	}
	const edge = rangeSince * 1000
	insertLogs(t, database, atMs(edge-1), atMs(edge), atMs(edge+2*900_000))

	scan, err := database.StatsScanSince(ctx, rangeSince, rangeSince-60)
	must(t, err)
	if scan.Series.Start != 1_704_067_200 || !slices.Equal(scan.Series.Total, []int64{1, 0, 1}) ||
		!slices.Equal(scan.Series.Heatmap, []int64{2, 0, 1}) || scan.Metrics.Latency.SampleCount != 2 {
		t.Fatalf("%+v", scan)
	}
	// Swap which window is wider: the row a millisecond before the edge is now
	// outside the heatmap's window and inside the range.
	scan, err = database.StatsScanSince(ctx, rangeSince-60, rangeSince)
	must(t, err)
	if !slices.Equal(scan.Series.Total, []int64{2, 0, 1}) || !slices.Equal(scan.Series.Heatmap, []int64{1, 0, 1}) {
		t.Fatalf("%+v", scan.Series)
	}
}

func TestTheStatsScanOfAnEmptyWindowReportsNothing(t *testing.T) {
	scan, err := rustTestDB(t).StatsScanSince(context.Background(), 0, 0)
	must(t, err)
	if len(scan.Series.Total) != 0 || len(scan.Series.Heatmap) != 0 || scan.Series.Start != 0 ||
		scan.Metrics.Latency.SampleCount != 0 || len(scan.Metrics.Outcomes) != 0 {
		t.Fatalf("%+v", scan)
	}
}

// recountDB is ~3 days of traffic from 1234 ms past an hour, one query every
// 86413 ms, so rows straddle every quarter and hour boundary and every grouped
// column varies.
func recountDB(t *testing.T) *DB {
	t.Helper()
	database := rustTestDB(t)
	const start = 472_222*hourMs + 1_234
	entries := make([]QueryLogEntry, 3000)
	for n := range entries {
		i := int64(n)
		entry := QueryLogEntry{
			Timestamp:  start + i*86_413,
			Domain:     fmt.Sprintf("d%d.example", (i*7)%23),
			QueryType:  []string{"A", "AAAA", "HTTPS"}[n%3],
			ClientIP:   fmt.Sprintf("10.0.0.%d", i%5),
			Blocked:    i%4 == 0,
			Cached:     i%3 == 0,
			ResponseMs: (i * 13) % 97,
		}
		if i%5 != 0 {
			entry.Upstream = ptr(fmt.Sprintf("udp://9.9.9.%d:53", i%3))
		}
		entry.DohToken = []*string{nil, ptr("phone"), ptr("tablet")}[n%3]
		if i%2 == 0 {
			entry.Result = ptr("1.2.3.4")
		}
		entries[n] = entry
	}
	for chunk := range slices.Chunk(entries, 500) {
		insertLogs(t, database, chunk...)
	}
	return database
}

// recountSinces are window starts in seconds: before the data, on an hour, on a
// quarter, inside a quarter, inside an hour, and after the data.
func recountSinces() []int64 {
	const startS = 472_222 * 3_600
	return []int64{0, startS + 5*3_600, startS + 7*3_600 + 900, startS + 20*3_600 + 1_000, startS + 41*3_600 + 2_345, startS + 100*3_600}
}

func rawQuery(t *testing.T, database *DB, query string, args ...any) *rowScanner {
	t.Helper()
	rows, err := database.reader.QueryContext(context.Background(), query, args...)
	must(t, err)
	return &rowScanner{t: t, rows: rows}
}

type rowScanner struct {
	t    *testing.T
	rows interface {
		Next() bool
		Scan(...any) error
		Close() error
	}
}

// each calls fn for every row; fn scans through the supplied function.
func (r *rowScanner) each(fn func(scan func(dest ...any))) {
	defer func() { must(r.t, r.rows.Close()) }()
	for r.rows.Next() {
		fn(func(dest ...any) { must(r.t, r.rows.Scan(dest...)) })
	}
}

const dashboardRecountSQL = `SELECT
	COUNT(CASE WHEN timestamp >= ?1 THEN 1 END),
	COALESCE(SUM(CASE WHEN timestamp >= ?1 THEN blocked END), 0),
	COUNT(CASE WHEN timestamp >= ?1 AND blocked = 0 THEN 1 END),
	COALESCE(SUM(CASE WHEN timestamp >= ?1 AND blocked = 0 THEN cached END), 0),
	COALESCE(AVG(CASE WHEN timestamp >= ?1 AND blocked = 0 THEN response_ms END), 0),
	COUNT(CASE WHEN timestamp >= ?2 THEN 1 END),
	COALESCE(SUM(CASE WHEN timestamp >= ?2 THEN blocked END), 0),
	COUNT(CASE WHEN timestamp >= ?2 AND blocked = 0 THEN 1 END),
	COALESCE(SUM(CASE WHEN timestamp >= ?2 AND blocked = 0 THEN cached END), 0),
	COALESCE(AVG(CASE WHEN timestamp >= ?2 AND blocked = 0 THEN response_ms END), 0),
	COUNT(*), COALESCE(SUM(blocked), 0), COUNT(CASE WHEN blocked = 0 THEN 1 END),
	COALESCE(SUM(CASE WHEN blocked = 0 THEN cached END), 0),
	COALESCE(AVG(CASE WHEN blocked = 0 THEN response_ms END), 0)
	FROM query_logs WHERE timestamp >= ?3`

// The dashboard's readings fold rollups (plus the table where a window starts
// inside a unit), so each is checked against a plain recount of the table.
func TestDashboardReadingsEqualARecountOfTheTable(t *testing.T) {
	ctx := context.Background()
	database := recountDB(t)
	for _, since := range recountSinces() {
		s1, s7, s30 := since, since-2*3_600-17, since-30*3_600-900
		summary, err := database.SummaryMultiSince(ctx, s1, s7, s30)
		must(t, err)
		var raw [15]float64
		var ints [15]int64
		rawQuery(t, database, dashboardRecountSQL, s1*1000, s7*1000, s30*1000).each(func(scan func(...any)) {
			dest := make([]any, 15)
			for i := range dest {
				if i%5 == 4 {
					dest[i] = &raw[i]
				} else {
					dest[i] = &ints[i]
				}
			}
			scan(dest...)
		})
		for w, got := range summary {
			want := WindowSummary{Total: ints[w*5], Blocked: ints[w*5+1], Allowed: ints[w*5+2], CacheHits: ints[w*5+3], AvgResponseMs: raw[w*5+4]}
			if got != want {
				t.Fatalf("summary from %d window %d: got %+v want %+v", since, w, got, want)
			}
		}

		for _, bucketSecs := range []int64{60, 600, 1_800, 3_600} {
			got, err := database.TimelineSince(ctx, since, bucketSecs)
			must(t, err)
			var want []TimelinePoint
			rawQuery(t, database, "SELECT (timestamp / ?1) * ?1 / 1000, COUNT(*), COALESCE(SUM(blocked), 0) FROM query_logs WHERE timestamp >= ?2 GROUP BY 1 ORDER BY 1",
				bucketSecs*1000, since*1000).each(func(scan func(...any)) {
				var point TimelinePoint
				scan(&point.Timestamp, &point.Total, &point.Blocked)
				want = append(want, point)
			})
			if !slices.Equal(got, want) {
				t.Fatalf("timeline from %d by %ds:\n got %+v\nwant %+v", since, bucketSecs, got, want)
			}
		}

		for _, limit := range []int64{5, 1_000} {
			checkDashboardLists(t, database, since, limit)
		}
	}
}

func checkDashboardLists(t *testing.T, database *DB, since, limit int64) {
	t.Helper()
	ctx := context.Background()
	var wantDomains []TopDomain
	rawQuery(t, database, "SELECT domain, COUNT(*) FROM query_logs WHERE timestamp >= ?1 GROUP BY domain ORDER BY 2 DESC, domain LIMIT ?2",
		since*1000, limit).each(func(scan func(...any)) {
		var domain TopDomain
		scan(&domain.Domain, &domain.Count)
		wantDomains = append(wantDomains, domain)
	})
	var wantUnique int64
	rawQuery(t, database, "SELECT COUNT(DISTINCT domain) FROM query_logs WHERE timestamp >= ?1", since*1000).each(func(scan func(...any)) { scan(&wantUnique) })
	var wantClients []TopClient
	rawQuery(t, database, "SELECT client_ip, doh_token, COUNT(*) FROM query_logs WHERE timestamp >= ?1 GROUP BY client_ip, doh_token ORDER BY 3 DESC, client_ip, doh_token LIMIT ?2",
		since*1000, limit).each(func(scan func(...any)) {
		var client TopClient
		var token *string
		scan(&client.ClientIP, &token, &client.Count)
		client.DohToken = token
		wantClients = append(wantClients, client)
	})
	var wantUpstreams []TopUpstream
	rawQuery(t, database, "SELECT upstream, COUNT(*), AVG(response_ms) FROM query_logs WHERE timestamp >= ?1 AND upstream IS NOT NULL GROUP BY upstream ORDER BY 2 DESC, upstream LIMIT ?2",
		since*1000, limit).each(func(scan func(...any)) {
		var upstream TopUpstream
		scan(&upstream.Upstream, &upstream.Count, &upstream.AvgMs)
		wantUpstreams = append(wantUpstreams, upstream)
	})

	lists, err := database.TrafficListsSince(ctx, since, limit)
	must(t, err)
	domains, err := database.DomainStatsSince(ctx, since, limit)
	must(t, err)
	upstreams, err := database.TopUpstreamsSince(ctx, since, limit)
	must(t, err)
	tag := fmt.Sprintf("from %d, limit %d", since, limit)
	if !slices.Equal(lists.Domains.Top, wantDomains) || lists.Domains.Unique != wantUnique {
		t.Fatalf("traffic lists' domains %s: %+v vs %+v (unique %d vs %d)", tag, lists.Domains, wantDomains, lists.Domains.Unique, wantUnique)
	}
	// The count rides on the rows, so an empty window reports 0.
	if !slices.EqualFunc(domains.Top, wantDomains, func(a, b TopDomain) bool { return a == b }) || (len(wantDomains) > 0 && domains.Unique != wantUnique) || (len(wantDomains) == 0 && domains.Unique != 0) {
		t.Fatalf("domain stats %s: %+v", tag, domains)
	}
	if !slices.EqualFunc(lists.Clients, wantClients, equalClient) {
		t.Fatalf("traffic lists' clients %s:\n got %+v\nwant %+v", tag, lists.Clients, wantClients)
	}
	if !slices.Equal(upstreams, wantUpstreams) {
		t.Fatalf("top upstreams %s:\n got %+v\nwant %+v", tag, upstreams, wantUpstreams)
	}
}

func equalClient(a, b TopClient) bool {
	if a.ClientIP != b.ClientIP || a.Count != b.Count || (a.DohToken == nil) != (b.DohToken == nil) {
		return false
	}
	return a.DohToken == nil || *a.DohToken == *b.DohToken
}

// The Statistics page's scan and the API's timeline, heatmap and window
// readings, checked against a recount of the table for every window start.
// Offsets include half- and three-quarter-hour zones, and seven minutes, which
// no zone uses and the readers answer from the table.
func TestStatisticsReadingsEqualARecountOfTheTable(t *testing.T) {
	database := recountDB(t)
	for _, since := range recountSinces() {
		checkWindowRecount(t, database, since)
		for _, offsetMinutes := range []int64{0, 480, -300, 330, 345, -570, 7} {
			checkOffsetRecount(t, database, since, offsetMinutes*60)
		}
	}
}

func rawPairs(t *testing.T, database *DB, query string, sinceMs int64) []NameCount {
	var rows []NameCount
	rawQuery(t, database, query, sinceMs).each(func(scan func(...any)) {
		var row NameCount
		scan(&row.Name, &row.Count)
		rows = append(rows, row)
	})
	return sortedNameCounts(rows)
}

func checkWindowRecount(t *testing.T, database *DB, since int64) {
	t.Helper()
	ctx := context.Background()
	sinceMs := since * 1000
	outcomes := rawPairs(t, database, `SELECT CASE WHEN blocked = 1 THEN 'Blocked' WHEN cached = 1 THEN 'Cached'
		WHEN result IS NOT NULL AND result != '' THEN 'Resolved' ELSE 'Empty' END, COUNT(*)
		FROM query_logs WHERE timestamp >= ?1 GROUP BY 1`, sinceMs)
	queryTypes := rawPairs(t, database, "SELECT query_type, COUNT(*) FROM query_logs WHERE timestamp >= ?1 GROUP BY 1", sinceMs)
	var latencies []int64
	rawQuery(t, database, "SELECT response_ms FROM query_logs WHERE timestamp >= ?1 ORDER BY 1", sinceMs).each(func(scan func(...any)) {
		var ms int64
		scan(&ms)
		latencies = append(latencies, ms)
	})
	percentile := func(p float64) int64 {
		rank := max(int64(float64(len(latencies))*p), 1)
		if rank > int64(len(latencies)) {
			return 0
		}
		return latencies[rank-1]
	}
	wantLatency := LatencySummary{SampleCount: int64(len(latencies)), P50Ms: percentile(0.50), P95Ms: percentile(0.95), P99Ms: percentile(0.99)}

	window, err := database.WindowMetricsSince(ctx, since)
	must(t, err)
	if !slices.Equal(sortedNameCounts(window.Outcomes), outcomes) || !slices.Equal(sortedNameCounts(window.QueryTypes), queryTypes) || window.Latency != wantLatency {
		t.Fatalf("window from %d: %+v\nwant %v %v %+v", since, window, outcomes, queryTypes, wantLatency)
	}

	for _, heatmapSince := range []int64{since - 3*3_600 - 437, since, since + 3_600 + 5} {
		tag := fmt.Sprintf("range from %d, heatmap from %d", since, heatmapSince)
		scan, err := database.StatsScanSince(ctx, since, heatmapSince)
		must(t, err)
		if !slices.Equal(sortedNameCounts(scan.Metrics.Outcomes), outcomes) || !slices.Equal(sortedNameCounts(scan.Metrics.QueryTypes), queryTypes) || scan.Metrics.Latency != wantLatency {
			t.Fatalf("scan metrics, %s: %+v", tag, scan.Metrics)
		}
		if want := expectedSeries(t, database, sinceMs, heatmapSince*1000); !equalSeries(scan.Series, want) {
			t.Fatalf("series, %s:\n got %+v\nwant %+v", tag, scan.Series, want)
		}
	}
}

func equalSeries(a, b QuarterSeries) bool {
	return a.Start == b.Start && slices.Equal(a.Total, b.Total) && slices.Equal(a.Blocked, b.Blocked) &&
		slices.Equal(a.Cached, b.Cached) && slices.Equal(a.Heatmap, b.Heatmap)
}

func perQuarter(t *testing.T, database *DB, sinceMs int64) map[int64][3]int64 {
	quarters := map[int64][3]int64{}
	rawQuery(t, database, "SELECT timestamp / 900000, COUNT(*), SUM(blocked), SUM(cached) FROM query_logs WHERE timestamp >= ?1 GROUP BY 1", sinceMs).each(func(scan func(...any)) {
		var quarter int64
		var counts [3]int64
		scan(&quarter, &counts[0], &counts[1], &counts[2])
		quarters[quarter] = counts
	})
	return quarters
}

func expectedSeries(t *testing.T, database *DB, rangeSinceMs, heatmapSinceMs int64) QuarterSeries {
	quarters := map[int64]*[4]int64{}
	slot := func(quarter int64) *[4]int64 {
		if quarters[quarter] == nil {
			quarters[quarter] = new([4]int64)
		}
		return quarters[quarter]
	}
	for quarter, counts := range perQuarter(t, database, rangeSinceMs) {
		copy(slot(quarter)[:3], counts[:])
	}
	for quarter, counts := range perQuarter(t, database, heatmapSinceMs) {
		slot(quarter)[3] = counts[0]
	}
	if len(quarters) == 0 {
		return QuarterSeries{}
	}
	keys := slices.Sorted(maps.Keys(quarters))
	first, last := keys[0], keys[len(keys)-1]
	length := last - first + 1
	series := QuarterSeries{Start: first * QuarterSecs, Total: make([]int64, length), Blocked: make([]int64, length), Cached: make([]int64, length), Heatmap: make([]int64, length)}
	for quarter, counts := range quarters {
		series.Total[quarter-first], series.Blocked[quarter-first], series.Cached[quarter-first], series.Heatmap[quarter-first] = counts[0], counts[1], counts[2], counts[3]
	}
	return series
}

func checkOffsetRecount(t *testing.T, database *DB, since, offset int64) {
	t.Helper()
	ctx := context.Background()
	for _, bucket := range []int64{60, 900, 3_600, 6 * 3_600, 86_400} {
		var want []TimelineMultiPoint
		rawQuery(t, database, `SELECT ((timestamp + ?3) / ?1) * ?1 - ?3 AS bucket, COUNT(*), SUM(blocked), SUM(cached)
			FROM query_logs WHERE timestamp >= ?2 GROUP BY bucket ORDER BY bucket`,
			bucket*1000, since*1000, offset*1000).each(func(scan func(...any)) {
			var point TimelineMultiPoint
			scan(&point.Timestamp, &point.Total, &point.Blocked, &point.Cached)
			point.Timestamp /= 1000
			want = append(want, point)
		})
		got, err := database.TimelineMultiSince(ctx, since, bucket, offset)
		must(t, err)
		if !slices.Equal(got, want) {
			t.Fatalf("timeline from %d, offset %ds, bucket %ds:\n got %+v\nwant %+v", since, offset, bucket, got, want)
		}
	}
	var want []HeatmapCell
	rawQuery(t, database, `SELECT ((timestamp / 1000 + ?2) / 86400 + 4) % 7 AS wday, (timestamp / 1000 + ?2) % 86400 / 3600 AS hr, COUNT(*)
		FROM query_logs WHERE timestamp >= ?1 GROUP BY wday, hr ORDER BY wday, hr`, since*1000, offset).each(func(scan func(...any)) {
		var cell HeatmapCell
		scan(&cell.Weekday, &cell.Hour, &cell.Count)
		want = append(want, cell)
	})
	got, err := database.HourlyHeatmapSince(ctx, since, offset)
	must(t, err)
	if !slices.Equal(got, want) {
		t.Fatalf("heatmap from %d, offset %ds:\n got %+v\nwant %+v", since, offset, got, want)
	}
}
