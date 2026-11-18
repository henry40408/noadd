package stats

import (
	"context"
	"encoding/json"
	"math"
	"testing"

	"github.com/henry40408/noadd/internal/db"
)

const nowSecs int64 = 10 * daySecs

func strPtr(value string) *string { return &value }

// seedTraffic logs three queries an hour before nowSecs: one allowed, one
// cached and one blocked, from two clients.
func seedTraffic(t *testing.T, database *db.DB) {
	t.Helper()
	atMs := (nowSecs - 3600) * 1000
	entries := []db.QueryLogEntry{
		{Timestamp: atMs, Domain: "a.example", QueryType: "A", ClientIP: "10.0.0.1", ResponseMs: 10, Upstream: strPtr("up1")},
		{Timestamp: atMs, Domain: "a.example", QueryType: "AAAA", ClientIP: "10.0.0.1", ResponseMs: 0, Cached: true},
		{Timestamp: atMs, Domain: "b.example", QueryType: "A", ClientIP: "10.0.0.2", ResponseMs: 0, Blocked: true},
	}
	if err := database.InsertQueryLogs(context.Background(), entries); err != nil {
		t.Fatal(err)
	}
}

func closedDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(context.Background(), t.TempDir()+"/closed.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	return database
}

func TestRatioIsZeroWithoutAWhole(t *testing.T) {
	for _, whole := range []int64{0, -5} {
		if got := ratio(3, whole); got != 0 {
			t.Fatalf("ratio(3, %d) = %v, want 0", whole, got)
		}
	}
	if got := ratio(1, 4); got != 0.25 {
		t.Fatalf("ratio(1, 4) = %v", got)
	}
}

func TestComputeSummaryDerivesRatiosFromWindows(t *testing.T) {
	database := openDB(t)
	seedTraffic(t, database)
	summary, err := ComputeSummary(context.Background(), database, nowSecs)
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalToday != 3 || summary.BlockedToday != 1 || summary.Total7d != 3 || summary.Total30d != 3 {
		t.Fatalf("totals = %+v", summary)
	}
	if math.Abs(summary.BlockRatioToday-1.0/3) > 1e-9 {
		t.Fatalf("block ratio = %v", summary.BlockRatioToday)
	}
	// Cache hit rate is over allowed queries only: 1 hit of 2 allowed.
	if summary.CacheHitRateToday != 0.5 || summary.CacheHitRate7d != 0.5 || summary.CacheHitRate30d != 0.5 {
		t.Fatalf("cache hit rate = %+v", summary)
	}
	if summary.Queries1m != 0 {
		t.Fatalf("queries_1m = %d, want 0", summary.Queries1m)
	}
}

func TestComputeSummaryCountsLastMinute(t *testing.T) {
	database := openDB(t)
	if err := database.InsertQueryLogs(context.Background(), []db.QueryLogEntry{logFor("x.example", (nowSecs-30)*1000)}); err != nil {
		t.Fatal(err)
	}
	summary, err := ComputeSummary(context.Background(), database, nowSecs)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Queries1m != 1 {
		t.Fatalf("queries_1m = %d, want 1", summary.Queries1m)
	}
}

func TestComputeTopListsOverLastDay(t *testing.T) {
	database := openDB(t)
	seedTraffic(t, database)
	ctx := context.Background()

	domains, err := ComputeTopDomains(ctx, database, nowSecs, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || domains[0].Domain != "a.example" || domains[0].Count != 2 {
		t.Fatalf("domains = %+v", domains)
	}
	clients, err := ComputeTopClients(ctx, database, nowSecs, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 || clients[0].ClientIP != "10.0.0.1" || clients[0].Count != 2 {
		t.Fatalf("clients = %+v", clients)
	}
	bothDomains, bothClients, err := ComputeTopDomainsAndClients(ctx, database, nowSecs, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(bothDomains) != 2 || len(bothClients) != 2 {
		t.Fatalf("lists = %+v %+v", bothDomains, bothClients)
	}
	upstreams, err := ComputeTopUpstreams(ctx, database, nowSecs, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(upstreams) != 1 || upstreams[0].Upstream != "up1" {
		t.Fatalf("upstreams = %+v", upstreams)
	}
}

func TestComputeTimelineStartsAtFirstLog(t *testing.T) {
	database := openDB(t)
	seedTraffic(t, database)
	points, err := ComputeTimeline(context.Background(), database, nowSecs, 24)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, point := range points {
		total += point.Total
	}
	if total != 3 {
		t.Fatalf("timeline total = %d, want 3 (%+v)", total, points)
	}
}

func TestComputeTimelineOnEmptyLogUsesFullWindow(t *testing.T) {
	points, err := ComputeTimeline(context.Background(), openDB(t), nowSecs, 24)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 0 {
		t.Fatalf("points = %+v", points)
	}
}

func TestTimelineBucketSecsBoundaries(t *testing.T) {
	cases := map[int64]int64{
		0:            60,
		48 * 60:      60,
		48*60 + 48:   300,
		48 * 300:     300,
		48*300 + 48:  600,
		48 * 600:     600,
		48*600 + 48:  1800,
		48 * 1800:    1800,
		48*1800 + 48: 3600,
		30 * daySecs: 3600,
	}
	for rangeSecs, want := range cases {
		if got := timelineBucketSecs(rangeSecs); got != want {
			t.Errorf("timelineBucketSecs(%d) = %d, want %d", rangeSecs, got, want)
		}
	}
}

func TestParseRangeAcceptsOnlyKnownLabels(t *testing.T) {
	for label, want := range map[string]Range{"7d": Days7, "30d": Days30, "90d": Days90} {
		got, ok := ParseRange(label)
		if !ok || got != want {
			t.Fatalf("ParseRange(%q) = %v, %v", label, got, ok)
		}
		if got.Label() != label {
			t.Fatalf("Label() = %q, want %q", got.Label(), label)
		}
	}
	for _, raw := range []string{"", "1d", "7", "7D", " 7d"} {
		if _, ok := ParseRange(raw); ok {
			t.Fatalf("ParseRange(%q) accepted", raw)
		}
	}
}

func TestRangeBucketAndWindowGrowTogether(t *testing.T) {
	cases := []struct {
		rng            Range
		bucket, window int64
	}{
		{Days7, 3600, 7 * daySecs},
		{Days30, 6 * 3600, 30 * daySecs},
		{Days90, daySecs, 90 * daySecs},
	}
	for _, tc := range cases {
		if tc.rng.BucketSecs() != tc.bucket || tc.rng.windowSecs() != tc.window {
			t.Errorf("%s: bucket %d window %d", tc.rng.Label(), tc.rng.BucketSecs(), tc.rng.windowSecs())
		}
	}
}

func TestNameCountSerialisesAsPair(t *testing.T) {
	raw, err := json.Marshal(Breakdowns{
		QueryTypes: []NameCount{{Name: "A", Count: 2}},
		Outcomes:   nameCounts([]db.NameCount{{Name: "blocked", Count: 1}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"query_types":[["A",2]],"outcomes":[["blocked",1]]}`
	if string(raw) != want {
		t.Fatalf("json = %s, want %s", raw, want)
	}
}

func TestComputeBreakdownsCountsTypesAndOutcomes(t *testing.T) {
	database := openDB(t)
	seedTraffic(t, database)
	breakdowns, err := ComputeBreakdowns(context.Background(), database, nowSecs, Days7)
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]int64{}
	for _, entry := range breakdowns.QueryTypes {
		types[entry.Name] = entry.Count
	}
	if types["A"] != 2 || types["AAAA"] != 1 {
		t.Fatalf("query types = %+v", breakdowns.QueryTypes)
	}
	var outcomes int64
	for _, entry := range breakdowns.Outcomes {
		outcomes += entry.Count
	}
	if outcomes != 3 {
		t.Fatalf("outcomes = %+v", breakdowns.Outcomes)
	}
}

func TestComputeHighlightsCountsUniqueDomains(t *testing.T) {
	database := openDB(t)
	seedTraffic(t, database)
	highlights, err := ComputeHighlights(context.Background(), database, nowSecs, Days7)
	if err != nil {
		t.Fatal(err)
	}
	if highlights.UniqueDomains != 2 {
		t.Fatalf("unique domains = %d, want 2", highlights.UniqueDomains)
	}
}

func TestComputeStatsTimelineAndHeatmapSeeTraffic(t *testing.T) {
	database := openDB(t)
	seedTraffic(t, database)
	ctx := context.Background()
	series, err := ComputeStatsTimeline(ctx, database, nowSecs, Days7, 0)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, point := range series {
		total += point.Total
	}
	if total != 3 {
		t.Fatalf("timeline total = %d (%+v)", total, series)
	}
	cells, err := ComputeHeatmap(ctx, database, nowSecs, 0)
	if err != nil {
		t.Fatal(err)
	}
	total = 0
	for _, cell := range cells {
		total += cell.Count
	}
	if total != 3 {
		t.Fatalf("heatmap total = %d (%+v)", total, cells)
	}
}

func TestComputeRangeStatsAndRangedTops(t *testing.T) {
	database := openDB(t)
	seedTraffic(t, database)
	ctx := context.Background()
	stats, err := ComputeRangeStats(ctx, database, nowSecs, Days30, 5)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Domains.Unique != 2 || len(stats.Domains.Top) != 2 || len(stats.Clients) != 2 {
		t.Fatalf("range stats = %+v", stats)
	}
	domains, err := ComputeTopDomainsRanged(ctx, database, nowSecs, Days7, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 1 || domains[0].Domain != "a.example" {
		t.Fatalf("domains = %+v", domains)
	}
	clients, err := ComputeTopClientsRanged(ctx, database, nowSecs, Days90, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].ClientIP != "10.0.0.1" {
		t.Fatalf("clients = %+v", clients)
	}
}

func TestComputeSnapshotNeverSerialisesNullLists(t *testing.T) {
	snapshot, err := ComputeSnapshot(context.Background(), openDB(t), nowSecs)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"timeline", "top_domains", "top_clients", "top_upstreams"} {
		if string(decoded[key]) != "[]" {
			t.Errorf("%s = %s, want []", key, decoded[key])
		}
	}
}

func TestComputeSnapshotFillsTablesFromTraffic(t *testing.T) {
	database := openDB(t)
	seedTraffic(t, database)
	snapshot, err := ComputeSnapshot(context.Background(), database, nowSecs)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Summary.TotalToday != 3 || len(snapshot.TopDomains) != 2 ||
		len(snapshot.TopClients) != 2 || len(snapshot.TopUpstreams) != 1 || len(snapshot.Timeline) == 0 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestBuildDBHealthZeroInputsStayZero(t *testing.T) {
	health := buildDBHealth(healthInputs{retention: 7})
	if health.FragmentationRatio != 0 || health.BytesPerLog != 0 || health.AvgNewRowsPerDay != 0 ||
		health.LogCoverageDays != 0 || health.ProjectedFullBytes != 0 || health.OldestLogTimestamp != nil {
		t.Fatalf("health = %+v", health)
	}
}

func TestBuildDBHealthRatiosAndProjection(t *testing.T) {
	health := buildDBHealth(healthInputs{
		storage: db.StorageStats{MainBytes: 1000, ReclaimableBytes: 250},
		total:   10, now: 3 * daySecs, retention: 30,
		earliestMs: daySecs * 1000, hasEarliest: true,
		latestMs: 2 * daySecs * 1000, hasLatest: true,
	})
	if health.FragmentationRatio != 0.25 || health.BytesPerLog != 100 {
		t.Fatalf("ratios = %+v", health)
	}
	// 10 logs over a 2-day span.
	if health.AvgNewRowsPerDay != 5 {
		t.Fatalf("avg rows = %v", health.AvgNewRowsPerDay)
	}
	if health.LogCoverageDays != 1 {
		t.Fatalf("coverage = %v", health.LogCoverageDays)
	}
	if health.ProjectedFullBytes != 100*5*30 {
		t.Fatalf("projection = %d", health.ProjectedFullBytes)
	}
	if health.OldestLogTimestamp == nil || *health.OldestLogTimestamp != daySecs {
		t.Fatalf("oldest = %v", health.OldestLogTimestamp)
	}
}

func TestBuildDBHealthSpanFloorsAtOneDay(t *testing.T) {
	health := buildDBHealth(healthInputs{
		storage: db.StorageStats{MainBytes: 100},
		total:   4, now: daySecs/2 + 1, retention: 7,
		earliestMs: 1000, hasEarliest: true,
	})
	if health.AvgNewRowsPerDay != 4 {
		t.Fatalf("avg rows = %v, want 4", health.AvgNewRowsPerDay)
	}
}

func TestBuildDBHealthNoProjectionWithoutRetention(t *testing.T) {
	health := buildDBHealth(healthInputs{
		storage: db.StorageStats{MainBytes: 100},
		total:   4, now: 2 * daySecs, retention: 0,
		earliestMs: 1000, hasEarliest: true,
	})
	if health.ProjectedFullBytes != 0 {
		t.Fatalf("projection = %d, want 0", health.ProjectedFullBytes)
	}
}

func TestComputeFunctionsReportReadFailures(t *testing.T) {
	database := closedDB(t)
	ctx := context.Background()
	checks := map[string]error{}
	_, checks["summary"] = ComputeSummary(ctx, database, nowSecs)
	_, checks["top domains"] = ComputeTopDomains(ctx, database, nowSecs, 1)
	_, checks["top clients"] = ComputeTopClients(ctx, database, nowSecs, 1)
	_, _, checks["lists"] = ComputeTopDomainsAndClients(ctx, database, nowSecs, 1)
	_, checks["upstreams"] = ComputeTopUpstreams(ctx, database, nowSecs, 1)
	_, checks["timeline"] = ComputeTimeline(ctx, database, nowSecs, 24)
	_, checks["stats timeline"] = ComputeStatsTimeline(ctx, database, nowSecs, Days7, 0)
	_, checks["heatmap"] = ComputeHeatmap(ctx, database, nowSecs, 0)
	_, checks["breakdowns"] = ComputeBreakdowns(ctx, database, nowSecs, Days7)
	_, checks["highlights"] = ComputeHighlights(ctx, database, nowSecs, Days7)
	_, checks["range stats"] = ComputeRangeStats(ctx, database, nowSecs, Days7, 5)
	_, checks["domains ranged"] = ComputeTopDomainsRanged(ctx, database, nowSecs, Days7, 1)
	_, checks["clients ranged"] = ComputeTopClientsRanged(ctx, database, nowSecs, Days7, 1)
	_, checks["db health"] = ComputeDBHealth(ctx, database, nowSecs)
	_, checks["snapshot"] = ComputeSnapshot(ctx, database, nowSecs)
	for name, err := range checks {
		if err == nil {
			t.Errorf("%s: no error from a closed database", name)
		}
	}
	if got := DomainSuggestions(ctx, database, nowSecs); got != nil {
		t.Fatalf("suggestions = %v, want nil", got)
	}
}
