package server

import (
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/stats"
	"github.com/henry40408/noadd/internal/views"
)

func cardByLabel(t *testing.T, cards []views.StatCard, label string) views.StatCard {
	t.Helper()
	for _, card := range cards {
		if card.Label == label {
			return card
		}
	}
	t.Fatalf("no card %q in %v", label, cards)
	return views.StatCard{}
}

func TestHealthCardsScaleTheFragmentationRatioToAPercentage(t *testing.T) {
	cards := healthCards(stats.DBHealth{FragmentationRatio: 0.25, ReclaimableBytes: 2048})
	reclaimable := cardByLabel(t, cards, "Reclaimable")
	if reclaimable.Sub != "25% of file" || reclaimable.Value != "2.0 KB" {
		t.Errorf("Reclaimable = %+v", reclaimable)
	}
}

func TestHealthCardsNeverShowNegativeReclaimableBytes(t *testing.T) {
	reclaimable := cardByLabel(t, healthCards(stats.DBHealth{ReclaimableBytes: -5}), "Reclaimable")
	if reclaimable.Value != "0 B" {
		t.Errorf("Reclaimable = %q", reclaimable.Value)
	}
}

func TestHealthCardsWordLogCoverageByMagnitude(t *testing.T) {
	cases := map[float64]string{
		0:     "—",
		0.04:  "0.0d",
		3.25:  "3.2d",
		9.96:  "10.0d",
		10:    "10d",
		12.4:  "12d",
		364.6: "365d",
	}
	for days, want := range cases {
		got := cardByLabel(t, healthCards(stats.DBHealth{LogCoverageDays: days}), "Log Coverage").Value
		if got != want {
			t.Errorf("coverage %v = %q, want %q", days, got, want)
		}
	}
}

func TestHealthCardsAverageRowsPerDayIsADashOnlyWhenThereAreNone(t *testing.T) {
	cases := map[float64]string{0: "—", 0.4: "0", 1500: "1.5K", 2_000_000: "2M"}
	for average, want := range cases {
		got := cardByLabel(t, healthCards(stats.DBHealth{AvgNewRowsPerDay: average}), "Avg / Day").Value
		if got != want {
			t.Errorf("avg %v = %q, want %q", average, got, want)
		}
	}
}

func TestHealthCardsGrowthPerDayMultipliesBytesByRows(t *testing.T) {
	cards := healthCards(stats.DBHealth{BytesPerLog: 100, AvgNewRowsPerDay: 50})
	if got := cardByLabel(t, cards, "Growth / Day").Value; got != "4.9 KB" {
		t.Errorf("Growth / Day = %q", got)
	}
	if got := cardByLabel(t, cards, "Bytes / Log").Value; got != "100 B" {
		t.Errorf("Bytes / Log = %q", got)
	}
	empty := healthCards(stats.DBHealth{})
	if got := cardByLabel(t, empty, "Growth / Day").Value; got != "—" {
		t.Errorf("empty Growth / Day = %q", got)
	}
}

func TestHealthCardsOldestLogIsADashUnlessThereIsATimestamp(t *testing.T) {
	oldest := cardByLabel(t, healthCards(stats.DBHealth{OldestLogTimestamp: ptr(int64(86_400))}), "Oldest Log")
	if oldest.Value != "1970-01-02" || oldest.TS != 86_400 {
		t.Errorf("oldest = %+v", oldest)
	}
	for name, health := range map[string]stats.DBHealth{
		"unset": {},
		"zero":  {OldestLogTimestamp: ptr(int64(0))},
		"below": {OldestLogTimestamp: ptr(int64(-1))},
	} {
		got := cardByLabel(t, healthCards(health), "Oldest Log")
		if got.Value != "—" || got.TS != 0 {
			t.Errorf("%s: oldest = %+v", name, got)
		}
	}
}

func TestHealthCardsRetentionAndProjectionNeedTheirInputs(t *testing.T) {
	cards := healthCards(stats.DBHealth{LogRetentionDays: ptr(int64(30)), ProjectedFullBytes: 3 * 1024 * 1024})
	if got := cardByLabel(t, cards, "Retention").Value; got != "30d" {
		t.Errorf("Retention = %q", got)
	}
	projected := cardByLabel(t, cards, "Projected Full")
	if projected.Value != "3.00 MB" || projected.Sub != "at full retention" {
		t.Errorf("Projected Full = %+v", projected)
	}
	forever := healthCards(stats.DBHealth{LogRetentionDays: ptr(int64(0))})
	if got := cardByLabel(t, forever, "Retention").Value; got != "0d" {
		t.Errorf("zero retention = %q", got)
	}
	bare := healthCards(stats.DBHealth{})
	if got := cardByLabel(t, bare, "Retention").Value; got != "—" {
		t.Errorf("unset Retention = %q", got)
	}
	if got := cardByLabel(t, bare, "Projected Full").Value; got != "—" {
		t.Errorf("unset Projected Full = %q", got)
	}
}

func TestHealthCardsGroupTotalLogsAndKeepTheFullFigureAsTitle(t *testing.T) {
	cards := healthCards(stats.DBHealth{TotalLogCount: 12_345_678, DBSizeBytes: 5 * 1024})
	total := cardByLabel(t, cards, "Total Logs")
	if total.Value != "12.3M" || total.Title != "12,345,678" {
		t.Errorf("Total Logs = %+v", total)
	}
	below := cardByLabel(t, healthCards(stats.DBHealth{TotalLogCount: 9_999_999}), "Total Logs")
	if below.Value != "9,999,999" {
		t.Errorf("below the tile threshold = %q", below.Value)
	}
	if got := cardByLabel(t, cards, "Database Size").Value; got != "5.0 KB" {
		t.Errorf("Database Size = %q", got)
	}
}

func TestSignIsTheSignOfTheDifference(t *testing.T) {
	for n, want := range map[int64]int64{5: 1, 1: 1, 0: 0, -1: -1, -9: -1} {
		if got := sign(n); got != want {
			t.Errorf("sign(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestBarRowsAreLargestFirstAndTiesKeepTheirOrder(t *testing.T) {
	rows := barRows([]db.NameCount{
		{Name: "small", Count: 1}, {Name: "first-tie", Count: 4},
		{Name: "second-tie", Count: 4}, {Name: "big", Count: 8},
	})
	var order []string
	for _, row := range rows {
		order = append(order, row.Label)
	}
	if got := strings.Join(order, ","); got != "big,first-tie,second-tie,small" {
		t.Fatalf("order = %s", got)
	}
	if rows[0].Width != "100.0" || rows[1].Width != "50.0" || rows[3].Width != "12.5" {
		t.Errorf("widths = %s %s %s", rows[0].Width, rows[1].Width, rows[3].Width)
	}
	if rows[0].Share != "47.1%" || rows[0].CountTitle != "8 (47.1%)" {
		t.Errorf("share = %q, title = %q", rows[0].Share, rows[0].CountTitle)
	}
}

func TestBarRowsOfZeroCountsHaveNoShareAndNoWidth(t *testing.T) {
	rows := barRows([]db.NameCount{{Name: "none", Count: 0}})
	if len(rows) != 1 || rows[0].Width != "0.0" || rows[0].Share != "" || rows[0].CountTitle != "0" {
		t.Errorf("rows = %+v", rows)
	}
	if got := barRows(nil); len(got) != 0 {
		t.Errorf("rows = %+v", got)
	}
}

func TestClientBarEntriesNameADoHClientByIPAndToken(t *testing.T) {
	entries := clientBarEntries([]db.TopClient{
		{ClientIP: "10.0.0.1", Count: 3},
		{ClientIP: "10.0.0.2", DohToken: ptr("phone"), Count: 2},
		{ClientIP: "10.0.0.3", DohToken: ptr(""), Count: 1},
	})
	want := []db.NameCount{{Name: "10.0.0.1", Count: 3}, {Name: "10.0.0.2 · phone", Count: 2}, {Name: "10.0.0.3", Count: 1}}
	if len(entries) != len(want) {
		t.Fatalf("entries = %+v", entries)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, entries[i], want[i])
		}
	}
}

func TestSeriesJSONIsTheEmptySeriesWithoutAReadAndTheReadOtherwise(t *testing.T) {
	const empty = `{"start":0,"total":[],"blocked":[],"cached":[],"heatmap":[]}`
	if got := seriesJSON(nil); got != empty {
		t.Errorf("nil = %s", got)
	}
	read := &stats.RangeStats{Series: db.QuarterSeries{Start: 900, Total: []int64{1, 2}}}
	const want = `{"start":900,"total":[1,2],"blocked":[],"cached":[],"heatmap":[]}`
	if got := seriesJSON(read); got != want {
		t.Errorf("read = %s", got)
	}
}

func TestHighlightCardsShowPercentilesOnlyWithSamples(t *testing.T) {
	none := highlightCards(nil)
	if got := cardByLabel(t, none, "Latency p95"); got.Value != "—" || got.Unit != "" {
		t.Errorf("no read: %+v", got)
	}
	unsampled := highlightCards(&stats.RangeStats{Domains: db.DomainStats{Unique: 7}})
	if got := cardByLabel(t, unsampled, "Latency p50"); got.Value != "—" {
		t.Errorf("no samples: %+v", got)
	}
	sampled := highlightCards(&stats.RangeStats{
		Domains: db.DomainStats{Unique: 12_345},
		Metrics: db.WindowMetrics{Latency: db.LatencySummary{SampleCount: 1, P50Ms: 4, P95Ms: 1_500, P99Ms: 9}},
	})
	if got := cardByLabel(t, sampled, "Latency p95"); got.Value != "1.5K" || got.Unit != "ms" {
		t.Errorf("sampled: %+v", got)
	}
	unique := cardByLabel(t, sampled, "Unique Domains")
	if unique.Value != "12,345" || unique.Title != "12,345" {
		t.Errorf("unique = %+v", unique)
	}
}

func TestTopRowsShareTheirCountsAndSumOnlyWhatIsListed(t *testing.T) {
	domains := topDomainRows([]db.TopDomain{{Domain: "a.example", Count: 3}, {Domain: "b.example", Count: 1}})
	if domains[0].Count != "3" || domains[0].Share != "75.0%" || domains[1].Share != "25.0%" {
		t.Errorf("domains = %+v", domains)
	}
	clients := topClientRows([]db.TopClient{{ClientIP: "10.0.0.1", DohToken: ptr("tok"), Count: 1}, {ClientIP: "10.0.0.2", Count: 3}})
	if clients[0].SubLabel != "tok" || clients[0].Share != "25.0%" || clients[1].SubLabel != "" || clients[1].Share != "75.0%" {
		t.Errorf("clients = %+v", clients)
	}
	upstreams := topUpstreamRows([]db.TopUpstream{{Upstream: "1.1.1.1:53", Count: 1, AvgMs: 2.25}, {Upstream: "9.9.9.9:53", Count: 1, AvgMs: 4}})
	if upstreams[0].Share != "50.0%" || upstreams[0].AvgMS != "2.2ms" || upstreams[1].AvgMS != "4.0ms" {
		t.Errorf("upstreams = %+v", upstreams)
	}
}

func TestDashboardRatesDivideTheCountsByTheirWindow(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedQueries("busy.example.com", "10.0.0.5", 120, false)
	body := h.pageBody("/")
	wantContains(t, body, "2.00")
	wantContains(t, body, "24h: 0.00 / 7d: 0.00")
}

func TestDashboardCountsTrafficFromAnyWindowAsHavingQueries(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	threeDaysAgo := time.Now().Add(-72 * time.Hour).UnixMilli()
	h.seedLogs(db.QueryLogEntry{Timestamp: threeDaysAgo, Domain: "old.example.com", QueryType: "A", ClientIP: "10.0.0.5", ResponseMs: 3})
	wantContains(t, h.pageBody("/"), `data-testid="dashboard-empty-state" style="display:none"`)
}

func TestStatsPageMarksTheRequestedRangeActive(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	cases := map[string]string{"30d": "30d", "90d": "90d", "bogus": "7d", "": "7d"}
	for query, active := range cases {
		body := h.pageBody("/stats?range=" + query)
		for _, label := range []string{"7d", "30d", "90d"} {
			link := `<a href="/stats?range=` + label + `" class="active"`
			if has := strings.Contains(body, link); has != (label == active) {
				t.Errorf("range=%q: %s active = %v", query, label, has)
			}
		}
	}
}
