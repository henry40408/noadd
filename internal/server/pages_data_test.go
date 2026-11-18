package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/db"
)

// seedQueries logs count queries for one domain, newest first, ending now.
func (h *apiHarness) seedQueries(domain, client string, count int, blocked bool) {
	h.t.Helper()
	nowMs := time.Now().UnixMilli()
	entries := make([]db.QueryLogEntry, count)
	for i := range entries {
		entries[i] = db.QueryLogEntry{
			Timestamp: nowMs - int64(i), Domain: domain, QueryType: "A", ClientIP: client,
			Blocked: blocked, ResponseMs: 3, Upstream: ptr("1.1.1.1:53"),
		}
	}
	h.seedLogs(entries...)
}

// logRows is the table body, so a filter echoed in the form cannot pass for a row.
func logRows(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, "<tbody")
	if start < 0 {
		return ""
	}
	return body[start:]
}

func TestTheLogsPageRendersRowsAndKeepsItsFilters(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedQueries("ads.example.com", "10.0.0.5", 2, true)
	h.seedQueries("good.example.com", "10.0.0.6", 1, false)

	body := h.pageBody("/logs")
	rows := logRows(t, body)
	wantContains(t, rows, "ads.example.com")
	wantContains(t, rows, "good.example.com")
	wantContains(t, body, "Page 1 / 1")
	wantContains(t, body, "<logs-page>")

	blocked := h.pageBody("/logs?action=blocked")
	wantContains(t, logRows(t, blocked), "ads.example.com")
	wantAbsent(t, logRows(t, blocked), "good.example.com")
	wantContains(t, blocked, `<option value="blocked" selected>`)

	searched := h.pageBody("/logs?q=good")
	wantContains(t, searched, `value="good"`)
	wantAbsent(t, logRows(t, searched), "ads.example.com")
}

func TestPagingKeepsTheFiltersInTheLink(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedQueries("ads.example.com", "10.0.0.5", 60, true)

	first := h.pageBody("/logs?action=blocked")
	wantContains(t, first, "Page 1 / 2")
	if !strings.Contains(first, "action=blocked") || !strings.Contains(first, "page=2") {
		t.Fatal("the next link dropped the filter")
	}
	second := h.pageBody("/logs?action=blocked&page=2")
	wantContains(t, second, "Page 2 / 2")
	wantContains(t, second, `href="/logs?action=blocked"`)
}

func TestAnEmptyLogIsToldApartFromAnEmptyFilter(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantContains(t, h.pageBody("/logs"), `data-testid="logs-empty-state"`)

	h.seedQueries("good.example.com", "10.0.0.6", 1, false)
	missed := h.pageBody("/logs?q=nothing-matches")
	wantContains(t, missed, "No logs found")
	wantAbsent(t, missed, `data-testid="logs-empty-state"`)
}

func TestANonsensePageNumberRendersPageOne(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedQueries("good.example.com", "10.0.0.6", 1, false)
	for _, query := range []string{"?page=not-a-number", "?page=0", "?page=-3"} {
		wantContains(t, h.pageBody("/logs"+query), "Page 1 / 1")
	}
}

func TestARowActionAddsTheRuleAndReturnsToTheSameView(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedQueries("tracker.example.com", "10.0.0.5", 1, false)
	recorder := h.signedIn(http.MethodPost, "/logs/rules",
		"rule=%7C%7Ctracker.example.com%5E&next=/logs%3Faction%3Dblocked")
	wantRedirect(t, recorder, "/logs?action=blocked")
	wantContains(t, h.pageBody("/filters"), "tracker.example.com")
}

func TestARowActionRefusesAnOffOriginReturn(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.signedIn(http.MethodPost, "/logs/rules",
		"rule=%7C%7Cevil.example.com%5E&next=https://evil.example")
	wantRedirect(t, recorder, "/logs")
}

func TestClearingTheLogLandsOnAnUnfilteredFirstPage(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedQueries("ads.example.com", "10.0.0.5", 3, true)
	wantRedirect(t, h.signedIn(http.MethodPost, "/logs/clear", ""), "/logs")
	body := h.pageBody("/logs")
	wantAbsent(t, body, "ads.example.com")
	wantContains(t, body, `data-testid="logs-empty-state"`)
}

func TestTheLogsFormsRefuseAnAnonymousBrowser(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, path := range []string{"/logs/rules", "/logs/clear"} {
		recorder := h.page(pageRequest{method: http.MethodPost, path: path})
		if recorder.Code != http.StatusSeeOther {
			t.Errorf("%s = %d", path, recorder.Code)
		}
	}
}

func TestTheDomainBoxesSuggestRecentlyQueriedDomainsMostQueriedFirst(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, path := range []string{"/logs", "/filters"} {
		wantAbsent(t, h.pageBody(path), "<datalist")
	}
	h.seedQueries("rare.example.com", "10.0.0.5", 1, false)
	h.seedQueries("common.example.com", "10.0.0.6", 5, true)
	for path, listID := range map[string]string{"/logs": "log-domain-list", "/filters": "domain-list"} {
		body := h.pageBody(path)
		wantContains(t, body, `<datalist id="`+listID+`">`)
		wantContains(t, body, `list="`+listID+`"`)
		common := strings.Index(body, `<option value="common.example.com">`)
		rare := strings.Index(body, `<option value="rare.example.com">`)
		if common < 0 || rare < 0 || common > rare {
			t.Errorf("%s: suggestion order common=%d rare=%d", path, common, rare)
		}
	}
}

func TestTheDashboardRendersItsNumbersAndTables(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedQueries("ads.example.com", "10.0.0.5", 3, true)
	h.seedQueries("good.example.com", "10.0.0.6", 1, false)
	body := h.pageBody("/")
	for _, fragment := range []string{
		`title="4">4</div>`, `<div class="stat-value red">75.0%</div>`, "ads.example.com",
		"good.example.com", "10.0.0.5", "1.1.1.1:53", "(75.0%)", "<dashboard-page>",
	} {
		wantContains(t, body, fragment)
	}
}

func TestAnApplianceWithNoQueriesIsToldHowToStart(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	body := h.pageBody("/")
	wantContains(t, body, "Point a device at noadd to get started")
	wantAbsent(t, body, `data-testid="dashboard-empty-state" style="display:none"`)
	// One merged style attribute: a second one would be dropped.
	wantContains(t, body, `id="chart-card" style="animation-delay:0.1s;display:none"`)
	wantContains(t, body, ">0.0%<")
}

func TestTheLiveToggleAndChartAreMarkedClientOnly(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	body := h.pageBody("/")
	wantContains(t, body, `id="live-btn"`)
	wantContains(t, body, "js-only")
	wantContains(t, body, `data-testid="chart-needs-js"`)
}

func TestTheStatsPageRendersItsReadings(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedQueries("ads.example.com", "10.0.0.5", 3, true)
	h.seedQueries("good.example.com", "10.0.0.6", 1, false)
	body := h.pageBody("/stats")
	for _, fragment := range []string{
		"<stats-page ", `data-bucket-secs="3600"`,
		`<div class="stat-label">Unique Domains</div><div class="stat-value accent" title="2">2</div>`,
		`title="A">A</div>`, `title="Blocked">Blocked</div>`, "ads.example.com", "good.example.com",
		"10.0.0.5", `<div class="bar-row-pct">75.0%</div>`, "width:100.0%",
		`data-testid="db-health-card"`, `<div class="stat-label">Database Size</div>`,
	} {
		wantContains(t, body, fragment)
	}
}

func TestTheRangeSwitcherSelectsTheWindow(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	def := h.pageBody("/stats")
	wantContains(t, def, `<a href="/stats?range=7d" class="active" aria-current="page">7d</a>`)
	wantContains(t, def, "Top Domains (last 7d)")

	month := h.pageBody("/stats?range=30d")
	wantContains(t, month, `<a href="/stats?range=30d" class="active" aria-current="page">30d</a>`)
	wantAbsent(t, month, `<a href="/stats?range=7d" class="active"`)
	for _, title := range []string{"Queries (last 30d)", "Block &amp; Cache rate (last 30d)", "Top Domains (last 30d)", "Top Sources (last 30d)"} {
		wantContains(t, month, title)
	}
	wantContains(t, h.pageBody("/stats?range=nonsense"), "Top Domains (last 7d)")
}

func TestTheChartsSayTheyAreDrawnInTheBrowser(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	body := h.pageBody("/stats")
	for _, id := range []string{"timeline-needs-js", "rate-trend-needs-js", "heatmap-needs-js"} {
		wantContains(t, body, `data-testid="`+id+`"`)
	}
}

func TestAStatsPageWithNoTrafficRendersEmptyLists(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	body := h.pageBody("/stats")
	if got := strings.Count(body, `<p class="text-dim">No data yet</p>`); got != 4 {
		t.Errorf("empty bar lists = %d, want 4", got)
	}
	wantContains(t, body, `<div class="stat-label">Latency p50</div><div class="stat-value text-green">—</div>`)
}

// benchmarkPage measures a page's full render against a database of
// benchmarkQueryCount rows. The Rust page-miss benches counted SQLite pages,
// which modernc cannot report, so this measures time and allocations instead.
func benchmarkPage(b *testing.B, path string) {
	const benchmarkQueryCount = 20000
	h := newAPIHarness(b, harnessOptions{})
	for i := range 20 {
		h.seedQueries(fmt.Sprintf("host%d.example.com", i), fmt.Sprintf("10.0.0.%d", i), benchmarkQueryCount/20, i%3 == 0)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if recorder := h.signedIn(http.MethodGet, path, ""); recorder.Code != http.StatusOK {
			b.Fatalf("%s = %d", path, recorder.Code)
		}
	}
}

func BenchmarkDashboardPage(b *testing.B) { benchmarkPage(b, "/") }

func BenchmarkLogsPage(b *testing.B) { benchmarkPage(b, "/logs") }

func BenchmarkLogsPageFiltered(b *testing.B) {
	benchmarkPage(b, "/logs?action=blocked&q=host3&page=2")
}

func BenchmarkStatsPage(b *testing.B) { benchmarkPage(b, "/stats") }
