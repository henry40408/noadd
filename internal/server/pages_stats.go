package server

import (
	"encoding/json"
	"math"
	"net/http"
	"slices"
	"strconv"

	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/stats"
	"github.com/henry40408/noadd/internal/views"
)

// statsTopN is how many rows the two ranged bar lists show. (The
// /api/stats/v2 lists default to 15.)
const statsTopN int64 = 10

// dashboardTopN is the rows each dashboard table shows.
const dashboardTopN int64 = 10

// dashboardPage handles GET /. The numbers are the same reads as the
// pushed stats snapshot, minus the chart's timeline. A failed read renders
// zeroes rather than an error page.
func (a *api) dashboardPage(w http.ResponseWriter, r *http.Request, _ authedUser) {
	ctx := r.Context()
	shell := a.shell(w, r)
	now := a.Now().Unix()

	summary, _ := stats.ComputeSummary(ctx, a.DB, now)
	domains, clients, _ := stats.ComputeTopDomainsAndClients(ctx, a.DB, now, dashboardTopN)
	upstreams, _ := stats.ComputeTopUpstreams(ctx, a.DB, now, dashboardTopN)

	perSecond := func(count int64, seconds float64) string { return formatQPS(float64(count) / seconds) }
	writeHTML(w, http.StatusOK, views.Dashboard(views.DashboardPage{
		Shell:            shell,
		QueriesToday:     formatNumAdaptive(summary.TotalToday),
		QueriesTodayFull: thousands(summary.TotalToday),
		Queries7d:        compact(summary.Total7d),
		Queries30d:       compact(summary.Total30d),
		BlockedToday:     formatNumAdaptive(summary.BlockedToday),
		BlockedTodayFull: thousands(summary.BlockedToday),
		Blocked7d:        compact(summary.Blocked7d),
		Blocked30d:       compact(summary.Blocked30d),
		BlockRate:        percent1(summary.BlockRatioToday),
		BlockRate7d:      percent1(summary.BlockRatio7d),
		BlockRate30d:     percent1(summary.BlockRatio30d),
		CacheRate:        percent1(summary.CacheHitRateToday),
		CacheRate7d:      percent1(summary.CacheHitRate7d),
		CacheRate30d:     percent1(summary.CacheHitRate30d),
		AvgMS:            oneDecimal(summary.AvgResponseMsToday),
		AvgMS7d:          oneDecimal(summary.AvgResponseMs7d),
		AvgMS30d:         oneDecimal(summary.AvgResponseMs30d),
		QPSNow:           perSecond(summary.Queries1m, 60),
		QPSToday:         perSecond(summary.TotalToday, 86_400),
		QPS7d:            perSecond(summary.Total7d, 7*86_400),
		HasQueries:       summary.TotalToday+summary.Total7d+summary.Total30d > 0,
		DNSAddr:          dnsTarget(requestHost(r), a.ServerInfo.DNSAddr),
		TopDomains:       topDomainRows(domains),
		TopClients:       topClientRows(clients),
		TopUpstreams:     topUpstreamRows(upstreams),
	}))
}

func oneDecimal(value float64) string { return strconv.FormatFloat(value, 'f', 1, 64) }

func topDomainRows(domains []db.TopDomain) []views.TopRow {
	var sum int64
	for _, d := range domains {
		sum += d.Count
	}
	rows := make([]views.TopRow, 0, len(domains))
	for _, d := range domains {
		rows = append(rows, views.TopRow{Label: d.Domain, Count: thousands(d.Count), Share: sharePercent(d.Count, sum)})
	}
	return rows
}

func topClientRows(clients []db.TopClient) []views.TopRow {
	var sum int64
	for _, c := range clients {
		sum += c.Count
	}
	rows := make([]views.TopRow, 0, len(clients))
	for _, c := range clients {
		rows = append(rows, views.TopRow{
			Label: c.ClientIP, SubLabel: deref(c.DohToken),
			Count: thousands(c.Count), Share: sharePercent(c.Count, sum),
		})
	}
	return rows
}

func topUpstreamRows(upstreams []db.TopUpstream) []views.TopRow {
	var sum int64
	for _, u := range upstreams {
		sum += u.Count
	}
	rows := make([]views.TopRow, 0, len(upstreams))
	for _, u := range upstreams {
		rows = append(rows, views.TopRow{
			Label: u.Upstream, Count: thousands(u.Count),
			Share: sharePercent(u.Count, sum), AvgMS: oneDecimal(u.AvgMs) + "ms",
		})
	}
	return rows
}

// barRows turns counted labels into a bar list, largest first. Bars are scaled
// to the largest count, so near-equal rows stay readable; the percentage is the
// share of the total.
func barRows(entries []db.NameCount) []views.BarRow {
	sorted := slices.Clone(entries)
	slices.SortStableFunc(sorted, func(x, y db.NameCount) int { return int(sign(y.Count - x.Count)) })
	var maxCount, sum int64
	for _, entry := range sorted {
		maxCount = max(maxCount, entry.Count)
		sum += entry.Count
	}
	rows := make([]views.BarRow, 0, len(sorted))
	for _, entry := range sorted {
		share := sharePercent(entry.Count, sum)
		width := "0.0"
		if maxCount > 0 {
			width = oneDecimal(float64(entry.Count) / float64(maxCount) * 100)
		}
		title := thousands(entry.Count)
		if share != "" {
			title += " (" + share + ")"
		}
		rows = append(rows, views.BarRow{
			Label: entry.Name, Width: width, Count: formatNumAdaptive(entry.Count),
			Share: share, CountTitle: title,
		})
	}
	return rows
}

func sign(n int64) int64 {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	}
	return 0
}

func statCard(label, value, valueClass string) views.StatCard {
	return views.StatCard{Label: label, Value: value, ValueClass: valueClass}
}

// highlightCards are the four tiles above the charts. No samples means no
// percentiles; a zero would read as impossibly fast.
func highlightCards(rangeStats *stats.RangeStats) []views.StatCard {
	var unique int64
	var latency db.LatencySummary
	if rangeStats != nil {
		unique = rangeStats.Domains.Unique
		latency = rangeStats.Metrics.Latency
	}
	hasLatency := latency.SampleCount > 0
	latencyCard := func(label string, value int64, class string) views.StatCard {
		if !hasLatency {
			return statCard(label, "—", class)
		}
		card := statCard(label, compact(value), class)
		card.Unit = "ms"
		return card
	}
	uniqueCard := statCard("Unique Domains", formatNumAdaptiveAt(unique, 10_000_000), "accent")
	uniqueCard.Title = thousands(unique)
	return []views.StatCard{
		uniqueCard,
		latencyCard("Latency p50", latency.P50Ms, "text-green"),
		latencyCard("Latency p95", latency.P95Ms, "text-orange"),
		latencyCard("Latency p99", latency.P99Ms, "text-red"),
	}
}

// seriesJSON ships the quarter series the charts fold in the browser; a
// failed read is the empty series.
func seriesJSON(rangeStats *stats.RangeStats) string {
	series := db.QuarterSeries{}
	if rangeStats != nil {
		series = rangeStats.Series
	}
	series.Total, series.Blocked = nonNil(series.Total), nonNil(series.Blocked)
	series.Cached, series.Heatmap = nonNil(series.Cached), nonNil(series.Heatmap)
	body, _ := json.Marshal(series)
	return string(body)
}

func clientBarEntries(clients []db.TopClient) []db.NameCount {
	entries := make([]db.NameCount, 0, len(clients))
	for _, c := range clients {
		label := c.ClientIP
		// Name a DoH client by IP and token; the IP alone would merge every
		// token behind one proxy.
		if token := deref(c.DohToken); token != "" {
			label += " · " + token
		}
		entries = append(entries, db.NameCount{Name: label, Count: c.Count})
	}
	return entries
}

func domainBarEntries(domains []db.TopDomain) []db.NameCount {
	entries := make([]db.NameCount, 0, len(domains))
	for _, d := range domains {
		entries = append(entries, db.NameCount{Name: d.Domain, Count: d.Count})
	}
	return entries
}

// statsPage handles GET /stats. Every reading is in this response, charts
// included: they ship as a UTC quarter-hour series that app.js folds into the
// viewer's calendar. A failed read renders as an empty list or a dash.
func (a *api) statsPage(w http.ResponseWriter, r *http.Request, _ authedUser) {
	ctx := r.Context()
	shell := a.shell(w, r)
	now := a.Now().Unix()
	// An unrecognised range renders the default rather than a 400.
	rng, ok := stats.ParseRange(r.URL.Query().Get("range"))
	if !ok {
		rng = stats.Days7
	}

	var rangeStats *stats.RangeStats
	if computed, err := stats.ComputeRangeStats(ctx, a.DB, now, rng, statsTopN); err == nil {
		rangeStats = &computed
	}
	page := views.StatsPage{
		Shell:      shell,
		Range:      rng.Label(),
		SeriesJSON: seriesJSON(rangeStats),
		BucketSecs: rng.BucketSecs(),
		Highlights: highlightCards(rangeStats),
	}
	if rangeStats != nil {
		page.QueryTypes = barRows(rangeStats.Metrics.QueryTypes)
		page.Outcomes = barRows(rangeStats.Metrics.Outcomes)
		page.TopDomains = barRows(domainBarEntries(rangeStats.Domains.Top))
		page.TopClients = barRows(clientBarEntries(rangeStats.Clients))
	}
	if health, err := stats.ComputeDBHealth(ctx, a.DB, now); err == nil {
		page.Health = healthCards(health)
	}
	for _, label := range []string{"7d", "30d", "90d"} {
		page.Ranges = append(page.Ranges, views.RangeOption{Label: label, Active: label == rng.Label()})
	}
	writeHTML(w, http.StatusOK, views.Stats(page))
}

// healthCards are the ten database-health tiles, in the order the grid shows
// them.
func healthCards(health stats.DBHealth) []views.StatCard {
	fragPct := int64(math.Round(health.FragmentationRatio * 100))
	coverage := "—"
	switch {
	case health.LogCoverageDays >= 10:
		coverage = strconv.FormatFloat(math.Round(health.LogCoverageDays), 'f', 0, 64) + "d"
	case health.LogCoverageDays > 0:
		coverage = oneDecimal(health.LogCoverageDays) + "d"
	}
	avgPerDay := "—"
	if health.AvgNewRowsPerDay > 0 {
		avgPerDay = compact(int64(math.Round(health.AvgNewRowsPerDay)))
	}
	var oldest int64
	if health.OldestLogTimestamp != nil && *health.OldestLogTimestamp > 0 {
		oldest = *health.OldestLogTimestamp
	}
	oldestText := "—"
	if oldest > 0 {
		oldestText = isoDate(oldest)
	}
	retention := "—"
	if health.LogRetentionDays != nil {
		retention = strconv.FormatInt(*health.LogRetentionDays, 10) + "d"
	}
	projected := "—"
	if health.ProjectedFullBytes > 0 {
		projected = formatBytes(health.ProjectedFullBytes)
	}

	totalLogs := statCard("Total Logs", formatNumAdaptiveAt(health.TotalLogCount, 10_000_000), "accent")
	totalLogs.Title = thousands(health.TotalLogCount)
	reclaimable := statCard("Reclaimable", formatBytes(max(health.ReclaimableBytes, 0)), "accent")
	reclaimable.Sub = strconv.FormatInt(fragPct, 10) + "% of file"
	oldestCard := statCard("Oldest Log", oldestText, "stat-date")
	oldestCard.TS = oldest
	projectedCard := statCard("Projected Full", projected, "accent")
	projectedCard.Sub = "at full retention"

	return []views.StatCard{
		statCard("Database Size", formatBytes(health.DBSizeBytes), "accent"),
		totalLogs,
		statCard("Bytes / Log", formatBytesOrDash(health.BytesPerLog), "accent"),
		reclaimable,
		oldestCard,
		statCard("Log Coverage", coverage, "accent"),
		statCard("Retention", retention, "accent"),
		statCard("Avg / Day", avgPerDay, "accent"),
		statCard("Growth / Day", formatBytesOrDash(health.BytesPerLog*health.AvgNewRowsPerDay), "accent"),
		projectedCard,
	}
}
