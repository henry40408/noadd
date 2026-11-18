package harness

import (
	"fmt"
	"strings"
	"time"
)

const (
	hourMillis = 3_600_000
	dayMillis  = 24 * hourMillis
)

// NowMillis is the anchor every backdated fixture counts from.
func NowMillis() int64 { return time.Now().UnixMilli() }

// Every query_logs.timestamp is epoch milliseconds.
const insertQueryLogs = "INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, " +
	"response_ms, upstream, doh_token, result, authenticated_data) VALUES\n"

// QueryLogRows is how many rows QueryLogSeed inserts: three pages at 50 rows a
// page (50, 50, 20), a third of them blocked, which fits on one page.
const QueryLogRows = 120

// QueryLogSeed is the query-log fixture. Every row's domain, type and outcome
// is predictable, so the filter assertions are exact.
func QueryLogSeed(now int64) string {
	rows := make([]string, 0, QueryLogRows)
	for i := int64(0); i < QueryLogRows; i++ {
		blocked := 0
		domain := fmt.Sprintf("site%d.example.com", i)
		if i%3 == 0 {
			blocked = 1
			domain = fmt.Sprintf("ads%d.tracker.example", i)
		}
		queryType := "A"
		if i%4 == 0 {
			queryType = "AAAA"
		}
		rows = append(rows, fmt.Sprintf("(%d, '%s', '%s', '10.0.0.%d', %d, 0, %d, '1.1.1.1:53', NULL, NULL, 0)",
			now-i*1000, domain, queryType, i%5, blocked, 10+i%30))
	}
	return insertQueryLogs + strings.Join(rows, ",\n") + ";\n"
}

// Counts in the statistics fixture.
const (
	StatsRecentBlocked = 30
	StatsRecentAllowed = 10
	StatsOld           = 20
)

// StatsSeed is the statistics fixture: two domains inside the 7-day window and
// a third only reachable from a wider one, so switching the range visibly
// changes the page.
func StatsSeed(now int64) string {
	row := func(timestamp int64, domain, queryType string, blocked int) string {
		return fmt.Sprintf("(%d, '%s', '%s', '10.0.0.7', %d, 0, 12, '1.1.1.1:53', NULL, '1.2.3.4', 0)",
			timestamp, domain, queryType, blocked)
	}
	var rows []string
	// Spread across the last six days so every bucket is not the same one.
	for i := int64(0); i < StatsRecentBlocked; i++ {
		rows = append(rows, row(now-(i%6)*dayMillis-i*1000, "ads.recent.example", "A", 1))
	}
	for i := int64(0); i < StatsRecentAllowed; i++ {
		rows = append(rows, row(now-(i%6)*dayMillis-i*1000, "site.recent.example", "AAAA", 0))
	}
	for i := int64(0); i < StatsOld; i++ {
		rows = append(rows, row(now-10*dayMillis-i*1000, "old.example", "A", 0))
	}
	// Retention defaults to seven days and the prune fires at boot, so widen
	// it or the ten-day-old rows delete themselves before the first request.
	return "INSERT OR REPLACE INTO settings (key, value) VALUES ('log_retention_days', '60');\n" +
		insertQueryLogs + strings.Join(rows, ",\n") + ";\n"
}

// ChartFoldSeed is traffic every seven minutes and a few seconds across the
// last six days, plus rows twenty days back (inside 30d and the heatmap,
// outside 7d) and sixty days back (inside 90d only). Every row sits at least
// an hour clear of every window's edge, so the page and the API, asked
// seconds apart, see the same rows.
func ChartFoldSeed(now int64) string {
	types := []string{"A", "AAAA", "HTTPS"}
	row := func(timestamp, i int64) string {
		return fmt.Sprintf("(%d, 'host%d.example', '%s', '10.0.0.%d', %d, %d, %d, '1.1.1.1:53', NULL, '1.2.3.4', 0)",
			timestamp, i%40, types[i%3], i%9, b2i(i%7 == 0), b2i(i%5 == 0), (i*13)%90)
	}
	var rows []string
	i := int64(0)
	for timestamp := now - hourMillis; timestamp > now-6*dayMillis; timestamp -= 7*60_000 + 3_217 {
		rows = append(rows, row(timestamp, i))
		i++
	}
	for k := int64(0); k < 50; k++ {
		rows = append(rows, row(now-20*dayMillis-k*11*60_000, k), row(now-60*dayMillis-k*11*60_000, k))
	}
	// Retention would otherwise prune the older rows at boot.
	return "INSERT OR REPLACE INTO settings (key, value) VALUES ('log_retention_days', '120');\n" +
		insertQueryLogs + strings.Join(rows, ",\n") + ";\n"
}

func b2i(value bool) int {
	if value {
		return 1
	}
	return 0
}
