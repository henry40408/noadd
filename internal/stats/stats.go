// Package stats turns the database's statistics readings into the shapes the
// dashboard, the Statistics page and /api/stats serve.
package stats

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/henry40408/noadd/internal/db"
)

// DefaultLogRetentionDays is kept when log_retention_days is unset or
// unparseable. The prune task and the DB health report share it, so the UI
// shows the retention actually in effect.
const DefaultLogRetentionDays int64 = 7

// LogRetentionDaysSuggestions are the spans the settings form suggests,
// ascending, including DefaultLogRetentionDays. The settings save does not
// validate the field, so each must itself parse as a positive integer.
var LogRetentionDaysSuggestions = []int64{1, 7, 14, 30, 90, 365}

const (
	daySecs = 86_400
	// HeatmapWindowSecs is the heatmap's window, whatever range the page shows.
	HeatmapWindowSecs = 30 * daySecs
	// timelineTargetBars is how many bars the dashboard chart aims for.
	timelineTargetBars = 48
	// domainSuggestionWindowSecs looks back a week, not the dashboard's day, so
	// something noticed on Friday is still offered on Monday.
	domainSuggestionWindowSecs = DefaultLogRetentionDays * daySecs
	domainSuggestionLimit      = 20
)

// Summary is the dashboard's headline numbers. The zero value is what the
// dashboard renders when the read fails.
type Summary struct {
	TotalToday         int64   `json:"total_today"`
	BlockedToday       int64   `json:"blocked_today"`
	Total7d            int64   `json:"total_7d"`
	Blocked7d          int64   `json:"blocked_7d"`
	Total30d           int64   `json:"total_30d"`
	Blocked30d         int64   `json:"blocked_30d"`
	BlockRatioToday    float64 `json:"block_ratio_today"`
	BlockRatio7d       float64 `json:"block_ratio_7d"`
	BlockRatio30d      float64 `json:"block_ratio_30d"`
	CacheHitRateToday  float64 `json:"cache_hit_rate_today"`
	CacheHitRate7d     float64 `json:"cache_hit_rate_7d"`
	CacheHitRate30d    float64 `json:"cache_hit_rate_30d"`
	AvgResponseMsToday float64 `json:"avg_response_ms_today"`
	AvgResponseMs7d    float64 `json:"avg_response_ms_7d"`
	AvgResponseMs30d   float64 `json:"avg_response_ms_30d"`
	Queries1m          int64   `json:"queries_1m"`
}

func ratio(part, whole int64) float64 {
	if whole <= 0 {
		return 0
	}
	return float64(part) / float64(whole)
}

// ComputeSummary reads the trailing 24 hours, 7 days and 30 days.
func ComputeSummary(ctx context.Context, database *db.DB, now int64) (Summary, error) {
	queries1m, err := database.CountQueriesSince(ctx, now-60)
	if err != nil {
		return Summary{}, err
	}
	windows, err := database.SummaryMultiSince(ctx, now-daySecs, now-7*daySecs, now-30*daySecs)
	if err != nil {
		return Summary{}, err
	}
	today, week, month := windows[0], windows[1], windows[2]
	return Summary{
		TotalToday:         today.Total,
		BlockedToday:       today.Blocked,
		Total7d:            week.Total,
		Blocked7d:          week.Blocked,
		Total30d:           month.Total,
		Blocked30d:         month.Blocked,
		BlockRatioToday:    ratio(today.Blocked, today.Total),
		BlockRatio7d:       ratio(week.Blocked, week.Total),
		BlockRatio30d:      ratio(month.Blocked, month.Total),
		CacheHitRateToday:  ratio(today.CacheHits, today.Allowed),
		CacheHitRate7d:     ratio(week.CacheHits, week.Allowed),
		CacheHitRate30d:    ratio(month.CacheHits, month.Allowed),
		AvgResponseMsToday: today.AvgResponseMs,
		AvgResponseMs7d:    week.AvgResponseMs,
		AvgResponseMs30d:   month.AvgResponseMs,
		Queries1m:          queries1m,
	}, nil
}

// ComputeTopDomains lists the busiest domains of the last 24 hours.
func ComputeTopDomains(ctx context.Context, database *db.DB, now, limit int64) ([]db.TopDomain, error) {
	return database.TopDomainsSince(ctx, now-daySecs, limit)
}

// ComputeTopClients lists the busiest clients of the last 24 hours.
func ComputeTopClients(ctx context.Context, database *db.DB, now, limit int64) ([]db.TopClient, error) {
	return database.TopClientsSince(ctx, now-daySecs, limit)
}

// ComputeTopDomainsAndClients reads the dashboard's two 24-hour lists from one
// statement.
func ComputeTopDomainsAndClients(ctx context.Context, database *db.DB, now, limit int64) ([]db.TopDomain, []db.TopClient, error) {
	lists, err := database.TrafficListsSince(ctx, now-daySecs, limit)
	if err != nil {
		return nil, nil, err
	}
	return lists.Domains.Top, lists.Clients, nil
}

// ComputeTopUpstreams lists the busiest upstreams of the last 24 hours.
func ComputeTopUpstreams(ctx context.Context, database *db.DB, now, limit int64) ([]db.TopUpstream, error) {
	return database.TopUpstreamsSince(ctx, now-daySecs, limit)
}

// DomainSuggestions are the domains to suggest in a box the operator types a
// domain into, most-queried first. It is empty on a read failure or an empty
// log, which the pages render as no datalist at all.
func DomainSuggestions(ctx context.Context, database *db.DB, now int64) []string {
	top, err := database.TopDomainsSince(ctx, now-domainSuggestionWindowSecs, domainSuggestionLimit)
	if err != nil {
		return nil
	}
	domains := make([]string, 0, len(top))
	for _, entry := range top {
		domains = append(domains, entry.Domain)
	}
	return domains
}

// ComputeTimeline buckets the last hours of traffic for the dashboard chart,
// starting no earlier than the first log.
func ComputeTimeline(ctx context.Context, database *db.DB, now, hours int64) ([]db.TimelinePoint, error) {
	since := now - hours*3600
	earliestMs, found, err := database.EarliestLogTimestamp(ctx)
	if err != nil {
		return nil, err
	}
	if found {
		since = max(earliestMs/1000, since)
	}
	return database.TimelineSince(ctx, since, timelineBucketSecs(max(now-since, 1)))
}

// timelineBucketSecs rounds the bucket to a clean interval, 60 s at the least.
func timelineBucketSecs(rangeSecs int64) int64 {
	raw := rangeSecs / timelineTargetBars
	switch {
	case raw <= 60:
		return 60
	case raw <= 300:
		return 300
	case raw <= 600:
		return 600
	case raw <= 1800:
		return 1800
	}
	return 3600
}

// Range is a Statistics page window.
type Range int

// The windows the page offers.
const (
	Days7 Range = iota
	Days30
	Days90
)

// ParseRange accepts exactly "7d", "30d" and "90d".
func ParseRange(raw string) (Range, bool) {
	switch raw {
	case "7d":
		return Days7, true
	case "30d":
		return Days30, true
	case "90d":
		return Days90, true
	}
	return 0, false
}

// Label is the spelling ParseRange accepts, used by the range switcher's URL
// and every card title.
func (r Range) Label() string {
	return [...]string{"7d", "30d", "90d"}[r]
}

// BucketSecs is the width of one timeline bucket.
func (r Range) BucketSecs() int64 {
	return [...]int64{3600, 6 * 3600, daySecs}[r]
}

// windowSecs is how far back the range reaches.
func (r Range) windowSecs() int64 {
	return [...]int64{7 * daySecs, 30 * daySecs, 90 * daySecs}[r]
}

// Breakdowns is the query-type and outcome counts of a window. Each entry
// serialises as a [name, count] pair.
type Breakdowns struct {
	QueryTypes []NameCount `json:"query_types"`
	Outcomes   []NameCount `json:"outcomes"`
}

// NameCount is a labelled count, serialised as a two-element array.
type NameCount db.NameCount

// MarshalJSON writes [name, count].
func (n NameCount) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]any{n.Name, n.Count})
}

func nameCounts(rows []db.NameCount) []NameCount {
	converted := make([]NameCount, 0, len(rows))
	for _, row := range rows {
		converted = append(converted, NameCount(row))
	}
	return converted
}

// DBHealth is the Database Health card.
type DBHealth struct {
	DBSizeBytes int64 `json:"db_size_bytes"`
	// ReclaimableBytes is what a VACUUM would return to the OS.
	ReclaimableBytes int64 `json:"reclaimable_bytes"`
	// FragmentationRatio is the reclaimable share of the main file, 0 to 1.
	FragmentationRatio float64 `json:"fragmentation_ratio"`
	TotalLogCount      int64   `json:"total_log_count"`
	// OldestLogTimestamp is in Unix seconds.
	OldestLogTimestamp *int64  `json:"oldest_log_timestamp"`
	LogRetentionDays   *int64  `json:"log_retention_days"`
	AvgNewRowsPerDay   float64 `json:"avg_new_rows_per_day"`
	// BytesPerLog is DBSizeBytes / TotalLogCount, 0 when there are no logs.
	BytesPerLog float64 `json:"bytes_per_log"`
	// LogCoverageDays is the span of retained data, 0 with fewer than two logs.
	LogCoverageDays float64 `json:"log_coverage_days"`
	// ProjectedFullBytes is the main-file size once retention is full, 0 when
	// any input is unavailable.
	ProjectedFullBytes int64 `json:"projected_full_bytes"`
}

// ComputeStatsTimeline reads the multi-series timeline of a range.
func ComputeStatsTimeline(ctx context.Context, database *db.DB, now int64, rng Range, tzOffsetSecs int64) ([]db.TimelineMultiPoint, error) {
	return database.TimelineMultiSince(ctx, now-rng.windowSecs(), rng.BucketSecs(), tzOffsetSecs)
}

// ComputeHeatmap reads the heatmap over its fixed window.
func ComputeHeatmap(ctx context.Context, database *db.DB, now, tzOffsetSecs int64) ([]db.HeatmapCell, error) {
	return database.HourlyHeatmapSince(ctx, now-HeatmapWindowSecs, tzOffsetSecs)
}

// ComputeBreakdowns reads both breakdowns from one statement.
func ComputeBreakdowns(ctx context.Context, database *db.DB, now int64, rng Range) (Breakdowns, error) {
	metrics, err := database.WindowMetricsSince(ctx, now-rng.windowSecs())
	if err != nil {
		return Breakdowns{}, err
	}
	return Breakdowns{QueryTypes: nameCounts(metrics.QueryTypes), Outcomes: nameCounts(metrics.Outcomes)}, nil
}

// Highlights is the Statistics page's headline readings.
type Highlights struct {
	UniqueDomains int64             `json:"unique_domains"`
	Latency       db.LatencySummary `json:"latency"`
}

// ComputeHighlights reads the distinct-domain count and latency percentiles.
func ComputeHighlights(ctx context.Context, database *db.DB, now int64, rng Range) (Highlights, error) {
	since := now - rng.windowSecs()
	unique, err := database.UniqueDomainsSince(ctx, since)
	if err != nil {
		return Highlights{}, err
	}
	latency, err := database.LatencySummarySince(ctx, since)
	if err != nil {
		return Highlights{}, err
	}
	return Highlights{UniqueDomains: unique, Latency: latency}, nil
}

// RangeStats is everything the Statistics page reads for its window, from two
// statements. A new reading should fold out of one of them rather than add a
// third.
type RangeStats struct {
	Metrics db.WindowMetrics
	Series  db.QuarterSeries
	Domains db.DomainStats
	Clients []db.TopClient
}

// ComputeRangeStats reads the whole Statistics page in one go.
func ComputeRangeStats(ctx context.Context, database *db.DB, now int64, rng Range, topN int64) (RangeStats, error) {
	since := now - rng.windowSecs()
	scan, err := database.StatsScanSince(ctx, since, now-HeatmapWindowSecs)
	if err != nil {
		return RangeStats{}, err
	}
	lists, err := database.TrafficListsSince(ctx, since, topN)
	if err != nil {
		return RangeStats{}, err
	}
	return RangeStats{Metrics: scan.Metrics, Series: scan.Series, Domains: lists.Domains, Clients: lists.Clients}, nil
}

// ComputeTopDomainsRanged lists the busiest domains of a range.
func ComputeTopDomainsRanged(ctx context.Context, database *db.DB, now int64, rng Range, limit int64) ([]db.TopDomain, error) {
	return database.TopDomainsSince(ctx, now-rng.windowSecs(), limit)
}

// ComputeTopClientsRanged lists the busiest clients of a range.
func ComputeTopClientsRanged(ctx context.Context, database *db.DB, now int64, rng Range, limit int64) ([]db.TopClient, error) {
	return database.TopClientsSince(ctx, now-rng.windowSecs(), limit)
}

// ComputeDBHealth reads the Database Health card.
func ComputeDBHealth(ctx context.Context, database *db.DB, now int64) (DBHealth, error) {
	storage, err := database.DBStorageStats(ctx)
	if err != nil {
		return DBHealth{}, err
	}
	total, err := database.TotalLogCount(ctx)
	if err != nil {
		return DBHealth{}, err
	}
	earliestMs, hasEarliest, err := database.EarliestLogTimestamp(ctx)
	if err != nil {
		return DBHealth{}, err
	}
	latestMs, hasLatest, err := database.LatestLogTimestamp(ctx)
	if err != nil {
		return DBHealth{}, err
	}
	retention, err := retentionDays(ctx, database)
	if err != nil {
		return DBHealth{}, err
	}
	return buildDBHealth(healthInputs{
		storage: storage, total: total, now: now, retention: retention,
		earliestMs: earliestMs, hasEarliest: hasEarliest,
		latestMs: latestMs, hasLatest: hasLatest,
	}), nil
}

func retentionDays(ctx context.Context, database *db.DB) (int64, error) {
	raw, found, err := database.GetSetting(ctx, "log_retention_days")
	if err != nil {
		return 0, err
	}
	if !found {
		return DefaultLogRetentionDays, nil
	}
	days, ok := parseInt64(raw)
	if !ok {
		return DefaultLogRetentionDays, nil
	}
	return days, nil
}

type healthInputs struct {
	storage                db.StorageStats
	total, now, retention  int64
	earliestMs, latestMs   int64
	hasEarliest, hasLatest bool
}

func buildDBHealth(in healthInputs) DBHealth {
	health := DBHealth{
		DBSizeBytes:      in.storage.MainBytes,
		ReclaimableBytes: in.storage.ReclaimableBytes,
		TotalLogCount:    in.total,
		LogRetentionDays: &in.retention,
	}
	if in.storage.MainBytes > 0 {
		health.FragmentationRatio = float64(in.storage.ReclaimableBytes) / float64(in.storage.MainBytes)
	}
	if in.total > 0 {
		health.BytesPerLog = float64(in.storage.MainBytes) / float64(in.total)
	}
	if in.hasEarliest {
		oldest := in.earliestMs / 1000
		health.OldestLogTimestamp = &oldest
		if in.now > oldest {
			spanDays := max(float64(in.now-oldest)/daySecs, 1.0)
			health.AvgNewRowsPerDay = float64(in.total) / spanDays
		}
	}
	if in.hasEarliest && in.hasLatest && in.latestMs > in.earliestMs {
		health.LogCoverageDays = float64(in.latestMs-in.earliestMs) / 86_400_000.0
	}
	if in.retention > 0 && health.AvgNewRowsPerDay > 0 && health.BytesPerLog > 0 {
		health.ProjectedFullBytes = int64(health.BytesPerLog * health.AvgNewRowsPerDay * float64(in.retention))
	}
	return health
}

func parseInt64(raw string) (int64, bool) {
	value, err := strconv.ParseInt(raw, 10, 64)
	return value, err == nil
}
