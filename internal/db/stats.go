package db

import (
	"context"
	"database/sql"
	"slices"
	"strings"
)

// QuarterSecs is the width of one QuarterSeries slot, in seconds.
const QuarterSecs int64 = 900

// StorageStats is the Database Health card's reading.
type StorageStats struct {
	MainBytes        int64 `json:"main_bytes"`
	ReclaimableBytes int64 `json:"reclaimable_bytes"`
}

// TopUpstream is one busy upstream with its mean response time.
type TopUpstream struct {
	Upstream string  `json:"upstream"`
	Count    int64   `json:"count"`
	AvgMs    float64 `json:"avg_ms"`
}

// TopDomain is one busy domain.
type TopDomain struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

// TopClient is one busy client, optionally behind a DoH token.
type TopClient struct {
	ClientIP string  `json:"client_ip"`
	DohToken *string `json:"doh_token"`
	Count    int64   `json:"count"`
}

// TimelinePoint is one bucket; Timestamp is its start in Unix seconds
// (query_logs.timestamp is milliseconds).
type TimelinePoint struct {
	Timestamp int64 `json:"timestamp"`
	Total     int64 `json:"total"`
	Blocked   int64 `json:"blocked"`
}

// TimelineMultiPoint is one bucket with the cached count too.
type TimelineMultiPoint struct {
	Timestamp int64 `json:"timestamp"`
	Total     int64 `json:"total"`
	Blocked   int64 `json:"blocked"`
	Cached    int64 `json:"cached"`
}

// MetricsBucket is the queries in one time bucket and (blocked, cached) pair.
type MetricsBucket struct {
	Timestamp int64
	Blocked   bool
	Cached    bool
	Count     int64
}

// WindowMetricsRow is the queries per outcome, query type and response time.
type WindowMetricsRow struct {
	Blocked bool
	Cached  bool
	// HasResult is carried by the rollup so classifying an outcome never
	// reads query_logs.
	HasResult  bool
	QueryType  string
	ResponseMs int64
	Count      int64
}

// NameCount is a labelled count; it stands for Rust's (String, i64) tuples.
type NameCount struct {
	Name  string
	Count int64
}

// LatencySummary holds response-time percentiles.
type LatencySummary struct {
	SampleCount int64 `json:"sample_count"`
	P50Ms       int64 `json:"p50_ms"`
	P95Ms       int64 `json:"p95_ms"`
	P99Ms       int64 `json:"p99_ms"`
}

// WindowMetrics is the three Statistics readings folded out of
// query_stats_metrics_hour in one statement.
type WindowMetrics struct {
	Outcomes   []NameCount
	QueryTypes []NameCount
	Latency    LatencySummary
}

// WindowSummary is one window of the dashboard summary.
type WindowSummary struct {
	Total   int64
	Blocked int64
	// Allowed is the queries that were not blocked: the denominator of the
	// cache hit rate.
	Allowed   int64
	CacheHits int64
	// AvgResponseMs is the mean of the allowed queries, 0 when there were none.
	AvgResponseMs float64
}

// QuarterSeries is query counts per quarter hour on UTC-epoch boundaries,
// dense from the first quarter that held a query to the last. Every UTC
// offset in use is a whole number of quarter hours, so the browser folds
// these exactly into local hours and days.
type QuarterSeries struct {
	// Start is the first quarter's start in Unix seconds; 0 when there are none.
	Start   int64   `json:"start"`
	Total   []int64 `json:"total"`
	Blocked []int64 `json:"blocked"`
	Cached  []int64 `json:"cached"`
	// Heatmap counts the heatmap's window, not the range's.
	Heatmap []int64 `json:"heatmap"`
}

// StatsScan is everything the Statistics page folds out of the quarter and
// metrics rollups.
type StatsScan struct {
	Metrics WindowMetrics
	Series  QuarterSeries
}

// DomainStats is the busiest domains alongside how many distinct ones the
// window held.
type DomainStats struct {
	Unique int64
	Top    []TopDomain
}

// TrafficLists is who asked for what in a window.
type TrafficLists struct {
	Domains DomainStats
	Clients []TopClient
}

// HeatmapCell is one weekday-hour cell; Weekday 0 is Sunday, like
// strftime('%w').
type HeatmapCell struct {
	Weekday int64 `json:"weekday"`
	Hour    int64 `json:"hour"`
	Count   int64 `json:"count"`
}

// EarliestLogTimestamp returns the oldest log timestamp in milliseconds, and
// false when there are no logs.
func (d *DB) EarliestLogTimestamp(ctx context.Context) (int64, bool, error) {
	return d.logTimestampBound(ctx, "SELECT MIN(timestamp) FROM query_logs")
}

// LatestLogTimestamp returns the newest log timestamp in milliseconds, and
// false when there are no logs.
func (d *DB) LatestLogTimestamp(ctx context.Context) (int64, bool, error) {
	return d.logTimestampBound(ctx, "SELECT MAX(timestamp) FROM query_logs")
}

func (d *DB) logTimestampBound(ctx context.Context, query string) (int64, bool, error) {
	var bound sql.NullInt64
	if err := d.reader.QueryRowContext(ctx, query).Scan(&bound); err != nil {
		return 0, false, err
	}
	return bound.Int64, bound.Valid, nil
}

// CountQueriesSince counts queries logged since the given Unix second.
func (d *DB) CountQueriesSince(ctx context.Context, since int64) (int64, error) {
	var total int64
	err := d.reader.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM query_logs WHERE timestamp >= ?1", since*1000).Scan(&total)
	return total, err
}

const summaryMultiSQL = `WITH p AS (
                        SELECT 'r' AS kind, quarter AS k, blocked, cached, count AS n, sum_ms AS ms
                            FROM query_stats_quarter WHERE quarter >= ?6
                        UNION ALL
                        SELECT 'h1', 0, blocked, cached, 1, response_ms
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?1 AND timestamp < ?4 * 900000
                        UNION ALL
                        SELECT 'h7', 0, blocked, cached, 1, response_ms
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?2 AND timestamp < ?5 * 900000
                        UNION ALL
                        SELECT 'h30', 0, blocked, cached, 1, response_ms
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?3 AND timestamp < ?6 * 900000
                    ),
                    w AS (
                        SELECT (kind = 'h1' OR (kind = 'r' AND k >= ?4)) AS in1,
                               (kind = 'h7' OR (kind = 'r' AND k >= ?5)) AS in7,
                               (kind = 'h30' OR kind = 'r') AS in30,
                               blocked, cached, n, ms
                        FROM p
                    )
                    SELECT
                    COALESCE(SUM(CASE WHEN in1 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in1 THEN n * blocked END), 0),
                    COALESCE(SUM(CASE WHEN in1 AND blocked = 0 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in1 AND blocked = 0 THEN n * cached END), 0),
                    COALESCE(CAST(SUM(CASE WHEN in1 AND blocked = 0 THEN ms END) AS REAL)
                             / SUM(CASE WHEN in1 AND blocked = 0 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in7 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in7 THEN n * blocked END), 0),
                    COALESCE(SUM(CASE WHEN in7 AND blocked = 0 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in7 AND blocked = 0 THEN n * cached END), 0),
                    COALESCE(CAST(SUM(CASE WHEN in7 AND blocked = 0 THEN ms END) AS REAL)
                             / SUM(CASE WHEN in7 AND blocked = 0 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in30 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in30 THEN n * blocked END), 0),
                    COALESCE(SUM(CASE WHEN in30 AND blocked = 0 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in30 AND blocked = 0 THEN n * cached END), 0),
                    COALESCE(CAST(SUM(CASE WHEN in30 AND blocked = 0 THEN ms END) AS REAL)
                             / SUM(CASE WHEN in30 AND blocked = 0 THEN n END), 0)
                    FROM w`

// SummaryMultiSince is the dashboard summary's figures for three nested
// windows, folded out of query_stats_quarter. Whole quarters come from the
// rollup, the partial first quarter from the table (see firstWholeUnit). All
// since values are Unix seconds, and the caller MUST pass the widest window
// as since30d.
func (d *DB) SummaryMultiSince(ctx context.Context, sinceToday, since7d, since30d int64) ([3]WindowSummary, error) {
	todayMs, d7Ms, d30Ms := sinceToday*1000, since7d*1000, since30d*1000
	var summaries [3]WindowSummary
	var targets []any
	for window := range summaries {
		w := &summaries[window]
		targets = append(targets, &w.Total, &w.Blocked, &w.Allowed, &w.CacheHits, &w.AvgResponseMs)
	}
	err := d.reader.QueryRowContext(ctx, summaryMultiSQL,
		todayMs, d7Ms, d30Ms,
		firstWholeUnit(todayMs, rollupQuarterMs),
		firstWholeUnit(d7Ms, rollupQuarterMs),
		firstWholeUnit(d30Ms, rollupQuarterMs)).Scan(targets...)
	return summaries, err
}

// TopDomainsSince returns the busiest domains in the window.
func (d *DB) TopDomainsSince(ctx context.Context, since, limit int64) ([]TopDomain, error) {
	stats, err := d.DomainStatsSince(ctx, since, limit)
	return stats.Top, err
}

// DomainStatsSince returns the busiest domains in the window and how many
// distinct ones there were, folded out of query_stats_domain_hour. Whole
// hours come from the rollup, the partial first hour from the table. The CTE
// is materialized once so the count and the list share one grouping; Unique
// is 0 exactly when Top is empty.
func (d *DB) DomainStatsSince(ctx context.Context, since, limit int64) (DomainStats, error) {
	sinceMs := since * 1000
	rows, err := d.reader.QueryContext(ctx,
		`WITH d AS (
                        SELECT domain, SUM(n) AS cnt FROM (
                            SELECT domain, count AS n FROM query_stats_domain_hour WHERE hour >= ?2
                            UNION ALL
                            SELECT domain, 1 FROM query_logs INDEXED BY idx_query_logs_timestamp
                                WHERE timestamp >= ?1 AND timestamp < ?2 * 3600000
                        ) GROUP BY domain
                    )
                    SELECT (SELECT COUNT(*) FROM d), domain, cnt
                    FROM d ORDER BY cnt DESC, domain LIMIT ?3`,
		sinceMs, firstWholeUnit(sinceMs, rollupHourMs), limit)
	if err != nil {
		return DomainStats{}, err
	}
	defer func() { _ = rows.Close() }()
	var stats DomainStats
	for rows.Next() {
		var top TopDomain
		if err := rows.Scan(&stats.Unique, &top.Domain, &top.Count); err != nil {
			return DomainStats{}, err
		}
		stats.Top = append(stats.Top, top)
	}
	return stats, rows.Err()
}

// TopClientsSince is a fold over TrafficListsSince.
func (d *DB) TopClientsSince(ctx context.Context, since, limit int64) ([]TopClient, error) {
	lists, err := d.TrafficListsSince(ctx, since, limit)
	return lists.Clients, err
}

type clientKey struct {
	clientIP string
	token    sql.NullString
}

// TrafficListsSince returns the busiest domains, how many distinct ones there
// were, and the busiest clients, folded out of query_stats_domain_hour and
// query_stats_client_hour. One statement, so both lists read one snapshot;
// the first column says which list a row belongs to. Ties break by name.
func (d *DB) TrafficListsSince(ctx context.Context, since, limit int64) (TrafficLists, error) {
	sinceMs := since * 1000
	// The rollup stores a missing token as ''; NULLIF restores NULL.
	rows, err := d.reader.QueryContext(ctx,
		`SELECT 0, domain, NULL, SUM(n) FROM (
                        SELECT domain, count AS n FROM query_stats_domain_hour WHERE hour >= ?2
                        UNION ALL
                        SELECT domain, 1 FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?1 AND timestamp < ?2 * 3600000
                    ) GROUP BY domain
                    UNION ALL
                    SELECT 1, client_ip, NULLIF(token, ''), SUM(n) FROM (
                        SELECT client_ip, doh_token AS token, count AS n
                            FROM query_stats_client_hour WHERE hour >= ?2
                        UNION ALL
                        SELECT client_ip, COALESCE(doh_token, ''), 1
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?1 AND timestamp < ?2 * 3600000
                    ) GROUP BY client_ip, token`,
		sinceMs, firstWholeUnit(sinceMs, rollupHourMs))
	if err != nil {
		return TrafficLists{}, err
	}
	defer func() { _ = rows.Close() }()
	domains := map[string]int64{}
	clients := map[clientKey]int64{}
	for rows.Next() {
		var kind, count int64
		var name string
		var token sql.NullString
		if err := rows.Scan(&kind, &name, &token, &count); err != nil {
			return TrafficLists{}, err
		}
		if kind == 0 {
			domains[name] = count
		} else {
			clients[clientKey{name, token}] = count
		}
	}
	if err := rows.Err(); err != nil {
		return TrafficLists{}, err
	}
	keep := int(max(limit, 0))
	return TrafficLists{
		Domains: DomainStats{Unique: int64(len(domains)), Top: topDomains(domains, keep)},
		Clients: topClients(clients, keep),
	}, nil
}

func topDomains(counts map[string]int64, keep int) []TopDomain {
	top := make([]TopDomain, 0, len(counts))
	for domain, count := range counts {
		top = append(top, TopDomain{Domain: domain, Count: count})
	}
	slices.SortFunc(top, func(a, b TopDomain) int {
		if a.Count != b.Count {
			return cmpInt(b.Count, a.Count)
		}
		return strings.Compare(a.Domain, b.Domain)
	})
	return top[:min(keep, len(top))]
}

func topClients(counts map[clientKey]int64, keep int) []TopClient {
	top := make([]TopClient, 0, len(counts))
	for key, count := range counts {
		client := TopClient{ClientIP: key.clientIP, Count: count}
		if key.token.Valid {
			token := key.token.String
			client.DohToken = &token
		}
		top = append(top, client)
	}
	slices.SortFunc(top, func(a, b TopClient) int {
		if a.Count != b.Count {
			return cmpInt(b.Count, a.Count)
		}
		if byIP := strings.Compare(a.ClientIP, b.ClientIP); byIP != 0 {
			return byIP
		}
		return compareOptionalString(a.DohToken, b.DohToken)
	})
	return top[:min(keep, len(top))]
}

// compareOptionalString orders nil before any string, like Rust's Option.
func compareOptionalString(a, b *string) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return strings.Compare(*a, *b)
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// TopUpstreamsSince returns the busiest upstreams in the window with their
// mean response time, folded out of query_stats_upstream_hour. Sum over count
// equals AVG exactly. Ties break by name, as the other lists do.
func (d *DB) TopUpstreamsSince(ctx context.Context, since, limit int64) ([]TopUpstream, error) {
	sinceMs := since * 1000
	rows, err := d.reader.QueryContext(ctx,
		`SELECT upstream, SUM(n) AS cnt, CAST(SUM(ms) AS REAL) / SUM(n) AS avg_ms FROM (
                        SELECT upstream, count AS n, sum_ms AS ms
                            FROM query_stats_upstream_hour WHERE hour >= ?2
                        UNION ALL
                        SELECT upstream, 1, response_ms
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?1 AND timestamp < ?2 * 3600000
                              AND upstream IS NOT NULL
                    ) GROUP BY upstream ORDER BY cnt DESC, upstream LIMIT ?3`,
		sinceMs, firstWholeUnit(sinceMs, rollupHourMs), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []TopUpstream
	for rows.Next() {
		var row TopUpstream
		if err := rows.Scan(&row.Upstream, &row.Count, &row.AvgMs); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// TimelineMultiSince returns query counts in bucketSecs-wide buckets aligned
// to the viewer's calendar via tzOffsetSecs (east-positive; 0 for UTC).
// Timestamp is each bucket's start in Unix seconds. A single offset
// approximates DST: a bucket spanning a transition can be off by the DST delta.
func (d *DB) TimelineMultiSince(ctx context.Context, since, bucketSecs, tzOffsetSecs int64) ([]TimelineMultiPoint, error) {
	buckets, err := d.metricsByBucketSince(ctx, since, bucketSecs, tzOffsetSecs)
	if err != nil {
		return nil, err
	}
	return timelineFromBuckets(buckets), nil
}

// WindowMetricsSince returns the outcome breakdown, the query-type breakdown
// and the latency histogram from one read of query_stats_metrics_hour.
func (d *DB) WindowMetricsSince(ctx context.Context, since int64) (WindowMetrics, error) {
	rows, err := d.metricsWindowSince(ctx, since)
	if err != nil {
		return WindowMetrics{}, err
	}
	return metricsFromWindow(rows), nil
}

func metricsFromWindow(rows []WindowMetricsRow) WindowMetrics {
	return WindowMetrics{
		Outcomes:   outcomesFromWindow(rows),
		QueryTypes: queryTypesFromWindow(rows),
		Latency:    latencyFromWindow(rows),
	}
}

// grainKey is (blocked, cached, has_result, response_ms) of one query type.
type grainKey struct {
	blocked, cached, hasResult bool
	responseMs                 int64
}

// quarterSlot is the counts of one quarter: total, blocked, cached, heatmap.
type quarterSlot [4]int64

const statsScanSQL = `SELECT 0, quarter, blocked, cached, NULL, NULL, NULL, count
                        FROM query_stats_quarter WHERE quarter >= ?3
                    UNION ALL
                    SELECT 1, hour, blocked, cached, has_result, query_type, response_ms, count
                        FROM query_stats_metrics_hour WHERE hour >= ?4
                    UNION ALL
                    SELECT 2, timestamp, blocked, cached, has_result, query_type, response_ms, 1
                        FROM query_logs INDEXED BY idx_query_logs_timestamp
                        WHERE timestamp >= ?1 AND timestamp < ?4 * 3600000
                    UNION ALL
                    SELECT 3, timestamp, blocked, cached, NULL, NULL, NULL, 1
                        FROM query_logs INDEXED BY idx_query_logs_timestamp
                        WHERE timestamp >= ?2 AND timestamp < ?5 * 900000`

// StatsScanSince returns the Statistics page's window readings and its
// charts' series, folded out of query_stats_quarter and
// query_stats_metrics_hour. Whole units come from the rollups, each window's
// partial first unit from the table.
//
// rangeSince bounds the metrics and timeline, heatmapSince the heatmap, each
// exactly (Unix seconds). The first column names the arm: the two rollups,
// then the range's partial first hour (which contains its partial first
// quarter), then the heatmap's partial first quarter. A table row in both
// windows arrives once per arm, and each arm counts it only for its own.
func (d *DB) StatsScanSince(ctx context.Context, rangeSince, heatmapSince int64) (StatsScan, error) {
	rangeMs, heatmapMs := rangeSince*1000, heatmapSince*1000
	rangeQuarter := firstWholeUnit(rangeMs, rollupQuarterMs)
	heatmapQuarter := firstWholeUnit(heatmapMs, rollupQuarterMs)
	rangeHour := firstWholeUnit(rangeMs, rollupHourMs)
	rows, err := d.reader.QueryContext(ctx, statsScanSQL,
		rangeMs, heatmapMs, min(rangeQuarter, heatmapQuarter), rangeHour, heatmapQuarter)
	if err != nil {
		return StatsScan{}, err
	}
	defer func() { _ = rows.Close() }()

	grains := map[string]map[grainKey]int64{}
	quarters := map[int64]*quarterSlot{}
	slot := func(quarter int64) *quarterSlot {
		if quarters[quarter] == nil {
			quarters[quarter] = &quarterSlot{}
		}
		return quarters[quarter]
	}
	for rows.Next() {
		var arm, at, blocked, cached, count int64
		var hasResult, responseMs sql.NullInt64
		var queryType sql.NullString
		if err := rows.Scan(&arm, &at, &blocked, &cached, &hasResult, &queryType, &responseMs, &count); err != nil {
			return StatsScan{}, err
		}
		switch arm {
		case 0:
			s := slot(at)
			if at >= heatmapQuarter {
				s[3] += count
			}
			if at >= rangeQuarter {
				s[0] += count
				s[1] += count * boolToInt(blocked != 0)
				s[2] += count * boolToInt(cached != 0)
			}
			continue
		case 3:
			slot(floorDiv(at, rollupQuarterMs))[3]++
			continue
		case 2:
			// Arm 2 spans the partial first hour; only its partial first
			// quarter is missing from arm 0.
			if at < rangeQuarter*rollupQuarterMs {
				s := slot(floorDiv(at, rollupQuarterMs))
				s[0]++
				s[1] += boolToInt(blocked != 0)
				s[2] += boolToInt(cached != 0)
			}
		}
		byGrain := grains[queryType.String]
		if byGrain == nil {
			byGrain = map[grainKey]int64{}
			grains[queryType.String] = byGrain
		}
		byGrain[grainKey{blocked != 0, cached != 0, hasResult.Int64 != 0, responseMs.Int64}] += count
	}
	if err := rows.Err(); err != nil {
		return StatsScan{}, err
	}

	var window []WindowMetricsRow
	for queryType, byGrain := range grains {
		for key, count := range byGrain {
			window = append(window, WindowMetricsRow{
				Blocked: key.blocked, Cached: key.cached, HasResult: key.hasResult,
				QueryType: queryType, ResponseMs: key.responseMs, Count: count,
			})
		}
	}
	return StatsScan{Metrics: metricsFromWindow(window), Series: seriesFromQuarters(quarters)}, nil
}

// metricsByBucketSince counts queries by time bucket, folded out of
// query_stats_quarter. When bucket and offset are whole quarters, each
// quarter lies inside one bucket (the API rounds tz_offset to a quarter hour
// for this); the partial first quarter comes from the table. Anything finer
// counts the table directly.
func (d *DB) metricsByBucketSince(ctx context.Context, since, bucketSecs, tzOffsetSecs int64) ([]MetricsBucket, error) {
	sinceMs, bucketMs, offsetMs := since*1000, bucketSecs*1000, tzOffsetSecs*1000
	var rows *sql.Rows
	var err error
	if bucketMs%rollupQuarterMs == 0 && offsetMs%rollupQuarterMs == 0 {
		rows, err = d.reader.QueryContext(ctx,
			`SELECT bucket, blocked, cached, SUM(n) FROM (
                            SELECT ((quarter * 900000 + ?3) / ?1) * ?1 - ?3 AS bucket,
                                   blocked, cached, count AS n
                                FROM query_stats_quarter WHERE quarter >= ?4
                            UNION ALL
                            SELECT ((timestamp + ?3) / ?1) * ?1 - ?3, blocked, cached, 1
                                FROM query_logs INDEXED BY idx_query_logs_timestamp
                                WHERE timestamp >= ?2 AND timestamp < ?4 * 900000
                        ) GROUP BY bucket, blocked, cached ORDER BY bucket`,
			bucketMs, sinceMs, offsetMs, firstWholeUnit(sinceMs, rollupQuarterMs))
	} else {
		rows, err = d.reader.QueryContext(ctx,
			`SELECT ((timestamp + ?3) / ?1) * ?1 - ?3 AS bucket, `+
				`blocked, cached, COUNT(*) `+
				`FROM query_logs `+
				`WHERE timestamp >= ?2 `+
				`GROUP BY bucket, blocked, cached `+
				`ORDER BY bucket`,
			bucketMs, sinceMs, offsetMs)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []MetricsBucket
	for rows.Next() {
		var bucketStart, blocked, cached, count int64
		if err := rows.Scan(&bucketStart, &blocked, &cached, &count); err != nil {
			return nil, err
		}
		out = append(out, MetricsBucket{Timestamp: bucketStart / 1000, Blocked: blocked != 0, Cached: cached != 0, Count: count})
	}
	return out, rows.Err()
}

// metricsWindowSince counts queries by outcome class, type and response time,
// from query_stats_metrics_hour plus the table for the partial first hour.
func (d *DB) metricsWindowSince(ctx context.Context, since int64) ([]WindowMetricsRow, error) {
	sinceMs := since * 1000
	rows, err := d.reader.QueryContext(ctx,
		`SELECT blocked, cached, has_result, query_type, response_ms, SUM(n) FROM (
                        SELECT blocked, cached, has_result, query_type, response_ms, count AS n
                            FROM query_stats_metrics_hour WHERE hour >= ?2
                        UNION ALL
                        SELECT blocked, cached, has_result, query_type, response_ms, 1
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?1 AND timestamp < ?2 * 3600000
                    ) GROUP BY blocked, cached, has_result, query_type, response_ms`,
		sinceMs, firstWholeUnit(sinceMs, rollupHourMs))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []WindowMetricsRow
	for rows.Next() {
		var row WindowMetricsRow
		var blocked, cached, hasResult int64
		if err := rows.Scan(&blocked, &cached, &hasResult, &row.QueryType, &row.ResponseMs, &row.Count); err != nil {
			return nil, err
		}
		row.Blocked, row.Cached, row.HasResult = blocked != 0, cached != 0, hasResult != 0
		out = append(out, row)
	}
	return out, rows.Err()
}

// HourlyHeatmapSince counts queries by weekday and hour in the viewer's
// calendar via tzOffsetSecs (east-positive; 0 for UTC), with the same DST
// caveat as TimelineMultiSince. A whole-quarter offset (every zone in use,
// every offset the API passes) folds query_stats_quarter plus the table for
// the partial first quarter; any other offset counts the table directly.
func (d *DB) HourlyHeatmapSince(ctx context.Context, since, tzOffsetSecs int64) ([]HeatmapCell, error) {
	sinceMs := since * 1000
	var rows *sql.Rows
	var err error
	// Integer arithmetic rather than strftime, which formats two strings per
	// row. "+ 4": 1970-01-01 was a Thursday and strftime('%w') counts from
	// Sunday = 0. Truncating division equals flooring here since shifted
	// seconds are non-negative.
	if tzOffsetSecs%QuarterSecs == 0 {
		rows, err = d.reader.QueryContext(ctx,
			`SELECT (s / 86400 + 4) % 7 AS wday, s % 86400 / 3600 AS hr, SUM(n) FROM (
                            SELECT quarter * 900 + ?2 AS s, count AS n
                                FROM query_stats_quarter WHERE quarter >= ?3
                            UNION ALL
                            SELECT timestamp / 1000 + ?2, 1
                                FROM query_logs INDEXED BY idx_query_logs_timestamp
                                WHERE timestamp >= ?1 AND timestamp < ?3 * 900000
                        ) GROUP BY wday, hr ORDER BY wday, hr`,
			sinceMs, tzOffsetSecs, firstWholeUnit(sinceMs, rollupQuarterMs))
	} else {
		// Reads only timestamp; otherwise the planner picks a wider index.
		rows, err = d.reader.QueryContext(ctx,
			`SELECT ((timestamp / 1000 + ?2) / 86400 + 4) % 7 AS wday, `+
				`(timestamp / 1000 + ?2) % 86400 / 3600 AS hr, `+
				`COUNT(*) `+
				`FROM query_logs INDEXED BY idx_query_logs_timestamp `+
				`WHERE timestamp >= ?1 `+
				`GROUP BY wday, hr `+
				`ORDER BY wday, hr`,
			sinceMs, tzOffsetSecs)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []HeatmapCell
	for rows.Next() {
		var cell HeatmapCell
		if err := rows.Scan(&cell.Weekday, &cell.Hour, &cell.Count); err != nil {
			return nil, err
		}
		out = append(out, cell)
	}
	return out, rows.Err()
}

// QueryTypeBreakdownSince counts queries per type, busiest first.
func (d *DB) QueryTypeBreakdownSince(ctx context.Context, since int64) ([]NameCount, error) {
	rows, err := d.metricsWindowSince(ctx, since)
	return queryTypesFromWindow(rows), err
}

// OutcomeBreakdownSince counts queries per outcome, busiest first.
func (d *DB) OutcomeBreakdownSince(ctx context.Context, since int64) ([]NameCount, error) {
	rows, err := d.metricsWindowSince(ctx, since)
	return outcomesFromWindow(rows), err
}

// UniqueDomainsSince counts the distinct domains in the window.
func (d *DB) UniqueDomainsSince(ctx context.Context, since int64) (int64, error) {
	stats, err := d.DomainStatsSince(ctx, since, 1)
	return stats.Unique, err
}

// LatencySummarySince returns percentiles over response_ms, derived from the
// metrics histogram: exact, since response_ms is integer milliseconds, and
// no sort of every row.
func (d *DB) LatencySummarySince(ctx context.Context, since int64) (LatencySummary, error) {
	rows, err := d.metricsWindowSince(ctx, since)
	return latencyFromWindow(rows), err
}

// DBStorageStats reads the Database Health card from PRAGMAs (no filesystem
// stat, so in-memory databases work too).
func (d *DB) DBStorageStats(ctx context.Context) (StorageStats, error) {
	var pageCount, pageSize, freelist int64
	if err := d.reader.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return StorageStats{}, err
	}
	if err := d.reader.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil {
		return StorageStats{}, err
	}
	if err := d.reader.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freelist); err != nil {
		return StorageStats{}, err
	}
	return StorageStats{MainBytes: pageCount * pageSize, ReclaimableBytes: freelist * pageSize}, nil
}

// TotalLogCount returns the maintained query_logs row count rather than a
// COUNT(*), which walks a whole index. With no counter row, it counts.
func (d *DB) TotalLogCount(ctx context.Context) (int64, error) {
	return readLogCount(ctx, d.reader)
}

// TimelineSince buckets queries into a total/blocked timeline on UTC-epoch
// boundaries. It takes and returns Unix seconds; milliseconds exist only
// inside the query.
func (d *DB) TimelineSince(ctx context.Context, since, bucketSecs int64) ([]TimelinePoint, error) {
	sinceMs, bucketMs := since*1000, bucketSecs*1000
	var rows *sql.Rows
	var err error
	// Whole-quarter buckets fold the rollup. Finer buckets only occur while
	// the log is a few hours old, so counting the table directly is cheap.
	if bucketMs%rollupQuarterMs == 0 {
		rows, err = d.reader.QueryContext(ctx,
			`SELECT bucket, SUM(total), SUM(blocked) FROM (
                            SELECT (quarter * 900000 / ?1) * ?1 AS bucket,
                                   count AS total, blocked * count AS blocked
                                FROM query_stats_quarter WHERE quarter >= ?3
                            UNION ALL
                            SELECT (timestamp / ?1) * ?1, 1, blocked
                                FROM query_logs INDEXED BY idx_query_logs_timestamp
                                WHERE timestamp >= ?2 AND timestamp < ?3 * 900000
                        ) GROUP BY bucket ORDER BY bucket`,
			bucketMs, sinceMs, firstWholeUnit(sinceMs, rollupQuarterMs))
	} else {
		rows, err = d.reader.QueryContext(ctx,
			`SELECT (timestamp / ?1) * ?1 as bucket, COUNT(*) as total, `+
				`COALESCE(SUM(blocked), 0) as blocked FROM query_logs `+
				`WHERE timestamp >= ?2 GROUP BY bucket ORDER BY bucket`,
			bucketMs, sinceMs)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []TimelinePoint
	for rows.Next() {
		var point TimelinePoint
		if err := rows.Scan(&point.Timestamp, &point.Total, &point.Blocked); err != nil {
			return nil, err
		}
		point.Timestamp /= 1000
		out = append(out, point)
	}
	return out, rows.Err()
}
