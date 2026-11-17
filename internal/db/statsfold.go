package db

import (
	"cmp"
	"slices"
	"strings"
)

// timelineFromBuckets sums each bucket's classifications back into one point
// per bucket. Input is ordered by bucket, so the output is too.
func timelineFromBuckets(buckets []MetricsBucket) []TimelineMultiPoint {
	var out []TimelineMultiPoint
	for _, bucket := range buckets {
		if len(out) == 0 || out[len(out)-1].Timestamp != bucket.Timestamp {
			out = append(out, TimelineMultiPoint{Timestamp: bucket.Timestamp})
		}
		point := &out[len(out)-1]
		point.Total += bucket.Count
		if bucket.Blocked {
			point.Blocked += bucket.Count
		}
		if bucket.Cached {
			point.Cached += bucket.Count
		}
	}
	return out
}

// seriesFromQuarters lays sparse quarter counts out densely: four integer
// arrays rather than an object per quarter.
func seriesFromQuarters(quarters map[int64]*quarterSlot) QuarterSeries {
	if len(quarters) == 0 {
		return QuarterSeries{}
	}
	first, last := int64(1<<63-1), int64(-1<<63)
	for quarter := range quarters {
		first, last = min(first, quarter), max(last, quarter)
	}
	length := last - first + 1
	series := QuarterSeries{
		Start:   first * QuarterSecs,
		Total:   make([]int64, length),
		Blocked: make([]int64, length),
		Cached:  make([]int64, length),
		Heatmap: make([]int64, length),
	}
	for quarter, counts := range quarters {
		i := quarter - first
		series.Total[i], series.Blocked[i], series.Cached[i], series.Heatmap[i] = counts[0], counts[1], counts[2], counts[3]
	}
	return series
}

// outcomesFromWindow totals each outcome across the window. Precedence
// (blocked, cached, answered) matches the query log's Verdict column, so no
// row counts twice.
func outcomesFromWindow(rows []WindowMetricsRow) []NameCount {
	var blocked, cached, resolved, empty int64
	for _, row := range rows {
		switch {
		case row.Blocked:
			blocked += row.Count
		case row.Cached:
			cached += row.Count
		case row.HasResult:
			resolved += row.Count
		default:
			empty += row.Count
		}
	}
	var out []NameCount
	for _, outcome := range []NameCount{{"Blocked", blocked}, {"Cached", cached}, {"Resolved", resolved}, {"Empty", empty}} {
		if outcome.Count > 0 {
			out = append(out, outcome)
		}
	}
	slices.SortStableFunc(out, func(a, b NameCount) int { return cmp.Compare(b.Count, a.Count) })
	return out
}

// queryTypesFromWindow counts per query type, busiest first. Rust leaves ties
// in hash order; Go breaks them by name so the output is deterministic.
func queryTypesFromWindow(rows []WindowMetricsRow) []NameCount {
	totals := map[string]int64{}
	for _, row := range rows {
		totals[row.QueryType] += row.Count
	}
	out := make([]NameCount, 0, len(totals))
	for name, count := range totals {
		out = append(out, NameCount{Name: name, Count: count})
	}
	slices.SortFunc(out, func(a, b NameCount) int {
		if a.Count != b.Count {
			return cmp.Compare(b.Count, a.Count)
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

type histogramBin struct{ responseMs, count int64 }

// latencyFromWindow collapses the window grain down to the ascending
// response_ms histogram the percentiles are read off.
func latencyFromWindow(rows []WindowMetricsRow) LatencySummary {
	byMs := map[int64]int64{}
	for _, row := range rows {
		byMs[row.ResponseMs] += row.Count
	}
	histogram := make([]histogramBin, 0, len(byMs))
	for ms, count := range byMs {
		histogram = append(histogram, histogramBin{ms, count})
	}
	slices.SortFunc(histogram, func(a, b histogramBin) int { return cmp.Compare(a.responseMs, b.responseMs) })
	return latencyFromHistogram(histogram)
}

// latencyFromHistogram derives a LatencySummary from an ascending
// (response_ms, count) histogram. p_k is the value at rank
// max(1, floor(total * k)).
func latencyFromHistogram(histogram []histogramBin) LatencySummary {
	var total int64
	for _, bin := range histogram {
		total += bin.count
	}
	if total == 0 {
		return LatencySummary{}
	}
	maxMs := histogram[len(histogram)-1].responseMs
	pick := func(fraction float64) int64 {
		// Truncation equals floor for non-negative inputs.
		target := max(int64(float64(total)*fraction), 1)
		var cumulative int64
		for _, bin := range histogram {
			cumulative += bin.count
			if cumulative >= target {
				return bin.responseMs
			}
		}
		return maxMs
	}
	return LatencySummary{SampleCount: total, P50Ms: pick(0.50), P95Ms: pick(0.95), P99Ms: pick(0.99)}
}
