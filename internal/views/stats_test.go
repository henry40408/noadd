package views

import (
	"strings"
	"testing"
)

const dataSeriesJSON = `{"start":1794928500,"total":[200],"blocked":[80],"cached":[111],"heatmap":[200]}`

func statsShell() ShellData {
	return ShellData{Version: goldenVersion, Host: "127.0.0.1:19080", CurrentPath: "/stats"}
}

func statsRanges(active string) []RangeOption {
	var options []RangeOption
	for _, label := range []string{"7d", "30d", "90d"} {
		options = append(options, RangeOption{Label: label, Active: label == active})
	}
	return options
}

func dataStats(rangeLabel string, bucketSecs int64) StatsPage {
	return StatsPage{
		Shell: statsShell(), Range: rangeLabel, Ranges: statsRanges(rangeLabel),
		SeriesJSON: dataSeriesJSON, BucketSecs: bucketSecs,
		Highlights: []StatCard{
			{Label: "Unique Domains", Value: "12", ValueClass: "accent", Title: "12"},
			{Label: "Latency p50", Value: "1", ValueClass: "text-green", Unit: "ms"},
			{Label: "Latency p95", Value: "1", ValueClass: "text-orange", Unit: "ms"},
			{Label: "Latency p99", Value: "1", ValueClass: "text-red", Unit: "ms"},
		},
		QueryTypes: []BarRow{
			{Label: "A", Width: "100.0", CountTitle: "145 (72.5%)", Count: "145", Share: "72.5%"},
			{Label: "AAAA", Width: "28.3", CountTitle: "41 (20.5%)", Count: "41", Share: "20.5%"},
			{Label: "MX", Width: "9.7", CountTitle: "14 (7.0%)", Count: "14", Share: "7.0%"},
		},
		Outcomes: []BarRow{
			{Label: "Cached", Width: "100.0", CountTitle: "111 (55.5%)", Count: "111", Share: "55.5%"},
			{Label: "Blocked", Width: "72.1", CountTitle: "80 (40.0%)", Count: "80", Share: "40.0%"},
			{Label: "Resolved", Width: "6.3", CountTitle: "7 (3.5%)", Count: "7", Share: "3.5%"},
			{Label: "Empty", Width: "1.8", CountTitle: "2 (1.0%)", Count: "2", Share: "1.0%"},
		},
		TopDomains: topDomainBars(),
		TopClients: []BarRow{
			{Label: "192.168.215.1", Width: "100.0", CountTitle: "100 (50.0%)", Count: "100", Share: "50.0%"},
			{Label: "192.168.215.1 · alpha-token", Width: "50.0", CountTitle: "50 (25.0%)", Count: "50", Share: "25.0%"},
			{Label: "192.168.215.1 · beta-token", Width: "50.0", CountTitle: "50 (25.0%)", Count: "50", Share: "25.0%"},
		},
		Health: []StatCard{
			{Label: "Database Size", Value: "152.0 KB", ValueClass: "accent"},
			{Label: "Total Logs", Value: "200", ValueClass: "accent", Title: "200"},
			{Label: "Bytes / Log", Value: "778 B", ValueClass: "accent"},
			{Label: "Reclaimable", Value: "0 B", ValueClass: "accent", Sub: "0% of file"},
			{Label: "Oldest Log", Value: "2026-11-17", ValueClass: "stat-date", TS: 1794928500},
			{Label: "Log Coverage", Value: "0.0d", ValueClass: "accent"},
			{Label: "Retention", Value: "30d", ValueClass: "accent"},
			{Label: "Avg / Day", Value: "200", ValueClass: "accent"},
			{Label: "Growth / Day", Value: "152.0 KB", ValueClass: "accent"},
			{Label: "Projected Full", Value: "4.45 MB", ValueClass: "accent", Sub: "at full retention"},
		},
	}
}

func topDomainBars() []BarRow {
	rows := []BarRow{
		{Label: "allowed.example.com", Width: "100.0", CountTitle: "42 (24.1%)", Count: "42", Share: "24.1%"},
		{Label: "ads.example.com", Width: "66.7", CountTitle: "28 (16.1%)", Count: "28", Share: "16.1%"},
	}
	for _, label := range []string{
		"ads.list-one.test", "adserver.list-two.test", "cname.example.com", "dnssec.example.com",
		"nodata.example.com", "nxd.example.com", "ok.ads.example.com", "ok.list-two.test",
	} {
		rows = append(rows, BarRow{Label: label, Width: "31.0", CountTitle: "13 (7.5%)", Count: "13", Share: "7.5%"})
	}
	return rows
}

func TestStatsMatchesGoldens(t *testing.T) {
	empty := StatsPage{
		Shell: statsShell(), Range: "7d", Ranges: statsRanges("7d"),
		SeriesJSON: `{"start":0,"total":[],"blocked":[],"cached":[],"heatmap":[]}`, BucketSecs: 3600,
	}
	assertGolden(t, "stats_data", Stats(dataStats("7d", 3600)))
	assertGolden(t, "stats_30d", Stats(dataStats("30d", 21600)))
	empty.Highlights = []StatCard{
		{Label: "Unique Domains", Value: "0", ValueClass: "accent", Title: "0"},
		{Label: "Latency p50", Value: "—", ValueClass: "text-green"},
		{Label: "Latency p95", Value: "—", ValueClass: "text-orange"},
		{Label: "Latency p99", Value: "—", ValueClass: "text-red"},
	}
	empty.Health = []StatCard{
		{Label: "Database Size", Value: "140.0 KB", ValueClass: "accent"},
		{Label: "Total Logs", Value: "0", ValueClass: "accent", Title: "0"},
		{Label: "Bytes / Log", Value: "—", ValueClass: "accent"},
		{Label: "Reclaimable", Value: "12.0 KB", ValueClass: "accent", Sub: "9% of file"},
		{Label: "Oldest Log", Value: "—", ValueClass: "stat-date"},
		{Label: "Log Coverage", Value: "—", ValueClass: "accent"},
		{Label: "Retention", Value: "7d", ValueClass: "accent"},
		{Label: "Avg / Day", Value: "—", ValueClass: "accent"},
		{Label: "Growth / Day", Value: "—", ValueClass: "accent"},
		{Label: "Projected Full", Value: "—", ValueClass: "accent", Sub: "at full retention"},
	}
	empty.Shell.ShowNextStep, empty.Shell.NextStepAddr = true, "127.0.0.1:53"
	assertGolden(t, "stats_empty", Stats(empty))
}

// 待 Opus 審查: XSS. series_json lands in an attribute and every label in text
// and title attributes.
func TestStatsEscapesEveryString(t *testing.T) {
	const payload = `"><script>alert(1)</script>`
	page := dataStats("7d", 3600)
	page.SeriesJSON = payload
	page.TopDomains = []BarRow{{Label: payload, Width: "1", CountTitle: payload, Count: payload, Share: payload}}
	page.Health = []StatCard{{Label: payload, Value: payload, ValueClass: "accent", Title: payload, Sub: payload, Unit: payload}}
	if strings.Contains(Stats(page), "<script>alert") {
		t.Fatal("unescaped payload in stats output")
	}
}
