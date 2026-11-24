package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/db"
)

func (h *apiHarness) seedRecentLogs() {
	h.t.Helper()
	nowMs := time.Now().UnixMilli()
	var entries []db.QueryLogEntry
	for i := range 10 {
		entries = append(entries, db.QueryLogEntry{
			Timestamp: nowMs - int64(i)*1000, Domain: "ads.example.com", QueryType: "A",
			ClientIP: "10.0.0.1", Blocked: i%2 == 0, Cached: i%3 == 0, ResponseMs: 2,
		})
	}
	entries = append(entries, db.QueryLogEntry{
		Timestamp: nowMs, Domain: "ok.example.com", QueryType: "AAAA", ClientIP: "10.0.0.2",
		ResponseMs: 4, Upstream: ptr("1.1.1.1:53"),
	})
	h.seedLogs(entries...)
}

func TestStatsRoutesRequireAnOperator(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	paths := []string{
		"/api/stats/summary", "/api/stats/timeline", "/api/stats/top-domains",
		"/api/stats/top-clients", "/api/stats/top-upstreams", "/api/stats/v2/timeline",
		"/api/stats/v2/heatmap", "/api/stats/v2/breakdown", "/api/stats/v2/health",
		"/api/stats/v2/highlights", "/api/stats/v2/top-domains", "/api/stats/v2/top-clients",
		"/api/events", "/api/openapi.json", "/api/docs",
	}
	for _, path := range paths {
		wantStatus(t, h.do(request{method: "GET", path: path}), http.StatusUnauthorized)
		wantStatus(t, h.authed("POST", path, ""), http.StatusMethodNotAllowed)
	}
}

func TestEmptyStatsSerialiseAsEmptyArraysNotNull(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, path := range []string{
		"/api/stats/timeline", "/api/stats/top-domains", "/api/stats/top-clients",
		"/api/stats/top-upstreams", "/api/stats/v2/timeline", "/api/stats/v2/heatmap",
		"/api/stats/v2/top-domains", "/api/stats/v2/top-clients",
	} {
		recorder := h.authed("GET", path, "")
		wantStatus(t, recorder, http.StatusOK)
		if recorder.Body.String() != "[]" {
			t.Errorf("%s = %q, want []", path, recorder.Body.String())
		}
	}
	var summary map[string]float64
	decodeBody(t, h.authed("GET", "/api/stats/summary", ""), &summary)
	if len(summary) != 16 || summary["total_today"] != 0 || summary["queries_1m"] != 0 {
		t.Fatalf("summary = %v", summary)
	}
}

func TestStatsReadSeededTraffic(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedRecentLogs()

	var summary map[string]float64
	decodeBody(t, h.authed("GET", "/api/stats/summary", ""), &summary)
	if summary["total_today"] != 11 || summary["blocked_today"] != 5 || summary["total_30d"] != 11 {
		t.Fatalf("summary = %v", summary)
	}
	var domains []db.TopDomain
	decodeBody(t, h.authed("GET", "/api/stats/top-domains?limit=1", ""), &domains)
	if len(domains) != 1 || domains[0].Domain != "ads.example.com" || domains[0].Count != 10 {
		t.Fatalf("top domains = %+v", domains)
	}
	var upstreams []db.TopUpstream
	decodeBody(t, h.authed("GET", "/api/stats/top-upstreams", ""), &upstreams)
	if len(upstreams) != 1 || upstreams[0].Upstream != "1.1.1.1:53" {
		t.Fatalf("top upstreams = %+v", upstreams)
	}

	var breakdown struct {
		QueryTypes [][]any `json:"query_types"`
		Outcomes   [][]any `json:"outcomes"`
	}
	decodeBody(t, h.authed("GET", "/api/stats/v2/breakdown?range=30d", ""), &breakdown)
	if len(breakdown.QueryTypes) != 2 || breakdown.QueryTypes[0][0] != "A" || breakdown.QueryTypes[0][1] != 10.0 {
		t.Fatalf("breakdown = %+v", breakdown)
	}
	var highlights struct {
		UniqueDomains int64 `json:"unique_domains"`
	}
	decodeBody(t, h.authed("GET", "/api/stats/v2/highlights", ""), &highlights)
	if highlights.UniqueDomains != 2 {
		t.Fatalf("highlights = %+v", highlights)
	}
	var health struct {
		TotalLogCount    int64 `json:"total_log_count"`
		LogRetentionDays int64 `json:"log_retention_days"`
	}
	decodeBody(t, h.authed("GET", "/api/stats/v2/health", ""), &health)
	if health.TotalLogCount != 11 || health.LogRetentionDays != 7 {
		t.Fatalf("health = %+v", health)
	}
	var timeline []db.TimelineMultiPoint
	decodeBody(t, h.authed("GET", "/api/stats/v2/timeline?range=7d&tz_offset=480", ""), &timeline)
	var total int64
	for _, point := range timeline {
		total += point.Total
	}
	if total != 11 {
		t.Fatalf("timeline total = %d, want 11 (%+v)", total, timeline)
	}
}

func TestStatsV2RejectsUnknownKeysAndBadValues(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	unknown := h.authed("GET", "/api/stats/v2/timeline?bogus=1", "")
	assertMatchesGolden(t, unknown, loadGolden(t, "api_stats_v2_unknown_param"))

	cases := map[string]string{
		"/api/stats/v2/heatmap?range=7d":      "Failed to deserialize query string: range: unknown field `range`, expected `tz_offset`",
		"/api/stats/v2/breakdown?tz_offset=1": "Failed to deserialize query string: tz_offset: unknown field `tz_offset`, expected `range`",
		"/api/stats/v2/top-domains?x=1":       "Failed to deserialize query string: x: unknown field `x`, expected `range` or `limit`",
		"/api/stats/v2/timeline?tz_offset=a":  "Failed to deserialize query string: tz_offset: invalid digit found in string",
		"/api/stats/top-domains?limit=abc":    "Failed to deserialize query string: limit: invalid digit found in string",
	}
	for path, want := range cases {
		recorder := h.authed("GET", path, "")
		wantStatus(t, recorder, http.StatusBadRequest)
		if recorder.Body.String() != want {
			t.Errorf("%s body %q, want %q", path, recorder.Body.String(), want)
		}
	}
	// v1 routes and the health route ignore unknown keys, like their Rust Query structs.
	wantStatus(t, h.authed("GET", "/api/stats/summary?x=1", ""), http.StatusOK)
	wantStatus(t, h.authed("GET", "/api/stats/top-domains?x=1", ""), http.StatusOK)
	wantStatus(t, h.authed("GET", "/api/stats/v2/health?x=1", ""), http.StatusOK)

	badRange := h.authed("GET", "/api/stats/v2/breakdown?range=1y", "")
	assertMatchesGolden(t, badRange, loadGolden(t, "api_stats_v2_bad_range"))
}

func TestTZOffsetClampsThenRoundsToAQuarterHour(t *testing.T) {
	cases := []struct {
		minutes *int64
		want    int64
	}{
		{nil, 0}, {ptr(int64(480)), 28800}, {ptr(int64(7)), 0}, {ptr(int64(8)), 900},
		{ptr(int64(-7)), 0}, {ptr(int64(-8)), -900}, {ptr(int64(345)), 20700},
		{ptr(int64(1000)), 50400}, {ptr(int64(-1000)), -50400}, {ptr(int64(-570)), -34200},
	}
	for _, c := range cases {
		if got := tzOffsetSeconds(c.minutes); got != c.want {
			t.Errorf("tzOffsetSeconds(%v) = %d, want %d", c.minutes, got, c.want)
		}
	}
}

// openAPIRustDigest is the SHA-256 of the OpenAPI document the Rust server
// answered with, written as canonical JSON: sorted keys, no whitespace, no HTML
// escaping. It is never regenerated from Go output.
const openAPIRustDigest = "bfe6d507c2eb46e519820a5484f18479eeedbc2310b292e4234f365f20cf4d0c"

func canonicalJSONDigest(t *testing.T, document []byte) string {
	t.Helper()
	var value any
	if err := json.Unmarshal(document, &value); err != nil {
		t.Fatal(err)
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bytes.TrimSuffix(canonical.Bytes(), []byte("\n")))
	return hex.EncodeToString(digest[:])
}

func TestOpenAPIAndDocsMatchTheRustResponses(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	// The Rust document is compared as JSON, and the response byte for byte
	// against the embedded copy.
	spec := h.authed("GET", "/api/openapi.json", "")
	wantStatus(t, spec, http.StatusOK)
	if spec.Header().Get("Content-Type") != "application/json" || !bytes.Equal(spec.Body.Bytes(), openAPIJSON) {
		t.Error("openapi response differs from the embedded document")
	}
	if got := canonicalJSONDigest(t, spec.Body.Bytes()); got != openAPIRustDigest {
		t.Errorf("openapi document differs from the Rust document (digest %s)", got)
	}
	assertMatchesGolden(t, h.authed("GET", "/api/docs", ""), loadGolden(t, "api_docs"))
}

// Every operation the OpenAPI document advertises must be a registered route,
// so the spec cannot drift from the router.
func TestOpenAPIPathsAreRegisteredRoutes(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	table := newRouteTable()
	newAPI(h.deps, nil).registerAPIRoutes(table)

	var spec struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(openAPIJSON, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Paths) == 0 {
		t.Fatal("spec has no paths")
	}
	for path, operations := range spec.Paths {
		registered := table.byPath[path]
		for method := range operations {
			if _, ok := registered[strings.ToUpper(method)]; !ok {
				t.Errorf("spec documents %s %s but no such route is registered", method, path)
			}
		}
	}
	for _, core := range []string{"/api/health", "/api/rules", "/api/lists", "/api/filter/check", "/api/stats/summary", "/api/api-keys", "/api/logs"} {
		if !slices.Contains(mapKeys(spec.Paths), core) {
			t.Errorf("spec missing core path %s", core)
		}
	}
}

func mapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
