package server

import (
	"maps"
	"math"
	"net/http"
	"slices"
	"strings"

	"github.com/henry40408/noadd/internal/upstream"
)

type filterCheckRequest struct {
	Domain *string `json:"domain"`
}

// filterCheck handles POST /api/filter/check: what the live engine decides for
// a domain, without querying DNS.
func (a *api) filterCheck(w http.ResponseWriter, r *http.Request, _ authedUser) {
	var body filterCheckRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Domain == nil {
		missingField(w, "domain")
		return
	}
	domain := strings.TrimRight(strings.TrimSpace(*body.Domain), ".")
	verdict := a.Filter.Load().Check(domain)
	if verdict.Blocked {
		writeJSON(w, http.StatusOK, map[string]any{"action": "blocked", "rule": verdict.Rule, "list": verdict.List})
		return
	}
	response := map[string]any{"action": "allowed"}
	if verdict.Rule != "" {
		response["rule"] = verdict.Rule
	}
	writeJSON(w, http.StatusOK, response)
}

type upstreamHealthEntry struct {
	Server    string `json:"server"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
}

// upstreamHealth handles GET /api/upstream/health.
func (a *api) upstreamHealth(w http.ResponseWriter, r *http.Request, _ authedUser) {
	results := a.Forwarder.HealthCheck(r.Context())
	response := make([]upstreamHealthEntry, 0, len(results))
	for _, result := range results {
		response = append(response, upstreamHealthEntry{Server: result.Server, OK: result.OK, LatencyMS: result.LatencyMS})
	}
	writeJSON(w, http.StatusOK, response)
}

type upstreamLatencyEntry struct {
	Server    string  `json:"server"`
	EMAMS     float64 `json:"ema_ms"`
	Preferred bool    `json:"preferred"`
}

// upstreamLatency handles GET /api/upstream/latency. Servers are sorted by
// label so the answer, and the preferred pick on a tie, is stable.
func (a *api) upstreamLatency(w http.ResponseWriter, _ *http.Request, _ authedUser) {
	latencies := a.Forwarder.Latencies()
	servers := slices.Sorted(maps.Keys(latencies))

	preferred := ""
	if a.Forwarder.Strategy() == upstream.LowestLatency {
		best := math.Inf(1)
		for _, server := range servers {
			if latencies[server] < best {
				best, preferred = latencies[server], server
			}
		}
	}
	response := make([]upstreamLatencyEntry, 0, len(servers))
	for _, server := range servers {
		response = append(response, upstreamLatencyEntry{
			Server:    server,
			EMAMS:     math.Round(latencies[server]*10) / 10,
			Preferred: preferred != "" && server == preferred,
		})
	}
	writeJSON(w, http.StatusOK, response)
}
