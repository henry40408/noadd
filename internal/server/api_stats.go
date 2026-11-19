package server

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/henry40408/noadd/internal/stats"
)

const (
	defaultTimelineHours = 24
	defaultTopLimit      = 20
	defaultTopUpstreams  = 10
	defaultRangedTop     = 15
	// maxTZOffsetMinutes is the largest UTC offset in use, 14 hours.
	maxTZOffsetMinutes = 14 * 60
	// tzOffsetGrainMinutes is the grain of the quarter-hour rollup the charts
	// fold; no zone in use is affected by the rounding.
	tzOffsetGrainMinutes = 15
)

// strictQuery is newQueryParams for the stats/v2 routes: a key outside allowed
// is a 400, as serde's deny_unknown_fields answers. Keys are checked in the
// order they appear, before any value is parsed.
func strictQuery(r *http.Request, allowed ...string) *queryParams {
	params := newQueryParams(r)
	for _, pair := range strings.Split(r.URL.RawQuery, "&") {
		rawKey, _, _ := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(rawKey)
		if rawKey == "" || err != nil || slices.Contains(allowed, key) {
			continue
		}
		params.fail(key, "unknown field `"+key+"`, "+expectedFields(allowed))
		break
	}
	return params
}

// expectedFields words the field list the way serde does.
func expectedFields(allowed []string) string {
	quoted := make([]string, len(allowed))
	for i, name := range allowed {
		quoted[i] = "`" + name + "`"
	}
	switch len(quoted) {
	case 1:
		return "expected " + quoted[0]
	case 2:
		return "expected " + quoted[0] + " or " + quoted[1]
	}
	return "expected one of " + strings.Join(quoted, ", ")
}

// tzOffsetSeconds resolves the viewer's east-positive UTC offset in minutes to
// seconds, clamped to 14 hours either way and rounded to a quarter hour.
func tzOffsetSeconds(minutes *int64) int64 {
	clamped := min(max(valueOr(minutes, 0), -maxTZOffsetMinutes), maxTZOffsetMinutes)
	half := int64(tzOffsetGrainMinutes / 2)
	return floorDiv(clamped+half, tzOffsetGrainMinutes) * tzOffsetGrainMinutes * 60
}

// floorDiv is Rust's div_euclid for a positive divisor.
func floorDiv(value, divisor int64) int64 {
	quotient := value / divisor
	if value%divisor < 0 {
		quotient--
	}
	return quotient
}

// statsRange reads the range parameter, 7d when absent. It answers 400 with an
// empty body for anything else, and reports whether the request may go on.
func statsRange(w http.ResponseWriter, raw *string) (stats.Range, bool) {
	spelled := "7d"
	if raw != nil {
		spelled = *raw
	}
	parsed, ok := stats.ParseRange(spelled)
	if !ok {
		writeStatus(w, http.StatusBadRequest)
	}
	return parsed, ok
}

// serveStats answers with the reading as JSON, or 500 when it failed.
func serveStats[T any](w http.ResponseWriter, value T, err error) {
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

// serveStatsList is serveStats for a list, which must never serialise as null.
func serveStatsList[T any](w http.ResponseWriter, items []T, err error) {
	serveStats(w, nonNil(items), err)
}

func (a *api) getStatsSummary(w http.ResponseWriter, r *http.Request, _ authedUser) {
	summary, err := stats.ComputeSummary(r.Context(), a.DB, a.Now().Unix())
	serveStats(w, summary, err)
}

func (a *api) getStatsTimeline(w http.ResponseWriter, r *http.Request, _ authedUser) {
	params := newQueryParams(r)
	hours := params.optionalInt("hours")
	if params.reject(w) {
		return
	}
	timeline, err := stats.ComputeTimeline(r.Context(), a.DB, a.Now().Unix(), valueOr(hours, defaultTimelineHours))
	serveStatsList(w, timeline, err)
}

// authedHandler is a handler that already has its operator.
type authedHandler = func(http.ResponseWriter, *http.Request, authedUser)

// limitParam reads ?limit= for the top-N routes; ok is false after a 400.
func limitParam(w http.ResponseWriter, r *http.Request, fallback int64) (limit int64, ok bool) {
	params := newQueryParams(r)
	value := params.optionalInt("limit")
	if params.reject(w) {
		return 0, false
	}
	return valueOr(value, fallback), true
}

// rangedTopParams reads ?range= and ?limit= for the stats/v2 top-N routes; ok
// is false after a 400.
func rangedTopParams(w http.ResponseWriter, r *http.Request) (rng stats.Range, limit int64, ok bool) {
	params := strictQuery(r, "range", "limit")
	rawRange, rawLimit := params.optionalString("range"), params.optionalInt("limit")
	if params.reject(w) {
		return 0, 0, false
	}
	rng, ok = statsRange(w, rawRange)
	return rng, valueOr(rawLimit, defaultRangedTop), ok
}

func (a *api) getStatsTopDomains(w http.ResponseWriter, r *http.Request, _ authedUser) {
	limit, ok := limitParam(w, r, defaultTopLimit)
	if !ok {
		return
	}
	domains, err := stats.ComputeTopDomains(r.Context(), a.DB, a.Now().Unix(), limit)
	serveStatsList(w, domains, err)
}

func (a *api) getStatsTopClients(w http.ResponseWriter, r *http.Request, _ authedUser) {
	limit, ok := limitParam(w, r, defaultTopLimit)
	if !ok {
		return
	}
	clients, err := stats.ComputeTopClients(r.Context(), a.DB, a.Now().Unix(), limit)
	serveStatsList(w, clients, err)
}

func (a *api) getStatsTopUpstreams(w http.ResponseWriter, r *http.Request, _ authedUser) {
	limit, ok := limitParam(w, r, defaultTopUpstreams)
	if !ok {
		return
	}
	upstreams, err := stats.ComputeTopUpstreams(r.Context(), a.DB, a.Now().Unix(), limit)
	serveStatsList(w, upstreams, err)
}

// rangedStats runs the stats/v2 routes that take only ?range=.
func rangedStats[T any](a *api, read func(ctx context.Context, now int64, rng stats.Range) (T, error)) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, _ authedUser) {
		params := strictQuery(r, "range")
		raw := params.optionalString("range")
		if params.reject(w) {
			return
		}
		rng, ok := statsRange(w, raw)
		if !ok {
			return
		}
		value, err := read(r.Context(), a.Now().Unix(), rng)
		serveStats(w, value, err)
	}
}

func (a *api) getStatsV2Timeline(w http.ResponseWriter, r *http.Request, _ authedUser) {
	params := strictQuery(r, "range", "tz_offset")
	raw, offset := params.optionalString("range"), params.optionalInt("tz_offset")
	if params.reject(w) {
		return
	}
	rng, ok := statsRange(w, raw)
	if !ok {
		return
	}
	timeline, err := stats.ComputeStatsTimeline(r.Context(), a.DB, a.Now().Unix(), rng, tzOffsetSeconds(offset))
	serveStatsList(w, timeline, err)
}

func (a *api) getStatsV2Heatmap(w http.ResponseWriter, r *http.Request, _ authedUser) {
	params := strictQuery(r, "tz_offset")
	offset := params.optionalInt("tz_offset")
	if params.reject(w) {
		return
	}
	cells, err := stats.ComputeHeatmap(r.Context(), a.DB, a.Now().Unix(), tzOffsetSeconds(offset))
	serveStatsList(w, cells, err)
}

func (a *api) getStatsV2Health(w http.ResponseWriter, r *http.Request, _ authedUser) {
	health, err := stats.ComputeDBHealth(r.Context(), a.DB, a.Now().Unix())
	serveStats(w, health, err)
}

func (a *api) getStatsV2TopDomains(w http.ResponseWriter, r *http.Request, _ authedUser) {
	rng, limit, ok := rangedTopParams(w, r)
	if !ok {
		return
	}
	domains, err := stats.ComputeTopDomainsRanged(r.Context(), a.DB, a.Now().Unix(), rng, limit)
	serveStatsList(w, domains, err)
}

func (a *api) getStatsV2TopClients(w http.ResponseWriter, r *http.Request, _ authedUser) {
	rng, limit, ok := rangedTopParams(w, r)
	if !ok {
		return
	}
	clients, err := stats.ComputeTopClientsRanged(r.Context(), a.DB, a.Now().Unix(), rng, limit)
	serveStatsList(w, clients, err)
}

// registerStatsRoutes adds /api/stats/* and /api/stats/v2/*.
func (a *api) registerStatsRoutes(t *routeTable) {
	const get = http.MethodGet
	t.handleFunc(get, "/api/stats/summary", a.authed(a.getStatsSummary))
	t.handleFunc(get, "/api/stats/timeline", a.authed(a.getStatsTimeline))
	t.handleFunc(get, "/api/stats/top-domains", a.authed(a.getStatsTopDomains))
	t.handleFunc(get, "/api/stats/top-clients", a.authed(a.getStatsTopClients))
	t.handleFunc(get, "/api/stats/top-upstreams", a.authed(a.getStatsTopUpstreams))

	t.handleFunc(get, "/api/stats/v2/timeline", a.authed(a.getStatsV2Timeline))
	t.handleFunc(get, "/api/stats/v2/heatmap", a.authed(a.getStatsV2Heatmap))
	t.handleFunc(get, "/api/stats/v2/breakdown", a.authed(rangedStats(a,
		func(ctx context.Context, now int64, rng stats.Range) (stats.Breakdowns, error) {
			return stats.ComputeBreakdowns(ctx, a.DB, now, rng)
		})))
	t.handleFunc(get, "/api/stats/v2/health", a.authed(a.getStatsV2Health))
	t.handleFunc(get, "/api/stats/v2/highlights", a.authed(rangedStats(a,
		func(ctx context.Context, now int64, rng stats.Range) (stats.Highlights, error) {
			return stats.ComputeHighlights(ctx, a.DB, now, rng)
		})))
	t.handleFunc(get, "/api/stats/v2/top-domains", a.authed(a.getStatsV2TopDomains))
	t.handleFunc(get, "/api/stats/v2/top-clients", a.authed(a.getStatsV2TopClients))
}
