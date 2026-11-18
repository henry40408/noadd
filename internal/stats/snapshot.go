package stats

import (
	"context"

	"github.com/henry40408/noadd/internal/db"
)

const (
	// snapshotTopN is how many rows each dashboard table shows.
	snapshotTopN = 10
	// snapshotTimelineHours is the history behind the dashboard chart.
	snapshotTimelineHours = 24
)

// DashboardSnapshot is everything the dashboard draws, in one payload. Each
// field has the shape of the matching /api/stats/* response.
type DashboardSnapshot struct {
	Summary      Summary            `json:"summary"`
	Timeline     []db.TimelinePoint `json:"timeline"`
	TopDomains   []db.TopDomain     `json:"top_domains"`
	TopClients   []db.TopClient     `json:"top_clients"`
	TopUpstreams []db.TopUpstream   `json:"top_upstreams"`
}

// ComputeSnapshot reads everything the dashboard shows.
func ComputeSnapshot(ctx context.Context, database *db.DB, now int64) (*DashboardSnapshot, error) {
	summary, err := ComputeSummary(ctx, database, now)
	if err != nil {
		return nil, err
	}
	timeline, err := ComputeTimeline(ctx, database, now, snapshotTimelineHours)
	if err != nil {
		return nil, err
	}
	domains, clients, err := ComputeTopDomainsAndClients(ctx, database, now, snapshotTopN)
	if err != nil {
		return nil, err
	}
	upstreams, err := ComputeTopUpstreams(ctx, database, now, snapshotTopN)
	if err != nil {
		return nil, err
	}
	return &DashboardSnapshot{
		Summary:      summary,
		Timeline:     orEmpty(timeline),
		TopDomains:   orEmpty(domains),
		TopClients:   orEmpty(clients),
		TopUpstreams: orEmpty(upstreams),
	}, nil
}

// orEmpty keeps a nil slice from serialising as null.
func orEmpty[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}
