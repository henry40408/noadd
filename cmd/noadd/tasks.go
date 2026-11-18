package main

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/dnsserver"
	"github.com/henry40408/noadd/internal/events"
	"github.com/henry40408/noadd/internal/filter"
	"github.com/henry40408/noadd/internal/stats"
	"github.com/henry40408/noadd/internal/upstream"
)

// The background jobs. Each returns when ctx ends and never reports an error:
// a failed cycle is logged and retried at the next tick, as in the Rust server.
const (
	logPruneInterval  = time.Hour
	listUpdateEvery   = 24 * time.Hour
	rateLimitInterval = 10 * time.Minute
	probeInterval     = time.Minute
	// rateLimitIdle is how long a rate-limit bucket may go unseen before it is
	// evicted.
	rateLimitIdle = 10 * time.Minute
)

// ticker runs work at every interval until ctx ends. The first run is one
// interval after the start, never immediately.
func ticker(ctx context.Context, interval time.Duration, work func()) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			work()
		}
	}
}

// pruneLogs drops query logs older than the retention setting, then runs
// database maintenance, every interval.
func pruneLogs(ctx context.Context, interval time.Duration, database *db.DB, logger *slog.Logger) {
	ticker(ctx, interval, func() { pruneLogsOnce(ctx, database, logger) })
}

func pruneLogsOnce(ctx context.Context, database *db.DB, logger *slog.Logger) {
	cutoff := time.Now().Unix() - retentionDays(ctx, database)*86400
	count, err := database.PruneLogsBefore(ctx, cutoff)
	if err != nil {
		logger.Warn("failed to prune logs; will retry next cycle", "event", "db.prune_failed", "error", err)
		return
	}
	if count > 0 {
		logger.Info("pruned old query logs", "event", "db.logs_pruned", "count", count)
	}
	if err := database.RunMaintenance(ctx); err != nil {
		logger.Warn("database maintenance failed; will retry next cycle", "event", "db.maintenance_failed", "error", err)
	}
}

// retentionDays reads log_retention_days, falling back to the default for an
// unset, unreadable or unparsable value.
func retentionDays(ctx context.Context, database *db.DB) int64 {
	value, found, err := database.GetSetting(ctx, "log_retention_days")
	if err != nil || !found {
		return stats.DefaultLogRetentionDays
	}
	days, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return stats.DefaultLogRetentionDays
	}
	return days
}

// updateLists refreshes the filter lists every interval and rebuilds the
// filter when something changed.
func updateLists(ctx context.Context, interval time.Duration, manager *filter.Manager, rebuild *filter.Coordinator, logger *slog.Logger) {
	ticker(ctx, interval, func() {
		// A failed refresh still rebuilds: it may have updated some lists.
		changed, err := manager.UpdateAllListsNoRebuild(ctx)
		if err != nil {
			logger.Warn("failed to update filter lists; keeping previous lists", "event", "filter.list_refresh_failed", "error", err)
			changed = true
		}
		if !changed && !rebuild.LastFailed() {
			logger.Debug("no list content changed; keeping the current filter", "event", "filter.rebuild_skipped")
			return
		}
		rebuild.SpawnCoalesced(func() error { return manager.Rebuild(ctx) })
	})
}

// pruneTargets are the limiters whose idle buckets are evicted.
type pruneTargets struct {
	dns            *dnsserver.Limiter
	login          *auth.Limiter
	invalidSession *auth.Limiter
	setupToken     *auth.SetupToken
}

// pruneRateLimits evicts buckets unseen for rateLimitIdle, so roaming clients
// and scanners cannot grow the maps without bound.
func pruneRateLimits(ctx context.Context, interval time.Duration, targets pruneTargets, logger *slog.Logger) {
	ticker(ctx, interval, func() {
		for scope, removed := range map[string]int{
			"dns":             targets.dns.Prune(rateLimitIdle, time.Now()),
			"setup":           targets.setupToken.PruneAttempts(),
			"login":           targets.login.Prune(),
			"invalid_session": targets.invalidSession.Prune(),
		} {
			if removed > 0 {
				logger.Debug("pruned inactive rate-limit buckets", "event", "ratelimit.buckets_pruned", "scope", scope, "removed", removed)
			}
		}
	})
}

// probeUpstreams measures upstream latency every interval, only under the
// lowest-latency strategy, which is the one that uses the numbers.
func probeUpstreams(ctx context.Context, interval time.Duration, forwarder *upstream.Forwarder, logger *slog.Logger) {
	ticker(ctx, interval, func() {
		if forwarder.Strategy() != upstream.LowestLatency {
			return
		}
		forwarder.ProbeAll(ctx)
		logger.Debug("upstream latency probe complete", "event", "upstream.probe_completed")
	})
}

// dashboardSource is what the events hub reads on every tick.
func dashboardSource(database *db.DB) events.Source {
	return events.Source{
		HasAnyQueryLogs: database.HasAnyQueryLogs,
		// The hub's clock is in milliseconds; ComputeSnapshot takes seconds. A
		// millisecond value reads as a date far in the future, so every window
		// is empty and the dashboard blanks out on the first tick.
		Snapshot: func(ctx context.Context, nowMs int64) (any, error) {
			snapshot, err := stats.ComputeSnapshot(ctx, database, nowMs/1000)
			if err != nil {
				return nil, err
			}
			return snapshot, nil
		},
	}
}
