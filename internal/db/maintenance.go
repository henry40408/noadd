package db

import (
	"context"
	"database/sql"
)

// vacuumFreelistRatio is the free-page fraction at which RunMaintenance runs
// a full VACUUM; below it the whole-file rewrite and write lock are not worth
// it.
const vacuumFreelistRatio = 0.2

const (
	rollupQuarterMs int64 = QuarterSecs * 1000
	rollupHourMs    int64 = 3_600_000
)

// PruneLogsBefore deletes log rows older than timestamp (Unix seconds) and
// unwinds the rollups in the same transaction. It returns the rows deleted.
func (d *DB) PruneLogsBefore(ctx context.Context, timestamp int64) (int64, error) {
	timestampMs := timestamp * 1000
	var deleted int64
	err := d.inWriteTx(ctx, func(tx *sql.Tx) error {
		if err := unwindStatsRollups(ctx, tx, timestampMs); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, "DELETE FROM query_logs WHERE timestamp < ?1", timestampMs)
		if err != nil {
			return err
		}
		deleted = rowsAffected(result)
		return bumpLogCount(ctx, tx, -deleted)
	})
	return deleted, err
}

// RunMaintenance runs after the hourly retention prune: PRAGMA optimize, a
// VACUUM only past vacuumFreelistRatio, and a truncating WAL checkpoint.
func (d *DB) RunMaintenance(ctx context.Context) error {
	if _, err := d.writer.ExecContext(ctx, "PRAGMA optimize"); err != nil {
		return err
	}
	var pageCount, freelist int64
	if err := d.writer.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return err
	}
	if err := d.writer.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freelist); err != nil {
		return err
	}
	if pageCount > 0 && float64(freelist)/float64(pageCount) >= vacuumFreelistRatio {
		if _, err := d.writer.ExecContext(ctx, "VACUUM"); err != nil {
			return err
		}
	}
	_, err := d.writer.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

// unwindStatsRollups takes out of the rollups every row that
// DELETE FROM query_logs WHERE timestamp < cutoffMs is about to remove. It
// must run before that delete, in its transaction.
//
// Whole units before the cutoff are dropped; the unit containing it has the
// earlier rows recounted from the table and subtracted, so the prune keeps its
// exact cutoff and the rollups still equal the table.
func unwindStatsRollups(ctx context.Context, tx *sql.Tx, cutoffMs int64) error {
	quarterStart := floorDiv(cutoffMs, rollupQuarterMs) * rollupQuarterMs
	hourStart := floorDiv(cutoffMs, rollupHourMs) * rollupHourMs

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO query_stats_quarter (quarter, blocked, cached, count, sum_ms)
             SELECT timestamp / 900000, blocked, cached, -COUNT(*), -SUM(response_ms)
             FROM query_logs WHERE timestamp >= ?1 AND timestamp < ?2 GROUP BY 1, 2, 3
             ON CONFLICT DO UPDATE SET count = count + excluded.count,
                                       sum_ms = sum_ms + excluded.sum_ms`,
		quarterStart, cutoffMs); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM query_stats_quarter WHERE quarter < ?1 OR (quarter = ?1 AND count = 0)",
		quarterStart/rollupQuarterMs); err != nil {
		return err
	}

	hourlyUnwinds := []string{
		`INSERT INTO query_stats_domain_hour (hour, domain, count)
             SELECT timestamp / 3600000, domain, -COUNT(*)
             FROM query_logs WHERE timestamp >= ?1 AND timestamp < ?2 GROUP BY 1, 2
             ON CONFLICT DO UPDATE SET count = count + excluded.count`,
		`INSERT INTO query_stats_client_hour (hour, client_ip, doh_token, count)
             SELECT timestamp / 3600000, client_ip, COALESCE(doh_token, ''), -COUNT(*)
             FROM query_logs WHERE timestamp >= ?1 AND timestamp < ?2 GROUP BY 1, 2, 3
             ON CONFLICT DO UPDATE SET count = count + excluded.count`,
		`INSERT INTO query_stats_upstream_hour (hour, upstream, count, sum_ms)
             SELECT timestamp / 3600000, upstream, -COUNT(*), -SUM(response_ms)
             FROM query_logs
             WHERE timestamp >= ?1 AND timestamp < ?2 AND upstream IS NOT NULL GROUP BY 1, 2
             ON CONFLICT DO UPDATE SET count = count + excluded.count,
                                       sum_ms = sum_ms + excluded.sum_ms`,
		`INSERT INTO query_stats_metrics_hour
             (hour, blocked, cached, has_result, query_type, response_ms, count)
             SELECT timestamp / 3600000, blocked, cached, result IS NOT NULL AND result != '',
                    query_type, response_ms, -COUNT(*)
             FROM query_logs WHERE timestamp >= ?1 AND timestamp < ?2
             GROUP BY 1, 2, 3, 4, 5, 6
             ON CONFLICT DO UPDATE SET count = count + excluded.count`,
	}
	for _, statement := range hourlyUnwinds {
		if _, err := tx.ExecContext(ctx, statement, hourStart, cutoffMs); err != nil {
			return err
		}
	}
	hour := hourStart / rollupHourMs
	hourTables := []string{
		"query_stats_domain_hour",
		"query_stats_client_hour",
		"query_stats_upstream_hour",
		"query_stats_metrics_hour",
	}
	for _, table := range hourTables {
		if _, err := tx.ExecContext(ctx,
			"DELETE FROM "+table+" WHERE hour < ?1 OR (hour = ?1 AND count = 0)", hour); err != nil {
			return err
		}
	}
	return nil
}

// floorDiv divides rounding toward negative infinity, like Rust's div_euclid
// for a positive divisor; Go's / truncates toward zero.
func floorDiv(dividend, divisor int64) int64 {
	quotient := dividend / divisor
	if dividend%divisor != 0 && (dividend < 0) != (divisor < 0) {
		quotient--
	}
	return quotient
}

// firstWholeUnit is the first rollup unit wholly inside a window that starts
// at sinceMs. Readers take that unit onward from the rollup and
// [sinceMs, first*unitMs) from query_logs. The open end needs nothing:
// rollups are written in the rows' transaction, so even the current unit is
// complete.
func firstWholeUnit(sinceMs, unitMs int64) int64 {
	unit := floorDiv(sinceMs, unitMs)
	if sinceMs-unit*unitMs != 0 {
		unit++
	}
	return unit
}
