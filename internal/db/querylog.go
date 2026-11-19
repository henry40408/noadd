package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const queryLogCountKey = "query_log_count"

const queryLogColumns = "timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result, authenticated_data"

// QueryLogEntry is one logged DNS query. Timestamp is Unix milliseconds.
type QueryLogEntry struct {
	Timestamp         int64   `json:"timestamp"`
	Domain            string  `json:"domain"`
	QueryType         string  `json:"query_type"`
	ClientIP          string  `json:"client_ip"`
	Blocked           bool    `json:"blocked"`
	Cached            bool    `json:"cached"`
	ResponseMs        int64   `json:"response_ms"`
	Upstream          *string `json:"upstream"`
	DohToken          *string `json:"doh_token"`
	Result            *string `json:"result"`
	AuthenticatedData bool    `json:"authenticated_data"`
}

// QueryLogFilter narrows the query log; a nil field leaves that column
// unfiltered.
type QueryLogFilter struct {
	Search    *string
	Blocked   *bool
	Token     *string
	QueryType *string
}

// InsertQueryLogs writes a batch and moves the maintained row count in the
// same transaction.
func (d *DB) InsertQueryLogs(ctx context.Context, entries []QueryLogEntry) error {
	return d.inWriteTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx,
			"INSERT INTO query_logs ("+queryLogColumns+") VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)")
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()
		for _, entry := range entries {
			if _, err := stmt.ExecContext(ctx, entry.Timestamp, entry.Domain, entry.QueryType, entry.ClientIP,
				boolToInt(entry.Blocked), boolToInt(entry.Cached), entry.ResponseMs,
				entry.Upstream, entry.DohToken, entry.Result, boolToInt(entry.AuthenticatedData)); err != nil {
				return err
			}
		}
		return bumpLogCount(ctx, tx, int64(len(entries)))
	})
}

// QueryLogs returns one page of the log, newest first. A negative limit
// means no limit and a negative offset means zero, as in SQLite.
func (d *DB) QueryLogs(ctx context.Context, filter QueryLogFilter, limit, offset int64) ([]QueryLogEntry, error) {
	query := "SELECT " + queryLogColumns + " FROM query_logs WHERE 1=1"
	where, args := logFilterClauses(filter)
	if filter.QueryType != nil && len(args) == 1 {
		query, args = queryTypeOnlyPage(*filter.QueryType, limit, offset)
	} else {
		query += where + " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
	}
	rows, err := d.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []QueryLogEntry
	for rows.Next() {
		var entry QueryLogEntry
		var blocked, cached, authenticated int64
		if err := rows.Scan(&entry.Timestamp, &entry.Domain, &entry.QueryType, &entry.ClientIP, &blocked, &cached,
			&entry.ResponseMs, &entry.Upstream, &entry.DohToken, &entry.Result, &authenticated); err != nil {
			return nil, err
		}
		entry.Blocked, entry.Cached, entry.AuthenticatedData = blocked != 0, cached != 0, authenticated != 0
		out = append(out, entry)
	}
	return out, rows.Err()
}

// queryTypeOnlyPage reads (query_type, blocked, timestamp) as two
// timestamp-ordered runs, one per verdict, and merges them. With blocked in
// the middle of the index (there for the blocked filter) one range would read
// every row of the type and sort it; each run stops at offset+limit. The runs
// carry only indexed id/timestamp, so the table is read for the page's rows
// alone.
func queryTypeOnlyPage(queryType string, limit, offset int64) (string, []any) {
	query := "SELECT " + queryLogColumns + " FROM query_logs WHERE id IN ( " +
		"SELECT id FROM ( " +
		"SELECT id, timestamp FROM (SELECT id, timestamp FROM query_logs " +
		"INDEXED BY idx_query_logs_type_blocked_ts " +
		"WHERE query_type = ?1 AND blocked = 0 ORDER BY timestamp DESC LIMIT ?2) " +
		"UNION ALL " +
		"SELECT id, timestamp FROM (SELECT id, timestamp FROM query_logs " +
		"INDEXED BY idx_query_logs_type_blocked_ts " +
		"WHERE query_type = ?1 AND blocked = 1 ORDER BY timestamp DESC LIMIT ?2) " +
		"ORDER BY timestamp DESC LIMIT ?3 OFFSET ?4)) " +
		"ORDER BY timestamp DESC"
	run := int64(-1)
	if limit >= 0 {
		run = saturatingAdd(max(offset, 0), limit)
	}
	return query, []any{queryType, run, limit, offset}
}

func saturatingAdd(a, b int64) int64 {
	sum := a + b
	if a > 0 && b > 0 && sum < 0 {
		return int64(^uint64(0) >> 1)
	}
	return sum
}

// HasAnyQueryLogs reports whether any query was ever logged.
func (d *DB) HasAnyQueryLogs(ctx context.Context) (bool, error) {
	var exists int64
	err := d.reader.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM query_logs)").Scan(&exists)
	return exists != 0, err
}

// CountLogs counts rows matching the filter. Unfiltered it reads the
// maintained count instead of walking an index.
func (d *DB) CountLogs(ctx context.Context, filter QueryLogFilter) (int64, error) {
	where, args := logFilterClauses(filter)
	if len(args) == 0 {
		return readLogCount(ctx, d.reader)
	}
	var count int64
	err := d.reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM query_logs WHERE 1=1"+where, args...).Scan(&count)
	return count, err
}

// DeleteAllLogs empties the log and every rollup, and zeroes the count, in
// one transaction.
func (d *DB) DeleteAllLogs(ctx context.Context) error {
	return d.inWriteTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		statements := []string{
			"DELETE FROM query_logs",
			"DELETE FROM query_stats_quarter",
			"DELETE FROM query_stats_domain_hour",
			"DELETE FROM query_stats_client_hour",
			"DELETE FROM query_stats_upstream_hour",
			"DELETE FROM query_stats_metrics_hour",
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, "UPDATE settings SET value = ?1 WHERE key = ?2", 0, queryLogCountKey)
		return err
	})
}

// logFilterClauses builds the AND clauses shared by QueryLogs and CountLogs
// so their filters cannot drift.
//
// A plain search term is an index-backed prefix match (GLOB 'term*'). A term
// containing %, _, * or ? is a pattern: * and ? become % and _ and it is
// matched with LIKE as-is, so *foo* means "contains foo". Domains are stored
// lowercase, so the term is lowercased.
func logFilterClauses(filter QueryLogFilter) (string, []any) {
	var clauses strings.Builder
	var args []any
	if filter.Search != nil {
		if term := strings.ToLower(strings.TrimSpace(*filter.Search)); term != "" {
			if strings.ContainsAny(term, "%_*?") {
				pattern := strings.NewReplacer("*", "%", "?", "_").Replace(term)
				clauses.WriteString(" AND domain LIKE ?")
				args = append(args, pattern)
			} else {
				clauses.WriteString(" AND domain GLOB ?")
				args = append(args, term+"*")
			}
		}
	}
	if filter.Blocked != nil {
		clauses.WriteString(" AND blocked = ?")
		args = append(args, boolToInt(*filter.Blocked))
	}
	if filter.Token != nil {
		clauses.WriteString(" AND doh_token = ?")
		args = append(args, *filter.Token)
	}
	if filter.QueryType != nil {
		clauses.WriteString(" AND query_type = ?")
		args = append(args, *filter.QueryType)
	}
	return clauses.String(), args
}

// bumpLogCount moves the maintained query_logs row count by delta, on the
// write's own transaction.
func bumpLogCount(ctx context.Context, tx execer, delta int64) error {
	_, err := tx.ExecContext(ctx,
		"UPDATE settings SET value = CAST(value AS INTEGER) + ?1 WHERE key = ?2", delta, queryLogCountKey)
	return err
}

// readLogCount returns the maintained count, recounting only when the counter
// row is missing or unreadable.
func readLogCount(ctx context.Context, pool *sql.DB) (int64, error) {
	stored, found, err := queryOptional[string](ctx, pool, "SELECT value FROM settings WHERE key = ?1", queryLogCountKey)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if found {
		if count, parseErr := strconv.ParseInt(stored, 10, 64); parseErr == nil {
			return count, nil
		}
	}
	var count int64
	if err := pool.QueryRowContext(ctx, "SELECT COUNT(*) FROM query_logs").Scan(&count); err != nil {
		return 0, fmt.Errorf("count query_logs: %w", err)
	}
	return count, nil
}
