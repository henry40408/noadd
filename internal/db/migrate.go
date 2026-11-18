package db

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

// baseSchema runs on every open, before the migrations, so a fresh database
// starts from the shape the migrations expect. Every statement is idempotent.
// The text is stored verbatim in sqlite_master, so it must match the Rust
// schema character for character.
const baseSchema = `
                    CREATE TABLE IF NOT EXISTS settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS query_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp INTEGER NOT NULL,
                        domain TEXT NOT NULL,
                        query_type TEXT NOT NULL,
                        client_ip TEXT NOT NULL,
                        blocked INTEGER NOT NULL DEFAULT 0,
                        cached INTEGER NOT NULL DEFAULT 0,
                        response_ms INTEGER NOT NULL DEFAULT 0,
                        upstream TEXT,
                        doh_token TEXT,
                        result TEXT,
                        authenticated_data INTEGER NOT NULL DEFAULT 0,
                        has_result INTEGER GENERATED ALWAYS AS (result IS NOT NULL AND result != '') VIRTUAL
                    );
                    CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON query_logs(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_query_logs_domain_ts ON query_logs(domain, timestamp);
                    CREATE INDEX IF NOT EXISTS idx_query_logs_token_ts ON query_logs(doh_token, timestamp);
                    CREATE INDEX IF NOT EXISTS idx_query_logs_blocked_ts ON query_logs(blocked, timestamp);
                    CREATE INDEX IF NOT EXISTS idx_query_logs_type_blocked_ts ON query_logs(query_type, blocked, timestamp);

                    CREATE TABLE IF NOT EXISTS filter_lists (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        url TEXT NOT NULL,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        last_updated INTEGER NOT NULL DEFAULT 0,
                        rule_count INTEGER NOT NULL DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS custom_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule TEXT NOT NULL,
                        rule_type TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS filter_list_content (
                        list_id INTEGER PRIMARY KEY,
                        content TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS doh_tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        token TEXT NOT NULL UNIQUE
                    );

                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        -- NO_PASSWORD_SENTINEL for forward-auth accounts.
                        password_hash TEXT NOT NULL,
                        created_at INTEGER NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS api_keys (
                        id           INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        name         TEXT    NOT NULL,
                        token_hash   TEXT    NOT NULL UNIQUE,
                        prefix       TEXT    NOT NULL,
                        created_at   INTEGER NOT NULL,
                        last_used_at INTEGER,
                        expires_at   INTEGER
                    );
                    CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
                    `

// statsRollupSchema creates the statistics rollups and the trigger that
// maintains them on insert. See the Rust STATS_ROLLUP_SCHEMA for the design.
const statsRollupSchema = `
    CREATE TABLE IF NOT EXISTS query_stats_quarter (
        quarter INTEGER NOT NULL,
        blocked INTEGER NOT NULL,
        cached INTEGER NOT NULL,
        count INTEGER NOT NULL,
        sum_ms INTEGER NOT NULL,
        PRIMARY KEY (quarter, blocked, cached)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS query_stats_domain_hour (
        hour INTEGER NOT NULL,
        domain TEXT NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (hour, domain)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS query_stats_client_hour (
        hour INTEGER NOT NULL,
        client_ip TEXT NOT NULL,
        doh_token TEXT NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (hour, client_ip, doh_token)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS query_stats_upstream_hour (
        hour INTEGER NOT NULL,
        upstream TEXT NOT NULL,
        count INTEGER NOT NULL,
        sum_ms INTEGER NOT NULL,
        PRIMARY KEY (hour, upstream)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS query_stats_metrics_hour (
        hour INTEGER NOT NULL,
        blocked INTEGER NOT NULL,
        cached INTEGER NOT NULL,
        has_result INTEGER NOT NULL,
        query_type TEXT NOT NULL,
        response_ms INTEGER NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (hour, blocked, cached, has_result, query_type, response_ms)
    ) WITHOUT ROWID;
    CREATE TRIGGER IF NOT EXISTS query_logs_maintain_stats AFTER INSERT ON query_logs BEGIN
        INSERT INTO query_stats_quarter (quarter, blocked, cached, count, sum_ms)
            VALUES (NEW.timestamp / 900000, NEW.blocked, NEW.cached, 1, NEW.response_ms)
            ON CONFLICT DO UPDATE SET count = count + 1, sum_ms = sum_ms + excluded.sum_ms;
        INSERT INTO query_stats_domain_hour (hour, domain, count)
            VALUES (NEW.timestamp / 3600000, NEW.domain, 1)
            ON CONFLICT DO UPDATE SET count = count + 1;
        INSERT INTO query_stats_client_hour (hour, client_ip, doh_token, count)
            VALUES (NEW.timestamp / 3600000, NEW.client_ip, COALESCE(NEW.doh_token, ''), 1)
            ON CONFLICT DO UPDATE SET count = count + 1;
        INSERT INTO query_stats_upstream_hour (hour, upstream, count, sum_ms)
            SELECT NEW.timestamp / 3600000, NEW.upstream, 1, NEW.response_ms
            WHERE NEW.upstream IS NOT NULL
            ON CONFLICT DO UPDATE SET count = count + 1, sum_ms = sum_ms + excluded.sum_ms;
        INSERT INTO query_stats_metrics_hour
            (hour, blocked, cached, has_result, query_type, response_ms, count)
            VALUES (NEW.timestamp / 3600000, NEW.blocked, NEW.cached,
                    NEW.result IS NOT NULL AND NEW.result != '',
                    NEW.query_type, NEW.response_ms, 1)
            ON CONFLICT DO UPDATE SET count = count + 1;
    END;
`

// statsRollupBackfill fills the rollups from existing query_logs. The upsert
// replaces rather than adds, so an interrupted migration can re-run it
// without doubling. "WHERE true" stops the parser reading ON CONFLICT as part
// of the SELECT.
const statsRollupBackfill = `
    INSERT INTO query_stats_quarter (quarter, blocked, cached, count, sum_ms)
        SELECT timestamp / 900000, blocked, cached, COUNT(*), SUM(response_ms)
        FROM query_logs WHERE true GROUP BY 1, 2, 3
        ON CONFLICT DO UPDATE SET count = excluded.count, sum_ms = excluded.sum_ms;
    INSERT INTO query_stats_domain_hour (hour, domain, count)
        SELECT timestamp / 3600000, domain, COUNT(*)
        FROM query_logs WHERE true GROUP BY 1, 2
        ON CONFLICT DO UPDATE SET count = excluded.count;
    INSERT INTO query_stats_client_hour (hour, client_ip, doh_token, count)
        SELECT timestamp / 3600000, client_ip, COALESCE(doh_token, ''), COUNT(*)
        FROM query_logs WHERE true GROUP BY 1, 2, 3
        ON CONFLICT DO UPDATE SET count = excluded.count;
    INSERT INTO query_stats_upstream_hour (hour, upstream, count, sum_ms)
        SELECT timestamp / 3600000, upstream, COUNT(*), SUM(response_ms)
        FROM query_logs WHERE upstream IS NOT NULL GROUP BY 1, 2
        ON CONFLICT DO UPDATE SET count = excluded.count, sum_ms = excluded.sum_ms;
    INSERT INTO query_stats_metrics_hour
        (hour, blocked, cached, has_result, query_type, response_ms, count)
        SELECT timestamp / 3600000, blocked, cached, result IS NOT NULL AND result != '',
               query_type, response_ms, COUNT(*)
        FROM query_logs WHERE true GROUP BY 1, 2, 3, 4, 5, 6
        ON CONFLICT DO UPDATE SET count = excluded.count;
`

// execer is the part of *sql.Tx the migrations need.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type migration struct {
	version int
	apply   func(ctx context.Context, tx execer) error
}

// migrations are forward-only steps in ascending order; the last entry is the
// latest user_version. Never edit a released step: add a new one.
var migrations = []migration{
	{1, func(ctx context.Context, tx execer) error {
		return addColumnIfMissing(ctx, tx, "query_logs", "cached", "INTEGER NOT NULL DEFAULT 0")
	}},
	{2, migrateToV2},
	{3, func(ctx context.Context, tx execer) error {
		return addColumnIfMissing(ctx, tx, "query_logs", "upstream", "TEXT")
	}},
	{4, func(ctx context.Context, tx execer) error {
		return addColumnIfMissing(ctx, tx, "query_logs", "result", "TEXT")
	}},
	// ANALYZE is required after every index change here: with stale
	// sqlite_stat1 the planner keeps the old plan.
	{5, execScript(`DROP INDEX IF EXISTS idx_query_logs_domain;
         CREATE INDEX IF NOT EXISTS idx_query_logs_domain_ts ON query_logs(domain, timestamp);
         ANALYZE;`)},
	{6, execScript(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            ip TEXT,
            user_agent TEXT
        );
        DELETE FROM settings WHERE key = 'admin_password_hash';
        DELETE FROM settings WHERE key = 'sessions';`)},
	{7, func(ctx context.Context, tx execer) error {
		return addColumnIfMissing(ctx, tx, "query_logs", "authenticated_data", "INTEGER NOT NULL DEFAULT 0")
	}},
	{8, execScript(`CREATE TABLE IF NOT EXISTS api_keys (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name         TEXT    NOT NULL,
            token_hash   TEXT    NOT NULL UNIQUE,
            prefix       TEXT    NOT NULL,
            created_at   INTEGER NOT NULL,
            last_used_at INTEGER,
            expires_at   INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);`)},
	// Session tokens become BLAKE2b digests. Existing raw-token rows are
	// dropped, not rehashed: rehashing would leave the plaintext in freelist
	// pages and the WAL anyway. Operators sign in once more.
	{9, execScript(`DELETE FROM sessions;
         ALTER TABLE sessions RENAME COLUMN token TO token_hash;`)},
	// Versions 10, 11, 12, 14 and 15 add indexes for statistics that now read
	// the rollups; version 17 drops them again.
	{10, execScript(`CREATE INDEX IF NOT EXISTS idx_query_logs_client_ts ON query_logs(client_ip, doh_token, timestamp);
         ANALYZE;`)},
	{11, execScript(`CREATE INDEX IF NOT EXISTS idx_query_logs_ts_metrics ON query_logs(timestamp, blocked, cached, response_ms, query_type);
         ANALYZE;`)},
	{12, migrateToV12},
	// Seed the maintained row count; COUNT(*) walks a whole index.
	{13, execScript(`INSERT INTO settings (key, value) SELECT 'query_log_count', COUNT(*) FROM query_logs WHERE true ON CONFLICT(key) DO UPDATE SET value = excluded.value;`)},
	{14, execScript(`CREATE INDEX IF NOT EXISTS idx_query_logs_ts_upstream ON query_logs(timestamp, upstream, response_ms) WHERE upstream IS NOT NULL;
         ANALYZE;`)},
	// The domain index stays: the query log's domain search seeks it by prefix.
	{15, execScript(`DROP INDEX IF EXISTS idx_query_logs_client_ts;
         CREATE INDEX IF NOT EXISTS idx_query_logs_ts_domain_client ON query_logs(timestamp, domain, client_ip, doh_token);
         ANALYZE;`)},
	{16, execScript(statsRollupSchema + statsRollupBackfill)},
	// Statistics read the rollups, so the timestamp-first statistics indexes
	// go. What is left to index is the query log's filters. On large databases
	// the freed pages cross the vacuum threshold, so the first maintenance
	// after upgrading rewrites the file once.
	{17, execScript(`DROP INDEX IF EXISTS idx_query_logs_ts_metrics;
         DROP INDEX IF EXISTS idx_query_logs_ts_upstream;
         DROP INDEX IF EXISTS idx_query_logs_ts_domain_client;
         CREATE INDEX IF NOT EXISTS idx_query_logs_token_ts ON query_logs(doh_token, timestamp);
         CREATE INDEX IF NOT EXISTS idx_query_logs_blocked_ts ON query_logs(blocked, timestamp);
         CREATE INDEX IF NOT EXISTS idx_query_logs_type_blocked_ts ON query_logs(query_type, blocked, timestamp);
         ANALYZE;`)},
}

func execScript(script string) func(ctx context.Context, tx execer) error {
	return func(ctx context.Context, tx execer) error {
		_, err := tx.ExecContext(ctx, script)
		return err
	}
}

func migrateToV2(ctx context.Context, tx execer) error {
	if err := addColumnIfMissing(ctx, tx, "query_logs", "doh_token", "TEXT"); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS doh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL UNIQUE
        )`)
	return err
}

// migrateToV12 adds a VIRTUAL generated column: it costs no table space, and
// the planner would not treat an index on the bare expression as covering.
func migrateToV12(ctx context.Context, tx execer) error {
	err := addColumnIfMissing(ctx, tx, "query_logs", "has_result",
		"INTEGER GENERATED ALWAYS AS (result IS NOT NULL AND result != '') VIRTUAL")
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DROP INDEX IF EXISTS idx_query_logs_ts_metrics;
         CREATE INDEX idx_query_logs_ts_metrics ON query_logs(timestamp, blocked, cached, response_ms, query_type, has_result);
         ANALYZE;`)
	return err
}

// addColumnIfMissing adds a column to table unless it exists.
//
// table is interpolated into the SQL: trusted migration names only.
// pragma_table_xinfo, not _info, because the latter omits generated columns
// such as query_logs.has_result.
func addColumnIfMissing(ctx context.Context, tx execer, table, column, definition string) error {
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_xinfo('%s') WHERE name = ?", table)
	if err := tx.QueryRowContext(ctx, query, column).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition))
	return err
}

// migrate brings the schema to the latest version. A fresh database (version
// 0) runs every step too, so each must be idempotent against baseSchema.
// Each version commits on its own together with its user_version bump.
func migrate(ctx context.Context, writer *sql.DB) error {
	if err := inTx(ctx, writer, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, baseSchema)
		return err
	}); err != nil {
		return fmt.Errorf("base schema: %w", err)
	}
	var version int
	if err := writer.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	for _, step := range migrations {
		if version >= step.version {
			continue
		}
		err := inTx(ctx, writer, func(tx *sql.Tx) error {
			if err := step.apply(ctx, tx); err != nil {
				return err
			}
			// PRAGMA does not take bound parameters.
			_, err := tx.ExecContext(ctx, "PRAGMA user_version = "+strconv.Itoa(step.version))
			return err
		})
		if err != nil {
			return fmt.Errorf("migration v%d: %w", step.version, err)
		}
	}
	return nil
}

func inTx(ctx context.Context, pool *sql.DB, body func(tx *sql.Tx) error) error {
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := body(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
