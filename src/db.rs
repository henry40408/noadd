use rusqlite::{OpenFlags, OptionalExtension, params};
use serde::Serialize;
use thiserror::Error;
use tokio_rusqlite::Connection;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] tokio_rusqlite::Error),
    #[error("Rusqlite error: {0}")]
    Rusqlite(#[from] rusqlite::Error),
}

#[derive(Clone)]
pub struct Database {
    conn: Connection,
    read_conn: Connection,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryLogEntry {
    pub timestamp: i64,
    pub domain: String,
    pub query_type: String,
    pub client_ip: String,
    pub blocked: bool,
    pub cached: bool,
    pub response_ms: i64,
    pub upstream: Option<String>,
    pub doh_token: Option<String>,
    pub result: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopUpstream {
    pub upstream: String,
    pub count: i64,
    pub avg_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DohTokenRow {
    pub id: i64,
    pub token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FilterListRow {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub last_updated: i64,
    pub rule_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustomRuleRow {
    pub id: i64,
    pub rule: String,
    pub rule_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopDomain {
    pub domain: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopClient {
    pub client_ip: String,
    pub doh_token: Option<String>,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelinePoint {
    pub timestamp: i64,
    pub total: i64,
    pub blocked: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineMultiPoint {
    pub timestamp: i64,
    pub total: i64,
    pub blocked: i64,
    pub cached: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeatmapCell {
    pub weekday: i64, // 0 = Sunday, 6 = Saturday (matches strftime('%w'))
    pub hour: i64,    // 0..=23
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencySummary {
    pub sample_count: i64,
    pub avg_ms: f64,
    pub p50_ms: i64,
    pub p95_ms: i64,
    pub p99_ms: i64,
    pub max_ms: i64,
}

/// Default rusqlite cache is 16 statements; the read connection alone has
/// ~20 distinct hot SQL strings (settings, stats, filter, token lookup),
/// so anything below ~32 starts evicting on every admin poll.
const PREPARED_STATEMENT_CACHE_CAPACITY: usize = 64;

/// Open a second connection to the same SQLite file in read-only mode.
/// Used for admin SELECT queries so they run concurrently with the writer
/// under WAL without blocking on a single worker thread.
async fn open_read_conn(path: &str) -> Result<Connection, DbError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    let conn = Connection::open_with_flags(path, flags).await?;
    conn.call(|conn| {
        conn.set_prepared_statement_cache_capacity(PREPARED_STATEMENT_CACHE_CAPACITY);
        conn.execute_batch(
            "
            PRAGMA busy_timeout = 5000;
            PRAGMA cache_size = -20000;
            PRAGMA temp_store = MEMORY;
            ",
        )?;
        Ok(())
    })
    .await?;
    Ok(conn)
}

impl Database {
    pub async fn open(path: &str) -> Result<Self, DbError> {
        let conn = Connection::open(path).await?;
        let db_init = Self {
            conn: conn.clone(),
            // Placeholder — replaced below. We need schema init to run on
            // the write conn before opening the read conn so WAL is in effect.
            read_conn: conn.clone(),
        };
        db_init.init_schema().await?;
        // SQLite in-memory databases are per-connection; a second OPEN_READ_ONLY
        // connection to ":memory:" would be an empty, unrelated database. Fall
        // back to sharing the writer connection so tests using ":memory:" work.
        let read_conn = if path == ":memory:" {
            conn.clone()
        } else {
            open_read_conn(path).await?
        };
        Ok(Self { conn, read_conn })
    }

    async fn init_schema(&self) -> Result<(), DbError> {
        self.conn
            .call(|conn| {
                conn.set_prepared_statement_cache_capacity(PREPARED_STATEMENT_CACHE_CAPACITY);
                // Performance pragmas
                conn.execute_batch(
                    "
                    PRAGMA journal_mode = WAL;
                    PRAGMA synchronous = NORMAL;
                    PRAGMA foreign_keys = ON;
                    PRAGMA busy_timeout = 5000;
                    PRAGMA cache_size = -20000;
                    PRAGMA temp_store = MEMORY;
                    ",
                )?;

                conn.execute_batch(
                    "
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
                        result TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON query_logs(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_query_logs_domain ON query_logs(domain);

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
                    ",
                )?;
                Self::run_migrations(conn)?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Run forward-only migrations using PRAGMA user_version to track schema version.
    /// New databases start at the latest version (tables already have all columns).
    /// Existing databases get migrated incrementally.
    //
    // Fresh databases already have the target columns from CREATE TABLE, so
    // `add_column_if_missing` is used below to make each migration idempotent
    // whether run against a fresh or pre-existing DB.
    fn run_migrations(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

        if version < 1 {
            add_column_if_missing(conn, "query_logs", "cached", "INTEGER NOT NULL DEFAULT 0")?;
        }

        if version < 2 {
            add_column_if_missing(conn, "query_logs", "doh_token", "TEXT")?;
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS doh_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT NOT NULL UNIQUE
                )",
            )?;
        }

        if version < 3 {
            add_column_if_missing(conn, "query_logs", "upstream", "TEXT")?;
        }

        if version < 4 {
            add_column_if_missing(conn, "query_logs", "result", "TEXT")?;
        }

        const LATEST_VERSION: i64 = 4;
        if version < LATEST_VERSION {
            conn.pragma_update(None, "user_version", LATEST_VERSION)?;
        }

        Ok(())
    }

    /// List all table names (for testing).
    pub async fn list_tables(&self) -> Result<Vec<String>, DbError> {
        let tables = self
            .read_conn
            .call(|conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                )?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(tables)
    }

    // --- Settings ---

    pub async fn get_setting(&self, key: &str) -> Result<Option<String>, DbError> {
        let key = key.to_string();
        let val = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached("SELECT value FROM settings WHERE key = ?1")?;
                let result = stmt
                    .query_row(params![key], |row| row.get::<_, String>(0))
                    .optional()?;
                Ok(result)
            })
            .await?;
        Ok(val)
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> Result<(), DbError> {
        let key = key.to_string();
        let value = value.to_string();
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                )?;
                stmt.execute(params![key, value])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    // --- Query Logs ---

    pub async fn insert_query_logs(&self, entries: &[QueryLogEntry]) -> Result<(), DbError> {
        let entries: Vec<QueryLogEntry> = entries.to_vec();
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare_cached(
                        "INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    )?;
                    for e in &entries {
                        stmt.execute(params![
                            e.timestamp,
                            e.domain,
                            e.query_type,
                            e.client_ip,
                            e.blocked as i64,
                            e.cached as i64,
                            e.response_ms,
                            e.upstream,
                            e.doh_token,
                            e.result,
                        ])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn query_logs(
        &self,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        blocked: Option<bool>,
        token: Option<&str>,
        query_type: Option<&str>,
    ) -> Result<Vec<QueryLogEntry>, DbError> {
        let search = search.map(|s| s.to_string());
        let token = token.map(|s| s.to_string());
        let query_type = query_type.map(|s| s.to_string());
        let rows = self
            .read_conn
            .call(move |conn| {
                let mut sql = "SELECT timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result FROM query_logs WHERE 1=1".to_string();
                let mut param_values = append_log_filters(
                    &mut sql,
                    search.as_deref(),
                    blocked,
                    token.as_deref(),
                    query_type.as_deref(),
                );
                sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
                param_values.push(Box::new(limit));
                param_values.push(Box::new(offset));

                let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                    param_values.iter().map(|p| p.as_ref()).collect();

                let mut stmt = conn.prepare_cached(&sql)?;
                let rows = stmt
                    .query_map(params_refs.as_slice(), |row| {
                        Ok(QueryLogEntry {
                            timestamp: row.get(0)?,
                            domain: row.get(1)?,
                            query_type: row.get(2)?,
                            client_ip: row.get(3)?,
                            blocked: row.get::<_, i64>(4)? != 0,
                            cached: row.get::<_, i64>(5)? != 0,
                            response_ms: row.get(6)?,
                            upstream: row.get(7)?,
                            doh_token: row.get(8)?,
                            result: row.get(9)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn count_logs(
        &self,
        search: Option<&str>,
        blocked: Option<bool>,
        token: Option<&str>,
        query_type: Option<&str>,
    ) -> Result<i64, DbError> {
        let search = search.map(|s| s.to_string());
        let token = token.map(|s| s.to_string());
        let query_type = query_type.map(|s| s.to_string());
        let count = self
            .read_conn
            .call(move |conn| {
                let mut sql = "SELECT COUNT(*) FROM query_logs WHERE 1=1".to_string();
                let param_values = append_log_filters(
                    &mut sql,
                    search.as_deref(),
                    blocked,
                    token.as_deref(),
                    query_type.as_deref(),
                );

                let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                    param_values.iter().map(|p| p.as_ref()).collect();

                let mut stmt = conn.prepare_cached(&sql)?;
                stmt.query_row(params_refs.as_slice(), |row| row.get(0))
            })
            .await?;
        Ok(count)
    }

    pub async fn delete_all_logs(&self) -> Result<(), DbError> {
        self.conn
            .call(|conn| {
                conn.execute("DELETE FROM query_logs", [])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// `timestamp` is in seconds (epoch). Converts to ms internally.
    pub async fn prune_logs_before(&self, timestamp: i64) -> Result<u64, DbError> {
        let timestamp_ms = timestamp * 1000;
        let count = self
            .conn
            .call(move |conn| {
                let deleted = conn.execute(
                    "DELETE FROM query_logs WHERE timestamp < ?1",
                    params![timestamp_ms],
                )?;
                Ok(deleted as u64)
            })
            .await?;
        Ok(count)
    }

    // --- Filter Lists ---

    pub async fn add_filter_list(
        &self,
        name: &str,
        url: &str,
        enabled: bool,
    ) -> Result<i64, DbError> {
        let name = name.to_string();
        let url = url.to_string();
        let id = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO filter_lists (name, url, enabled) VALUES (?1, ?2, ?3)",
                    params![name, url, enabled as i64],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    pub async fn get_filter_lists(&self) -> Result<Vec<FilterListRow>, DbError> {
        let rows = self
            .read_conn
            .call(|conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT id, name, url, enabled, last_updated, rule_count FROM filter_lists ORDER BY id",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(FilterListRow {
                            id: row.get(0)?,
                            name: row.get(1)?,
                            url: row.get(2)?,
                            enabled: row.get::<_, i64>(3)? != 0,
                            last_updated: row.get(4)?,
                            rule_count: row.get(5)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn update_filter_list(&self, id: i64, name: &str, url: &str) -> Result<(), DbError> {
        let name = name.to_string();
        let url = url.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE filter_lists SET name = ?1, url = ?2 WHERE id = ?3",
                    params![name, url, id],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn update_filter_list_enabled(&self, id: i64, enabled: bool) -> Result<(), DbError> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE filter_lists SET enabled = ?1 WHERE id = ?2",
                    params![enabled as i64, id],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn update_filter_list_stats(
        &self,
        id: i64,
        last_updated: i64,
        rule_count: i64,
    ) -> Result<(), DbError> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE filter_lists SET last_updated = ?1, rule_count = ?2 WHERE id = ?3",
                    params![last_updated, rule_count, id],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn delete_filter_list(&self, id: i64) -> Result<(), DbError> {
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM filter_lists WHERE id = ?1", params![id])?;
                conn.execute(
                    "DELETE FROM filter_list_content WHERE list_id = ?1",
                    params![id],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    // --- Custom Rules ---

    pub async fn has_custom_rule(&self, rule: &str) -> Result<bool, DbError> {
        let rule = rule.to_string();
        let exists = self
            .read_conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM custom_rules WHERE rule = ?1",
                    params![rule],
                    |row| row.get::<_, i64>(0),
                )
            })
            .await?;
        Ok(exists > 0)
    }

    pub async fn add_custom_rule(&self, rule: &str, rule_type: &str) -> Result<i64, DbError> {
        let rule = rule.to_string();
        let rule_type = rule_type.to_string();
        let id = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO custom_rules (rule, rule_type) VALUES (?1, ?2)",
                    params![rule, rule_type],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    pub async fn get_all_custom_rules(&self) -> Result<Vec<CustomRuleRow>, DbError> {
        let rows = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn
                    .prepare_cached("SELECT id, rule, rule_type FROM custom_rules ORDER BY id")?;
                let rows = stmt
                    .query_map(params![], |row| {
                        Ok(CustomRuleRow {
                            id: row.get(0)?,
                            rule: row.get(1)?,
                            rule_type: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn get_custom_rules_by_type(
        &self,
        rule_type: &str,
    ) -> Result<Vec<CustomRuleRow>, DbError> {
        let rule_type = rule_type.to_string();
        let rows = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT id, rule, rule_type FROM custom_rules WHERE rule_type = ?1 ORDER BY id",
                )?;
                let rows = stmt
                    .query_map(params![rule_type], |row| {
                        Ok(CustomRuleRow {
                            id: row.get(0)?,
                            rule: row.get(1)?,
                            rule_type: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn delete_custom_rule(&self, id: i64) -> Result<(), DbError> {
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM custom_rules WHERE id = ?1", params![id])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    // --- Filter List Content ---

    pub async fn get_filter_list_content(&self, list_id: i64) -> Result<Option<String>, DbError> {
        let val = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn
                    .prepare_cached("SELECT content FROM filter_list_content WHERE list_id = ?1")?;
                let result = stmt
                    .query_row(params![list_id], |row| row.get::<_, String>(0))
                    .optional()?;
                Ok(result)
            })
            .await?;
        Ok(val)
    }

    pub async fn set_filter_list_content(
        &self,
        list_id: i64,
        content: &str,
    ) -> Result<(), DbError> {
        let content = content.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO filter_list_content (list_id, content) VALUES (?1, ?2) ON CONFLICT(list_id) DO UPDATE SET content = excluded.content",
                    params![list_id, content],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    // --- DoH Tokens ---

    pub async fn get_doh_tokens(&self) -> Result<Vec<DohTokenRow>, DbError> {
        let rows = self
            .read_conn
            .call(|conn| {
                let mut stmt =
                    conn.prepare_cached("SELECT id, token FROM doh_tokens ORDER BY id")?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(DohTokenRow {
                            id: row.get(0)?,
                            token: row.get(1)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn add_doh_token(&self, token: &str) -> Result<i64, DbError> {
        let token = token.to_string();
        let id = self
            .conn
            .call(move |conn| {
                conn.execute("INSERT INTO doh_tokens (token) VALUES (?1)", params![token])?;
                Ok(conn.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    pub async fn delete_doh_token(&self, id: i64) -> Result<(), DbError> {
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM doh_tokens WHERE id = ?1", params![id])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Validate a DoH token. Returns the token string if valid.
    pub async fn validate_doh_token(&self, token: &str) -> Result<Option<String>, DbError> {
        let token = token.to_string();
        let result = self
            .read_conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare_cached("SELECT token FROM doh_tokens WHERE token = ?1")?;
                let found: Option<String> = stmt.query_row(params![token], |row| row.get(0)).ok();
                Ok(found)
            })
            .await?;
        Ok(result)
    }

    pub async fn has_doh_tokens(&self) -> Result<bool, DbError> {
        let count = self
            .read_conn
            .call(|conn| {
                let count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM doh_tokens", [], |row| row.get(0))?;
                Ok(count)
            })
            .await?;
        Ok(count > 0)
    }

    // --- Stats ---

    /// Returns the earliest log timestamp in milliseconds, or None if no logs.
    pub async fn earliest_log_timestamp(&self) -> Result<Option<i64>, DbError> {
        let result = self
            .read_conn
            .call(|conn| {
                let ts: Option<i64> = conn
                    .query_row("SELECT MIN(timestamp) FROM query_logs", [], |row| {
                        row.get(0)
                    })
                    .ok();
                Ok(ts)
            })
            .await?;
        Ok(result)
    }

    /// `since` is in seconds (epoch). Internally converts to ms to match stored timestamps.
    pub async fn count_queries_since(&self, since: i64) -> Result<(i64, i64), DbError> {
        let since_ms = since * 1000;
        let result = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT COUNT(*), COALESCE(SUM(blocked), 0) FROM query_logs WHERE timestamp >= ?1",
                )?;
                let (total, blocked) = stmt.query_row(params![since_ms], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                })?;
                Ok((total, blocked))
            })
            .await?;
        Ok(result)
    }

    /// Returns (cache_hits, total_allowed, avg_response_ms) since the given timestamp.
    /// `since` is in seconds (epoch).
    pub async fn cache_stats_since(&self, since: i64) -> Result<(i64, i64, f64), DbError> {
        let since_ms = since * 1000;
        let result = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT COALESCE(SUM(cached), 0), COUNT(*), COALESCE(AVG(response_ms), 0) FROM query_logs WHERE timestamp >= ?1 AND blocked = 0",
                )?;
                let row = stmt.query_row(params![since_ms], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, f64>(2)?,
                    ))
                })?;
                Ok(row)
            })
            .await?;
        Ok(result)
    }

    /// Returns ((total, blocked), (total, blocked), (total, blocked)) for today / 7d / 30d in one scan.
    /// All `since_*` values are in epoch seconds. Caller MUST pass the widest window as `since_30d`.
    pub async fn count_queries_multi_since(
        &self,
        since_today: i64,
        since_7d: i64,
        since_30d: i64,
    ) -> Result<((i64, i64), (i64, i64), (i64, i64)), DbError> {
        let today_ms = since_today * 1000;
        let d7_ms = since_7d * 1000;
        let d30_ms = since_30d * 1000;
        let result = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT
                    COUNT(CASE WHEN timestamp >= ?1 THEN 1 END),
                    COALESCE(SUM(CASE WHEN timestamp >= ?1 THEN blocked ELSE 0 END), 0),
                    COUNT(CASE WHEN timestamp >= ?2 THEN 1 END),
                    COALESCE(SUM(CASE WHEN timestamp >= ?2 THEN blocked ELSE 0 END), 0),
                    COUNT(CASE WHEN timestamp >= ?3 THEN 1 END),
                    COALESCE(SUM(CASE WHEN timestamp >= ?3 THEN blocked ELSE 0 END), 0)
                 FROM query_logs
                 WHERE timestamp >= ?3",
                )?;
                let row = stmt.query_row(params![today_ms, d7_ms, d30_ms], |row| {
                    Ok((
                        (row.get::<_, i64>(0)?, row.get::<_, i64>(1)?),
                        (row.get::<_, i64>(2)?, row.get::<_, i64>(3)?),
                        (row.get::<_, i64>(4)?, row.get::<_, i64>(5)?),
                    ))
                })?;
                Ok(row)
            })
            .await?;
        Ok(result)
    }

    /// Returns ((cache_hits, allowed_total, avg_response_ms), ...) for today / 7d / 30d in one scan.
    /// All `since_*` values are in epoch seconds. Caller MUST pass the widest window as `since_30d`.
    pub async fn cache_stats_multi_since(
        &self,
        since_today: i64,
        since_7d: i64,
        since_30d: i64,
    ) -> Result<((i64, i64, f64), (i64, i64, f64), (i64, i64, f64)), DbError> {
        let today_ms = since_today * 1000;
        let d7_ms = since_7d * 1000;
        let d30_ms = since_30d * 1000;
        let result = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT
                    COALESCE(SUM(CASE WHEN timestamp >= ?1 THEN cached END), 0),
                    COUNT(CASE WHEN timestamp >= ?1 THEN 1 END),
                    COALESCE(AVG(CASE WHEN timestamp >= ?1 THEN response_ms END), 0),
                    COALESCE(SUM(CASE WHEN timestamp >= ?2 THEN cached END), 0),
                    COUNT(CASE WHEN timestamp >= ?2 THEN 1 END),
                    COALESCE(AVG(CASE WHEN timestamp >= ?2 THEN response_ms END), 0),
                    COALESCE(SUM(CASE WHEN timestamp >= ?3 THEN cached END), 0),
                    COUNT(CASE WHEN timestamp >= ?3 THEN 1 END),
                    COALESCE(AVG(CASE WHEN timestamp >= ?3 THEN response_ms END), 0)
                 FROM query_logs
                 WHERE timestamp >= ?3 AND blocked = 0",
                )?;
                let row = stmt.query_row(params![today_ms, d7_ms, d30_ms], |row| {
                    Ok((
                        (
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, f64>(2)?,
                        ),
                        (
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, f64>(5)?,
                        ),
                        (
                            row.get::<_, i64>(6)?,
                            row.get::<_, i64>(7)?,
                            row.get::<_, f64>(8)?,
                        ),
                    ))
                })?;
                Ok(row)
            })
            .await?;
        Ok(result)
    }

    pub async fn top_domains_since(
        &self,
        since: i64,
        limit: i64,
    ) -> Result<Vec<TopDomain>, DbError> {
        let since_ms = since * 1000;
        let rows = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT domain, COUNT(*) as cnt FROM query_logs WHERE timestamp >= ?1 GROUP BY domain ORDER BY cnt DESC LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(params![since_ms, limit], |row| {
                        Ok(TopDomain {
                            domain: row.get(0)?,
                            count: row.get(1)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn top_clients_since(
        &self,
        since: i64,
        limit: i64,
    ) -> Result<Vec<TopClient>, DbError> {
        let since_ms = since * 1000;
        let rows = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT client_ip, doh_token, COUNT(*) as cnt FROM query_logs WHERE timestamp >= ?1 GROUP BY client_ip, doh_token ORDER BY cnt DESC LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(params![since_ms, limit], |row| {
                        Ok(TopClient {
                            client_ip: row.get(0)?,
                            doh_token: row.get(1)?,
                            count: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn top_upstreams_since(
        &self,
        since: i64,
        limit: i64,
    ) -> Result<Vec<TopUpstream>, DbError> {
        let since_ms = since * 1000;
        let rows = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT upstream, COUNT(*) as cnt, AVG(response_ms) as avg_ms FROM query_logs WHERE timestamp >= ?1 AND upstream IS NOT NULL GROUP BY upstream ORDER BY cnt DESC LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(params![since_ms, limit], |row| {
                        Ok(TopUpstream {
                            upstream: row.get(0)?,
                            count: row.get(1)?,
                            avg_ms: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn timeline_multi_since(
        &self,
        since: i64, // unix seconds
        bucket_secs: i64,
    ) -> Result<Vec<TimelineMultiPoint>, DbError> {
        let since_ms = since * 1000;
        let bucket_ms = bucket_secs * 1000;
        let result = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT (timestamp / ?1) * ?1 AS bucket, \
                            COUNT(*), \
                            COALESCE(SUM(blocked), 0), \
                            COALESCE(SUM(cached), 0) \
                     FROM query_logs \
                     WHERE timestamp >= ?2 \
                     GROUP BY bucket \
                     ORDER BY bucket",
                )?;
                let rows = stmt
                    .query_map(params![bucket_ms, since_ms], |row| {
                        Ok(TimelineMultiPoint {
                            timestamp: row.get::<_, i64>(0)? / 1000, // return seconds
                            total: row.get(1)?,
                            blocked: row.get(2)?,
                            cached: row.get(3)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(result)
    }

    pub async fn hourly_heatmap_since(
        &self,
        since: i64, // unix seconds
    ) -> Result<Vec<HeatmapCell>, DbError> {
        let since_ms = since * 1000;
        let result = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT CAST(strftime('%w', timestamp / 1000, 'unixepoch') AS INTEGER) AS wday, \
                            CAST(strftime('%H', timestamp / 1000, 'unixepoch') AS INTEGER) AS hr, \
                            COUNT(*) \
                     FROM query_logs \
                     WHERE timestamp >= ?1 \
                     GROUP BY wday, hr \
                     ORDER BY wday, hr",
                )?;
                let rows = stmt
                    .query_map(params![since_ms], |row| {
                        Ok(HeatmapCell {
                            weekday: row.get(0)?,
                            hour: row.get(1)?,
                            count: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(result)
    }

    pub async fn query_type_breakdown_since(
        &self,
        since: i64,
    ) -> Result<Vec<(String, i64)>, DbError> {
        let since_ms = since * 1000;
        let result = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT query_type, COUNT(*) AS cnt \
                     FROM query_logs \
                     WHERE timestamp >= ?1 \
                     GROUP BY query_type \
                     ORDER BY cnt DESC",
                )?;
                let rows = stmt
                    .query_map(params![since_ms], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(result)
    }

    pub async fn outcome_breakdown_since(&self, since: i64) -> Result<Vec<(String, i64)>, DbError> {
        let since_ms = since * 1000;
        let result = self
            .read_conn
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT \
                        CASE \
                            WHEN blocked = 1 THEN 'Blocked' \
                            WHEN cached = 1 THEN 'Cached' \
                            WHEN result IS NOT NULL AND result != '' THEN 'Resolved' \
                            ELSE 'Empty' \
                        END AS outcome, \
                        COUNT(*) AS cnt \
                     FROM query_logs \
                     WHERE timestamp >= ?1 \
                     GROUP BY outcome \
                     ORDER BY cnt DESC",
                )?;
                let rows = stmt
                    .query_map(params![since_ms], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(result)
    }

    pub async fn unique_domains_since(&self, since: i64) -> Result<i64, DbError> {
        let since_ms = since * 1000;
        let count = self
            .read_conn
            .call(move |conn| {
                let n: i64 = conn.query_row(
                    "SELECT COUNT(DISTINCT domain) FROM query_logs WHERE timestamp >= ?1",
                    params![since_ms],
                    |row| row.get(0),
                )?;
                Ok(n)
            })
            .await?;
        Ok(count)
    }

    pub async fn latency_summary_since(&self, since: i64) -> Result<LatencySummary, DbError> {
        let since_ms = since * 1000;
        let summary = self
            .read_conn
            .call(move |conn| {
                // Single scan: order rows once via window functions, then take the
                // row at the desired percentile offset using MAX(CASE WHEN ...).
                let row = conn.query_row(
                    "WITH ordered AS ( \
                        SELECT response_ms, \
                               ROW_NUMBER() OVER (ORDER BY response_ms) AS rn, \
                               COUNT(*) OVER () AS total \
                        FROM query_logs \
                        WHERE timestamp >= ?1 \
                     ) \
                     SELECT \
                        COALESCE(MAX(total), 0) AS sample_count, \
                        COALESCE(AVG(response_ms), 0.0) AS avg_ms, \
                        COALESCE(MAX(CASE WHEN rn <= MAX(1, CAST(total * 0.50 AS INTEGER)) THEN response_ms END), 0) AS p50, \
                        COALESCE(MAX(CASE WHEN rn <= MAX(1, CAST(total * 0.95 AS INTEGER)) THEN response_ms END), 0) AS p95, \
                        COALESCE(MAX(CASE WHEN rn <= MAX(1, CAST(total * 0.99 AS INTEGER)) THEN response_ms END), 0) AS p99, \
                        COALESCE(MAX(response_ms), 0) AS max_ms \
                     FROM ordered",
                    params![since_ms],
                    |row| {
                        Ok(LatencySummary {
                            sample_count: row.get(0)?,
                            avg_ms: row.get(1)?,
                            p50_ms: row.get(2)?,
                            p95_ms: row.get(3)?,
                            p99_ms: row.get(4)?,
                            max_ms: row.get(5)?,
                        })
                    },
                )?;
                Ok(row)
            })
            .await?;
        Ok(summary)
    }

    pub async fn db_file_size(&self) -> Result<i64, DbError> {
        let result = self
            .read_conn
            .call(|conn| {
                let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
                let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
                Ok(page_count * page_size)
            })
            .await?;
        Ok(result)
    }

    pub async fn total_log_count(&self) -> Result<i64, DbError> {
        let result = self
            .read_conn
            .call(|conn| {
                let count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM query_logs", [], |row| row.get(0))?;
                Ok(count)
            })
            .await?;
        Ok(result)
    }

    pub async fn timeline_since(
        &self,
        since: i64,
        bucket_secs: i64,
    ) -> Result<Vec<TimelinePoint>, DbError> {
        let rows = self
            .read_conn
            .call(move |conn| {
                // Convert seconds to milliseconds to match timestamp storage
                let since_ms = since * 1000;
                let bucket_ms = bucket_secs * 1000;
                let mut stmt = conn.prepare_cached(
                    "SELECT (timestamp / ?1) * ?1 as bucket, COUNT(*) as total, COALESCE(SUM(blocked), 0) as blocked FROM query_logs WHERE timestamp >= ?2 GROUP BY bucket ORDER BY bucket",
                )?;
                let since = since_ms;
                let bucket_secs = bucket_ms;
                let rows = stmt
                    .query_map(params![bucket_secs, since], |row| {
                        Ok(TimelinePoint {
                            timestamp: row.get(0)?,
                            total: row.get(1)?,
                            blocked: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }
}

/// Add a column to `table` if it doesn't already exist.
///
/// SQLite doesn't support `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so we
/// probe `pragma_table_info` first. The `table` argument is interpolated into
/// the SQL — only call this from migration code with trusted table names.
fn add_column_if_missing(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), rusqlite::Error> {
    let exists: bool = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name = ?1"),
            params![column],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)?;
    if !exists {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )?;
    }
    Ok(())
}

/// Append the shared log-filter clauses to `sql` and return matching parameters.
///
/// Both `query_logs` and `count_logs` share the same four optional filters
/// (search, blocked, doh_token, query_type); centralising the builder keeps
/// the two code paths from drifting.
fn append_log_filters(
    sql: &mut String,
    search: Option<&str>,
    blocked: Option<bool>,
    token: Option<&str>,
    query_type: Option<&str>,
) -> Vec<Box<dyn rusqlite::types::ToSql>> {
    let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if let Some(s) = search {
        sql.push_str(" AND domain LIKE ?");
        values.push(Box::new(format!("%{s}%")));
    }
    if let Some(b) = blocked {
        sql.push_str(" AND blocked = ?");
        values.push(Box::new(b as i64));
    }
    if let Some(t) = token {
        sql.push_str(" AND doh_token = ?");
        values.push(Box::new(t.to_string()));
    }
    if let Some(qt) = query_type {
        sql.push_str(" AND query_type = ?");
        values.push(Box::new(qt.to_string()));
    }
    values
}
