use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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

impl DbError {
    /// True when the error is a `SQLite` constraint violation (e.g. inserting a
    /// duplicate `users.username`, which is the only UNIQUE constraint on that
    /// table). Callers use this to distinguish a duplicate-key conflict (HTTP
    /// 409) from a genuine database failure (HTTP 500).
    pub fn is_unique_violation(&self) -> bool {
        let inner = match self {
            DbError::Rusqlite(e)
            | DbError::Sqlite(
                tokio_rusqlite::Error::Error(e) | tokio_rusqlite::Error::Close((_, e)),
            ) => Some(e),
            DbError::Sqlite(_) => None,
        };
        matches!(
            inner,
            Some(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation
        )
    }
}

/// Number of read-only `SQLite` connections in the pool. Each connection owns
/// its own tokio-rusqlite worker thread, so this is the parallelism cap for
/// admin/stats queries. WAL lets readers proceed without blocking each other.
const READ_POOL_SIZE: usize = 4;

/// `run_maintenance` only triggers a full `VACUUM` once free pages reach this
/// fraction of the database file. Below it, reclaiming space is not worth the
/// whole-file rewrite and the write lock VACUUM holds.
const VACUUM_FREELIST_RATIO: f64 = 0.2;

#[derive(Clone)]
pub struct Database {
    conn: Connection,
    read_pool: Arc<ReadPool>,
}

struct ReadPool {
    conns: Vec<Connection>,
    next: AtomicUsize,
}

impl ReadPool {
    fn pick(&self) -> &Connection {
        let i = self.next.fetch_add(1, Ordering::Relaxed) % self.conns.len();
        &self.conns[i]
    }
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
    pub authenticated_data: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct StorageStats {
    pub main_bytes: i64,
    pub reclaimable_bytes: i64,
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

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ApiKeyRow {
    /// Key id.
    pub id: i64,
    /// Human-readable label given at creation time.
    pub name: String,
    /// Short, non-secret prefix used to identify the key; the full secret
    /// is never returned again after creation.
    pub prefix: String,
    /// Unix timestamp (seconds) the key was created.
    pub created_at: i64,
    /// Unix timestamp (seconds) the key was last used to authenticate, if ever.
    pub last_used_at: Option<i64>,
    /// Unix timestamp (seconds) after which the key stops working, if any.
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct UserAuth {
    pub id: i64,
    pub password_hash: String,
}

/// Result of attempting to delete an operator.
#[derive(Debug, PartialEq, Eq)]
pub enum DeleteUserOutcome {
    /// The operator was deleted.
    Deleted,
    /// Refused: this is the last remaining operator (would lock everyone out).
    LastOperator,
    /// No operator with the given id exists.
    NotFound,
}

#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct LoadedSession {
    pub token: String,
    pub id: i64,
    pub user_id: i64,
    pub created_at: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct FilterListRow {
    /// List id.
    pub id: i64,
    /// Display name.
    pub name: String,
    /// Source URL the list's contents are fetched from.
    pub url: String,
    /// Whether the list's rules are currently applied by the filter engine.
    pub enabled: bool,
    /// Unix timestamp (seconds) the list was last downloaded, or `0` if never.
    pub last_updated: i64,
    /// Number of rules parsed out of the list's content on last download.
    pub rule_count: i64,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct CustomRuleRow {
    /// Rule id.
    pub id: i64,
    /// Rule text in hosts-file or Adblock-style syntax.
    pub rule: String,
    /// Either `"block"` or `"allow"`.
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

/// Open a second connection to the same `SQLite` file in read-only mode.
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
            PRAGMA cache_size = -2000;
            PRAGMA mmap_size = 268435456;
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
        let placeholder_pool = Arc::new(ReadPool {
            conns: vec![conn.clone()],
            next: AtomicUsize::new(0),
        });
        let db_init = Self {
            conn: conn.clone(),
            // Placeholder — replaced below. We need schema init to run on
            // the write conn before opening readers so WAL is in effect.
            read_pool: placeholder_pool,
        };
        db_init.init_schema().await?;
        // SQLite in-memory databases are per-connection; a second OPEN_READ_ONLY
        // connection to ":memory:" would be an empty, unrelated database. Fall
        // back to sharing the writer connection so tests using ":memory:" work.
        let read_pool = if path == ":memory:" {
            Arc::new(ReadPool {
                conns: vec![conn.clone()],
                next: AtomicUsize::new(0),
            })
        } else {
            let mut conns = Vec::with_capacity(READ_POOL_SIZE);
            for _ in 0..READ_POOL_SIZE {
                conns.push(open_read_conn(path).await?);
            }
            Arc::new(ReadPool {
                conns,
                next: AtomicUsize::new(0),
            })
        };
        Ok(Self { conn, read_pool })
    }

    fn reader(&self) -> &Connection {
        self.read_pool.pick()
    }

    /// Flush the WAL back into the main database file and close every
    /// connection so `SQLite` can remove the `-wal`/`-shm` sidecar files.
    ///
    /// Read connections are closed first so the writer is the sole open
    /// connection when the truncating checkpoint runs; closing that final
    /// connection is what lets `SQLite` delete the sidecars. Errors are ignored
    /// because this only runs on shutdown — there is nothing left to recover,
    /// and an in-memory database (where readers share the writer connection)
    /// has no files to clean up regardless.
    pub async fn close(self) {
        for c in &self.read_pool.conns {
            let _ = c.clone().close().await;
        }
        let _: Result<(), tokio_rusqlite::Error> = self
            .conn
            .call(|conn| {
                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
                Ok(())
            })
            .await;
        let _ = self.conn.clone().close().await;
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
                    PRAGMA cache_size = -2000;
                    PRAGMA mmap_size = 268435456;
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
                        result TEXT,
                        authenticated_data INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON query_logs(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_query_logs_domain_ts ON query_logs(domain, timestamp);

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
                    ",
                )?;
                Self::run_migrations(conn)?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Run forward-only migrations using PRAGMA `user_version` to track schema version.
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

        if version < 5 {
            // Replace the single-column domain index with a composite
            // (domain, timestamp) index: dashboard aggregations (top_domains,
            // unique_domains) are then served by a covering index with the
            // timestamp filter pushed in, instead of scanning the whole domain
            // index and looking up rows. ANALYZE is REQUIRED here — without
            // fresh sqlite_stat1 the planner keeps the old plan and the new
            // index yields no benefit.
            conn.execute_batch(
                "DROP INDEX IF EXISTS idx_query_logs_domain;
                 CREATE INDEX IF NOT EXISTS idx_query_logs_domain_ts ON query_logs(domain, timestamp);
                 ANALYZE;",
            )?;
        }

        if version < 6 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS users (
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
                DELETE FROM settings WHERE key = 'sessions';",
            )?;
        }

        if version < 7 {
            add_column_if_missing(
                conn,
                "query_logs",
                "authenticated_data",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
        }

        if version < 8 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS api_keys (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    name         TEXT    NOT NULL,
                    token_hash   TEXT    NOT NULL UNIQUE,
                    prefix       TEXT    NOT NULL,
                    created_at   INTEGER NOT NULL,
                    last_used_at INTEGER,
                    expires_at   INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);",
            )?;
        }

        const LATEST_VERSION: i64 = 8;
        if version < LATEST_VERSION {
            conn.pragma_update(None, "user_version", LATEST_VERSION)?;
        }

        Ok(())
    }

    /// List all table names (for testing).
    pub async fn list_tables(&self) -> Result<Vec<String>, DbError> {
        let tables = self
            .reader()
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
            .reader()
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
                        "INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result, authenticated_data) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                            e.authenticated_data,
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
            .reader()
            .call(move |conn| {
                let mut sql = "SELECT timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result, authenticated_data FROM query_logs WHERE 1=1".to_string();
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
                            authenticated_data: row.get::<_, bool>(10)?,
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
            .reader()
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

    /// Periodic database maintenance, run after the hourly retention prune.
    ///
    /// - `PRAGMA optimize` refreshes the query planner's statistics so index
    ///   choices stay sane as the data distribution shifts (also what keeps
    ///   the composite `(domain, timestamp)` index getting picked).
    /// - A `VACUUM` reclaims pages freed by pruning, but only when the free
    ///   list has grown past [`VACUUM_FREELIST_RATIO`] of the file — VACUUM
    ///   rewrites the whole database and briefly holds a write lock, so it is
    ///   not worth doing for the handful of pages a typical hourly prune frees.
    /// - A `wal_checkpoint(TRUNCATE)` truncates the WAL, which a large prune
    ///   (or the VACUUM) can otherwise inflate until the next checkpoint.
    ///
    /// All three are individually cheap (~10ms) except the gated VACUUM.
    pub async fn run_maintenance(&self) -> Result<(), DbError> {
        self.conn
            .call(|conn| {
                conn.execute_batch("PRAGMA optimize;")?;

                let page_count: i64 =
                    conn.pragma_query_value(None, "page_count", |row| row.get(0))?;
                let freelist: i64 =
                    conn.pragma_query_value(None, "freelist_count", |row| row.get(0))?;
                if page_count > 0 && freelist as f64 / page_count as f64 >= VACUUM_FREELIST_RATIO {
                    conn.execute_batch("VACUUM;")?;
                }

                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
                Ok(())
            })
            .await?;
        Ok(())
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
            .reader()
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
            .reader()
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
            .reader()
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
            .reader()
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
            .reader()
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
            .reader()
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

    /// Validate a `DoH` token. Returns the token string if valid.
    pub async fn validate_doh_token(&self, token: &str) -> Result<Option<String>, DbError> {
        let token = token.to_string();
        let result = self
            .reader()
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
            .reader()
            .call(|conn| {
                let count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM doh_tokens", [], |row| row.get(0))?;
                Ok(count)
            })
            .await?;
        Ok(count > 0)
    }

    // --- API Keys ---

    pub async fn insert_api_key(
        &self,
        user_id: i64,
        name: &str,
        token_hash: &str,
        prefix: &str,
        created_at: i64,
        expires_at: Option<i64>,
    ) -> Result<i64, DbError> {
        let name = name.to_string();
        let token_hash = token_hash.to_string();
        let prefix = prefix.to_string();
        let id = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO api_keys (user_id, name, token_hash, prefix, created_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![user_id, name, token_hash, prefix, created_at, expires_at],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    pub async fn list_api_keys_for_user(&self, user_id: i64) -> Result<Vec<ApiKeyRow>, DbError> {
        let rows = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT id, name, prefix, created_at, last_used_at, expires_at
                     FROM api_keys WHERE user_id = ?1 ORDER BY id",
                )?;
                let rows = stmt
                    .query_map(params![user_id], |row| {
                        Ok(ApiKeyRow {
                            id: row.get(0)?,
                            name: row.get(1)?,
                            prefix: row.get(2)?,
                            created_at: row.get(3)?,
                            last_used_at: row.get(4)?,
                            expires_at: row.get(5)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    /// Delete a key scoped to its owner. Returns true if a row was removed.
    pub async fn delete_api_key(&self, id: i64, user_id: i64) -> Result<bool, DbError> {
        let n = self
            .conn
            .call(move |conn| {
                let n = conn.execute(
                    "DELETE FROM api_keys WHERE id = ?1 AND user_id = ?2",
                    params![id, user_id],
                )?;
                Ok(n)
            })
            .await?;
        Ok(n > 0)
    }

    /// Resolve a presented key hash to its owner. Rejects expired keys and
    /// refreshes `last_used_at` at most once per 60s to avoid a write per call.
    ///
    /// The lookup runs on a reader connection so authenticated reads never
    /// contend with the single writer; the writer is only taken when the
    /// throttled `last_used_at` update actually needs to fire.
    pub async fn validate_api_key(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<i64>, DbError> {
        let hash_for_lookup = token_hash.to_string();
        let row = self
            .reader()
            .call(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT id, user_id, expires_at, last_used_at
                         FROM api_keys WHERE token_hash = ?1",
                        params![hash_for_lookup],
                        |r| {
                            Ok((
                                r.get::<_, i64>(0)?,
                                r.get::<_, i64>(1)?,
                                r.get::<_, Option<i64>>(2)?,
                                r.get::<_, Option<i64>>(3)?,
                            ))
                        },
                    )
                    .optional()?;
                Ok(row)
            })
            .await?;
        let Some((id, user_id, expires_at, last_used_at)) = row else {
            return Ok(None);
        };
        if let Some(exp) = expires_at
            && exp <= now
        {
            return Ok(None);
        }
        let stale = match last_used_at {
            None => true,
            Some(t) => now - t >= 60,
        };
        if stale {
            self.conn
                .call(move |conn| {
                    conn.execute(
                        "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
                        params![now, id],
                    )?;
                    Ok(())
                })
                .await?;
        }
        Ok(Some(user_id))
    }

    // --- Users ---

    pub async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        created_at: i64,
    ) -> Result<i64, DbError> {
        let username = username.to_string();
        let password_hash = password_hash.to_string();
        let id = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
                    params![username, password_hash, created_at],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    pub async fn get_user_auth(&self, username: &str) -> Result<Option<UserAuth>, DbError> {
        let username = username.to_string();
        let row = self
            .reader()
            .call(move |conn| {
                let mut stmt =
                    conn.prepare_cached("SELECT id, password_hash FROM users WHERE username = ?1")?;
                let r = stmt
                    .query_row(params![username], |row| {
                        Ok(UserAuth {
                            id: row.get(0)?,
                            password_hash: row.get(1)?,
                        })
                    })
                    .optional()?;
                Ok(r)
            })
            .await?;
        Ok(row)
    }

    pub async fn get_user_password_hash(&self, id: i64) -> Result<Option<String>, DbError> {
        let val = self
            .reader()
            .call(move |conn| {
                let mut stmt =
                    conn.prepare_cached("SELECT password_hash FROM users WHERE id = ?1")?;
                let r = stmt
                    .query_row(params![id], |row| row.get::<_, String>(0))
                    .optional()?;
                Ok(r)
            })
            .await?;
        Ok(val)
    }

    pub async fn update_user_password(&self, id: i64, password_hash: &str) -> Result<(), DbError> {
        let password_hash = password_hash.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE users SET password_hash = ?1 WHERE id = ?2",
                    params![password_hash, id],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn list_users(&self) -> Result<Vec<UserRow>, DbError> {
        let rows = self
            .reader()
            .call(|conn| {
                let mut stmt =
                    conn.prepare_cached("SELECT id, username, created_at FROM users ORDER BY id")?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(UserRow {
                            id: row.get(0)?,
                            username: row.get(1)?,
                            created_at: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn count_users(&self) -> Result<i64, DbError> {
        let n = self
            .reader()
            .call(|conn| {
                let mut stmt = conn.prepare_cached("SELECT COUNT(*) FROM users")?;
                let n: i64 = stmt.query_row([], |row| row.get(0))?;
                Ok(n)
            })
            .await?;
        Ok(n)
    }

    pub async fn delete_user(&self, id: i64) -> Result<DeleteUserOutcome, DbError> {
        let outcome = self
            .conn
            .call(move |conn| {
                // Guard and delete in one writer closure so the count and the
                // delete cannot interleave with a concurrent deletion — that
                // race could otherwise remove the last two operators at once and
                // lock everyone out of the instance.
                let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
                if count <= 1 {
                    return Ok(DeleteUserOutcome::LastOperator);
                }
                let n = conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
                Ok(if n > 0 {
                    DeleteUserOutcome::Deleted
                } else {
                    DeleteUserOutcome::NotFound
                })
            })
            .await?;
        Ok(outcome)
    }

    pub async fn get_username(&self, id: i64) -> Result<Option<String>, DbError> {
        let val = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached("SELECT username FROM users WHERE id = ?1")?;
                let r = stmt
                    .query_row(params![id], |row| row.get::<_, String>(0))
                    .optional()?;
                Ok(r)
            })
            .await?;
        Ok(val)
    }

    // --- Sessions ---

    pub async fn insert_session(
        &self,
        token: &str,
        user_id: i64,
        created_at: i64,
        last_seen: i64,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<i64, DbError> {
        let token = token.to_string();
        let ip = ip.map(|s| s.to_string());
        let user_agent = user_agent.map(|s| s.to_string());
        let id = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO sessions (token, user_id, created_at, last_seen, ip, user_agent)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![token, user_id, created_at, last_seen, ip, user_agent],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    pub async fn delete_session_by_token(&self, token: &str) -> Result<(), DbError> {
        let token = token.to_string();
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn delete_session_by_id(&self, id: i64) -> Result<Option<String>, DbError> {
        let token = self
            .conn
            .call(move |conn| {
                // Single atomic statement: DELETE ... RETURNING removes the row and
                // yields its token in one step, so there is no SELECT-then-DELETE
                // window where a concurrent revoke of the same id could double-fire.
                let tok: Option<String> = conn
                    .query_row(
                        "DELETE FROM sessions WHERE id = ?1 RETURNING token",
                        params![id],
                        |row| row.get(0),
                    )
                    .optional()?;
                Ok(tok)
            })
            .await?;
        Ok(token)
    }

    pub async fn delete_all_sessions(&self) -> Result<(), DbError> {
        self.conn
            .call(|conn| {
                conn.execute("DELETE FROM sessions", [])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionRow>, DbError> {
        let rows = self
            .reader()
            .call(|conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT s.id, s.user_id, u.username, s.created_at, s.last_seen, s.ip, s.user_agent, s.token
                     FROM sessions s JOIN users u ON u.id = s.user_id
                     ORDER BY s.last_seen DESC",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(SessionRow {
                            id: row.get(0)?,
                            user_id: row.get(1)?,
                            username: row.get(2)?,
                            created_at: row.get(3)?,
                            last_seen: row.get(4)?,
                            ip: row.get(5)?,
                            user_agent: row.get(6)?,
                            token: row.get(7)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn load_sessions(
        &self,
        max_age_secs: i64,
        now: i64,
    ) -> Result<Vec<LoadedSession>, DbError> {
        let cutoff = now - max_age_secs;
        let rows = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "DELETE FROM sessions WHERE created_at < ?1",
                    params![cutoff],
                )?;
                let mut stmt =
                    conn.prepare("SELECT token, id, user_id, created_at, last_seen FROM sessions")?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(LoadedSession {
                            token: row.get(0)?,
                            id: row.get(1)?,
                            user_id: row.get(2)?,
                            created_at: row.get(3)?,
                            last_seen: row.get(4)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn flush_sessions_last_seen(&self, entries: &[(String, i64)]) -> Result<(), DbError> {
        if entries.is_empty() {
            return Ok(());
        }
        let entries: Vec<(String, i64)> = entries.to_vec();
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                {
                    let mut stmt =
                        tx.prepare_cached("UPDATE sessions SET last_seen = ?1 WHERE token = ?2")?;
                    for (token, last_seen) in &entries {
                        stmt.execute(params![last_seen, token])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    // --- Stats ---

    /// Returns the earliest log timestamp in milliseconds, or None if no logs.
    pub async fn earliest_log_timestamp(&self) -> Result<Option<i64>, DbError> {
        let result = self
            .reader()
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

    /// Returns the latest log timestamp in milliseconds, or None if no logs.
    /// Paired with [`Database::earliest_log_timestamp`] it gives the actual span
    /// of retained data ("Log Coverage").
    pub async fn latest_log_timestamp(&self) -> Result<Option<i64>, DbError> {
        let result = self
            .reader()
            .call(|conn| {
                let ts: Option<i64> = conn
                    .query_row("SELECT MAX(timestamp) FROM query_logs", [], |row| {
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
            .reader()
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

    /// Returns (`cache_hits`, `total_allowed`, `avg_response_ms`) since the given timestamp.
    /// `since` is in seconds (epoch).
    pub async fn cache_stats_since(&self, since: i64) -> Result<(i64, i64, f64), DbError> {
        let since_ms = since * 1000;
        let result = self
            .reader()
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
            .reader()
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

    /// Returns ((`cache_hits`, `allowed_total`, `avg_response_ms`), ...) for today / 7d / 30d in one scan.
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
            .reader()
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
            .reader()
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
            .reader()
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
            .reader()
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

    /// Aggregate query counts into `bucket_secs`-wide time buckets, aligned to
    /// the viewer's local calendar by shifting the epoch by `tz_offset_secs`
    /// (their east-positive UTC offset) before truncating, then shifting back.
    /// The returned `timestamp` is each bucket's start in unix seconds, which a
    /// browser in the same zone renders as the local boundary. A single offset
    /// approximates DST (a bucket spanning a transition can be off by the DST
    /// delta); pass 0 for plain UTC-aligned buckets.
    pub async fn timeline_multi_since(
        &self,
        since: i64, // unix seconds
        bucket_secs: i64,
        tz_offset_secs: i64,
    ) -> Result<Vec<TimelineMultiPoint>, DbError> {
        let since_ms = since * 1000;
        let bucket_ms = bucket_secs * 1000;
        let offset_ms = tz_offset_secs * 1000;
        let result = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT ((timestamp + ?3) / ?1) * ?1 - ?3 AS bucket, \
                            COUNT(*), \
                            COALESCE(SUM(blocked), 0), \
                            COALESCE(SUM(cached), 0) \
                     FROM query_logs \
                     WHERE timestamp >= ?2 \
                     GROUP BY bucket \
                     ORDER BY bucket",
                )?;
                let rows = stmt
                    .query_map(params![bucket_ms, since_ms, offset_ms], |row| {
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
            .reader()
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
            .reader()
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
            .reader()
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
            .reader()
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
        // The previous implementation ran a single window-function query
        // (`ROW_NUMBER() OVER (ORDER BY response_ms)`) which forced SQLite to
        // sort every matching row — ~150 ms for a 30-day window on a 196 k-row
        // DB. Instead, pull the response_ms histogram (response_ms → count,
        // ascending) and derive count/avg/max/p50/p95/p99 in Rust. The
        // histogram is exact because response_ms is integer milliseconds,
        // and SQLite needs only one hash-aggregate over the timestamp range
        // (~40 ms in the same workload).
        let hist: Vec<(i64, i64)> = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT response_ms, COUNT(*) FROM query_logs \
                     WHERE timestamp >= ?1 \
                     GROUP BY response_ms \
                     ORDER BY response_ms",
                )?;
                let rows = stmt
                    .query_map(params![since_ms], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;

        Ok(latency_summary_from_histogram(&hist))
    }

    /// On-disk storage breakdown for the Database Health card. Both figures come
    /// from built-in PRAGMAs (no filesystem stat), so they work uniformly for
    /// file-backed and in-memory databases.
    ///
    /// - `main_bytes`: the main database file (`page_count * page_size`).
    /// - `reclaimable_bytes`: free pages `SQLite` holds but is not using
    ///   (`freelist_count * page_size`); a `VACUUM` would return these to the
    ///   OS. This mirrors the freelist ratio that gates
    ///   [`Database::run_maintenance`].
    pub async fn db_storage_stats(&self) -> Result<StorageStats, DbError> {
        let stats = self
            .reader()
            .call(|conn| {
                let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
                let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
                let freelist: i64 =
                    conn.query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
                Ok(StorageStats {
                    main_bytes: page_count * page_size,
                    reclaimable_bytes: freelist * page_size,
                })
            })
            .await?;
        Ok(stats)
    }

    pub async fn total_log_count(&self) -> Result<i64, DbError> {
        let result = self
            .reader()
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
            .reader()
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

/// Derive a `LatencySummary` from a sorted-ascending response-time histogram.
///
/// The histogram is the list of `(response_ms, count)` pairs returned by the
/// `GROUP BY response_ms` query: each entry says "there were `count` rows with
/// this `response_ms` value." Because `response_ms` is integer milliseconds, the
/// histogram is loss-free (no bucket rounding), so the derived percentiles are
/// bit-identical to those produced by the old `ROW_NUMBER()` SQL.
///
/// Percentile semantics match the SQL version: `p_k` is the value at rank
/// `max(1, floor(total * k))` when rows are sorted ascending by `response_ms`.
fn latency_summary_from_histogram(hist: &[(i64, i64)]) -> LatencySummary {
    let total: i64 = hist.iter().map(|(_, c)| *c).sum();
    if total == 0 {
        return LatencySummary {
            sample_count: 0,
            avg_ms: 0.0,
            p50_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
            max_ms: 0,
        };
    }
    let weighted_sum: i64 = hist.iter().map(|(ms, c)| ms * c).sum();
    let avg_ms = weighted_sum as f64 / total as f64;
    let max_ms = hist.last().map_or(0, |(ms, _)| *ms);

    // Mirror SQL's `MAX(1, CAST(total * p AS INTEGER))` — CAST truncates toward
    // zero, so this is `max(1, floor(total * p))` for non-negative inputs.
    let rank_for = |p: f64| ((total as f64 * p) as i64).max(1);
    let pick = |target: i64| -> i64 {
        let mut cum = 0i64;
        for &(ms, c) in hist {
            cum += c;
            if cum >= target {
                return ms;
            }
        }
        max_ms
    };

    LatencySummary {
        sample_count: total,
        avg_ms,
        p50_ms: pick(rank_for(0.50)),
        p95_ms: pick(rank_for(0.95)),
        p99_ms: pick(rank_for(0.99)),
        max_ms,
    }
}

/// Add a column to `table` if it doesn't already exist.
///
/// `SQLite` doesn't support `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so we
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
/// (search, blocked, `doh_token`, `query_type`); centralising the builder keeps
/// the two code paths from drifting.
///
/// Search semantics: a plain term (no wildcard metachars) does an index-backed
/// prefix match via `GLOB 'term*'`. A term containing `%`, `_`, `*`, or `?`
/// is treated as a user-supplied pattern: glob-style `*`/`?` are translated
/// to LIKE's `%`/`_`, then matched with `LIKE` directly (no auto-wrap), so
/// `*foo*` and `%foo%` both mean "contains foo". Domains are stored
/// lowercase, so the term is lowercased to keep both branches
/// case-insensitive against the column.
fn append_log_filters(
    sql: &mut String,
    search: Option<&str>,
    blocked: Option<bool>,
    token: Option<&str>,
    query_type: Option<&str>,
) -> Vec<Box<dyn rusqlite::types::ToSql>> {
    let mut values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if let Some(s) = search {
        let s = s.trim().to_lowercase();
        if !s.is_empty() {
            if s.contains(['%', '_', '*', '?']) {
                let pattern: String = s
                    .chars()
                    .map(|c| match c {
                        '*' => '%',
                        '?' => '_',
                        other => other,
                    })
                    .collect();
                sql.push_str(" AND domain LIKE ?");
                values.push(Box::new(pattern));
            } else {
                sql.push_str(" AND domain GLOB ?");
                values.push(Box::new(format!("{s}*")));
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migration_v8_adds_api_keys_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v7.db");
        let path_str = path.to_str().unwrap().to_string();

        // Simulate a v7 database with a user and unrelated data.
        {
            let conn = rusqlite::Connection::open(&path_str).unwrap();
            conn.execute_batch(
                "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
                 INSERT INTO users (username, password_hash, created_at) VALUES ('op', 'x', 100);
                 PRAGMA user_version = 7;",
            )
            .unwrap();
        }

        let db = Database::open(&path_str).await.unwrap();

        // Table exists and is usable; user row preserved.
        let id = db
            .insert_api_key(1, "ci", "deadbeef", "noadd_dead", 200, None)
            .await
            .unwrap();
        assert!(id > 0);
        let keys = db.list_api_keys_for_user(1).await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "ci");
        assert_eq!(keys[0].prefix, "noadd_dead");
    }

    #[tokio::test]
    async fn validate_api_key_respects_expiry_and_scoping() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.db");
        let db = Database::open(path.to_str().unwrap()).await.unwrap();
        db.create_user("op", "x", 100).await.unwrap(); // id = 1
        db.create_user("op2", "y", 100).await.unwrap(); // id = 2

        // Live key resolves to its owner.
        db.insert_api_key(1, "live", "hash-live", "noadd_aaaa", 100, None)
            .await
            .unwrap();
        assert_eq!(
            db.validate_api_key("hash-live", 200).await.unwrap(),
            Some(1)
        );

        // Expired key is rejected.
        db.insert_api_key(1, "old", "hash-old", "noadd_bbbb", 100, Some(150))
            .await
            .unwrap();
        assert_eq!(db.validate_api_key("hash-old", 200).await.unwrap(), None);

        // Unknown hash -> None.
        assert_eq!(db.validate_api_key("nope", 200).await.unwrap(), None);

        // delete is owner-scoped: user 2 cannot delete user 1's key.
        let keys = db.list_api_keys_for_user(1).await.unwrap();
        let live_id = keys.iter().find(|k| k.name == "live").unwrap().id;
        assert!(!db.delete_api_key(live_id, 2).await.unwrap());
        assert!(db.delete_api_key(live_id, 1).await.unwrap());
    }

    #[tokio::test]
    async fn validate_api_key_throttles_last_used_updates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("throttle.db");
        let db = Database::open(path.to_str().unwrap()).await.unwrap();
        db.create_user("op", "x", 100).await.unwrap(); // id = 1
        db.insert_api_key(1, "ci", "hash-ci", "noadd_cccc", 100, None)
            .await
            .unwrap();

        async fn last_used(db: &Database) -> Option<i64> {
            db.list_api_keys_for_user(1).await.unwrap()[0].last_used_at
        }

        // `insert_api_key` starts `last_used_at` as NULL, so the first
        // validation is stale and sets it.
        let t0 = 1_000;
        assert_eq!(db.validate_api_key("hash-ci", t0).await.unwrap(), Some(1));
        assert_eq!(last_used(&db).await, Some(t0));

        // Within the 60s throttle window: no update.
        assert_eq!(
            db.validate_api_key("hash-ci", t0 + 30).await.unwrap(),
            Some(1)
        );
        assert_eq!(last_used(&db).await, Some(t0));

        // Past the 60s throttle window: updates again.
        assert_eq!(
            db.validate_api_key("hash-ci", t0 + 61).await.unwrap(),
            Some(1)
        );
        assert_eq!(last_used(&db).await, Some(t0 + 61));
    }

    #[tokio::test]
    async fn deleting_user_cascades_api_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cascade.db");
        let db = Database::open(path.to_str().unwrap()).await.unwrap();
        db.create_user("a", "x", 100).await.unwrap(); // id 1
        db.create_user("b", "y", 100).await.unwrap(); // id 2 (so delete isn't the last operator)
        db.insert_api_key(1, "k", "h", "noadd_cccc", 100, None)
            .await
            .unwrap();
        assert_eq!(
            db.delete_user(1).await.unwrap(),
            crate::db::DeleteUserOutcome::Deleted
        );
        assert!(db.list_api_keys_for_user(1).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn close_removes_wal_sidecar_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("noadd.sqlite3");
        let path_str = path.to_str().unwrap().to_string();

        let db = Database::open(&path_str).await.unwrap();

        // WAL-mode schema creation leaves the sidecar files in place while open.
        let wal = format!("{path_str}-wal");
        let shm = format!("{path_str}-shm");
        assert!(
            std::path::Path::new(&wal).exists(),
            "-wal should exist while open"
        );
        assert!(
            std::path::Path::new(&shm).exists(),
            "-shm should exist while open"
        );

        db.close().await;

        assert!(
            !std::path::Path::new(&wal).exists(),
            "-wal should be removed after close"
        );
        assert!(
            !std::path::Path::new(&shm).exists(),
            "-shm should be removed after close"
        );
        assert!(path.exists(), "main database file should remain");
    }

    fn sample_entry(timestamp: i64, domain: &str) -> QueryLogEntry {
        QueryLogEntry {
            timestamp,
            domain: domain.to_string(),
            query_type: "A".to_string(),
            client_ip: "10.0.0.1".to_string(),
            blocked: false,
            cached: false,
            response_ms: 5,
            upstream: None,
            doh_token: None,
            result: None,
            authenticated_data: false,
        }
    }

    async fn query_log_index_names(db: &Database) -> Vec<String> {
        db.reader()
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='query_logs'",
                )?;
                let names = stmt
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, tokio_rusqlite::Error>(names)
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn fresh_schema_uses_composite_domain_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("noadd.sqlite3");
        let db = Database::open(path.to_str().unwrap()).await.unwrap();

        let indexes = query_log_index_names(&db).await;
        assert!(
            indexes.iter().any(|n| n == "idx_query_logs_domain_ts"),
            "composite (domain, timestamp) index should exist: {indexes:?}"
        );
        assert!(
            !indexes.iter().any(|n| n == "idx_query_logs_domain"),
            "legacy single-column domain index should not exist: {indexes:?}"
        );
    }

    #[tokio::test]
    async fn migration_replaces_legacy_domain_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        let path_str = path.to_str().unwrap().to_string();

        // Simulate a pre-v5 database: the old single-column domain index with
        // user_version = 4.
        {
            let conn = rusqlite::Connection::open(&path_str).unwrap();
            conn.execute_batch(
                "CREATE TABLE query_logs (
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
                CREATE INDEX idx_query_logs_domain ON query_logs(domain);
                PRAGMA user_version = 4;",
            )
            .unwrap();
        }

        let db = Database::open(&path_str).await.unwrap();

        let indexes = query_log_index_names(&db).await;
        assert!(
            !indexes.iter().any(|n| n == "idx_query_logs_domain"),
            "legacy index should be dropped after migration: {indexes:?}"
        );
        assert!(
            indexes.iter().any(|n| n == "idx_query_logs_domain_ts"),
            "composite index should be created by migration: {indexes:?}"
        );
    }

    #[tokio::test]
    async fn migration_v6_drops_credential_and_adds_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v5.db");
        let path_str = path.to_str().unwrap().to_string();

        // Simulate a v5 database holding the old single-password credential and
        // some unrelated business data.
        {
            let conn = rusqlite::Connection::open(&path_str).unwrap();
            conn.execute_batch(
                "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE custom_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, rule_type TEXT NOT NULL);
                 INSERT INTO settings (key, value) VALUES ('admin_password_hash', '$argon2id$xxx');
                 INSERT INTO settings (key, value) VALUES ('sessions', 'tok:123');
                 INSERT INTO settings (key, value) VALUES ('log_retention_days', '14');
                 INSERT INTO custom_rules (rule, rule_type) VALUES ('ads.example.com', 'block');
                 PRAGMA user_version = 5;",
            )
            .unwrap();
        }

        let db = Database::open(&path_str).await.unwrap();

        // Credential + old sessions blob dropped.
        assert!(
            db.get_setting("admin_password_hash")
                .await
                .unwrap()
                .is_none()
        );
        assert!(db.get_setting("sessions").await.unwrap().is_none());
        // Unrelated data preserved.
        assert_eq!(
            db.get_setting("log_retention_days")
                .await
                .unwrap()
                .as_deref(),
            Some("14")
        );
        // New tables exist and are empty.
        let tables = db.list_tables().await.unwrap();
        assert!(tables.contains(&"users".to_string()));
        assert!(tables.contains(&"sessions".to_string()));
        assert_eq!(db.count_users().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn query_log_roundtrips_authenticated_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let db = Database::open(path.to_str().unwrap()).await.unwrap();
        let entry = QueryLogEntry {
            timestamp: 1,
            domain: "example.com".into(),
            query_type: "A".into(),
            client_ip: "127.0.0.1".into(),
            blocked: false,
            cached: false,
            response_ms: 1,
            upstream: Some("1.1.1.1:53".into()),
            doh_token: None,
            result: None,
            authenticated_data: true,
        };
        db.insert_query_logs(&[entry]).await.unwrap();
        let rows = db.query_logs(10, 0, None, None, None, None).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].authenticated_data);
    }

    #[tokio::test]
    async fn run_maintenance_keeps_data_queryable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("noadd.sqlite3");
        let db = Database::open(path.to_str().unwrap()).await.unwrap();

        let entries: Vec<QueryLogEntry> = (0..100)
            .map(|i| sample_entry(1_700_000_000_000 + i, "example.com"))
            .collect();
        db.insert_query_logs(&entries).await.unwrap();

        // Nothing is old enough to prune; maintenance should still succeed
        // (PRAGMA optimize + WAL checkpoint; VACUUM stays below threshold).
        db.prune_logs_before(0).await.unwrap();
        db.run_maintenance().await.unwrap();

        let logs = db.query_logs(10, 0, None, None, None, None).await.unwrap();
        assert_eq!(
            logs.len(),
            10,
            "data should remain queryable after maintenance"
        );
    }
}
