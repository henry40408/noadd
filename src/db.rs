use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{OpenFlags, OptionalExtension, params};
use serde::Serialize;
use thiserror::Error;
use tokio_rusqlite::Connection;

use crate::admin::auth::NO_PASSWORD_SENTINEL;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] tokio_rusqlite::Error),
    #[error("Rusqlite error: {0}")]
    Rusqlite(#[from] rusqlite::Error),
}

impl DbError {
    /// True for a `SQLite` constraint violation (e.g. a duplicate
    /// `users.username`), so callers can answer 409 rather than 500.
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

/// Read-only connections in the pool; each owns a worker thread, so this caps
/// admin/stats query parallelism.
const READ_POOL_SIZE: usize = 4;

/// Free-page fraction at which `run_maintenance` runs a full `VACUUM`; below
/// it the whole-file rewrite and write lock are not worth it.
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
    /// A forward-auth-provisioned account holds
    /// [`NO_PASSWORD_SENTINEL`](crate::admin::auth::NO_PASSWORD_SENTINEL)
    /// here instead of a real hash — password login is impossible for it.
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
    pub username: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    /// `BLAKE2b` digest of the session token, never the token itself (see
    /// `crate::admin::auth::hash_session_token`); also the `SessionStore` key.
    pub token_hash: String,
}

#[derive(Debug, Clone)]
pub struct LoadedSession {
    /// See [`SessionRow::token_hash`].
    pub token_hash: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// Start of the bucket in **Unix seconds**, like the rest of the API
    /// (`query_logs.timestamp` is milliseconds; see [`Database::timeline_since`]).
    pub timestamp: i64,
    pub total: i64,
    pub blocked: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimelineMultiPoint {
    /// Start of the bucket in **Unix seconds**, like [`TimelinePoint::timestamp`].
    pub timestamp: i64,
    pub total: i64,
    pub blocked: i64,
    pub cached: i64,
}

/// One grain of [`Database::metrics_by_bucket_since`]: queries per time bucket
/// and (blocked, cached) pair; the timeline folds these.
#[derive(Debug, Clone)]
pub struct MetricsBucket {
    /// Start of the bucket in **Unix seconds**.
    pub timestamp: i64,
    pub blocked: bool,
    pub cached: bool,
    pub count: i64,
}

/// One grain of [`Database::metrics_window_since`]: queries per outcome, query
/// type and response time. The outcome and query-type breakdowns and the
/// latency percentiles all fold these.
#[derive(Debug, Clone)]
pub struct WindowMetricsRow {
    pub blocked: bool,
    pub cached: bool,
    /// Whether `result` held an answer; carried by the rollup so classifying an
    /// outcome never reads `query_logs`.
    pub has_result: bool,
    pub query_type: String,
    pub response_ms: i64,
    pub count: i64,
}

/// The three Statistics readings folded out of `query_stats_metrics_hour` in
/// one statement, answered together by [`Database::window_metrics_since`].
#[derive(Debug, Clone)]
pub struct WindowMetrics {
    pub outcomes: Vec<(String, i64)>,
    pub query_types: Vec<(String, i64)>,
    pub latency: LatencySummary,
}

/// One window of the dashboard summary — see [`Database::summary_multi_since`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowSummary {
    pub total: i64,
    pub blocked: i64,
    /// Queries that were not blocked; the denominator of the cache hit rate.
    pub allowed: i64,
    /// Cache hits among the allowed queries.
    pub cache_hits: i64,
    /// Mean response time of the allowed queries, 0 when there were none.
    pub avg_response_ms: f64,
}

/// Width of one [`QuarterSeries`] slot, in seconds.
pub const QUARTER_SECS: i64 = 900;

/// Query counts per quarter hour on UTC-epoch boundaries, dense from the first
/// quarter that held a query to the last.
///
/// Every UTC offset in use is a whole number of quarter hours, so the browser
/// folds these exactly into local hours and days (`timelineFromQuarters`,
/// `heatmapFromQuarters` in `app.js`) without the server knowing the offset.
/// [`Database::timeline_multi_since`] and [`Database::hourly_heatmap_since`]
/// answer the same for API callers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct QuarterSeries {
    /// Start of the first quarter, in Unix seconds. 0 when there are none.
    pub start: i64,
    /// Queries in the page's range window, by quarter.
    pub total: Vec<i64>,
    pub blocked: Vec<i64>,
    pub cached: Vec<i64>,
    /// Queries in the heatmap's window (not the range's), by quarter.
    pub heatmap: Vec<i64>,
}

/// Everything the Statistics page folds out of the quarter and metrics
/// rollups, from the one statement [`Database::stats_scan_since`] makes.
#[derive(Debug, Clone)]
pub struct StatsScan {
    pub metrics: WindowMetrics,
    pub series: QuarterSeries,
}

/// Pager counters for the read pool — see
/// [`Database::read_page_cache_stats`].
#[derive(Debug, Clone, Copy)]
pub struct PageCacheStats {
    pub hits: i64,
    pub misses: i64,
}

/// The busiest domains in a window alongside how many distinct ones it held —
/// see [`Database::domain_stats_since`] for why they travel together.
#[derive(Debug, Clone)]
pub struct DomainStats {
    pub unique: i64,
    pub top: Vec<TopDomain>,
}

/// Who asked for what in a window: the busiest domains with the distinct count,
/// and the busiest clients — see [`Database::traffic_lists_since`].
#[derive(Debug, Clone)]
pub struct TrafficLists {
    pub domains: DomainStats,
    pub clients: Vec<TopClient>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeatmapCell {
    pub weekday: i64, // 0 = Sunday, 6 = Saturday (matches strftime('%w'))
    pub hour: i64,    // 0..=23
    pub count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LatencySummary {
    pub sample_count: i64,
    pub p50_ms: i64,
    pub p95_ms: i64,
    pub p99_ms: i64,
}

/// `settings` key holding the maintained `query_logs` row count (internal, not
/// an operator setting).
const QUERY_LOG_COUNT_KEY: &str = "query_log_count";

/// Width of one `query_stats_quarter` row, in milliseconds.
const ROLLUP_QUARTER_MS: i64 = QUARTER_SECS * 1000;

/// Width of one row of the hourly rollups, in milliseconds.
const ROLLUP_HOUR_MS: i64 = 3_600_000;

/// The first rollup unit wholly inside a window that starts at `since_ms`.
///
/// Readers take that unit onward from the rollup and `[since_ms, first *
/// unit_ms)` from `query_logs`. The open end needs nothing: rollups are written
/// in the rows' transaction, so even the current unit is complete.
fn first_whole_unit(since_ms: i64, unit_ms: i64) -> i64 {
    since_ms.div_euclid(unit_ms) + i64::from(since_ms.rem_euclid(unit_ms) != 0)
}

/// Pre-aggregated counts of `query_logs`, one table per grain a reader folds.
///
/// Every dashboard/Statistics reading is a count, sum or histogram over a
/// window that, at default retention, spans the whole table; a rollup row
/// stands for every query sharing its key and unit, so a window reads thousands
/// of rows instead of millions.
///
/// Grains are the coarsest that answer every reader exactly: the quarter hour
/// (finest chart bucket, and every UTC offset in use is a whole number of them)
/// and the hour for lists and histograms. `doh_token` is `''` for plain DNS
/// since a primary key column cannot be `NULL`; `has_result` is spelled out so
/// the trigger does not depend on the generated column from migration 12.
///
/// Inserts are maintained by trigger, so rows written any other way (the e2e
/// fixtures use the `sqlite3` CLI) count too; it writes the same pages as a
/// per-batch grouped upsert. Deletes are not a trigger — it would unwind row by
/// row and disable the truncate optimisation for Clear All — so
/// [`unwind_stats_rollups`] runs in the deleting statement's transaction.
const STATS_ROLLUP_SCHEMA: &str = "
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
";

/// Fills the rollups from existing `query_logs`. The upsert replaces rather
/// than adds, so an interrupted migration can re-run it without doubling.
/// `WHERE true` stops the parser reading `ON CONFLICT` as part of the `SELECT`.
const STATS_ROLLUP_BACKFILL: &str = "
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
";

/// rusqlite's default of 16 statements is fewer than the read connections' hot
/// SQL strings, which would evict on every admin request.
const PREPARED_STATEMENT_CACHE_CAPACITY: usize = 64;

/// Turn off `SQLite`'s global memory accounting, once per process, before any
/// connection exists.
///
/// `SQLITE_CONFIG_MEMSTATUS` (on by default) makes every allocation update
/// process-global counters behind one static mutex. The read pool's
/// aggregations allocate hard (each `GROUP BY` builds a temp b-tree), so
/// concurrent readers queued on that mutex and the pool ran slower than serial
/// queries; `tests/stats_contention_bench.rs` isolates the effect.
///
/// Nothing in this crate reads those counters (`sqlite3_memory_used`,
/// `sqlite3_status`, `soft_heap_limit`), and thread safety is governed by
/// separate mutexes this does not touch.
fn disable_sqlite_memstatus() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: `SQLITE_CONFIG_MEMSTATUS` takes a single `int`, and this runs
        // from a `Once` before any connection opens, as `sqlite3_config`
        // requires (it returns SQLITE_MISUSE once SQLite has initialized).
        // No safe rusqlite wrapper exists for it.
        #[allow(unsafe_code)]
        let rc =
            unsafe { rusqlite::ffi::sqlite3_config(rusqlite::ffi::SQLITE_CONFIG_MEMSTATUS, 0_i32) };
        if rc != rusqlite::ffi::SQLITE_OK {
            // Not fatal, but means something initialized SQLite before us.
            tracing::warn!(
                event = "db.memstatus_config_failed",
                rc,
                "could not disable SQLite global memory accounting"
            );
        }
    });
}

/// Open a read-only connection for admin SELECTs, which under WAL run
/// concurrently with the writer.
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
        // Must precede the process's first connection.
        disable_sqlite_memstatus();
        let conn = Connection::open(path).await?;
        let placeholder_pool = Arc::new(ReadPool {
            conns: vec![conn.clone()],
            next: AtomicUsize::new(0),
        });
        let db_init = Self {
            conn: conn.clone(),
            // Placeholder: schema init must run on the writer before readers
            // open, so WAL is in effect.
            read_pool: placeholder_pool,
        };
        db_init.init_schema().await?;
        // Each ":memory:" connection is its own empty database, so readers
        // share the writer there.
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

    /// Running page-cache hits and misses (`SQLITE_DBSTATUS_CACHE_*`) summed
    /// across the read pool — the unit the `*_page_miss_bench` tests report.
    /// Pages, not time, because they compare across an SSD and the appliance's
    /// SD card. Only meaningful after [`Self::reset_read_page_accounting`].
    pub async fn read_page_cache_stats(&self) -> Result<PageCacheStats, DbError> {
        let mut total = PageCacheStats { hits: 0, misses: 0 };
        for conn in &self.read_pool.conns {
            let stats = conn
                .call(|conn| {
                    let read = |op: std::ffi::c_int| {
                        let (mut current, mut high) = (0, 0);
                        // SAFETY: `handle()` is live for the closure's body, and
                        // both out-params are valid for the call's duration.
                        #[allow(unsafe_code, reason = "no safe wrapper for sqlite3_db_status")]
                        unsafe {
                            rusqlite::ffi::sqlite3_db_status(
                                conn.handle(),
                                op,
                                &raw mut current,
                                &raw mut high,
                                0,
                            );
                        }
                        i64::from(current)
                    };
                    Ok(PageCacheStats {
                        hits: read(rusqlite::ffi::SQLITE_DBSTATUS_CACHE_HIT),
                        misses: read(rusqlite::ffi::SQLITE_DBSTATUS_CACHE_MISS),
                    })
                })
                .await?;
            total.hits += stats.hits;
            total.misses += stats.misses;
        }
        Ok(total)
    }

    /// Make [`Self::read_page_cache_stats`] meaningful and drop the pool's cache
    /// so the next query runs cold. Counters are not reset; callers take a delta.
    ///
    /// Turns `mmap_size` off: pages read through a memory mapping bypass the
    /// pager cache and would report almost no misses. The pages fetched are the
    /// same either way, only the accounting differs.
    pub async fn reset_read_page_accounting(&self) -> Result<(), DbError> {
        for conn in &self.read_pool.conns {
            conn.call(|conn| {
                conn.execute_batch("PRAGMA mmap_size = 0; PRAGMA shrink_memory;")?;
                Ok(())
            })
            .await?;
        }
        Ok(())
    }

    /// Flush the WAL back into the main database file and close every
    /// connection so `SQLite` can remove the `-wal`/`-shm` sidecar files.
    ///
    /// Readers close first so the writer is the sole connection at the
    /// truncating checkpoint. Errors are ignored: this only runs on shutdown.
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
                    ",
                )?;
                Self::run_migrations(conn)?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Run forward-only migrations, tracked by PRAGMA `user_version`. A fresh
    /// database (version 0) runs every step too, so each must be idempotent
    /// against the schema batch above (hence `add_column_if_missing`).
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
            // ANALYZE is required after every index change here: with stale
            // sqlite_stat1 the planner keeps the old plan.
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

        if version < 9 {
            // Session tokens become BLAKE2b digests. Existing raw-token rows are
            // dropped, not rehashed: rehashing would leave the plaintext in
            // freelist pages and the WAL anyway. Operators sign in once more.
            conn.execute_batch(
                "DELETE FROM sessions;
                 ALTER TABLE sessions RENAME COLUMN token TO token_hash;",
            )?;
        }

        if version < 10 {
            // Versions 10, 11, 12, 14 and 15 add indexes for statistics that
            // now read the rollups; version 17 drops them again.
            conn.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_query_logs_client_ts \
                 ON query_logs(client_ip, doh_token, timestamp);
                 ANALYZE;",
            )?;
        }

        if version < 11 {
            conn.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_query_logs_ts_metrics \
                 ON query_logs(timestamp, blocked, cached, response_ms, query_type);
                 ANALYZE;",
            )?;
        }

        if version < 12 {
            // A VIRTUAL generated column costs no table space; the planner
            // would not treat an index on the bare expression as covering.
            add_column_if_missing(
                conn,
                "query_logs",
                "has_result",
                "INTEGER GENERATED ALWAYS AS (result IS NOT NULL AND result != '') VIRTUAL",
            )?;
            conn.execute_batch(
                "DROP INDEX IF EXISTS idx_query_logs_ts_metrics;
                 CREATE INDEX idx_query_logs_ts_metrics \
                 ON query_logs(timestamp, blocked, cached, response_ms, query_type, has_result);
                 ANALYZE;",
            )?;
        }

        if version < 13 {
            // Seed the maintained row count (`QUERY_LOG_COUNT_KEY`); `COUNT(*)`
            // walks a whole index. `WHERE true`: see `STATS_ROLLUP_BACKFILL`.
            conn.execute_batch(
                "INSERT INTO settings (key, value) \
                 SELECT 'query_log_count', COUNT(*) FROM query_logs WHERE true \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            )?;
        }

        if version < 14 {
            conn.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_query_logs_ts_upstream \
                 ON query_logs(timestamp, upstream, response_ms) WHERE upstream IS NOT NULL;
                 ANALYZE;",
            )?;
        }

        if version < 15 {
            // The domain index stays: the query log's domain search seeks it
            // by prefix.
            conn.execute_batch(
                "DROP INDEX IF EXISTS idx_query_logs_client_ts;
                 CREATE INDEX IF NOT EXISTS idx_query_logs_ts_domain_client \
                 ON query_logs(timestamp, domain, client_ip, doh_token);
                 ANALYZE;",
            )?;
        }

        if version < 16 {
            // Statistics rollups (see `STATS_ROLLUP_SCHEMA`), backfilled from
            // the rows already logged.
            conn.execute_batch(STATS_ROLLUP_SCHEMA)?;
            conn.execute_batch(STATS_ROLLUP_BACKFILL)?;
        }

        if version < 17 {
            // Statistics read the rollups, so the timestamp-first statistics
            // indexes go. What is left to index is the query log's filters, and
            // each gets an index leading with what it matches, so a quiet token
            // or record type no longer walks the whole window (see
            // `Database::query_logs` for why the type index carries `blocked`).
            // On large databases the freed pages cross `VACUUM_FREELIST_RATIO`,
            // so the first maintenance after upgrading rewrites the file once.
            conn.execute_batch(
                "DROP INDEX IF EXISTS idx_query_logs_ts_metrics;
                 DROP INDEX IF EXISTS idx_query_logs_ts_upstream;
                 DROP INDEX IF EXISTS idx_query_logs_ts_domain_client;
                 CREATE INDEX IF NOT EXISTS idx_query_logs_token_ts \
                 ON query_logs(doh_token, timestamp);
                 CREATE INDEX IF NOT EXISTS idx_query_logs_blocked_ts \
                 ON query_logs(blocked, timestamp);
                 CREATE INDEX IF NOT EXISTS idx_query_logs_type_blocked_ts \
                 ON query_logs(query_type, blocked, timestamp);
                 ANALYZE;",
            )?;
        }

        const LATEST_VERSION: i64 = 17;
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
                bump_log_count(&tx, entries.len() as i64)?;
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
        let search = search.map(std::string::ToString::to_string);
        let token = token.map(std::string::ToString::to_string);
        let query_type = query_type.map(std::string::ToString::to_string);
        let rows = self
            .reader()
            .call(move |conn| {
                const COLUMNS: &str = "timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result, authenticated_data";
                let mut sql = format!("SELECT {COLUMNS} FROM query_logs WHERE 1=1");
                let mut param_values = append_log_filters(
                    &mut sql,
                    search.as_deref(),
                    blocked,
                    token.as_deref(),
                    query_type.as_deref(),
                );
                if let (Some(qt), [_]) = (&query_type, param_values.as_slice()) {
                    // A query type alone reads `(query_type, blocked, timestamp)`
                    // as two timestamp-ordered runs, one per verdict, and merges
                    // them. `blocked` in the middle of the index (there for the
                    // blocked filter) means one range would read every row of
                    // the type and sort it; each run stops at `offset + limit`.
                    // The runs carry only indexed `id`/`timestamp`, so the table
                    // is read for the page's rows alone.
                    sql = format!(
                        "SELECT {COLUMNS} FROM query_logs WHERE id IN ( \
                         SELECT id FROM ( \
                         SELECT id, timestamp FROM (SELECT id, timestamp FROM query_logs \
                         INDEXED BY idx_query_logs_type_blocked_ts \
                         WHERE query_type = ?1 AND blocked = 0 ORDER BY timestamp DESC LIMIT ?2) \
                         UNION ALL \
                         SELECT id, timestamp FROM (SELECT id, timestamp FROM query_logs \
                         INDEXED BY idx_query_logs_type_blocked_ts \
                         WHERE query_type = ?1 AND blocked = 1 ORDER BY timestamp DESC LIMIT ?2) \
                         ORDER BY timestamp DESC LIMIT ?3 OFFSET ?4)) \
                         ORDER BY timestamp DESC"
                    );
                    // Mirror `SQLite`: negative `LIMIT` is none, negative
                    // `OFFSET` is zero (`/api/logs` passes both through).
                    let run = if limit < 0 {
                        -1
                    } else {
                        offset.max(0).saturating_add(limit)
                    };
                    param_values = vec![
                        Box::new(qt.clone()),
                        Box::new(run),
                        Box::new(limit),
                        Box::new(offset),
                    ];
                } else {
                    sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
                    param_values.push(Box::new(limit));
                    param_values.push(Box::new(offset));
                }

                let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                    param_values.iter().map(std::convert::AsRef::as_ref).collect();

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

    /// Has this appliance ever logged a query? `EXISTS` stops at the first row.
    ///
    /// # Errors
    ///
    /// Fails when the query cannot be run.
    pub async fn has_any_query_logs(&self) -> Result<bool, DbError> {
        let exists = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM query_logs)")?;
                stmt.query_row([], |row| row.get::<_, i64>(0))
            })
            .await?;
        Ok(exists != 0)
    }

    pub async fn count_logs(
        &self,
        search: Option<&str>,
        blocked: Option<bool>,
        token: Option<&str>,
        query_type: Option<&str>,
    ) -> Result<i64, DbError> {
        let search = search.map(std::string::ToString::to_string);
        let token = token.map(std::string::ToString::to_string);
        let query_type = query_type.map(std::string::ToString::to_string);
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
                // Unfiltered: use the maintained count instead of walking an index.
                if param_values.is_empty() {
                    return read_log_count(conn);
                }

                let params_refs: Vec<&dyn rusqlite::types::ToSql> = param_values
                    .iter()
                    .map(std::convert::AsRef::as_ref)
                    .collect();

                let mut stmt = conn.prepare_cached(&sql)?;
                stmt.query_row(params_refs.as_slice(), |row| row.get(0))
            })
            .await?;
        Ok(count)
    }

    pub async fn delete_all_logs(&self) -> Result<(), DbError> {
        self.conn
            .call(|conn| {
                let tx = conn.transaction()?;
                tx.execute("DELETE FROM query_logs", [])?;
                tx.execute_batch(
                    "DELETE FROM query_stats_quarter;
                     DELETE FROM query_stats_domain_hour;
                     DELETE FROM query_stats_client_hour;
                     DELETE FROM query_stats_upstream_hour;
                     DELETE FROM query_stats_metrics_hour;",
                )?;
                set_log_count(&tx, 0)?;
                tx.commit()?;
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
                let tx = conn.transaction()?;
                unwind_stats_rollups(&tx, timestamp_ms)?;
                let deleted = tx.execute(
                    "DELETE FROM query_logs WHERE timestamp < ?1",
                    params![timestamp_ms],
                )?;
                bump_log_count(&tx, -(deleted as i64))?;
                tx.commit()?;
                Ok(deleted as u64)
            })
            .await?;
        Ok(count)
    }

    /// Periodic database maintenance, run after the hourly retention prune.
    ///
    /// - `PRAGMA optimize` keeps planner statistics current.
    /// - `VACUUM` only past [`VACUUM_FREELIST_RATIO`], since it rewrites the
    ///   whole file under a write lock.
    /// - `wal_checkpoint(TRUNCATE)` shrinks a WAL a large prune or VACUUM grew.
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

    /// One list's URL by id, without loading every list.
    pub async fn filter_list_url(&self, id: i64) -> Result<Option<String>, DbError> {
        let url = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached("SELECT url FROM filter_lists WHERE id = ?1")?;
                let url = stmt
                    .query_row(params![id], |row| row.get::<_, String>(0))
                    .optional()?;
                Ok(url)
            })
            .await?;
        Ok(url)
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

    /// Resolve a presented key hash to its owner, rejecting expired keys.
    /// Looks up on a reader; the writer is taken only for the `last_used_at`
    /// refresh, throttled to once per 60s.
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

    /// Create a passwordless operator provisioned from a trusted forward-auth
    /// header; its hash is
    /// [`NO_PASSWORD_SENTINEL`](crate::admin::auth::NO_PASSWORD_SENTINEL).
    pub async fn create_user_no_password(
        &self,
        username: &str,
        created_at: i64,
    ) -> Result<i64, DbError> {
        let username = username.to_string();
        let id = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
                    params![username, NO_PASSWORD_SENTINEL, created_at],
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

    /// `None` means no such user.
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
                // Count and delete in one writer closure, so two concurrent
                // deletions cannot remove the last two operators.
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

    /// Persist a session. `token_hash` is the digest, never the raw token —
    /// see [`SessionRow::token_hash`].
    pub async fn insert_session(
        &self,
        token_hash: &str,
        user_id: i64,
        created_at: i64,
        last_seen: i64,
        ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<i64, DbError> {
        let token_hash = token_hash.to_string();
        let ip = ip.map(std::string::ToString::to_string);
        let user_agent = user_agent.map(std::string::ToString::to_string);
        let id = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO sessions (token_hash, user_id, created_at, last_seen, ip, user_agent)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![token_hash, user_id, created_at, last_seen, ip, user_agent],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    pub async fn delete_session_by_token_hash(&self, token_hash: &str) -> Result<(), DbError> {
        let token_hash = token_hash.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "DELETE FROM sessions WHERE token_hash = ?1",
                    params![token_hash],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Delete the session with `id`, returning its `token_hash` so the caller
    /// can evict the matching in-memory entry.
    pub async fn delete_session_by_id(&self, id: i64) -> Result<Option<String>, DbError> {
        let token_hash = self
            .conn
            .call(move |conn| {
                // DELETE ... RETURNING: no SELECT-then-DELETE window for a
                // concurrent revoke of the same id to double-fire.
                let hash: Option<String> = conn
                    .query_row(
                        "DELETE FROM sessions WHERE id = ?1 RETURNING token_hash",
                        params![id],
                        |row| row.get(0),
                    )
                    .optional()?;
                Ok(hash)
            })
            .await?;
        Ok(token_hash)
    }

    /// Delete every session. Returns the number of rows removed.
    pub async fn delete_all_sessions(&self) -> Result<usize, DbError> {
        let n = self
            .conn
            .call(|conn| conn.execute("DELETE FROM sessions", []))
            .await?;
        Ok(n)
    }

    /// Delete every session except `keep_token_hash` (log out other devices).
    /// Returns the number of rows removed.
    pub async fn delete_sessions_except(&self, keep_token_hash: &str) -> Result<usize, DbError> {
        let keep_token_hash = keep_token_hash.to_string();
        let n = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "DELETE FROM sessions WHERE token_hash != ?1",
                    params![keep_token_hash],
                )
            })
            .await?;
        Ok(n)
    }

    /// Delete `user_id`'s sessions except `keep_token_hash` (`None` deletes all
    /// of them); other operators are untouched. Returns rows deleted.
    pub async fn delete_user_sessions_except(
        &self,
        user_id: i64,
        keep_token_hash: Option<&str>,
    ) -> Result<usize, DbError> {
        let keep_token_hash = keep_token_hash.map(str::to_string);
        let deleted =
            self.conn
                .call(move |conn| {
                    let n = match &keep_token_hash {
                        Some(hash) => conn.execute(
                            "DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2",
                            params![user_id, hash],
                        )?,
                        None => conn
                            .execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?,
                    };
                    Ok(n)
                })
                .await?;
        Ok(deleted)
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionRow>, DbError> {
        let rows = self
            .reader()
            .call(|conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT s.id, u.username, s.created_at, s.last_seen, s.ip, s.user_agent, s.token_hash
                     FROM sessions s JOIN users u ON u.id = s.user_id
                     ORDER BY s.last_seen DESC",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(SessionRow {
                            id: row.get(0)?,
                            username: row.get(1)?,
                            created_at: row.get(2)?,
                            last_seen: row.get(3)?,
                            ip: row.get(4)?,
                            user_agent: row.get(5)?,
                            token_hash: row.get(6)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    /// Predicate shared by `purge_expired_sessions` and `load_sessions`.
    ///
    /// `<=`, not `<`, to agree at the exact boundary with the `>=` expiry in
    /// `validate_session` / `prune_expired` (`src/admin/auth.rs`).
    const PURGE_EXPIRED_SESSIONS_SQL: &str =
        "DELETE FROM sessions WHERE created_at <= ?1 OR last_seen <= ?2";

    /// Delete session rows past either timeout; returns rows removed. Shared by
    /// startup restore (`load_sessions`) and the periodic sweep.
    pub async fn purge_expired_sessions(
        &self,
        max_age_secs: i64,
        idle_secs: i64,
        now: i64,
    ) -> Result<usize, DbError> {
        let absolute_cutoff = now - max_age_secs;
        let idle_cutoff = now - idle_secs;
        let deleted = self
            .conn
            .call(move |conn| {
                let n = conn.execute(
                    Self::PURGE_EXPIRED_SESSIONS_SQL,
                    params![absolute_cutoff, idle_cutoff],
                )?;
                Ok(n)
            })
            .await?;
        Ok(deleted)
    }

    pub async fn load_sessions(
        &self,
        max_age_secs: i64,
        idle_secs: i64,
        now: i64,
    ) -> Result<Vec<LoadedSession>, DbError> {
        let absolute_cutoff = now - max_age_secs;
        let idle_cutoff = now - idle_secs;
        let rows = self
            .conn
            .call(move |conn| {
                conn.execute(
                    Self::PURGE_EXPIRED_SESSIONS_SQL,
                    params![absolute_cutoff, idle_cutoff],
                )?;
                let mut stmt = conn.prepare(
                    "SELECT token_hash, id, user_id, created_at, last_seen FROM sessions",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(LoadedSession {
                            token_hash: row.get(0)?,
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

    /// Flush `last_seen` for each `(token_hash, last_seen)` pair.
    pub async fn flush_sessions_last_seen(&self, entries: &[(String, i64)]) -> Result<(), DbError> {
        if entries.is_empty() {
            return Ok(());
        }
        let entries: Vec<(String, i64)> = entries.to_vec();
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare_cached(
                        "UPDATE sessions SET last_seen = ?1 WHERE token_hash = ?2",
                    )?;
                    for (token_hash, last_seen) in &entries {
                        stmt.execute(params![last_seen, token_hash])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await?;
        Ok(())
    }

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
    /// With [`Database::earliest_log_timestamp`], the retained span.
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

    /// Count queries logged since `since` (epoch seconds).
    pub async fn count_queries_since(&self, since: i64) -> Result<i64, DbError> {
        let since_ms = since * 1000;
        let result = self
            .reader()
            .call(move |conn| {
                let mut stmt =
                    conn.prepare_cached("SELECT COUNT(*) FROM query_logs WHERE timestamp >= ?1")?;
                let total = stmt.query_row(params![since_ms], |row| row.get::<_, i64>(0))?;
                Ok(total)
            })
            .await?;
        Ok(result)
    }

    /// The dashboard summary's figures for three nested windows, folded out of
    /// `query_stats_quarter`.
    ///
    /// Whole quarters come from the rollup, the partial first quarter from the
    /// table (see `first_whole_unit`). A table row belongs to the one window
    /// whose partial quarter it fills, told apart by the arm it came from.
    ///
    /// All `since_*` values are epoch seconds. Caller MUST pass the widest
    /// window as `since_30d`.
    pub async fn summary_multi_since(
        &self,
        since_today: i64,
        since_7d: i64,
        since_30d: i64,
    ) -> Result<[WindowSummary; 3], DbError> {
        let today_ms = since_today * 1000;
        let d7_ms = since_7d * 1000;
        let d30_ms = since_30d * 1000;
        let quarters = [today_ms, d7_ms, d30_ms].map(|ms| first_whole_unit(ms, ROLLUP_QUARTER_MS));
        let result = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "WITH p AS (
                        SELECT 'r' AS kind, quarter AS k, blocked, cached, count AS n, sum_ms AS ms
                            FROM query_stats_quarter WHERE quarter >= ?6
                        UNION ALL
                        SELECT 'h1', 0, blocked, cached, 1, response_ms
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?1 AND timestamp < ?4 * 900000
                        UNION ALL
                        SELECT 'h7', 0, blocked, cached, 1, response_ms
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?2 AND timestamp < ?5 * 900000
                        UNION ALL
                        SELECT 'h30', 0, blocked, cached, 1, response_ms
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?3 AND timestamp < ?6 * 900000
                    ),
                    w AS (
                        SELECT (kind = 'h1' OR (kind = 'r' AND k >= ?4)) AS in1,
                               (kind = 'h7' OR (kind = 'r' AND k >= ?5)) AS in7,
                               (kind = 'h30' OR kind = 'r') AS in30,
                               blocked, cached, n, ms
                        FROM p
                    )
                    SELECT
                    COALESCE(SUM(CASE WHEN in1 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in1 THEN n * blocked END), 0),
                    COALESCE(SUM(CASE WHEN in1 AND blocked = 0 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in1 AND blocked = 0 THEN n * cached END), 0),
                    COALESCE(CAST(SUM(CASE WHEN in1 AND blocked = 0 THEN ms END) AS REAL)
                             / SUM(CASE WHEN in1 AND blocked = 0 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in7 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in7 THEN n * blocked END), 0),
                    COALESCE(SUM(CASE WHEN in7 AND blocked = 0 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in7 AND blocked = 0 THEN n * cached END), 0),
                    COALESCE(CAST(SUM(CASE WHEN in7 AND blocked = 0 THEN ms END) AS REAL)
                             / SUM(CASE WHEN in7 AND blocked = 0 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in30 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in30 THEN n * blocked END), 0),
                    COALESCE(SUM(CASE WHEN in30 AND blocked = 0 THEN n END), 0),
                    COALESCE(SUM(CASE WHEN in30 AND blocked = 0 THEN n * cached END), 0),
                    COALESCE(CAST(SUM(CASE WHEN in30 AND blocked = 0 THEN ms END) AS REAL)
                             / SUM(CASE WHEN in30 AND blocked = 0 THEN n END), 0)
                    FROM w",
                )?;
                let args = params![
                    today_ms,
                    d7_ms,
                    d30_ms,
                    quarters[0],
                    quarters[1],
                    quarters[2]
                ];
                let row = stmt.query_row(args, |row| {
                    let window = |at: usize| -> rusqlite::Result<WindowSummary> {
                        Ok(WindowSummary {
                            total: row.get(at)?,
                            blocked: row.get(at + 1)?,
                            allowed: row.get(at + 2)?,
                            cache_hits: row.get(at + 3)?,
                            avg_response_ms: row.get(at + 4)?,
                        })
                    };
                    Ok([window(0)?, window(5)?, window(10)?])
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
        Ok(self.domain_stats_since(since, limit).await?.top)
    }

    /// The busiest domains in the window and how many distinct ones there were,
    /// folded out of `query_stats_domain_hour`.
    ///
    /// Whole hours from the rollup, the partial first hour from the table (see
    /// `first_whole_unit`). The CTE is materialized once so the count and the
    /// list share one grouping; `unique` is 0 exactly when `top` is empty.
    pub async fn domain_stats_since(&self, since: i64, limit: i64) -> Result<DomainStats, DbError> {
        let since_ms = since * 1000;
        let hour = first_whole_unit(since_ms, ROLLUP_HOUR_MS);
        let stats = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "WITH d AS (
                        SELECT domain, SUM(n) AS cnt FROM (
                            SELECT domain, count AS n FROM query_stats_domain_hour WHERE hour >= ?2
                            UNION ALL
                            SELECT domain, 1 FROM query_logs INDEXED BY idx_query_logs_timestamp
                                WHERE timestamp >= ?1 AND timestamp < ?2 * 3600000
                        ) GROUP BY domain
                    )
                    SELECT (SELECT COUNT(*) FROM d), domain, cnt
                    FROM d ORDER BY cnt DESC, domain LIMIT ?3",
                )?;
                let rows = stmt
                    .query_map(params![since_ms, hour, limit], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            TopDomain {
                                domain: row.get(1)?,
                                count: row.get(2)?,
                            },
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                let unique = rows.first().map_or(0, |(n, _)| *n);
                Ok(DomainStats {
                    unique,
                    top: rows.into_iter().map(|(_, d)| d).collect(),
                })
            })
            .await?;
        Ok(stats)
    }

    /// A fold over [`Self::traffic_lists_since`].
    pub async fn top_clients_since(
        &self,
        since: i64,
        limit: i64,
    ) -> Result<Vec<TopClient>, DbError> {
        Ok(self.traffic_lists_since(since, limit).await?.clients)
    }

    /// The busiest domains, how many distinct ones there were, and the busiest
    /// clients, folded out of `query_stats_domain_hour` and
    /// `query_stats_client_hour`.
    ///
    /// Whole hours from the rollups, the partial first hour from the table (see
    /// `first_whole_unit`). One statement, so both lists read one snapshot; the
    /// first column says which list a row belongs to. Ties break by name, as in
    /// [`Self::domain_stats_since`], so the two agree row for row.
    pub async fn traffic_lists_since(
        &self,
        since: i64,
        limit: i64,
    ) -> Result<TrafficLists, DbError> {
        let since_ms = since * 1000;
        let hour = first_whole_unit(since_ms, ROLLUP_HOUR_MS);
        let limit = usize::try_from(limit).unwrap_or(0);
        let lists = self
            .reader()
            .call(move |conn| {
                // The rollup stores a missing token as ''; `NULLIF` restores `NULL`.
                let mut stmt = conn.prepare_cached(
                    "SELECT 0, domain, NULL, SUM(n) FROM (
                        SELECT domain, count AS n FROM query_stats_domain_hour WHERE hour >= ?2
                        UNION ALL
                        SELECT domain, 1 FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?1 AND timestamp < ?2 * 3600000
                    ) GROUP BY domain
                    UNION ALL
                    SELECT 1, client_ip, NULLIF(token, ''), SUM(n) FROM (
                        SELECT client_ip, doh_token AS token, count AS n
                            FROM query_stats_client_hour WHERE hour >= ?2
                        UNION ALL
                        SELECT client_ip, COALESCE(doh_token, ''), 1
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?1 AND timestamp < ?2 * 3600000
                    ) GROUP BY client_ip, token",
                )?;
                let mut domains: HashMap<String, i64> = HashMap::new();
                let mut clients: HashMap<(String, Option<String>), i64> = HashMap::new();
                let mut rows = stmt.query(params![since_ms, hour])?;
                while let Some(row) = rows.next()? {
                    let count: i64 = row.get(3)?;
                    if row.get::<_, i64>(0)? == 0 {
                        domains.insert(row.get(1)?, count);
                    } else {
                        clients.insert((row.get(1)?, row.get(2)?), count);
                    }
                }
                Ok((domains, clients))
            })
            .await?;
        let (domains, clients) = lists;

        let unique = i64::try_from(domains.len()).unwrap_or(i64::MAX);
        let mut top: Vec<TopDomain> = domains
            .into_iter()
            .map(|(domain, count)| TopDomain { domain, count })
            .collect();
        top.sort_unstable_by(|a, b| b.count.cmp(&a.count).then_with(|| a.domain.cmp(&b.domain)));
        top.truncate(limit);

        let mut clients: Vec<TopClient> = clients
            .into_iter()
            .map(|((client_ip, doh_token), count)| TopClient {
                client_ip,
                doh_token,
                count,
            })
            .collect();
        clients.sort_unstable_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.client_ip.cmp(&b.client_ip))
                .then_with(|| a.doh_token.cmp(&b.doh_token))
        });
        clients.truncate(limit);

        Ok(TrafficLists {
            domains: DomainStats { unique, top },
            clients,
        })
    }

    /// The busiest upstreams in the window with their mean response time,
    /// folded out of `query_stats_upstream_hour`.
    ///
    /// Whole hours from the rollup, the partial first hour from the table (see
    /// `first_whole_unit`). Sum over count equals `AVG` exactly. Ties break by
    /// name, as the other lists do.
    pub async fn top_upstreams_since(
        &self,
        since: i64,
        limit: i64,
    ) -> Result<Vec<TopUpstream>, DbError> {
        let since_ms = since * 1000;
        let hour = first_whole_unit(since_ms, ROLLUP_HOUR_MS);
        let rows = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT upstream, SUM(n) AS cnt, CAST(SUM(ms) AS REAL) / SUM(n) AS avg_ms FROM (
                        SELECT upstream, count AS n, sum_ms AS ms
                            FROM query_stats_upstream_hour WHERE hour >= ?2
                        UNION ALL
                        SELECT upstream, 1, response_ms
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?1 AND timestamp < ?2 * 3600000
                              AND upstream IS NOT NULL
                    ) GROUP BY upstream ORDER BY cnt DESC, upstream LIMIT ?3",
                )?;
                let rows = stmt
                    .query_map(params![since_ms, hour, limit], |row| {
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

    /// Query counts in `bucket_secs`-wide buckets aligned to the viewer's local
    /// calendar via `tz_offset_secs` (east-positive; 0 for UTC). `timestamp` is
    /// each bucket's start in Unix seconds. A single offset approximates DST: a
    /// bucket spanning a transition can be off by the DST delta.
    pub async fn timeline_multi_since(
        &self,
        since: i64, // unix seconds
        bucket_secs: i64,
        tz_offset_secs: i64,
    ) -> Result<Vec<TimelineMultiPoint>, DbError> {
        let buckets = self
            .metrics_by_bucket_since(since, bucket_secs, tz_offset_secs)
            .await?;
        Ok(timeline_from_buckets(&buckets))
    }

    /// The outcome breakdown, the query-type breakdown and the latency
    /// histogram, in one read of `query_stats_metrics_hour`.
    ///
    /// All three fold the same grain, so one scan serves them. The grain has no
    /// time bucket, which would only multiply the rows the folds read.
    pub async fn window_metrics_since(&self, since: i64) -> Result<WindowMetrics, DbError> {
        let rows = self.metrics_window_since(since).await?;
        Ok(WindowMetrics {
            outcomes: outcomes_from_window(&rows),
            query_types: query_types_from_window(&rows),
            latency: latency_from_window(&rows),
        })
    }

    /// The Statistics page's window readings and its charts' series, folded out
    /// of `query_stats_quarter` and `query_stats_metrics_hour`.
    ///
    /// Whole units from the rollups, each window's partial first unit from the
    /// table (see `first_whole_unit`); the charts come out as a
    /// [`QuarterSeries`] for the browser to fold.
    ///
    /// `range_since` bounds the metrics and timeline, `heatmap_since` the
    /// heatmap, each exactly. The first column names the arm: the two rollups,
    /// then the range's partial first hour (which contains its partial first
    /// quarter), then the heatmap's partial first quarter. A table row in both
    /// windows arrives once per arm, and each arm counts it only for its own.
    ///
    /// Folded in Rust rather than grouped in SQL, avoiding a temp b-tree.
    pub async fn stats_scan_since(
        &self,
        range_since: i64,   // unix seconds
        heatmap_since: i64, // unix seconds
    ) -> Result<StatsScan, DbError> {
        let range_ms = range_since * 1000;
        let heatmap_ms = heatmap_since * 1000;
        let range_quarter = first_whole_unit(range_ms, ROLLUP_QUARTER_MS);
        let heatmap_quarter = first_whole_unit(heatmap_ms, ROLLUP_QUARTER_MS);
        let range_hour = first_whole_unit(range_ms, ROLLUP_HOUR_MS);
        let scan = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT 0, quarter, blocked, cached, NULL, NULL, NULL, count
                        FROM query_stats_quarter WHERE quarter >= ?3
                    UNION ALL
                    SELECT 1, hour, blocked, cached, has_result, query_type, response_ms, count
                        FROM query_stats_metrics_hour WHERE hour >= ?4
                    UNION ALL
                    SELECT 2, timestamp, blocked, cached, has_result, query_type, response_ms, 1
                        FROM query_logs INDEXED BY idx_query_logs_timestamp
                        WHERE timestamp >= ?1 AND timestamp < ?4 * 3600000
                    UNION ALL
                    SELECT 3, timestamp, blocked, cached, NULL, NULL, NULL, 1
                        FROM query_logs INDEXED BY idx_query_logs_timestamp
                        WHERE timestamp >= ?2 AND timestamp < ?5 * 900000",
                )?;
                // Keyed by query type first so a repeat type is looked up by
                // `&str` without allocating.
                // (blocked, cached, has_result, response_ms) → count
                type Grains = HashMap<(bool, bool, bool, i64), i64>;
                let mut grains: HashMap<String, Grains> = HashMap::new();
                // quarter index → [total, blocked, cached, heatmap]
                let mut quarters: BTreeMap<i64, [i64; 4]> = BTreeMap::new();
                let args = params![
                    range_ms,
                    heatmap_ms,
                    range_quarter.min(heatmap_quarter),
                    range_hour,
                    heatmap_quarter
                ];
                let mut rows = stmt.query(args)?;
                while let Some(row) = rows.next()? {
                    let arm: i64 = row.get(0)?;
                    let at: i64 = row.get(1)?;
                    let blocked = row.get::<_, i64>(2)? != 0;
                    let cached = row.get::<_, i64>(3)? != 0;
                    let count: i64 = row.get(7)?;
                    match arm {
                        0 => {
                            let slot = quarters.entry(at).or_default();
                            if at >= heatmap_quarter {
                                slot[3] += count;
                            }
                            if at >= range_quarter {
                                slot[0] += count;
                                slot[1] += count * i64::from(blocked);
                                slot[2] += count * i64::from(cached);
                            }
                            continue;
                        }
                        3 => {
                            quarters
                                .entry(at.div_euclid(ROLLUP_QUARTER_MS))
                                .or_default()[3] += 1;
                            continue;
                        }
                        // Arm 2 spans the partial first hour; only its partial
                        // first quarter is missing from arm 0.
                        2 if at < range_quarter * ROLLUP_QUARTER_MS => {
                            let slot = quarters
                                .entry(at.div_euclid(ROLLUP_QUARTER_MS))
                                .or_default();
                            slot[0] += 1;
                            slot[1] += i64::from(blocked);
                            slot[2] += i64::from(cached);
                        }
                        _ => {}
                    }

                    let has_result = row.get::<_, i64>(4)? != 0;
                    let query_type = row.get_ref(5)?.as_str()?;
                    let key = (blocked, cached, has_result, row.get::<_, i64>(6)?);
                    if let Some(by_grain) = grains.get_mut(query_type) {
                        *by_grain.entry(key).or_default() += count;
                    } else {
                        grains.insert(query_type.to_owned(), HashMap::from([(key, count)]));
                    }
                }

                let window: Vec<WindowMetricsRow> = grains
                    .into_iter()
                    .flat_map(|(query_type, by_grain)| {
                        by_grain.into_iter().map(
                            move |((blocked, cached, has_result, response_ms), count)| {
                                WindowMetricsRow {
                                    blocked,
                                    cached,
                                    has_result,
                                    query_type: query_type.clone(),
                                    response_ms,
                                    count,
                                }
                            },
                        )
                    })
                    .collect();
                Ok(StatsScan {
                    metrics: WindowMetrics {
                        outcomes: outcomes_from_window(&window),
                        query_types: query_types_from_window(&window),
                        latency: latency_from_window(&window),
                    },
                    series: series_from_quarters(&quarters),
                })
            })
            .await?;
        Ok(scan)
    }

    /// Query counts by time bucket, folded out of `query_stats_quarter`.
    ///
    /// When bucket and offset are whole quarters, each quarter lies inside one
    /// bucket (the API rounds `tz_offset` to a quarter hour for this); the
    /// partial first quarter comes from the table (see `first_whole_unit`).
    /// Anything finer counts the table directly.
    async fn metrics_by_bucket_since(
        &self,
        since: i64, // unix seconds
        bucket_secs: i64,
        tz_offset_secs: i64,
    ) -> Result<Vec<MetricsBucket>, DbError> {
        let since_ms = since * 1000;
        let bucket_ms = bucket_secs * 1000;
        let offset_ms = tz_offset_secs * 1000;
        let quarter = first_whole_unit(since_ms, ROLLUP_QUARTER_MS);
        let result = self
            .reader()
            .call(move |conn| {
                let bucket = |row: &rusqlite::Row<'_>| {
                    Ok(MetricsBucket {
                        timestamp: row.get::<_, i64>(0)? / 1000, // return seconds
                        blocked: row.get::<_, i64>(1)? != 0,
                        cached: row.get::<_, i64>(2)? != 0,
                        count: row.get(3)?,
                    })
                };
                let rows =
                    if bucket_ms % ROLLUP_QUARTER_MS == 0 && offset_ms % ROLLUP_QUARTER_MS == 0 {
                        conn.prepare_cached(
                            "SELECT bucket, blocked, cached, SUM(n) FROM (
                            SELECT ((quarter * 900000 + ?3) / ?1) * ?1 - ?3 AS bucket,
                                   blocked, cached, count AS n
                                FROM query_stats_quarter WHERE quarter >= ?4
                            UNION ALL
                            SELECT ((timestamp + ?3) / ?1) * ?1 - ?3, blocked, cached, 1
                                FROM query_logs INDEXED BY idx_query_logs_timestamp
                                WHERE timestamp >= ?2 AND timestamp < ?4 * 900000
                        ) GROUP BY bucket, blocked, cached ORDER BY bucket",
                        )?
                        .query_map(params![bucket_ms, since_ms, offset_ms, quarter], bucket)?
                        .collect::<Result<Vec<_>, _>>()?
                    } else {
                        conn.prepare_cached(
                            "SELECT ((timestamp + ?3) / ?1) * ?1 - ?3 AS bucket, \
                                blocked, cached, COUNT(*) \
                         FROM query_logs \
                         WHERE timestamp >= ?2 \
                         GROUP BY bucket, blocked, cached \
                         ORDER BY bucket",
                        )?
                        .query_map(params![bucket_ms, since_ms, offset_ms], bucket)?
                        .collect::<Result<Vec<_>, _>>()?
                    };
                Ok(rows)
            })
            .await?;
        Ok(result)
    }

    /// Query counts by outcome class, type and response time, from
    /// `query_stats_metrics_hour` plus the table for the partial first hour.
    async fn metrics_window_since(
        &self,
        since: i64, // unix seconds
    ) -> Result<Vec<WindowMetricsRow>, DbError> {
        let since_ms = since * 1000;
        let hour = first_whole_unit(since_ms, ROLLUP_HOUR_MS);
        let rows = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT blocked, cached, has_result, query_type, response_ms, SUM(n) FROM (
                        SELECT blocked, cached, has_result, query_type, response_ms, count AS n
                            FROM query_stats_metrics_hour WHERE hour >= ?2
                        UNION ALL
                        SELECT blocked, cached, has_result, query_type, response_ms, 1
                            FROM query_logs INDEXED BY idx_query_logs_timestamp
                            WHERE timestamp >= ?1 AND timestamp < ?2 * 3600000
                    ) GROUP BY blocked, cached, has_result, query_type, response_ms",
                )?;
                let rows = stmt
                    .query_map(params![since_ms, hour], |row| {
                        Ok(WindowMetricsRow {
                            blocked: row.get::<_, i64>(0)? != 0,
                            cached: row.get::<_, i64>(1)? != 0,
                            has_result: row.get::<_, i64>(2)? != 0,
                            query_type: row.get(3)?,
                            response_ms: row.get(4)?,
                            count: row.get(5)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    /// Query counts by weekday and hour in the viewer's local calendar, via
    /// `tz_offset_secs` (east-positive; 0 for UTC), with the same DST caveat as
    /// [`Self::timeline_multi_since`].
    ///
    /// A whole-quarter offset (every zone in use, every offset the API passes)
    /// folds `query_stats_quarter` plus the table for the partial first
    /// quarter; any other offset counts the table directly.
    pub async fn hourly_heatmap_since(
        &self,
        since: i64, // unix seconds
        tz_offset_secs: i64,
    ) -> Result<Vec<HeatmapCell>, DbError> {
        let since_ms = since * 1000;
        let quarter = first_whole_unit(since_ms, ROLLUP_QUARTER_MS);
        let result = self
            .reader()
            .call(move |conn| {
                // Integer arithmetic rather than `strftime`, which formats two
                // strings per row. `+ 4`: 1970-01-01 was a Thursday and
                // `strftime('%w')` counts from Sunday = 0. Truncating division
                // equals flooring here since shifted seconds are non-negative.
                let cell = |row: &rusqlite::Row<'_>| {
                    Ok(HeatmapCell {
                        weekday: row.get(0)?,
                        hour: row.get(1)?,
                        count: row.get(2)?,
                    })
                };
                let rows = if tz_offset_secs % QUARTER_SECS == 0 {
                    conn.prepare_cached(
                        "SELECT (s / 86400 + 4) % 7 AS wday, s % 86400 / 3600 AS hr, SUM(n) FROM (
                            SELECT quarter * 900 + ?2 AS s, count AS n
                                FROM query_stats_quarter WHERE quarter >= ?3
                            UNION ALL
                            SELECT timestamp / 1000 + ?2, 1
                                FROM query_logs INDEXED BY idx_query_logs_timestamp
                                WHERE timestamp >= ?1 AND timestamp < ?3 * 900000
                        ) GROUP BY wday, hr ORDER BY wday, hr",
                    )?
                    .query_map(params![since_ms, tz_offset_secs, quarter], cell)?
                    .collect::<Result<Vec<_>, _>>()?
                } else {
                    // Reads only `timestamp`; otherwise the planner picks a
                    // wider index.
                    conn.prepare_cached(
                        "SELECT ((timestamp / 1000 + ?2) / 86400 + 4) % 7 AS wday, \
                                (timestamp / 1000 + ?2) % 86400 / 3600 AS hr, \
                                COUNT(*) \
                         FROM query_logs INDEXED BY idx_query_logs_timestamp \
                         WHERE timestamp >= ?1 \
                         GROUP BY wday, hr \
                         ORDER BY wday, hr",
                    )?
                    .query_map(params![since_ms, tz_offset_secs], cell)?
                    .collect::<Result<Vec<_>, _>>()?
                };
                Ok(rows)
            })
            .await?;
        Ok(result)
    }

    pub async fn query_type_breakdown_since(
        &self,
        since: i64,
    ) -> Result<Vec<(String, i64)>, DbError> {
        let rows = self.metrics_window_since(since).await?;
        Ok(query_types_from_window(&rows))
    }

    pub async fn outcome_breakdown_since(&self, since: i64) -> Result<Vec<(String, i64)>, DbError> {
        let rows = self.metrics_window_since(since).await?;
        Ok(outcomes_from_window(&rows))
    }

    pub async fn unique_domains_since(&self, since: i64) -> Result<i64, DbError> {
        Ok(self.domain_stats_since(since, 1).await?.unique)
    }

    /// Percentiles over `response_ms`, derived from the histogram
    /// [`Self::metrics_window_since`] returns — exact, since `response_ms` is
    /// integer milliseconds, and no sort of every row.
    pub async fn latency_summary_since(&self, since: i64) -> Result<LatencySummary, DbError> {
        let rows = self.metrics_window_since(since).await?;
        Ok(latency_from_window(&rows))
    }

    /// Storage breakdown for the Database Health card, from PRAGMAs (no
    /// filesystem stat, so in-memory databases work too).
    ///
    /// - `main_bytes`: `page_count * page_size`.
    /// - `reclaimable_bytes`: `freelist_count * page_size`, what a `VACUUM`
    ///   would return (see [`Database::run_maintenance`]).
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

    /// How many rows `query_logs` holds, from the maintained counter rather
    /// than `COUNT(*)` (which walks a whole index). The counter moves inside the
    /// transaction of every insert, prune and clear; [`Self::count_logs`] reads
    /// it too when unfiltered. With no counter row, it counts.
    pub async fn total_log_count(&self) -> Result<i64, DbError> {
        let result = self.reader().call(|conn| read_log_count(conn)).await?;
        Ok(result)
    }

    /// Bucket queries into a total/blocked timeline on UTC-epoch boundaries.
    ///
    /// Takes and returns Unix **seconds**; milliseconds exist only inside the
    /// query.
    pub async fn timeline_since(
        &self,
        since: i64, // unix seconds
        bucket_secs: i64,
    ) -> Result<Vec<TimelinePoint>, DbError> {
        let since_ms = since * 1000;
        let bucket_ms = bucket_secs * 1000;
        let quarter = first_whole_unit(since_ms, ROLLUP_QUARTER_MS);
        let rows = self
            .reader()
            .call(move |conn| {
                // Whole-quarter buckets fold the rollup. Finer buckets only
                // occur while the log is a few hours old, so counting the table
                // directly is cheap.
                let point = |row: &rusqlite::Row<'_>| {
                    Ok(TimelinePoint {
                        timestamp: row.get::<_, i64>(0)? / 1000, // return seconds
                        total: row.get(1)?,
                        blocked: row.get(2)?,
                    })
                };
                let rows = if bucket_ms % ROLLUP_QUARTER_MS == 0 {
                    conn.prepare_cached(
                        "SELECT bucket, SUM(total), SUM(blocked) FROM (
                            SELECT (quarter * 900000 / ?1) * ?1 AS bucket,
                                   count AS total, blocked * count AS blocked
                                FROM query_stats_quarter WHERE quarter >= ?3
                            UNION ALL
                            SELECT (timestamp / ?1) * ?1, 1, blocked
                                FROM query_logs INDEXED BY idx_query_logs_timestamp
                                WHERE timestamp >= ?2 AND timestamp < ?3 * 900000
                        ) GROUP BY bucket ORDER BY bucket",
                    )?
                    .query_map(params![bucket_ms, since_ms, quarter], point)?
                    .collect::<Result<Vec<_>, _>>()?
                } else {
                    conn.prepare_cached(
                        "SELECT (timestamp / ?1) * ?1 as bucket, COUNT(*) as total, \
                         COALESCE(SUM(blocked), 0) as blocked FROM query_logs \
                         WHERE timestamp >= ?2 GROUP BY bucket ORDER BY bucket",
                    )?
                    .query_map(params![bucket_ms, since_ms], point)?
                    .collect::<Result<Vec<_>, _>>()?
                };
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }
}

/// Sum each bucket's classifications back into one point per bucket. Input is
/// ordered by bucket, so the output is too.
fn timeline_from_buckets(buckets: &[MetricsBucket]) -> Vec<TimelineMultiPoint> {
    let mut out: Vec<TimelineMultiPoint> = Vec::new();
    for b in buckets {
        let point = match out.last_mut() {
            Some(p) if p.timestamp == b.timestamp => p,
            _ => {
                out.push(TimelineMultiPoint {
                    timestamp: b.timestamp,
                    total: 0,
                    blocked: 0,
                    cached: 0,
                });
                out.last_mut().expect("just pushed")
            }
        };
        point.total += b.count;
        if b.blocked {
            point.blocked += b.count;
        }
        if b.cached {
            point.cached += b.count;
        }
    }
    out
}

/// Lay sparse quarter counts out densely: four integer arrays rather than an
/// object per quarter.
fn series_from_quarters(quarters: &BTreeMap<i64, [i64; 4]>) -> QuarterSeries {
    let (Some((&first, _)), Some((&last, _))) =
        (quarters.first_key_value(), quarters.last_key_value())
    else {
        return QuarterSeries::default();
    };
    let len = usize::try_from(last - first + 1).expect("quarters are ordered");
    let mut series = QuarterSeries {
        start: first * QUARTER_SECS,
        total: vec![0; len],
        blocked: vec![0; len],
        cached: vec![0; len],
        heatmap: vec![0; len],
    };
    for (&quarter, &[total, blocked, cached, heatmap]) in quarters {
        let i = usize::try_from(quarter - first).expect("quarters are ordered");
        series.total[i] = total;
        series.blocked[i] = blocked;
        series.cached[i] = cached;
        series.heatmap[i] = heatmap;
    }
    series
}

/// Total each outcome across the window. Precedence (blocked, cached, answered)
/// matches the query log's Verdict column, so no row counts twice.
fn outcomes_from_window(rows: &[WindowMetricsRow]) -> Vec<(String, i64)> {
    let (mut blocked, mut cached, mut resolved, mut empty) = (0i64, 0i64, 0i64, 0i64);
    for b in rows {
        let slot = if b.blocked {
            &mut blocked
        } else if b.cached {
            &mut cached
        } else if b.has_result {
            &mut resolved
        } else {
            &mut empty
        };
        *slot += b.count;
    }
    let mut rows: Vec<(String, i64)> = [
        ("Blocked", blocked),
        ("Cached", cached),
        ("Resolved", resolved),
        ("Empty", empty),
    ]
    .into_iter()
    .filter(|(_, n)| *n > 0)
    .map(|(name, n)| (name.to_string(), n))
    .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    rows
}

/// Counts per query type, busiest first.
fn query_types_from_window(rows: &[WindowMetricsRow]) -> Vec<(String, i64)> {
    let mut totals: HashMap<&str, i64> = HashMap::new();
    for row in rows {
        *totals.entry(row.query_type.as_str()).or_default() += row.count;
    }
    let mut out: Vec<(String, i64)> = totals
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    out.sort_by_key(|r| std::cmp::Reverse(r.1));
    out
}

/// Collapse the window grain down to the ascending `response_ms` histogram the
/// percentiles are read off.
fn latency_from_window(rows: &[WindowMetricsRow]) -> LatencySummary {
    let mut hist: BTreeMap<i64, i64> = BTreeMap::new();
    for row in rows {
        *hist.entry(row.response_ms).or_default() += row.count;
    }
    let hist: Vec<(i64, i64)> = hist.into_iter().collect();
    latency_summary_from_histogram(&hist)
}

/// Derive a `LatencySummary` from an ascending `(response_ms, count)`
/// histogram. `p_k` is the value at rank `max(1, floor(total * k))`.
fn latency_summary_from_histogram(hist: &[(i64, i64)]) -> LatencySummary {
    let total: i64 = hist.iter().map(|(_, c)| *c).sum();
    if total == 0 {
        return LatencySummary {
            sample_count: 0,
            p50_ms: 0,
            p95_ms: 0,
            p99_ms: 0,
        };
    }
    // pick()'s fallback.
    let max_ms = hist.last().map_or(0, |(ms, _)| *ms);

    // Truncation equals floor for non-negative inputs.
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
        p50_ms: pick(rank_for(0.50)),
        p95_ms: pick(rank_for(0.95)),
        p99_ms: pick(rank_for(0.99)),
    }
}

/// Move the maintained `query_logs` row count by `delta`, on the write's own
/// connection so it lands in that transaction.
fn bump_log_count(conn: &rusqlite::Connection, delta: i64) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE settings SET value = CAST(value AS INTEGER) + ?1 WHERE key = ?2")?
        .execute(params![delta, QUERY_LOG_COUNT_KEY])?;
    Ok(())
}

/// Set the maintained `query_logs` row count outright (e.g. Clear All).
fn set_log_count(conn: &rusqlite::Connection, count: i64) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE settings SET value = ?1 WHERE key = ?2")?
        .execute(params![count, QUERY_LOG_COUNT_KEY])?;
    Ok(())
}

/// Take out of the rollups every row `DELETE FROM query_logs WHERE timestamp <
/// cutoff_ms` is about to remove. Must run before that delete, in its
/// transaction.
///
/// Whole units before the cutoff are dropped; the unit containing it has the
/// earlier rows recounted from the table and subtracted, so the prune keeps its
/// exact cutoff and the rollups still equal the table.
fn unwind_stats_rollups(conn: &rusqlite::Connection, cutoff_ms: i64) -> rusqlite::Result<()> {
    let quarter_start = cutoff_ms.div_euclid(ROLLUP_QUARTER_MS) * ROLLUP_QUARTER_MS;
    let hour_start = cutoff_ms.div_euclid(ROLLUP_HOUR_MS) * ROLLUP_HOUR_MS;

    conn.prepare_cached(
        "INSERT INTO query_stats_quarter (quarter, blocked, cached, count, sum_ms)
             SELECT timestamp / 900000, blocked, cached, -COUNT(*), -SUM(response_ms)
             FROM query_logs WHERE timestamp >= ?1 AND timestamp < ?2 GROUP BY 1, 2, 3
             ON CONFLICT DO UPDATE SET count = count + excluded.count,
                                       sum_ms = sum_ms + excluded.sum_ms",
    )?
    .execute(params![quarter_start, cutoff_ms])?;
    conn.prepare_cached(
        "DELETE FROM query_stats_quarter WHERE quarter < ?1 OR (quarter = ?1 AND count = 0)",
    )?
    .execute(params![quarter_start / ROLLUP_QUARTER_MS])?;

    for sql in [
        "INSERT INTO query_stats_domain_hour (hour, domain, count)
             SELECT timestamp / 3600000, domain, -COUNT(*)
             FROM query_logs WHERE timestamp >= ?1 AND timestamp < ?2 GROUP BY 1, 2
             ON CONFLICT DO UPDATE SET count = count + excluded.count",
        "INSERT INTO query_stats_client_hour (hour, client_ip, doh_token, count)
             SELECT timestamp / 3600000, client_ip, COALESCE(doh_token, ''), -COUNT(*)
             FROM query_logs WHERE timestamp >= ?1 AND timestamp < ?2 GROUP BY 1, 2, 3
             ON CONFLICT DO UPDATE SET count = count + excluded.count",
        "INSERT INTO query_stats_upstream_hour (hour, upstream, count, sum_ms)
             SELECT timestamp / 3600000, upstream, -COUNT(*), -SUM(response_ms)
             FROM query_logs
             WHERE timestamp >= ?1 AND timestamp < ?2 AND upstream IS NOT NULL GROUP BY 1, 2
             ON CONFLICT DO UPDATE SET count = count + excluded.count,
                                       sum_ms = sum_ms + excluded.sum_ms",
        "INSERT INTO query_stats_metrics_hour
             (hour, blocked, cached, has_result, query_type, response_ms, count)
             SELECT timestamp / 3600000, blocked, cached, result IS NOT NULL AND result != '',
                    query_type, response_ms, -COUNT(*)
             FROM query_logs WHERE timestamp >= ?1 AND timestamp < ?2
             GROUP BY 1, 2, 3, 4, 5, 6
             ON CONFLICT DO UPDATE SET count = count + excluded.count",
    ] {
        conn.prepare_cached(sql)?
            .execute(params![hour_start, cutoff_ms])?;
    }
    let hour = hour_start / ROLLUP_HOUR_MS;
    for table in [
        "query_stats_domain_hour",
        "query_stats_client_hour",
        "query_stats_upstream_hour",
        "query_stats_metrics_hour",
    ] {
        conn.prepare_cached(&format!(
            "DELETE FROM {table} WHERE hour < ?1 OR (hour = ?1 AND count = 0)"
        ))?
        .execute(params![hour])?;
    }
    Ok(())
}

/// The maintained `query_logs` row count, counted instead only when the
/// counter row is missing or unreadable.
fn read_log_count(conn: &rusqlite::Connection) -> rusqlite::Result<i64> {
    let stored: Option<String> = conn
        .prepare_cached("SELECT value FROM settings WHERE key = ?1")?
        .query_row(params![QUERY_LOG_COUNT_KEY], |row| row.get(0))
        .optional()?;
    if let Some(count) = stored.and_then(|v| v.parse::<i64>().ok()) {
        return Ok(count);
    }
    conn.query_row("SELECT COUNT(*) FROM query_logs", [], |row| row.get(0))
}

/// Add a column to `table` if it doesn't already exist.
///
/// `table` is interpolated into the SQL: trusted migration names only.
/// `pragma_table_xinfo`, not `_info`, because the latter omits generated
/// columns such as `query_logs.has_result`.
fn add_column_if_missing(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), rusqlite::Error> {
    let exists: bool = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM pragma_table_xinfo('{table}') WHERE name = ?1"),
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
/// Shared by `query_logs` and `count_logs` so their filters cannot drift.
///
/// Search: a plain term is an index-backed prefix match (`GLOB 'term*'`). A
/// term containing `%`, `_`, `*` or `?` is a pattern: `*`/`?` become `%`/`_`
/// and it is matched with `LIKE` as-is, so `*foo*` means "contains foo".
/// Domains are stored lowercase, so the term is lowercased.
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

        // A v7 database with a user and unrelated data. It needs `sessions`
        // (created by the v6 step, which will not re-run) for the v9 step.
        {
            let conn = rusqlite::Connection::open(&path_str).unwrap();
            conn.execute_batch(
                "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
                 INSERT INTO users (username, password_hash, created_at) VALUES ('op', 'x', 100);
                 CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, ip TEXT, user_agent TEXT);
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
    async fn migration_v9_drops_plaintext_sessions_and_renames_the_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v8.db");
        let path_str = path.to_str().unwrap().to_string();

        // A v8 database holding a live session under a plaintext token.
        {
            let conn = rusqlite::Connection::open(&path_str).unwrap();
            conn.execute_batch(
                "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
                 INSERT INTO users (username, password_hash, created_at) VALUES ('op', 'x', 100);
                 CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, ip TEXT, user_agent TEXT);
                 INSERT INTO sessions (token, user_id, created_at, last_seen) VALUES ('plaintext-token', 1, 100, 100);
                 PRAGMA user_version = 8;",
            )
            .unwrap();
        }

        let db = Database::open(&path_str).await.unwrap();

        // The plaintext credential is gone, not carried forward.
        assert!(db.list_sessions().await.unwrap().is_empty());

        // And the renamed column is what the queries now use end to end.
        let sid = db
            .insert_session("a-hash", 1, 200, 200, None, None)
            .await
            .unwrap();
        let rows = db.list_sessions().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].token_hash, "a-hash");
        assert_eq!(
            db.delete_session_by_id(sid).await.unwrap().as_deref(),
            Some("a-hash")
        );
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

    /// Every starting version opens to the same `query_logs` indexes: those
    /// versions 10–15 created are gone after version 17, and every statement
    /// that names an index with `INDEXED BY` still prepares (proved by running).
    #[tokio::test]
    async fn every_database_opens_to_the_same_query_log_indexes() {
        const LEGACY_TABLE: &str = "CREATE TABLE query_logs (
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
        CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp);
        CREATE INDEX idx_query_logs_domain_ts ON query_logs(domain, timestamp);";
        let legacy = [
            ("v9", String::new(), 9),
            (
                "v10",
                "CREATE INDEX idx_query_logs_client_ts ON query_logs(client_ip, doh_token, timestamp);"
                    .to_string(),
                10,
            ),
            (
                "v11",
                "CREATE INDEX idx_query_logs_client_ts ON query_logs(client_ip, doh_token, timestamp);
                 CREATE INDEX idx_query_logs_ts_metrics
                     ON query_logs(timestamp, blocked, cached, response_ms, query_type);"
                    .to_string(),
                11,
            ),
        ];

        let dir = tempfile::tempdir().unwrap();
        let mut databases = Vec::new();
        for (label, indexes, version) in legacy {
            let path = dir.path().join(format!("{label}.db"));
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(&format!(
                "{LEGACY_TABLE}\n{indexes}\nPRAGMA user_version = {version};"
            ))
            .unwrap();
            drop(conn);
            databases.push((label, path));
        }
        // Reshaped into version 16 as it shipped, with every index it had.
        let v16 = dir.path().join("v16.db");
        {
            let db = Database::open(v16.to_str().unwrap()).await.unwrap();
            db.close().await;
        }
        rusqlite::Connection::open(&v16)
            .unwrap()
            .execute_batch(
                "DROP INDEX idx_query_logs_token_ts;
                 DROP INDEX idx_query_logs_blocked_ts;
                 DROP INDEX idx_query_logs_type_blocked_ts;
                 CREATE INDEX idx_query_logs_ts_domain_client
                     ON query_logs(timestamp, domain, client_ip, doh_token);
                 CREATE INDEX idx_query_logs_ts_metrics
                     ON query_logs(timestamp, blocked, cached, response_ms, query_type, has_result);
                 CREATE INDEX idx_query_logs_ts_upstream
                     ON query_logs(timestamp, upstream, response_ms) WHERE upstream IS NOT NULL;
                 PRAGMA user_version = 16;",
            )
            .unwrap();
        databases.push(("v16", v16));
        databases.push(("fresh", dir.path().join("fresh.db")));

        let expected = [
            "idx_query_logs_blocked_ts",
            "idx_query_logs_domain_ts",
            "idx_query_logs_timestamp",
            "idx_query_logs_token_ts",
            "idx_query_logs_type_blocked_ts",
        ];
        for (label, path) in databases {
            let db = Database::open(path.to_str().unwrap()).await.unwrap();
            let mut entries: Vec<QueryLogEntry> = (0..6)
                .map(|i| sample_entry(1_000_000 + i, "example.com"))
                .collect();
            entries[1].blocked = true;
            entries[2].upstream = Some("tls://1.1.1.1:853".to_string());
            entries[3].doh_token = Some("phone".to_string());
            entries[4].result = Some("1.2.3.4".to_string());
            db.insert_query_logs(&entries).await.unwrap();

            let mut indexes = query_log_index_names(&db).await;
            indexes.retain(|n| !n.starts_with("sqlite_autoindex"));
            indexes.sort();
            assert_eq!(indexes, expected, "{label} database's indexes");

            assert_eq!(db.summary_multi_since(0, 0, 0).await.unwrap()[2].total, 6);
            assert_eq!(
                db.traffic_lists_since(0, 10).await.unwrap().clients.len(),
                2
            );
            assert_eq!(db.top_upstreams_since(0, 10).await.unwrap().len(), 1);
            assert_eq!(
                db.stats_scan_since(0, 0).await.unwrap().series.total,
                vec![6]
            );
            assert_eq!(db.timeline_multi_since(0, 3_600, 0).await.unwrap().len(), 1);
            assert_eq!(db.hourly_heatmap_since(0, 0).await.unwrap().len(), 1);
            assert_eq!(
                db.outcome_breakdown_since(0).await.unwrap().len(),
                3,
                "{label}: blocked, resolved and empty"
            );
            assert_eq!(
                db.query_logs(10, 0, None, None, Some("phone"), None)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                db.query_logs(10, 0, None, None, None, Some("A"))
                    .await
                    .unwrap()
                    .len(),
                6
            );
            assert_eq!(
                db.count_logs(None, Some(true), None, Some("A"))
                    .await
                    .unwrap(),
                1
            );
        }
    }

    /// The counter must be seeded from the table: a counter row seeded at zero
    /// would never trigger `read_log_count`'s fallback.
    #[tokio::test]
    async fn migration_v13_seeds_the_log_count_from_the_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v12.db");
        let path_str = path.to_str().unwrap().to_string();

        let entries: Vec<QueryLogEntry> = (0..3)
            .map(|i| QueryLogEntry {
                timestamp: 1_000_000 + i,
                domain: "example.com".to_string(),
                query_type: "A".to_string(),
                client_ip: "10.0.0.1".to_string(),
                blocked: false,
                cached: false,
                upstream: None,
                doh_token: None,
                result: None,
                response_ms: 1,
                authenticated_data: false,
            })
            .collect();
        {
            let db = Database::open(&path_str).await.unwrap();
            db.insert_query_logs(&entries).await.unwrap();
            db.close().await;
        }

        // Wind it back to version 12: the rows stay, the counter does not.
        {
            let conn = rusqlite::Connection::open(&path_str).unwrap();
            conn.execute_batch(
                "DELETE FROM settings WHERE key = 'query_log_count';
                 PRAGMA user_version = 12;",
            )
            .unwrap();
        }

        let migrated = Database::open(&path_str).await.unwrap();
        assert_eq!(
            migrated
                .get_setting(QUERY_LOG_COUNT_KEY)
                .await
                .unwrap()
                .as_deref(),
            Some("3"),
            "the migration did not seed the counter"
        );
        assert_eq!(migrated.total_log_count().await.unwrap(), 3);
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

        // Nothing to prune; maintenance still succeeds (VACUUM stays below
        // threshold).
        db.prune_logs_before(0).await.unwrap();
        db.run_maintenance().await.unwrap();

        let logs = db.query_logs(10, 0, None, None, None, None).await.unwrap();
        assert_eq!(
            logs.len(),
            10,
            "data should remain queryable after maintenance"
        );
    }

    /// Each rollup, the same grouping recounted from `query_logs`, and the
    /// ordering that makes the two comparable row for row.
    const ROLLUP_RECOUNTS: &[(&str, &str, &str)] = &[
        (
            "query_stats_quarter",
            "SELECT quarter, blocked, cached, count, sum_ms FROM query_stats_quarter",
            "SELECT timestamp / 900000, blocked, cached, COUNT(*), SUM(response_ms) \
             FROM query_logs GROUP BY 1, 2, 3",
        ),
        (
            "query_stats_domain_hour",
            "SELECT hour, domain, count FROM query_stats_domain_hour",
            "SELECT timestamp / 3600000, domain, COUNT(*) FROM query_logs GROUP BY 1, 2",
        ),
        (
            "query_stats_client_hour",
            "SELECT hour, client_ip, doh_token, count FROM query_stats_client_hour",
            "SELECT timestamp / 3600000, client_ip, COALESCE(doh_token, ''), COUNT(*) \
             FROM query_logs GROUP BY 1, 2, 3",
        ),
        (
            "query_stats_upstream_hour",
            "SELECT hour, upstream, count, sum_ms FROM query_stats_upstream_hour",
            "SELECT timestamp / 3600000, upstream, COUNT(*), SUM(response_ms) \
             FROM query_logs WHERE upstream IS NOT NULL GROUP BY 1, 2",
        ),
        (
            "query_stats_metrics_hour",
            "SELECT hour, blocked, cached, has_result, query_type, response_ms, count \
             FROM query_stats_metrics_hour",
            "SELECT timestamp / 3600000, blocked, cached, (result IS NOT NULL AND result != ''), \
             query_type, response_ms, COUNT(*) FROM query_logs GROUP BY 1, 2, 3, 4, 5, 6",
        ),
    ];

    /// Every row of `sql`, rendered and sorted, so two spellings of the same
    /// grouping compare equal regardless of the order either returns.
    fn rendered_rows(conn: &rusqlite::Connection, sql: &str) -> Vec<String> {
        let mut stmt = conn.prepare(sql).unwrap();
        let columns = stmt.column_count();
        let mut rows: Vec<String> = stmt
            .query_map([], |row| {
                Ok((0..columns)
                    .map(|i| format!("{:?}", row.get_ref(i).unwrap()))
                    .collect::<Vec<_>>()
                    .join("|"))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        rows.sort();
        rows
    }

    /// Asserts every rollup holds exactly what recounting `query_logs` gives.
    fn assert_rollups_match(path: &str, step: &str) {
        let conn = rusqlite::Connection::open(path).unwrap();
        for (table, rollup, recount) in ROLLUP_RECOUNTS {
            assert_eq!(
                rendered_rows(&conn, rollup),
                rendered_rows(&conn, recount),
                "{table} disagrees with query_logs after {step}"
            );
        }
    }

    fn rollup_entry(timestamp: i64, i: i64) -> QueryLogEntry {
        QueryLogEntry {
            timestamp,
            domain: format!("host{}.example.com", i % 3),
            query_type: if i % 2 == 0 { "A" } else { "AAAA" }.to_string(),
            client_ip: format!("10.0.0.{}", i % 2),
            blocked: i % 4 == 0,
            cached: i % 5 == 0,
            upstream: (i % 3 != 0).then(|| format!("udp://9.9.9.{}:53", i % 2)),
            doh_token: (i % 2 == 0).then(|| "phone".to_string()),
            // All three shapes `has_result` distinguishes: none, empty, an answer.
            result: match i % 3 {
                0 => None,
                1 => Some(String::new()),
                _ => Some("1.2.3.4".to_string()),
            },
            response_ms: 1 + i % 7,
            authenticated_data: false,
        }
    }

    /// Every write to `query_logs` must change the rollups identically,
    /// including a prune cutting through a quarter and an hour, and rows
    /// written straight into the table as the e2e fixtures do.
    #[tokio::test]
    async fn rollups_follow_every_write_that_changes_query_logs() {
        const HOUR: i64 = 3_600_000;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollups.db");
        let path_str = path.to_str().unwrap().to_string();
        let db = Database::open(&path_str).await.unwrap();

        // Straddles quarter and hour boundaries on both sides.
        let offsets = [
            0,
            899_999,
            900_000,
            1_000_000,
            2_700_001,
            HOUR - 1,
            HOUR + 5,
            2 * HOUR + 30_000,
        ];
        let first: Vec<QueryLogEntry> = offsets
            .iter()
            .enumerate()
            .map(|(i, off)| rollup_entry(10 * HOUR + off, i as i64))
            .collect();
        db.insert_query_logs(&first).await.unwrap();
        assert_rollups_match(&path_str, "the first batch");

        // Same units again, so every rollup row has to accumulate, not replace.
        let second: Vec<QueryLogEntry> = offsets
            .iter()
            .enumerate()
            .map(|(i, off)| rollup_entry(10 * HOUR + off + 1, i as i64 + 1))
            .collect();
        db.insert_query_logs(&second).await.unwrap();
        assert_rollups_match(&path_str, "a batch into the same units");

        {
            let conn = rusqlite::Connection::open(&path_str).unwrap();
            conn.execute_batch(&format!(
                "INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, \
                 cached, response_ms, upstream, doh_token, result, authenticated_data) VALUES \
                 ({}, 'host0.example.com', 'A', '10.0.0.9', 0, 1, 40, NULL, NULL, '9.9.9.9', 0);",
                10 * HOUR + 1_200_000
            ))
            .unwrap();
        }
        assert_rollups_match(&path_str, "a row written straight into the table");

        // Inside the second quarter of hour 10: both units are cut in half.
        let cutoff_ms = 10 * HOUR + 1_000_000;
        let pruned = db.prune_logs_before(cutoff_ms / 1000).await.unwrap();
        assert!(pruned > 0, "the prune has to remove something to test");
        assert_rollups_match(&path_str, "a prune inside a quarter and an hour");

        assert_eq!(db.prune_logs_before(cutoff_ms / 1000).await.unwrap(), 0);
        assert_rollups_match(&path_str, "a prune that matched nothing");

        // On an hour boundary: whole units go, none is left partial.
        db.prune_logs_before(11 * HOUR / 1000).await.unwrap();
        assert_rollups_match(&path_str, "a prune on an hour boundary");

        db.delete_all_logs().await.unwrap();
        assert_rollups_match(&path_str, "clearing the log");

        db.insert_query_logs(&first).await.unwrap();
        assert_rollups_match(&path_str, "a batch after clearing");
    }

    /// A pre-v16 database opens with its rollups backfilled and the trigger in
    /// place; empty rollups would report no traffic for the whole retention.
    #[tokio::test]
    async fn migration_v16_backfills_the_rollups() {
        const HOUR: i64 = 3_600_000;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v15.db");
        let path_str = path.to_str().unwrap().to_string();

        let entries: Vec<QueryLogEntry> = (0..24)
            .map(|i| rollup_entry(20 * HOUR + i * 700_000, i))
            .collect();
        {
            let db = Database::open(&path_str).await.unwrap();
            db.insert_query_logs(&entries).await.unwrap();
            db.close().await;
        }

        // Wind it back to version 15: the rows stay, the rollups do not.
        {
            let conn = rusqlite::Connection::open(&path_str).unwrap();
            conn.execute_batch(
                "DROP TRIGGER query_logs_maintain_stats;
                 DROP TABLE query_stats_quarter;
                 DROP TABLE query_stats_domain_hour;
                 DROP TABLE query_stats_client_hour;
                 DROP TABLE query_stats_upstream_hour;
                 DROP TABLE query_stats_metrics_hour;
                 PRAGMA user_version = 15;",
            )
            .unwrap();
        }

        let migrated = Database::open(&path_str).await.unwrap();
        assert_rollups_match(&path_str, "the migration");

        migrated
            .insert_query_logs(&[rollup_entry(21 * HOUR + 5, 99)])
            .await
            .unwrap();
        assert_rollups_match(&path_str, "an insert into the migrated database");
    }
}
