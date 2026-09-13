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
    /// `BLAKE2b` digest of the session token, never the token itself — see
    /// `crate::admin::auth::hash_session_token`. Doubles as the in-memory
    /// `SessionStore` key, so it is what identifies a session everywhere
    /// except the cookie on the wire.
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
    /// Start of the bucket, in **Unix seconds** — the same unit as
    /// [`TimelineMultiPoint::timestamp`] and the rest of the API's timestamps.
    /// The underlying `query_logs.timestamp` column is milliseconds; the
    /// conversion happens in [`Database::timeline_since`].
    pub timestamp: i64,
    pub total: i64,
    pub blocked: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimelineMultiPoint {
    /// Start of the bucket, in **Unix seconds** — the same unit as
    /// [`TimelinePoint::timestamp`]. The underlying `query_logs.timestamp`
    /// column is milliseconds; the conversion happens in
    /// [`Database::timeline_multi_since`].
    pub timestamp: i64,
    pub total: i64,
    pub blocked: i64,
    pub cached: i64,
}

/// One grain of [`Database::metrics_by_bucket_since`]: how many queries fell in
/// a time bucket, blocked and cached counted separately. The timeline is a
/// folding of these.
#[derive(Debug, Clone)]
pub struct MetricsBucket {
    /// Start of the bucket, in **Unix seconds** — the same unit as
    /// [`TimelineMultiPoint::timestamp`].
    pub timestamp: i64,
    pub blocked: bool,
    pub cached: bool,
    pub count: i64,
}

/// One grain of [`Database::metrics_window_since`]: how many queries in the
/// window carried a given outcome classification, query type and response time.
/// The outcome breakdown, the query-type breakdown and the latency percentiles
/// are all foldings of these.
#[derive(Debug, Clone)]
pub struct WindowMetricsRow {
    pub blocked: bool,
    pub cached: bool,
    /// Whether `result` held an answer. Carried by `idx_query_logs_ts_metrics`
    /// as a generated column so classifying an outcome never reads the table.
    pub has_result: bool,
    pub query_type: String,
    pub response_ms: i64,
    pub count: i64,
}

/// The three Statistics readings that come off `idx_query_logs_ts_metrics` in
/// one scan, answered together by [`Database::window_metrics_since`].
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
/// This is what lets the Statistics page draw its calendar-aligned charts
/// without a scan of their own. A viewer's UTC offset is a whole number of
/// quarter hours in every zone in use, so every quarter lies wholly inside one
/// of that viewer's local hours, and the browser can fold these into its own
/// hours and days exactly — the server never needs to know the offset.
/// `timelineFromQuarters` and `heatmapFromQuarters` in `app.js` are those
/// folds, and answer what [`Database::timeline_multi_since`] and
/// [`Database::hourly_heatmap_since`] answer for API callers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct QuarterSeries {
    /// Start of the first quarter, in Unix seconds. 0 when there are none.
    pub start: i64,
    /// Queries in the page's range window, by quarter.
    pub total: Vec<i64>,
    pub blocked: Vec<i64>,
    pub cached: Vec<i64>,
    /// Queries in the heatmap's window, by quarter. That window is not the
    /// range's, so a quarter can count here and not in `total`, or the reverse.
    pub heatmap: Vec<i64>,
}

/// Everything the Statistics page reads off `idx_query_logs_ts_metrics`, from
/// the one scan [`Database::stats_scan_since`] makes.
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

#[derive(Debug, Clone, Serialize)]
pub struct HeatmapCell {
    pub weekday: i64, // 0 = Sunday, 6 = Saturday (matches strftime('%w'))
    pub hour: i64,    // 0..=23
    pub count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LatencySummary {
    pub sample_count: i64,
    /// Percentiles only. A mean was dropped as superseded by p50, and a max as
    /// an outlier the highlights grid never rendered; neither reached the UI.
    pub p50_ms: i64,
    pub p95_ms: i64,
    pub p99_ms: i64,
}

/// `settings` key holding the `query_logs` row count. Not an operator-facing
/// setting — nothing enumerates this table, so it is simply the one row-shaped
/// place a counter can live without a table of its own.
const QUERY_LOG_COUNT_KEY: &str = "query_log_count";

/// Default rusqlite cache is 16 statements; the read connection alone has
/// ~20 distinct hot SQL strings (settings, stats, filter, token lookup),
/// so anything below ~32 starts evicting on every admin poll.
const PREPARED_STATEMENT_CACHE_CAPACITY: usize = 64;

/// Turn off `SQLite`'s global memory accounting, once per process, before any
/// connection exists.
///
/// `SQLITE_CONFIG_MEMSTATUS` defaults to on, and it makes every
/// `sqlite3_malloc`/`sqlite3_free` update a set of process-global counters
/// behind a single static mutex. The read pool's aggregation queries allocate
/// hard — every `GROUP BY` in `src/admin/stats.rs` builds a temp b-tree — so
/// with four readers running the Statistics page's fan-out concurrently, they
/// spend more time queueing on that mutex than scanning. Measured against a
/// 447 k-row production database, the page's seven endpoints under
/// `tokio::join!` went from a 1.69 s median to 283 ms, and the pool stopped
/// being *slower* than running the same queries one after another.
/// `tests/stats_contention_bench.rs` isolates the effect.
///
/// Nothing here reads the counters back: the statistics this disables are
/// `sqlite3_memory_used`, `sqlite3_status` and the `soft_heap_limit` machinery,
/// none of which appear in this crate. Thread safety is untouched — that is
/// governed by `bCoreMutex`/`bFullMutex`, which this does not alter.
fn disable_sqlite_memstatus() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: `sqlite3_config` is variadic; `SQLITE_CONFIG_MEMSTATUS` takes
        // a single `int`. Called from a `Once` before this process opens any
        // connection, which is the documented requirement (it returns
        // SQLITE_MISUSE once SQLite has initialized).
        // FFI: no safe rusqlite wrapper exists for sqlite3_config
        #[allow(unsafe_code)]
        let rc =
            unsafe { rusqlite::ffi::sqlite3_config(rusqlite::ffi::SQLITE_CONFIG_MEMSTATUS, 0_i32) };
        if rc != rusqlite::ffi::SQLITE_OK {
            // Not fatal: the database still works, it just keeps the slow
            // global accounting. Worth knowing about, since it means something
            // initialized SQLite before us.
            tracing::warn!(
                event = "db.memstatus_config_failed",
                rc,
                "could not disable SQLite global memory accounting"
            );
        }
    });
}

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
        // Must precede the first connection in the process — see the function's
        // own docs for why the read pool depends on it.
        disable_sqlite_memstatus();
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

    /// Pages the read pool has had to fetch from the database file, summed
    /// across its connections, and the pages it answered from its own cache.
    ///
    /// This is `SQLITE_DBSTATUS_CACHE_MISS`, a running count of pager-level
    /// reads. It is the unit `tests/stats_page_miss_bench.rs` reports, and it
    /// is deliberately not a duration: the appliance runs off an SD card and
    /// development runs off an SSD, so the same query costs wildly different
    /// wall time on each while fetching exactly the same pages. Counting pages
    /// compares across both. The counter is unaffected by `mmap_size` —
    /// memory-mapped reads are counted the same as `read()` ones.
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

    /// Put the read pool in the state [`Self::read_page_cache_stats`] can
    /// account for, and drop what it has cached so the next query is measured
    /// cold. The running counters are untouched — callers take a delta around
    /// the query they care about.
    ///
    /// Turning `mmap_size` off is what makes the counter usable: pages the
    /// pager takes from a memory mapping never pass through its cache, so a
    /// connection running with the configured 256 MiB mapping reports almost no
    /// misses however much of the file it reads. The appliance still fetches
    /// those pages — as page faults against the SD card rather than `read()`
    /// calls — so the count with mmap off is the count either way; only the
    /// accounting differs.
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
                    CREATE INDEX IF NOT EXISTS idx_query_logs_client_ts ON query_logs(client_ip, doh_token, timestamp);
                    -- Without has_result: a database predating version 12 has
                    -- no such column until that migration adds it, and this
                    -- batch runs first. Migration 12 rebuilds the index with it
                    -- for fresh and legacy databases alike.
                    CREATE INDEX IF NOT EXISTS idx_query_logs_ts_metrics ON query_logs(timestamp, blocked, cached, response_ms, query_type);
                    CREATE INDEX IF NOT EXISTS idx_query_logs_ts_upstream ON query_logs(timestamp, upstream, response_ms) WHERE upstream IS NOT NULL;

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
                        -- An account provisioned by forward auth (a trusted
                        -- reverse proxy vouching for the username) stores
                        -- NO_PASSWORD_SENTINEL here instead of a real hash,
                        -- so it can never authenticate with a password. The
                        -- sentinel keeps this column NOT NULL.
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
    // `add_column_if_missing` keeps each step idempotent, so the same migration
    // runs against a fresh database and a pre-existing one alike.
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

        if version < 9 {
            // Session tokens are now stored as a BLAKE2b digest, the way API
            // keys always have been, so a copy of the database — a backup, a
            // stray WAL file — no longer hands over every live session.
            //
            // Existing rows hold raw tokens and are dropped rather than
            // rehashed: SQLite has no BLAKE2b to do it in SQL, and doing it in
            // Rust would rewrite the rows while leaving the plaintext behind
            // in freelist pages and the WAL regardless, so the migration would
            // claim a protection it had not actually delivered. Sessions are
            // short-lived by construction; the cost is that every operator
            // signs in once more after the upgrade.
            conn.execute_batch(
                "DELETE FROM sessions;
                 ALTER TABLE sessions RENAME COLUMN token TO token_hash;",
            )?;
        }

        if version < 10 {
            // "Top Clients" groups by (client_ip, doh_token) over a timestamp
            // range, which had no index to serve it: the planner fell back to
            // idx_query_logs_timestamp and then built a temp b-tree over every
            // row in the window. Ordering the columns group-first makes this a
            // covering index, so the scan reads the index alone. Measured on a
            // 447 k-row production database, the 7-day query went from 143 ms
            // to 20 ms; `dbstat` puts the index itself at ~18 MiB against a
            // 103 MiB database, though that scales with how many distinct
            // client_ip/doh_token pairs a deployment actually sees.
            //
            // Contrast idx_query_logs_domain_ts, which is why the equivalent
            // "Top Domains" query was already fast.
            //
            // ANALYZE for the same reason the version-5 migration runs it, and
            // because the hourly `PRAGMA optimize` had let sqlite_stat1 drift
            // badly on real databases — one 447 k-row instance still described
            // itself as holding 232 k.
            conn.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_query_logs_client_ts \
                 ON query_logs(client_ip, doh_token, timestamp);
                 ANALYZE;",
            )?;
        }

        if version < 11 {
            // The remaining Statistics aggregations — the timeline, the
            // query-type breakdown, the latency histogram — all filter on
            // timestamp and then read a few narrow columns. They were served
            // by idx_query_logs_timestamp, which meant a row lookup per match
            // into a table whose rows average ~84 bytes of strings (domain,
            // client_ip, upstream, result) that none of them want. Carrying
            // those narrow columns in the index makes all three covering.
            //
            // Measured on a 447 k-row database over a 7-day window: timeline
            // 78 -> 60 ms, query_type 75 -> 62 ms, latency 60 -> 45 ms, for
            // ~9 MiB of index against a 103 MiB database.
            //
            conn.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_query_logs_ts_metrics \
                 ON query_logs(timestamp, blocked, cached, response_ms, query_type);
                 ANALYZE;",
            )?;
        }

        if version < 12 {
            // Version 11 left `outcome_breakdown_since` uncovered on the
            // strength of a wall-clock measurement, which on an SSD hides what
            // the query actually costs: classifying an outcome needs `result`
            // tested for emptiness, so every matching row took a rowid lookup
            // into the table. Counted in pages fetched from the file
            // (`SQLITE_DBSTATUS_CACHE_MISS`, the unit `stats_page_miss_bench`
            // reports) that is the whole 10 784-page table on a 370 k-row
            // database — 12 173 pages against 2 157 for the same answer read
            // out of the index. On the SD card these appliances run from,
            // those 40 MiB are the page's single largest cost.
            //
            // The emptiness test rides the index as a VIRTUAL generated
            // column, which occupies no table space and added 65 pages (3%) to
            // the index. An index on the bare expression was tried first and
            // the planner would not treat it as covering; a named column it
            // does.
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
            // `SELECT COUNT(*)` has no shortcut in `SQLite`: it walks the
            // smallest index end to end, 1 386 pages on a 370 k-row database,
            // and the Database Health card asks for it on every Statistics
            // page load. The count lives in `settings` from here, seeded once
            // and then moved by the three statements that change it.
            //
            // `WHERE true` is what lets an upsert follow a SELECT — without it
            // the parser reads `ON CONFLICT` as part of the SELECT.
            conn.execute_batch(
                "INSERT INTO settings (key, value) \
                 SELECT 'query_log_count', COUNT(*) FROM query_logs WHERE true \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            )?;
        }

        if version < 14 {
            // The dashboard's top upstreams read `upstream` and `response_ms`,
            // which no index carried, so every tick paid a rowid lookup into the
            // table per forwarded query in the last 24 hours: 1 608 pages on a
            // 370 k-row database, against 211 read out of this index.
            //
            // Partial, because blocked and cached answers never reach an
            // upstream — 56% of that table's rows are NULL here, and the query
            // excludes them anyway. Timestamp first, because the logger appends
            // at the newest end: an upstream-first index spreads each batch
            // across one insertion point per upstream, and measured 65 pages
            // written per 500-row batch against 56 for this one and 53 with no
            // index at all.
            //
            // The schema batch above already creates it on every open; this
            // step exists for the `ANALYZE`, like every other index migration.
            conn.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_query_logs_ts_upstream \
                 ON query_logs(timestamp, upstream, response_ms) WHERE upstream IS NOT NULL;
                 ANALYZE;",
            )?;
        }

        const LATEST_VERSION: i64 = 14;
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

    /// Has this appliance ever logged a query?
    ///
    /// `EXISTS` rather than a count or a windowed sum: the only caller asks
    /// whether the machine has ever served traffic — to decide whether to tell
    /// an operator how to point a device at it — and that question stops at the
    /// first row. A count would read every one of them on a busy appliance to
    /// answer something a single row settles.
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

    /// Fetch one list's URL by id, without materialising every column of every
    /// row the way `get_filter_lists` does for callers that need a single field.
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

    /// Create an operator with no password, as provisioned from a trusted
    /// forward-auth header. Stores
    /// [`NO_PASSWORD_SENTINEL`](crate::admin::auth::NO_PASSWORD_SENTINEL) in
    /// place of a real hash, which makes password login impossible for this
    /// account since no password can ever verify against it.
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
                // Single atomic statement: DELETE ... RETURNING removes the row and
                // yields its token hash in one step, so there is no
                // SELECT-then-DELETE window where a concurrent revoke of the same
                // id could double-fire.
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

    /// Delete every session except the one identified by `keep_token_hash`
    /// (log out other devices while keeping the caller signed in). Returns the
    /// number of rows removed.
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

    /// Delete every session belonging to `user_id` except the one identified by
    /// `keep_token_hash`. Passing `None` revokes all of that user's sessions.
    /// Other operators' sessions are never touched. Returns the number of rows
    /// deleted.
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
    /// Deliberately `<=`, not `<`: `validate_session` and `prune_expired` in
    /// `src/admin/auth.rs` expire a session with `>=` (`now - created_at >=
    /// SESSION_MAX_AGE_SECS`, likewise for `last_seen`), so at the exact
    /// boundary this must agree by deleting too, not by leaving the row for
    /// the in-memory side to reject on next access.
    const PURGE_EXPIRED_SESSIONS_SQL: &str =
        "DELETE FROM sessions WHERE created_at <= ?1 OR last_seen <= ?2";

    /// Delete session rows that have hit either the absolute or the idle timeout.
    /// Returns the number of rows removed. Shared by startup restore
    /// (`load_sessions`) and the periodic sweep so both use identical rules —
    /// anything this deletes is already dead to `validate_session`.
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

    /// Count queries logged since `since` (epoch seconds; converted to ms
    /// internally to match stored timestamps).
    ///
    /// Counts only. The blocked total was selected alongside it and bound to
    /// `_` by the sole caller, so `SQLite` summed a column nothing read.
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

    /// The dashboard summary's figures for three nested windows, in one scan of
    /// `idx_query_logs_ts_metrics`.
    ///
    /// Totals and blocks came from one statement and cache hits and latency
    /// from another, each walking the same 30 days of the same index — on every
    /// dashboard tick, 4 304 pages on a 370 k-row database where 2 152 answer
    /// both. The allowed-only figures take their filter into the `CASE` rather
    /// than the `WHERE`, so one pass serves both halves.
    ///
    /// All `since_*` values are in epoch seconds. Caller MUST pass the widest
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
        let result = self
            .reader()
            .call(move |conn| {
                // `INDEXED BY` for the reason `metrics_by_bucket_since` gives.
                let mut stmt = conn.prepare_cached(
                    "SELECT
                    COUNT(CASE WHEN timestamp >= ?1 THEN 1 END),
                    COALESCE(SUM(CASE WHEN timestamp >= ?1 THEN blocked END), 0),
                    COUNT(CASE WHEN timestamp >= ?1 AND blocked = 0 THEN 1 END),
                    COALESCE(SUM(CASE WHEN timestamp >= ?1 AND blocked = 0 THEN cached END), 0),
                    COALESCE(AVG(CASE WHEN timestamp >= ?1 AND blocked = 0 THEN response_ms END), 0),
                    COUNT(CASE WHEN timestamp >= ?2 THEN 1 END),
                    COALESCE(SUM(CASE WHEN timestamp >= ?2 THEN blocked END), 0),
                    COUNT(CASE WHEN timestamp >= ?2 AND blocked = 0 THEN 1 END),
                    COALESCE(SUM(CASE WHEN timestamp >= ?2 AND blocked = 0 THEN cached END), 0),
                    COALESCE(AVG(CASE WHEN timestamp >= ?2 AND blocked = 0 THEN response_ms END), 0),
                    COUNT(*),
                    COALESCE(SUM(blocked), 0),
                    COUNT(CASE WHEN blocked = 0 THEN 1 END),
                    COALESCE(SUM(CASE WHEN blocked = 0 THEN cached END), 0),
                    COALESCE(AVG(CASE WHEN blocked = 0 THEN response_ms END), 0)
                 FROM query_logs INDEXED BY idx_query_logs_ts_metrics
                 WHERE timestamp >= ?3",
                )?;
                let row = stmt.query_row(params![today_ms, d7_ms, d30_ms], |row| {
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
    /// from one pass over `idx_query_logs_domain_ts`.
    ///
    /// Asked separately these are two statements — `GROUP BY domain ORDER BY
    /// cnt DESC LIMIT n` and `COUNT(DISTINCT domain)` — that group the same
    /// rows the same way and each scan the whole index, because the index is
    /// ordered `(domain, timestamp)` and a timestamp range cannot restrict it.
    /// The CTE is materialized once and read twice, which is 3 977 page misses
    /// instead of 7 954 on a 370 k-row database.
    ///
    /// `unique` is 0 when the window is empty, which is also when `top` is: the
    /// count rides on the rows, so there is nothing to report either way.
    pub async fn domain_stats_since(&self, since: i64, limit: i64) -> Result<DomainStats, DbError> {
        let since_ms = since * 1000;
        let stats = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "WITH d AS (                         SELECT domain, COUNT(*) AS cnt                         FROM query_logs                         WHERE timestamp >= ?1                         GROUP BY domain                      )                      SELECT (SELECT COUNT(*) FROM d), domain, cnt                      FROM d ORDER BY cnt DESC LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(params![since_ms, limit], |row| {
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
                // `INDEXED BY` so a drift in the planner's statistics cannot send
                // this back to `idx_query_logs_timestamp` and a lookup per row.
                // The `upstream IS NOT NULL` term is what lets the partial index
                // answer at all.
                let mut stmt = conn.prepare_cached(
                    "SELECT upstream, COUNT(*) as cnt, AVG(response_ms) as avg_ms \
                     FROM query_logs INDEXED BY idx_query_logs_ts_upstream \
                     WHERE timestamp >= ?1 AND upstream IS NOT NULL \
                     GROUP BY upstream ORDER BY cnt DESC LIMIT ?2",
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
        let buckets = self
            .metrics_by_bucket_since(since, bucket_secs, tz_offset_secs)
            .await?;
        Ok(timeline_from_buckets(&buckets))
    }

    /// Every `idx_query_logs_ts_metrics` reading the Statistics page renders,
    /// in one scan of that index.
    ///
    /// The outcome breakdown, the query-type breakdown and the latency
    /// histogram are three foldings of the same window of the same index.
    /// Asked one statement each, `SQLite` reads that index end to end three
    /// times — and the read pool round-robins them onto four connections with
    /// 2 MiB of page cache each, so nothing is warm for the next one. The
    /// grain below is fine enough to derive all three and costs one scan:
    /// 2 157 pages instead of 6 471 on a 370 k-row database.
    ///
    /// The window carries no time bucket because the page renders no timeline
    /// — that chart is the client's, and [`Self::timeline_multi_since`] is its
    /// own scan. Bucketing here only multiplied the rows the folds read: at
    /// the 7-day range's hourly grain, 68 846 of them against 4 658.
    pub async fn window_metrics_since(&self, since: i64) -> Result<WindowMetrics, DbError> {
        let rows = self.metrics_window_since(since).await?;
        Ok(WindowMetrics {
            outcomes: outcomes_from_window(&rows),
            query_types: query_types_from_window(&rows),
            latency: latency_from_window(&rows),
        })
    }

    /// The Statistics page's window readings and its charts' series, in one
    /// scan of `idx_query_logs_ts_metrics`.
    ///
    /// The page used to pay for that index three times: once here for the
    /// breakdowns and the latency histogram, once more for the timeline the
    /// browser fetched with its UTC offset, and `idx_query_logs_timestamp` for
    /// the heatmap on top — 5 690 pages on a 370 k-row database where 2 152
    /// answer all of it. The charts come out of the same rows as a
    /// [`QuarterSeries`], which the browser folds into its own calendar.
    ///
    /// The scan starts at the earlier of the two windows; `range_since` bounds
    /// the metrics and the timeline, `heatmap_since` the heatmap, each exactly.
    ///
    /// Rows are folded here rather than grouped in SQL. A `GROUP BY` at a grain
    /// carrying both the quarter and `response_ms` approaches one group per
    /// row, which is a temp b-tree the size of the window held in memory on the
    /// appliance; the folds below hold one entry per distinct value instead.
    pub async fn stats_scan_since(
        &self,
        range_since: i64,   // unix seconds
        heatmap_since: i64, // unix seconds
    ) -> Result<StatsScan, DbError> {
        let range_ms = range_since * 1000;
        let heatmap_ms = heatmap_since * 1000;
        let quarter_ms = QUARTER_SECS * 1000;
        let scan = self
            .reader()
            .call(move |conn| {
                // `INDEXED BY` for the reason `metrics_window_since` gives.
                let mut stmt = conn.prepare_cached(
                    "SELECT timestamp, blocked, cached, has_result, query_type, response_ms \
                     FROM query_logs INDEXED BY idx_query_logs_ts_metrics \
                     WHERE timestamp >= ?1",
                )?;
                // Keyed by query type first so a row that repeats a type — nearly
                // all of them — is looked up by `&str` without allocating.
                // (blocked, cached, has_result, response_ms) → count
                type Grains = HashMap<(bool, bool, bool, i64), i64>;
                let mut grains: HashMap<String, Grains> = HashMap::new();
                // quarter index → [total, blocked, cached, heatmap]
                let mut quarters: BTreeMap<i64, [i64; 4]> = BTreeMap::new();
                let mut rows = stmt.query(params![range_ms.min(heatmap_ms)])?;
                while let Some(row) = rows.next()? {
                    let ts: i64 = row.get(0)?;
                    let blocked = row.get::<_, i64>(1)? != 0;
                    let cached = row.get::<_, i64>(2)? != 0;
                    let slot = quarters.entry(ts.div_euclid(quarter_ms)).or_default();
                    if ts >= heatmap_ms {
                        slot[3] += 1;
                    }
                    if ts < range_ms {
                        continue;
                    }
                    slot[0] += 1;
                    slot[1] += i64::from(blocked);
                    slot[2] += i64::from(cached);

                    let has_result = row.get::<_, i64>(3)? != 0;
                    let query_type = row.get_ref(4)?.as_str()?;
                    let key = (blocked, cached, has_result, row.get::<_, i64>(5)?);
                    if let Some(by_grain) = grains.get_mut(query_type) {
                        *by_grain.entry(key).or_default() += 1;
                    } else {
                        grains.insert(query_type.to_owned(), HashMap::from([(key, 1)]));
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

    /// Query counts by time bucket. Every column is carried by
    /// `idx_query_logs_ts_metrics`, so the scan never looks a row up.
    ///
    /// `INDEXED BY` because the planner will not choose it on its own: with
    /// `idx_query_logs_timestamp` also matching the range it picks that one —
    /// it is the smaller index — and then pays a rowid lookup per row to reach
    /// `blocked` and `cached`. Measured on a 370 k-row database that is 12 173
    /// page misses against 2 157 for the identical answer.
    async fn metrics_by_bucket_since(
        &self,
        since: i64, // unix seconds
        bucket_secs: i64,
        tz_offset_secs: i64,
    ) -> Result<Vec<MetricsBucket>, DbError> {
        let since_ms = since * 1000;
        let bucket_ms = bucket_secs * 1000;
        let offset_ms = tz_offset_secs * 1000;
        let result = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT ((timestamp + ?3) / ?1) * ?1 - ?3 AS bucket, \
                            blocked, cached, COUNT(*) \
                     FROM query_logs INDEXED BY idx_query_logs_ts_metrics \
                     WHERE timestamp >= ?2 \
                     GROUP BY bucket, blocked, cached \
                     ORDER BY bucket",
                )?;
                let rows = stmt
                    .query_map(params![bucket_ms, since_ms, offset_ms], |row| {
                        Ok(MetricsBucket {
                            timestamp: row.get::<_, i64>(0)? / 1000, // return seconds
                            blocked: row.get::<_, i64>(1)? != 0,
                            cached: row.get::<_, i64>(2)? != 0,
                            count: row.get(3)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(result)
    }

    /// Query counts by outcome class, type and response time — the grain the
    /// outcome breakdown, the query-type breakdown and the latency histogram
    /// all fold out of. Every column sits in `idx_query_logs_ts_metrics`.
    ///
    /// `INDEXED BY` for the same reason [`Self::metrics_by_bucket_since`] needs
    /// it: `idx_query_logs_timestamp` also matches the range and is the smaller
    /// index, so the planner picks that one and then pays a rowid lookup per
    /// row to reach `has_result`.
    async fn metrics_window_since(
        &self,
        since: i64, // unix seconds
    ) -> Result<Vec<WindowMetricsRow>, DbError> {
        let since_ms = since * 1000;
        let rows = self
            .reader()
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT blocked, cached, has_result, query_type, response_ms, COUNT(*) \
                     FROM query_logs INDEXED BY idx_query_logs_ts_metrics \
                     WHERE timestamp >= ?1 \
                     GROUP BY blocked, cached, has_result, query_type, response_ms",
                )?;
                let rows = stmt
                    .query_map(params![since_ms], |row| {
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

    /// Bucket queries by weekday and hour-of-day in the viewer's local calendar,
    /// shifting each timestamp by `tz_offset_secs` (their east-positive UTC
    /// offset) before extracting the fields. Mirrors the alignment
    /// [`Self::timeline_multi_since`] applies, and carries the same DST caveat:
    /// a single offset can misplace rows recorded under the other DST phase.
    /// Pass 0 for plain UTC buckets.
    pub async fn hourly_heatmap_since(
        &self,
        since: i64, // unix seconds
        tz_offset_secs: i64,
    ) -> Result<Vec<HeatmapCell>, DbError> {
        let since_ms = since * 1000;
        let result = self
            .reader()
            .call(move |conn| {
                // Weekday and hour by integer arithmetic rather than
                // `strftime`, which would format two strings per row — ~894 k
                // calls for a 30-day window on a busy resolver, and the single
                // most expensive thing the Statistics page did (155 ms, versus
                // 61 ms for this form on a 447 k-row database).
                //
                // `INDEXED BY` because this reads nothing but `timestamp`,
                // and `idx_query_logs_timestamp` is the smallest index that
                // covers it. Left to itself the planner took
                // `idx_query_logs_ts_metrics` — also covering, also correct,
                // and 2 153 pages against 1 386 on a 370 k-row database purely
                // because it carries four columns this query never reads.
                //
                // The `+ 4` is because Unix day 0 (1970-01-01) was a Thursday
                // and `strftime('%w')` counts from Sunday = 0. Truncating
                // division is only equal to flooring for non-negative inputs,
                // which is what `timestamp / 1000 + ?2` always is here:
                // timestamps come from the system clock and the offset is at
                // most ±14 h.
                let mut stmt = conn.prepare_cached(
                    "SELECT ((timestamp / 1000 + ?2) / 86400 + 4) % 7 AS wday, \
                            (timestamp / 1000 + ?2) % 86400 / 3600 AS hr, \
                            COUNT(*) \
                     FROM query_logs INDEXED BY idx_query_logs_timestamp \
                     WHERE timestamp >= ?1 \
                     GROUP BY wday, hr \
                     ORDER BY wday, hr",
                )?;
                let rows = stmt
                    .query_map(params![since_ms, tz_offset_secs], |row| {
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

    /// Percentiles over `response_ms`, derived in Rust from the histogram
    /// [`Self::metrics_window_since`] returns.
    ///
    /// The first implementation ran a window function
    /// (`ROW_NUMBER() OVER (ORDER BY response_ms)`), which forced `SQLite` to
    /// sort every matching row. A histogram is exact here because `response_ms`
    /// is integer milliseconds, and it costs one aggregate over the range.
    pub async fn latency_summary_since(&self, since: i64) -> Result<LatencySummary, DbError> {
        let rows = self.metrics_window_since(since).await?;
        Ok(latency_from_window(&rows))
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

    /// How many rows `query_logs` holds, read from the counter the write paths
    /// maintain rather than counted.
    ///
    /// `SELECT COUNT(*)` has no shortcut in `SQLite` — it walks the smallest
    /// index end to end, 1 386 pages on a 370 k-row database — and the Database
    /// Health card asks for it on every Statistics page load, for a number it
    /// prints and two of its estimates divide by. The counter is one row of
    /// `settings`, written inside the same transaction as every insert, prune
    /// and clear, so it cannot report a total the table does not hold.
    ///
    /// A database with no counter row counts, which is what the migration
    /// seeded it from.
    pub async fn total_log_count(&self) -> Result<i64, DbError> {
        let result = self
            .reader()
            .call(|conn| {
                let stored: Option<String> = conn
                    .prepare_cached("SELECT value FROM settings WHERE key = ?1")?
                    .query_row(params![QUERY_LOG_COUNT_KEY], |row| row.get(0))
                    .optional()?;
                if let Some(count) = stored.and_then(|v| v.parse::<i64>().ok()) {
                    return Ok(count);
                }
                let count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM query_logs", [], |row| row.get(0))?;
                Ok(count)
            })
            .await?;
        Ok(result)
    }

    /// Bucket queries into a total/blocked timeline on UTC-epoch boundaries.
    ///
    /// Takes and returns Unix **seconds**, matching
    /// [`Self::timeline_multi_since`]; milliseconds exist only inside the
    /// query, because that is the unit the `query_logs.timestamp` column uses.
    pub async fn timeline_since(
        &self,
        since: i64, // unix seconds
        bucket_secs: i64,
    ) -> Result<Vec<TimelinePoint>, DbError> {
        let rows = self
            .reader()
            .call(move |conn| {
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
                            timestamp: row.get::<_, i64>(0)? / 1000, // return seconds
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

/// Lay sparse quarter counts out densely, so the page ships four arrays of
/// integers rather than an object per quarter.
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

/// Classify each grain and total across the whole window. The precedence —
/// blocked, then cached, then whether an answer came back — is the one the
/// query log's Verdict column shows, so a row cannot be counted twice.
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

/// Counts per query type, busiest first — the same order the single-purpose
/// `GROUP BY query_type ORDER BY cnt DESC` returned.
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
    // Still needed as the pick() fallback, even though it is no longer reported.
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
        p50_ms: pick(rank_for(0.50)),
        p95_ms: pick(rank_for(0.95)),
        p99_ms: pick(rank_for(0.99)),
    }
}

/// Move the maintained `query_logs` row count by `delta`. Takes the connection
/// the write is on so it lands in that write's transaction: a counter updated
/// beside its table rather than inside it is a counter that can disagree.
fn bump_log_count(conn: &rusqlite::Connection, delta: i64) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE settings SET value = CAST(value AS INTEGER) + ?1 WHERE key = ?2")?
        .execute(params![delta, QUERY_LOG_COUNT_KEY])?;
    Ok(())
}

/// Set the maintained `query_logs` row count outright, for the write that
/// leaves a known number of rows behind rather than a known change.
fn set_log_count(conn: &rusqlite::Connection, count: i64) -> rusqlite::Result<()> {
    conn.prepare_cached("UPDATE settings SET value = ?1 WHERE key = ?2")?
        .execute(params![count, QUERY_LOG_COUNT_KEY])?;
    Ok(())
}

/// Add a column to `table` if it doesn't already exist.
///
/// `SQLite` doesn't support `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so we
/// probe the table's columns first. The `table` argument is interpolated into
/// the SQL — only call this from migration code with trusted table names.
///
/// `pragma_table_xinfo` rather than `pragma_table_info`, because the latter
/// omits generated columns: a fresh database, whose `CREATE TABLE` already
/// declared `query_logs.has_result`, would be told the column was missing and
/// fail the migration on `duplicate column name`.
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

        // Simulate a v7 database with a user and unrelated data. `sessions` is
        // part of the fixture because a real v7 database has one — it is created
        // by the v6 step, which does not re-run for a database already stamped
        // v7 — and the v9 step below rewrites that table.
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

        // The plaintext row is gone rather than carried forward: keeping it
        // would leave a usable credential sitting in the file, which is the
        // whole point of the migration.
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

    #[tokio::test]
    async fn fresh_schema_has_client_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("noadd.sqlite3");
        let db = Database::open(path.to_str().unwrap()).await.unwrap();

        let indexes = query_log_index_names(&db).await;
        assert!(
            indexes.iter().any(|n| n == "idx_query_logs_client_ts"),
            "(client_ip, doh_token, timestamp) index should exist: {indexes:?}"
        );
    }

    #[tokio::test]
    async fn fresh_schema_has_metrics_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("noadd.sqlite3");
        let db = Database::open(path.to_str().unwrap()).await.unwrap();

        let indexes = query_log_index_names(&db).await;
        assert!(
            indexes.iter().any(|n| n == "idx_query_logs_ts_metrics"),
            "(timestamp, blocked, cached, response_ms, query_type) index should exist: {indexes:?}"
        );
    }

    /// The metrics index only earns its disk if the planner treats it as
    /// *covering* — a plain `SEARCH … USING INDEX` would still pay the row
    /// lookup this index exists to avoid.
    #[tokio::test]
    async fn timeline_query_uses_the_metrics_index_as_covering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plan.db");
        let db = Database::open(path.to_str().unwrap()).await.unwrap();

        let logs: Vec<QueryLogEntry> = (0..500)
            .map(|i| QueryLogEntry {
                timestamp: 1_704_067_200_000 + i * 60_000,
                domain: format!("d{}.example", i % 50),
                query_type: if i % 3 == 0 { "AAAA" } else { "A" }.into(),
                client_ip: format!("10.0.0.{}", i % 25),
                blocked: i % 5 == 0,
                cached: i % 4 == 0,
                response_ms: i % 7,
                upstream: None,
                doh_token: None,
                result: None,
                authenticated_data: false,
            })
            .collect();
        db.insert_query_logs(&logs).await.unwrap();

        let plan = db
            .conn
            .call(|conn| {
                conn.execute_batch("ANALYZE;")?;
                let mut stmt = conn.prepare(
                    "EXPLAIN QUERY PLAN \
                     SELECT (timestamp / 3600000) * 3600000 AS b, COUNT(*), \
                            COALESCE(SUM(blocked), 0), COALESCE(SUM(cached), 0) \
                     FROM query_logs WHERE timestamp >= ?1 GROUP BY b",
                )?;
                let rows = stmt
                    .query_map(params![0_i64], |row| row.get::<_, String>(3))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, tokio_rusqlite::Error>(rows.join(" | "))
            })
            .await
            .unwrap();

        assert!(
            plan.contains("COVERING INDEX idx_query_logs_ts_metrics"),
            "timeline query should be covered by the metrics index, got: {plan}"
        );
    }

    #[tokio::test]
    async fn migration_v11_adds_metrics_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v10.db");
        let path_str = path.to_str().unwrap().to_string();

        // A v10 database: has the client index, lacks the metrics one.
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
                    result TEXT,
                    authenticated_data INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp);
                CREATE INDEX idx_query_logs_domain_ts ON query_logs(domain, timestamp);
                CREATE INDEX idx_query_logs_client_ts
                    ON query_logs(client_ip, doh_token, timestamp);
                PRAGMA user_version = 10;",
            )
            .unwrap();
        }

        let db = Database::open(&path_str).await.unwrap();

        let indexes = query_log_index_names(&db).await;
        assert!(
            indexes.iter().any(|n| n == "idx_query_logs_ts_metrics"),
            "metrics index should be created by migration: {indexes:?}"
        );
    }

    /// The metrics index has to end up carrying `has_result` whichever way the
    /// database arrived at version 12 — created fresh, or migrated from a
    /// version whose `query_logs` had no such column.
    #[tokio::test]
    async fn migration_v12_puts_the_outcome_flag_in_the_metrics_index() {
        async fn metrics_index_columns(db: &Database) -> Vec<String> {
            db.reader()
                .call(|conn| {
                    let mut stmt = conn.prepare(
                        "SELECT name FROM pragma_index_info('idx_query_logs_ts_metrics')",
                    )?;
                    let names = stmt
                        .query_map([], |row| row.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok::<_, tokio_rusqlite::Error>(names)
                })
                .await
                .unwrap()
        }

        let dir = tempfile::tempdir().unwrap();

        // A v11 database: the metrics index exists, without the outcome flag.
        let legacy = dir.path().join("v11.db");
        let legacy_str = legacy.to_str().unwrap().to_string();
        {
            let conn = rusqlite::Connection::open(&legacy_str).unwrap();
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
                    result TEXT,
                    authenticated_data INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp);
                CREATE INDEX idx_query_logs_domain_ts ON query_logs(domain, timestamp);
                CREATE INDEX idx_query_logs_client_ts
                    ON query_logs(client_ip, doh_token, timestamp);
                CREATE INDEX idx_query_logs_ts_metrics
                    ON query_logs(timestamp, blocked, cached, response_ms, query_type);
                PRAGMA user_version = 11;",
            )
            .unwrap();
        }
        let migrated = Database::open(&legacy_str).await.unwrap();

        let fresh_path = dir.path().join("fresh.db");
        let fresh = Database::open(fresh_path.to_str().unwrap()).await.unwrap();

        for (label, db) in [("migrated", &migrated), ("fresh", &fresh)] {
            let columns = metrics_index_columns(db).await;
            assert!(
                columns.iter().any(|c| c == "has_result"),
                "{label} database's metrics index lacks has_result: {columns:?}"
            );
            // Reachable through the query that depends on it — the index could
            // carry the column and still be the wrong one for `INDEXED BY`.
            assert!(db.outcome_breakdown_since(0).await.is_ok());
        }
    }

    /// The counter has to arrive holding what the table already holds. A
    /// database that upgrades with a million rows in it and a counter seeded at
    /// zero would report zero for as long as it kept those rows, and the
    /// fallback in `total_log_count` would never fire to correct it — the row
    /// exists, it is just wrong.
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

    /// A database from before version 14 has to come out of `open` holding the
    /// upstream index, because `top_upstreams_since` names it with `INDEXED BY`
    /// and a statement naming a missing index does not prepare at all — the
    /// dashboard would lose its upstream list rather than merely run slower.
    #[tokio::test]
    async fn migration_v14_adds_the_upstream_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v13.db");
        let path_str = path.to_str().unwrap().to_string();

        let entries: Vec<QueryLogEntry> = (0..4)
            .map(|i| QueryLogEntry {
                timestamp: 1_000_000 + i,
                domain: "example.com".to_string(),
                query_type: "A".to_string(),
                client_ip: "10.0.0.1".to_string(),
                blocked: false,
                cached: false,
                upstream: (i != 0).then(|| "tls://1.1.1.1:853".to_string()),
                doh_token: None,
                result: None,
                response_ms: 10 * i,
                authenticated_data: false,
            })
            .collect();
        {
            let db = Database::open(&path_str).await.unwrap();
            db.insert_query_logs(&entries).await.unwrap();
            db.close().await;
        }
        {
            let conn = rusqlite::Connection::open(&path_str).unwrap();
            conn.execute_batch(
                "DROP INDEX idx_query_logs_ts_upstream;
                 PRAGMA user_version = 13;",
            )
            .unwrap();
        }

        let migrated = Database::open(&path_str).await.unwrap();
        let indexes = query_log_index_names(&migrated).await;
        assert!(
            indexes.iter().any(|n| n == "idx_query_logs_ts_upstream"),
            "upstream index should exist after migrating: {indexes:?}"
        );
        let top = migrated.top_upstreams_since(0, 10).await.unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].count, 3, "the unforwarded row is not an upstream's");
        assert!((top[0].avg_ms - 20.0).abs() < 1e-9);
    }

    #[tokio::test]
    async fn migration_v10_adds_client_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v9.db");
        let path_str = path.to_str().unwrap().to_string();

        // A v9 database: everything current except the client index.
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
                    result TEXT,
                    authenticated_data INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX idx_query_logs_timestamp ON query_logs(timestamp);
                CREATE INDEX idx_query_logs_domain_ts ON query_logs(domain, timestamp);
                PRAGMA user_version = 9;",
            )
            .unwrap();
        }

        let db = Database::open(&path_str).await.unwrap();

        let indexes = query_log_index_names(&db).await;
        assert!(
            indexes.iter().any(|n| n == "idx_query_logs_client_ts"),
            "client index should be created by migration: {indexes:?}"
        );
    }

    /// The index only pays off if the planner actually picks it — the
    /// version-5 migration's comment records that a new index alone was not
    /// enough there. Assert the plan, not just the index's existence.
    #[tokio::test]
    async fn top_clients_query_uses_the_client_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plan.db");
        let db = Database::open(path.to_str().unwrap()).await.unwrap();

        let logs: Vec<QueryLogEntry> = (0..500)
            .map(|i| QueryLogEntry {
                timestamp: 1_000_000 + i,
                domain: format!("d{}.example", i % 50),
                query_type: "A".into(),
                client_ip: format!("10.0.0.{}", i % 25),
                blocked: false,
                cached: false,
                response_ms: i % 7,
                upstream: None,
                doh_token: None,
                result: None,
                authenticated_data: false,
            })
            .collect();
        db.insert_query_logs(&logs).await.unwrap();

        // The writer, not `reader()`: ANALYZE writes sqlite_stat1, and the read
        // pool is opened SQLITE_OPEN_READ_ONLY.
        let plan = db
            .conn
            .call(|conn| {
                conn.execute_batch("ANALYZE;")?;
                let mut stmt = conn.prepare(
                    "EXPLAIN QUERY PLAN SELECT client_ip, doh_token, COUNT(*) c \
                     FROM query_logs WHERE timestamp >= ?1 \
                     GROUP BY client_ip, doh_token ORDER BY c DESC LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(params![0_i64, 10_i64], |row| row.get::<_, String>(3))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok::<_, tokio_rusqlite::Error>(rows.join(" | "))
            })
            .await
            .unwrap();

        assert!(
            plan.contains("idx_query_logs_client_ts"),
            "top-clients query should be served by the client index, got: {plan}"
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
