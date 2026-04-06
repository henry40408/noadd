use rusqlite::{OptionalExtension, params};
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

impl Database {
    pub async fn open(path: &str) -> Result<Self, DbError> {
        let conn = Connection::open(path).await?;
        let db = Self { conn };
        db.init_schema().await?;
        Ok(db)
    }

    async fn init_schema(&self) -> Result<(), DbError> {
        self.conn
            .call(|conn| {
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
    fn run_migrations(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

        // Migration 1: add `cached` column to query_logs
        if version < 1 {
            // Only run ALTER if table existed before (i.e. not a fresh DB).
            // For fresh DBs the column already exists in CREATE TABLE.
            let has_cached: bool = conn
                .prepare(
                    "SELECT COUNT(*) FROM pragma_table_info('query_logs') WHERE name='cached'",
                )?
                .query_row([], |row| row.get::<_, i64>(0))
                .map(|c| c > 0)?;
            if !has_cached {
                conn.execute(
                    "ALTER TABLE query_logs ADD COLUMN cached INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
            }
        }

        // Migration 2: add `doh_token` column to query_logs, create doh_tokens table
        if version < 2 {
            let has_col: bool = conn
                .prepare(
                    "SELECT COUNT(*) FROM pragma_table_info('query_logs') WHERE name='doh_token'",
                )?
                .query_row([], |row| row.get::<_, i64>(0))
                .map(|c| c > 0)?;
            if !has_col {
                conn.execute("ALTER TABLE query_logs ADD COLUMN doh_token TEXT", [])?;
            }
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS doh_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT NOT NULL UNIQUE
                )",
            )?;
        }

        // Migration 3: add `upstream` column to query_logs
        if version < 3 {
            let has_col: bool = conn
                .prepare(
                    "SELECT COUNT(*) FROM pragma_table_info('query_logs') WHERE name='upstream'",
                )?
                .query_row([], |row| row.get::<_, i64>(0))
                .map(|c| c > 0)?;
            if !has_col {
                conn.execute("ALTER TABLE query_logs ADD COLUMN upstream TEXT", [])?;
            }
        }

        // Migration 4: add `result` column to query_logs
        if version < 4 {
            let has_col: bool = conn
                .prepare(
                    "SELECT COUNT(*) FROM pragma_table_info('query_logs') WHERE name='result'",
                )?
                .query_row([], |row| row.get::<_, i64>(0))
                .map(|c| c > 0)?;
            if !has_col {
                conn.execute("ALTER TABLE query_logs ADD COLUMN result TEXT", [])?;
            }
        }

        // Set to latest version
        const LATEST_VERSION: i64 = 4;
        if version < LATEST_VERSION {
            conn.pragma_update(None, "user_version", LATEST_VERSION)?;
        }

        Ok(())
    }

    /// List all table names (for testing).
    pub async fn list_tables(&self) -> Result<Vec<String>, DbError> {
        let tables = self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
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
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
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
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![key, value],
                )?;
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
                    let mut stmt = tx.prepare(
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
            .conn
            .call(move |conn| {
                let mut sql = "SELECT timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result FROM query_logs WHERE 1=1".to_string();
                let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

                if let Some(ref s) = search {
                    sql.push_str(" AND domain LIKE ?");
                    param_values.push(Box::new(format!("%{s}%")));
                }
                if let Some(b) = blocked {
                    sql.push_str(" AND blocked = ?");
                    param_values.push(Box::new(b as i64));
                }
                if let Some(ref t) = token {
                    sql.push_str(" AND doh_token = ?");
                    param_values.push(Box::new(t.clone()));
                }
                if let Some(ref qt) = query_type {
                    sql.push_str(" AND query_type = ?");
                    param_values.push(Box::new(qt.clone()));
                }
                sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
                param_values.push(Box::new(limit));
                param_values.push(Box::new(offset));

                let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                    param_values.iter().map(|p| p.as_ref()).collect();

                let mut stmt = conn.prepare(&sql)?;
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
            .conn
            .call(move |conn| {
                let mut sql = "SELECT COUNT(*) FROM query_logs WHERE 1=1".to_string();
                let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

                if let Some(ref s) = search {
                    sql.push_str(" AND domain LIKE ?");
                    param_values.push(Box::new(format!("%{s}%")));
                }
                if let Some(b) = blocked {
                    sql.push_str(" AND blocked = ?");
                    param_values.push(Box::new(b as i64));
                }
                if let Some(ref t) = token {
                    sql.push_str(" AND doh_token = ?");
                    param_values.push(Box::new(t.clone()));
                }
                if let Some(ref qt) = query_type {
                    sql.push_str(" AND query_type = ?");
                    param_values.push(Box::new(qt.clone()));
                }

                let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                    param_values.iter().map(|p| p.as_ref()).collect();

                conn.query_row(&sql, params_refs.as_slice(), |row| row.get(0))
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
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
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
            .conn
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
            .conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT id, rule, rule_type FROM custom_rules ORDER BY id")?;
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
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
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
            .conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT content FROM filter_list_content WHERE list_id = ?1")?;
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
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare("SELECT id, token FROM doh_tokens ORDER BY id")?;
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
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare("SELECT token FROM doh_tokens WHERE token = ?1")?;
                let found: Option<String> = stmt.query_row(params![token], |row| row.get(0)).ok();
                Ok(found)
            })
            .await?;
        Ok(result)
    }

    pub async fn has_doh_tokens(&self) -> Result<bool, DbError> {
        let count = self
            .conn
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
            .conn
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
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
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
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
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

    pub async fn top_domains_since(
        &self,
        since: i64,
        limit: i64,
    ) -> Result<Vec<TopDomain>, DbError> {
        let since_ms = since * 1000;
        let rows = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
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
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
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
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
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

    pub async fn timeline_since(
        &self,
        since: i64,
        bucket_secs: i64,
    ) -> Result<Vec<TimelinePoint>, DbError> {
        let rows = self
            .conn
            .call(move |conn| {
                // Convert seconds to milliseconds to match timestamp storage
                let since_ms = since * 1000;
                let bucket_ms = bucket_secs * 1000;
                let mut stmt = conn.prepare(
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
