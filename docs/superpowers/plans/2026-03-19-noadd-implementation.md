# noadd Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-hosted DNS-over-HTTPS adblock DNS server with admin UI, targeting personal/home deployment as a single Rust binary.

**Architecture:** Single async binary using tokio. axum serves DoH endpoints, Admin REST API, and embedded frontend SPA. DNS queries flow through a filter engine (HashMap + reverse domain trie) before being forwarded to privacy-focused upstream DNS servers. SQLite stores configuration and query logs. Filter rules are hot-swappable via ArcSwap.

**Tech Stack:** Rust (edition 2024), tokio, axum, hickory-proto, hickory-resolver, tokio-rusqlite, moka, arc-swap, rustls, clap, serde, tracing

**Spec:** `docs/superpowers/specs/2026-03-19-noadd-doh-adblock-dns-design.md`

**Testing:** `cargo nextest run` (per CLAUDE.md). All tests use `#[tokio::test]` for async.

---

## Review Errata — Must-Read Before Implementation

The following corrections apply to the code examples throughout this plan. The implementer MUST apply these during implementation:

### Critical Fixes

1. **moka Cache API**: `Cache::insert_with_ttl()` does not exist. Use `Cache::builder().time_to_live(Duration::from_secs(300)).build()` for a global TTL, or implement the `moka::Expiry` trait for per-entry TTL. The `DnsCache::insert` in Task 6 must be adjusted accordingly.

2. **Upstream Forwarder must use encrypted DNS**: Task 5's raw UDP forwarding violates the spec's privacy requirements. Use `hickory-resolver` with DoH/DoT to forward to upstream DNS servers. The `UpstreamForwarder` should wrap `hickory_resolver::TokioAsyncResolver` configured with the privacy-focused upstreams (Cloudflare DoH, Quad9 DoH, Mullvad DoH).

3. **hickory-proto serialization API**: `Message::to_vec()` may not exist in all versions. If unavailable, use `BinEncoder`: `let mut buf = Vec::new(); let mut encoder = BinEncoder::new(&mut buf); msg.emit(&mut encoder)?;`. Verify against the actual installed version.

4. **hickory-proto default-features**: Do NOT use `default-features = false` on `hickory-proto` — it may disable essential serialization features. Keep default features enabled.

5. **hickory-resolver features**: Change from `features = ["tokio-runtime"]` to `features = ["dns-over-https-rustls", "dns-over-tls-rustls", "tokio-runtime"]` to enable encrypted upstream DNS.

### Important Fixes

6. **Dependencies missing in Cargo.toml**: Add these from the start in Task 1:
   - `anyhow = "1"` in `[dependencies]` (used by Tasks 8, 9)
   - `tower = "0.5"` in `[dev-dependencies]` (used by Task 10 tests)
   - `mime_guess = "2"` in `[dependencies]` (used by Task 18)
   - `rustls-pemfile = "2"` in `[dependencies]` (used by Task 17)

7. **CSRF protection**: In Task 13's admin API, add a CSRF token middleware. Generate a random token per session, store it alongside the session, include it in responses as `X-CSRF-Token` header, and validate it on all state-changing requests (POST/PUT/DELETE). The SPA must send this token in request headers.

8. **Login rate limiting**: In Task 12, add a simple in-memory rate limiter using `HashMap<IpAddr, (u32, Instant)>` — track attempts per IP, reject after 5 within 60 seconds. Wire it into the login handler in Task 13.

9. **30-day stats**: In Task 14, add `total_30d` and `blocked_30d` fields to the `Summary` struct and query them in `compute_summary`.

10. **Filter list content storage**: Task 15 stores list content in the `settings` table which is inappropriate for multi-megabyte data. Add a `filter_list_content` table with columns `(list_id INTEGER PRIMARY KEY, content TEXT)` to the schema in Task 2, and use it instead of `settings` for list content.

11. **DoH client IP extraction**: In Task 10, extract the real client IP from `ConnectInfo` (axum) or `X-Forwarded-For` header instead of hardcoding `127.0.0.1`.

12. **SessionStore test fix**: In Task 12 tests, use `new_session_store()` instead of `SessionStore::new()` — `SessionStore` is a type alias, not a struct.

13. **Circular dependency**: In Task 14, define `TopDomain`, `TopClient`, and `TimelinePoint` structs in `src/db.rs` (not `src/admin/stats.rs`) and import them in both `stats.rs` and `api.rs`. This avoids the circular `db ↔ admin::stats` dependency.

14. **TCP connection reuse**: In Task 9, wrap the read/handle/write in a loop to support multiple queries per TCP connection (RFC 7766).

15. **Test robustness**: In Task 20 integration tests, drop the `log_tx` sender and `await` the logger handle instead of using `sleep` for flushing. Use `tempfile::tempdir()` instead of `NamedTempFile` for SQLite test databases throughout.

---

## Task Dependency Graph

```
Task 1 (scaffolding)
  └─► Task 2 (database)
       └─► Task 3 (filter parser)
            └─► Task 4 (filter engine)
                 └─► Task 5 (upstream forwarder)
                      └─► Task 6 (DNS cache)
                           └─► Task 7 (DNS handler)
                                ├─► Task 8 (UDP listener)
                                ├─► Task 9 (TCP listener)
                                └─► Task 10 (DoH endpoint)
                                     └─► Task 11 (query logger)
                                          └─► Task 12 (admin auth)
                                               └─► Task 13 (admin API - settings & lists)
                                                    └─► Task 14 (admin API - stats & logs)
                                                         └─► Task 15 (list download & update)
                                                              └─► Task 16 (build.rs & embedded lists)
                                                                   └─► Task 17 (TLS/ACME)
                                                                        └─► Task 18 (admin web UI) @frontend-design
                                                                             └─► Task 19 (graceful shutdown)
                                                                                  └─► Task 20 (integration tests)
                                                                                       └─► Task 21 (main.rs wiring)
```

---

### Task 1: Project Scaffolding

**Files:**
- Modify: `Cargo.toml`
- Create: `src/lib.rs`

- [ ] **Step 1: Update Cargo.toml with all dependencies**

```toml
[package]
name = "noadd"
version = "0.1.0"
edition = "2024"

[dependencies]
tokio = { version = "1", default-features = false, features = ["rt-multi-thread", "net", "time", "sync", "macros", "signal", "io-util"] }
axum = "0.8"
axum-extra = { version = "0.10", default-features = false, features = ["cookie"] }
hickory-proto = "0.25"
hickory-resolver = { version = "0.25", default-features = false, features = ["dns-over-https-rustls", "dns-over-tls-rustls", "tokio-runtime"] }
tokio-rusqlite = { version = "0.6", features = ["bundled"] }
moka = { version = "0.12", default-features = false, features = ["future"] }
arc-swap = "1"
rustls = { version = "0.23", default-features = false }
rustls-acme = { version = "0.12", default-features = false }
argon2 = "0.5"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "gzip"] }
serde = { version = "1", default-features = false, features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", default-features = false, features = ["fmt", "env-filter"] }
include_dir = "0.7"
clap = { version = "4", default-features = false, features = ["derive", "std", "help"] }
base64 = "0.22"
rand = "0.9"
bytes = "1"
tower-http = { version = "0.6", default-features = false, features = ["cors"] }
thiserror = "2"
anyhow = "1"
mime_guess = "2"
rustls-pemfile = "2"

[dev-dependencies]
tokio-test = "0.4"
tempfile = "3"
tower = "0.5"
```

Note: Exact version numbers should be verified against crates.io at implementation time. The `hickory-*` crates in particular may have newer releases. Adjust versions as needed while keeping `default-features = false` where specified.

- [ ] **Step 2: Create src/lib.rs with module declarations**

```rust
pub mod admin;
pub mod cache;
pub mod config;
pub mod db;
pub mod dns;
pub mod filter;
pub mod logger;
pub mod tls;
pub mod upstream;
```

- [ ] **Step 3: Create empty module files so it compiles**

Create these files, each with just `// TODO` or appropriate empty module declarations:
- `src/admin/mod.rs` — `pub mod api; pub mod auth; pub mod stats;`
- `src/admin/api.rs`
- `src/admin/auth.rs`
- `src/admin/stats.rs`
- `src/cache.rs`
- `src/config.rs`
- `src/db.rs`
- `src/dns/mod.rs` — `pub mod doh; pub mod handler; pub mod tcp; pub mod udp;`
- `src/dns/doh.rs`
- `src/dns/handler.rs`
- `src/dns/tcp.rs`
- `src/dns/udp.rs`
- `src/filter/mod.rs` — `pub mod engine; pub mod lists; pub mod parser;`
- `src/filter/engine.rs`
- `src/filter/lists.rs`
- `src/filter/parser.rs`
- `src/logger.rs`
- `src/tls.rs`
- `src/upstream/mod.rs` — `pub mod forwarder;`
- `src/upstream/forwarder.rs`

- [ ] **Step 4: Verify it compiles**

Run: `cd /home/nixos/Develop/claude/noadd && cargo check`
Expected: compiles with no errors (warnings OK)

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/
git commit -m "chore: scaffold project structure with dependencies"
```

---

### Task 2: Database Layer

**Files:**
- Modify: `src/db.rs`
- Create: `tests/db_test.rs`

- [ ] **Step 1: Write failing tests for database initialization and settings CRUD**

```rust
// tests/db_test.rs
use noadd::db::Database;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_database_creates_tables() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();
    // Verify tables exist by querying sqlite_master
    let tables = db.list_tables().await.unwrap();
    assert!(tables.contains(&"settings".to_string()));
    assert!(tables.contains(&"query_logs".to_string()));
    assert!(tables.contains(&"filter_lists".to_string()));
    assert!(tables.contains(&"custom_rules".to_string()));
}

#[tokio::test]
async fn test_settings_get_set() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();
    db.set_setting("dns_port", "5353").await.unwrap();
    let val = db.get_setting("dns_port").await.unwrap();
    assert_eq!(val, Some("5353".to_string()));
}

#[tokio::test]
async fn test_settings_get_missing_returns_none() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();
    let val = db.get_setting("nonexistent").await.unwrap();
    assert_eq!(val, None);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test db_test`
Expected: FAIL — `Database` type doesn't exist yet

- [ ] **Step 3: Implement Database struct with schema creation and settings CRUD**

```rust
// src/db.rs
use tokio_rusqlite::Connection;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] tokio_rusqlite::Error),
    #[error("rusqlite error: {0}")]
    Rusqlite(#[from] rusqlite::Error),
}

pub type DbResult<T> = Result<T, DbError>;

#[derive(Clone)]
pub struct Database {
    conn: Connection,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS query_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    client_ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    query_type TEXT NOT NULL,
    action TEXT NOT NULL,
    upstream TEXT,
    response_time_ms INTEGER NOT NULL,
    matched_rule TEXT,
    matched_list TEXT
);
CREATE INDEX IF NOT EXISTS idx_query_logs_timestamp ON query_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_query_logs_domain ON query_logs(domain);
CREATE INDEX IF NOT EXISTS idx_query_logs_client_ip ON query_logs(client_ip);

CREATE TABLE IF NOT EXISTS filter_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    builtin INTEGER NOT NULL DEFAULT 0,
    last_updated INTEGER,
    rule_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    rule_type TEXT NOT NULL CHECK(rule_type IN ('allow', 'block')),
    created_at INTEGER NOT NULL
);
";

impl Database {
    pub async fn open(path: &std::path::Path) -> DbResult<Self> {
        let conn = Connection::open(path).await?;
        conn.call(|conn| {
            conn.execute_batch(SCHEMA)?;
            Ok(())
        })
        .await?;
        Ok(Self { conn })
    }

    pub async fn list_tables(&self) -> DbResult<Vec<String>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
                )?;
                let tables = stmt
                    .query_map([], |row| row.get(0))?
                    .collect::<Result<Vec<String>, _>>()?;
                Ok(tables)
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn get_setting(&self, key: &str) -> DbResult<Option<String>> {
        let key = key.to_string();
        self.conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
                let mut rows = stmt.query_map([&key], |row| row.get(0))?;
                match rows.next() {
                    Some(val) => Ok(Some(val?)),
                    None => Ok(None),
                }
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn set_setting(&self, key: &str, value: &str) -> DbResult<()> {
        let key = key.to_string();
        let value = value.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [&key, &value],
                )?;
                Ok(())
            })
            .await
            .map_err(DbError::from)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test db_test`
Expected: 3 tests PASS

- [ ] **Step 5: Write failing tests for query_logs insert and retrieval**

```rust
// Append to tests/db_test.rs
use noadd::db::QueryLogEntry;

#[tokio::test]
async fn test_insert_and_query_logs() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();
    let entry = QueryLogEntry {
        timestamp: 1000,
        client_ip: "192.168.1.1".into(),
        domain: "ads.example.com".into(),
        query_type: "A".into(),
        action: "blocked".into(),
        upstream: None,
        response_time_ms: 5,
        matched_rule: Some("||ads.example.com^".into()),
        matched_list: Some("AdGuard DNS Filter".into()),
    };
    db.insert_query_logs(&[entry]).await.unwrap();

    let logs = db
        .get_query_logs(None, None, None, 10, 0)
        .await
        .unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].domain, "ads.example.com");
    assert_eq!(logs[0].action, "blocked");
}

#[tokio::test]
async fn test_query_logs_pagination() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();
    for i in 0..20 {
        let entry = QueryLogEntry {
            timestamp: 1000 + i,
            client_ip: "192.168.1.1".into(),
            domain: format!("domain{i}.com"),
            query_type: "A".into(),
            action: "allowed".into(),
            upstream: Some("1.1.1.1".into()),
            response_time_ms: 10,
            matched_rule: None,
            matched_list: None,
        };
        db.insert_query_logs(&[entry]).await.unwrap();
    }
    let page1 = db.get_query_logs(None, None, None, 10, 0).await.unwrap();
    let page2 = db.get_query_logs(None, None, None, 10, 10).await.unwrap();
    assert_eq!(page1.len(), 10);
    assert_eq!(page2.len(), 10);
    // Newest first
    assert!(page1[0].timestamp > page1[9].timestamp);
}
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test db_test`
Expected: new tests FAIL — `QueryLogEntry` and methods don't exist yet

- [ ] **Step 7: Implement QueryLogEntry and log methods**

Add to `src/db.rs`:

```rust
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct QueryLogEntry {
    pub timestamp: i64,
    pub client_ip: String,
    pub domain: String,
    pub query_type: String,
    pub action: String,
    pub upstream: Option<String>,
    pub response_time_ms: i64,
    pub matched_rule: Option<String>,
    pub matched_list: Option<String>,
}

impl Database {
    // ... existing methods ...

    pub async fn insert_query_logs(&self, entries: &[QueryLogEntry]) -> DbResult<()> {
        let entries = entries.to_vec();
        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare(
                        "INSERT INTO query_logs (timestamp, client_ip, domain, query_type, action, upstream, response_time_ms, matched_rule, matched_list)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    )?;
                    for e in &entries {
                        stmt.execute(rusqlite::params![
                            e.timestamp,
                            e.client_ip,
                            e.domain,
                            e.query_type,
                            e.action,
                            e.upstream,
                            e.response_time_ms,
                            e.matched_rule,
                            e.matched_list,
                        ])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(DbError::from)
    }

    /// Query logs with optional filters. Returns newest first.
    /// - `domain_filter`: substring match on domain
    /// - `action_filter`: exact match on action ("allowed" or "blocked")
    /// - `client_filter`: exact match on client_ip
    pub async fn get_query_logs(
        &self,
        domain_filter: Option<&str>,
        action_filter: Option<&str>,
        client_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> DbResult<Vec<QueryLogEntry>> {
        let domain_filter = domain_filter.map(String::from);
        let action_filter = action_filter.map(String::from);
        let client_filter = client_filter.map(String::from);
        self.conn
            .call(move |conn| {
                let mut sql = "SELECT timestamp, client_ip, domain, query_type, action, upstream, response_time_ms, matched_rule, matched_list FROM query_logs WHERE 1=1".to_string();
                let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
                if let Some(ref d) = domain_filter {
                    sql.push_str(" AND domain LIKE ?");
                    params.push(Box::new(format!("%{d}%")));
                }
                if let Some(ref a) = action_filter {
                    sql.push_str(" AND action = ?");
                    params.push(Box::new(a.clone()));
                }
                if let Some(ref c) = client_filter {
                    sql.push_str(" AND client_ip = ?");
                    params.push(Box::new(c.clone()));
                }
                sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
                params.push(Box::new(limit));
                params.push(Box::new(offset));

                let mut stmt = conn.prepare(&sql)?;
                let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                    params.iter().map(|p| p.as_ref()).collect();
                let rows = stmt
                    .query_map(param_refs.as_slice(), |row| {
                        Ok(QueryLogEntry {
                            timestamp: row.get(0)?,
                            client_ip: row.get(1)?,
                            domain: row.get(2)?,
                            query_type: row.get(3)?,
                            action: row.get(4)?,
                            upstream: row.get(5)?,
                            response_time_ms: row.get(6)?,
                            matched_rule: row.get(7)?,
                            matched_list: row.get(8)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn delete_all_logs(&self) -> DbResult<()> {
        self.conn
            .call(|conn| {
                conn.execute("DELETE FROM query_logs", [])?;
                Ok(())
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn prune_logs_before(&self, timestamp: i64) -> DbResult<u64> {
        self.conn
            .call(move |conn| {
                let count =
                    conn.execute("DELETE FROM query_logs WHERE timestamp < ?1", [timestamp])?;
                Ok(count as u64)
            })
            .await
            .map_err(DbError::from)
    }
}
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test db_test`
Expected: all 5 tests PASS

- [ ] **Step 9: Write failing tests for filter_lists and custom_rules CRUD**

```rust
// Append to tests/db_test.rs
use noadd::db::{FilterListRow, CustomRuleRow};

#[tokio::test]
async fn test_filter_lists_crud() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();

    let id = db
        .add_filter_list("Test List", "https://example.com/list.txt", false)
        .await
        .unwrap();
    assert!(id > 0);

    let lists = db.get_filter_lists().await.unwrap();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].name, "Test List");
    assert!(lists[0].enabled);

    db.update_filter_list_enabled(id, false).await.unwrap();
    let lists = db.get_filter_lists().await.unwrap();
    assert!(!lists[0].enabled);

    db.delete_filter_list(id).await.unwrap();
    let lists = db.get_filter_lists().await.unwrap();
    assert!(lists.is_empty());
}

#[tokio::test]
async fn test_custom_rules_crud() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();

    let id = db.add_custom_rule("||ads.com^", "block").await.unwrap();
    assert!(id > 0);

    let rules = db.get_custom_rules("block").await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].rule, "||ads.com^");

    let allow_rules = db.get_custom_rules("allow").await.unwrap();
    assert!(allow_rules.is_empty());

    db.delete_custom_rule(id).await.unwrap();
    let rules = db.get_custom_rules("block").await.unwrap();
    assert!(rules.is_empty());
}
```

- [ ] **Step 10: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test db_test`
Expected: new tests FAIL

- [ ] **Step 11: Implement filter_lists and custom_rules CRUD methods**

Add to `src/db.rs`:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct FilterListRow {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub builtin: bool,
    pub last_updated: Option<i64>,
    pub rule_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustomRuleRow {
    pub id: i64,
    pub rule: String,
    pub rule_type: String,
    pub created_at: i64,
}

impl Database {
    // ... existing methods ...

    pub async fn add_filter_list(
        &self,
        name: &str,
        url: &str,
        builtin: bool,
    ) -> DbResult<i64> {
        let name = name.to_string();
        let url = url.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO filter_lists (name, url, builtin) VALUES (?1, ?2, ?3)",
                    rusqlite::params![name, url, builtin as i32],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn get_filter_lists(&self) -> DbResult<Vec<FilterListRow>> {
        self.conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, name, url, enabled, builtin, last_updated, rule_count FROM filter_lists ORDER BY id",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(FilterListRow {
                            id: row.get(0)?,
                            name: row.get(1)?,
                            url: row.get(2)?,
                            enabled: row.get::<_, i32>(3)? != 0,
                            builtin: row.get::<_, i32>(4)? != 0,
                            last_updated: row.get(5)?,
                            rule_count: row.get(6)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn update_filter_list_enabled(&self, id: i64, enabled: bool) -> DbResult<()> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE filter_lists SET enabled = ?1 WHERE id = ?2",
                    rusqlite::params![enabled as i32, id],
                )?;
                Ok(())
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn update_filter_list_stats(
        &self,
        id: i64,
        rule_count: i64,
        last_updated: i64,
    ) -> DbResult<()> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE filter_lists SET rule_count = ?1, last_updated = ?2 WHERE id = ?3",
                    rusqlite::params![rule_count, last_updated, id],
                )?;
                Ok(())
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn delete_filter_list(&self, id: i64) -> DbResult<()> {
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM filter_lists WHERE id = ?1", [id])?;
                Ok(())
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn add_custom_rule(&self, rule: &str, rule_type: &str) -> DbResult<i64> {
        let rule = rule.to_string();
        let rule_type = rule_type.to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO custom_rules (rule, rule_type, created_at) VALUES (?1, ?2, ?3)",
                    rusqlite::params![rule, rule_type, now],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn get_custom_rules(&self, rule_type: &str) -> DbResult<Vec<CustomRuleRow>> {
        let rule_type = rule_type.to_string();
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, rule, rule_type, created_at FROM custom_rules WHERE rule_type = ?1 ORDER BY id",
                )?;
                let rows = stmt
                    .query_map([&rule_type], |row| {
                        Ok(CustomRuleRow {
                            id: row.get(0)?,
                            rule: row.get(1)?,
                            rule_type: row.get(2)?,
                            created_at: row.get(3)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn delete_custom_rule(&self, id: i64) -> DbResult<()> {
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM custom_rules WHERE id = ?1", [id])?;
                Ok(())
            })
            .await
            .map_err(DbError::from)
    }
}
```

- [ ] **Step 12: Run all tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test db_test`
Expected: all 7 tests PASS

- [ ] **Step 13: Commit**

```bash
git add src/db.rs tests/db_test.rs
git commit -m "feat: implement database layer with settings, logs, lists, and rules CRUD"
```

---

### Task 3: Filter Rule Parser

**Files:**
- Modify: `src/filter/parser.rs`
- Modify: `src/filter/mod.rs`
- Create: `tests/filter_parser_test.rs`

- [ ] **Step 1: Write failing tests for rule parsing**

```rust
// tests/filter_parser_test.rs
use noadd::filter::parser::{parse_rule, ParsedRule, RuleAction};

#[test]
fn test_parse_adblock_block_rule() {
    let rule = parse_rule("||ads.example.com^");
    assert_eq!(
        rule,
        Some(ParsedRule {
            domain: "ads.example.com".into(),
            action: RuleAction::Block,
            is_subdomain: true,
        })
    );
}

#[test]
fn test_parse_adblock_allow_rule() {
    let rule = parse_rule("@@||safe.example.com^");
    assert_eq!(
        rule,
        Some(ParsedRule {
            domain: "safe.example.com".into(),
            action: RuleAction::Allow,
            is_subdomain: true,
        })
    );
}

#[test]
fn test_parse_hosts_format_zero() {
    let rule = parse_rule("0.0.0.0 ads.example.com");
    assert_eq!(
        rule,
        Some(ParsedRule {
            domain: "ads.example.com".into(),
            action: RuleAction::Block,
            is_subdomain: false,
        })
    );
}

#[test]
fn test_parse_hosts_format_localhost() {
    let rule = parse_rule("127.0.0.1 tracker.com");
    assert_eq!(
        rule,
        Some(ParsedRule {
            domain: "tracker.com".into(),
            action: RuleAction::Block,
            is_subdomain: false,
        })
    );
}

#[test]
fn test_parse_plain_domain() {
    let rule = parse_rule("ads.example.com");
    assert_eq!(
        rule,
        Some(ParsedRule {
            domain: "ads.example.com".into(),
            action: RuleAction::Block,
            is_subdomain: false,
        })
    );
}

#[test]
fn test_parse_comment_hash() {
    assert_eq!(parse_rule("# this is a comment"), None);
}

#[test]
fn test_parse_comment_bang() {
    assert_eq!(parse_rule("! this is a comment"), None);
}

#[test]
fn test_parse_empty_line() {
    assert_eq!(parse_rule(""), None);
    assert_eq!(parse_rule("   "), None);
}

#[test]
fn test_parse_hosts_localhost_entry_skipped() {
    // localhost entries should be ignored
    assert_eq!(parse_rule("0.0.0.0 localhost"), None);
    assert_eq!(parse_rule("127.0.0.1 localhost"), None);
    assert_eq!(parse_rule("0.0.0.0 local"), None);
}

#[test]
fn test_parse_list_multiple_rules() {
    use noadd::filter::parser::parse_list;
    let content = "# Comment\n||ads.com^\n0.0.0.0 tracker.com\n\n! Another comment\nexample.org\n";
    let rules = parse_list(content);
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0].domain, "ads.com");
    assert_eq!(rules[1].domain, "tracker.com");
    assert_eq!(rules[2].domain, "example.org");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test filter_parser_test`
Expected: FAIL

- [ ] **Step 3: Implement the parser**

```rust
// src/filter/parser.rs

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Block,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRule {
    pub domain: String,
    pub action: RuleAction,
    /// If true, also matches all subdomains
    pub is_subdomain: bool,
}

const SKIP_HOSTS: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
];

pub fn parse_rule(line: &str) -> Option<ParsedRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return None;
    }

    // AdGuard/ABP allowlist: @@||domain.com^
    if let Some(rest) = line.strip_prefix("@@||") {
        let domain = rest.trim_end_matches('^').trim_end_matches('$');
        if domain.is_empty() {
            return None;
        }
        return Some(ParsedRule {
            domain: domain.to_lowercase(),
            action: RuleAction::Allow,
            is_subdomain: true,
        });
    }

    // AdGuard/ABP block: ||domain.com^
    if let Some(rest) = line.strip_prefix("||") {
        let domain = rest.trim_end_matches('^').trim_end_matches('$');
        if domain.is_empty() {
            return None;
        }
        return Some(ParsedRule {
            domain: domain.to_lowercase(),
            action: RuleAction::Block,
            is_subdomain: true,
        });
    }

    // Hosts format: 0.0.0.0 domain / 127.0.0.1 domain
    if line.starts_with("0.0.0.0 ") || line.starts_with("127.0.0.1 ") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let domain = parts[1].to_lowercase();
            // Skip inline comments
            if SKIP_HOSTS.contains(&domain.as_str()) {
                return None;
            }
            return Some(ParsedRule {
                domain,
                action: RuleAction::Block,
                is_subdomain: false,
            });
        }
        return None;
    }

    // Plain domain (one domain per line, no spaces)
    if !line.contains(' ') && line.contains('.') {
        return Some(ParsedRule {
            domain: line.to_lowercase(),
            action: RuleAction::Block,
            is_subdomain: false,
        });
    }

    None
}

pub fn parse_list(content: &str) -> Vec<ParsedRule> {
    content.lines().filter_map(parse_rule).collect()
}
```

Update `src/filter/mod.rs`:

```rust
pub mod engine;
pub mod lists;
pub mod parser;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test filter_parser_test`
Expected: all 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/filter/parser.rs src/filter/mod.rs tests/filter_parser_test.rs
git commit -m "feat: implement adblock/hosts rule parser"
```

---

### Task 4: Filter Engine

**Files:**
- Modify: `src/filter/engine.rs`
- Create: `tests/filter_engine_test.rs`

- [ ] **Step 1: Write failing tests for the filter engine**

```rust
// tests/filter_engine_test.rs
use noadd::filter::engine::{FilterEngine, FilterResult};
use noadd::filter::parser::{parse_list, ParsedRule, RuleAction};

fn make_engine(block_rules: &str, allow_rules: &str) -> FilterEngine {
    let blocks = parse_list(block_rules);
    let allows = parse_list(allow_rules);
    FilterEngine::new(
        blocks.into_iter().map(|r| (r, "test-list".into())).collect(),
        allows,
    )
}

#[test]
fn test_exact_block() {
    let engine = make_engine("ads.example.com\n", "");
    let result = engine.check("ads.example.com");
    assert!(matches!(result, FilterResult::Blocked { .. }));
}

#[test]
fn test_subdomain_block() {
    let engine = make_engine("||ads.example.com^\n", "");
    // Exact match
    assert!(matches!(
        engine.check("ads.example.com"),
        FilterResult::Blocked { .. }
    ));
    // Subdomain match
    assert!(matches!(
        engine.check("sub.ads.example.com"),
        FilterResult::Blocked { .. }
    ));
    // Parent domain should NOT be blocked
    assert!(matches!(engine.check("example.com"), FilterResult::Allowed));
}

#[test]
fn test_allowed_domain() {
    let engine = make_engine("||ads.example.com^\n", "");
    assert!(matches!(engine.check("safe.example.com"), FilterResult::Allowed));
}

#[test]
fn test_allowlist_overrides_blocklist() {
    let engine = make_engine(
        "||ads.example.com^\n",
        "@@||special.ads.example.com^\n",
    );
    // Blocked by block rule
    assert!(matches!(
        engine.check("ads.example.com"),
        FilterResult::Blocked { .. }
    ));
    // Allowed by allow rule (overrides block)
    assert!(matches!(
        engine.check("special.ads.example.com"),
        FilterResult::Allowed
    ));
}

#[test]
fn test_provenance_tracking() {
    let blocks: Vec<(ParsedRule, String)> = vec![(
        ParsedRule {
            domain: "tracker.com".into(),
            action: RuleAction::Block,
            is_subdomain: false,
        },
        "My Custom List".into(),
    )];
    let engine = FilterEngine::new(blocks, vec![]);
    match engine.check("tracker.com") {
        FilterResult::Blocked { rule, list } => {
            assert_eq!(rule, "tracker.com");
            assert_eq!(list, "My Custom List");
        }
        _ => panic!("expected blocked"),
    }
}

#[test]
fn test_empty_engine_allows_everything() {
    let engine = FilterEngine::new(vec![], vec![]);
    assert!(matches!(engine.check("anything.com"), FilterResult::Allowed));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test filter_engine_test`
Expected: FAIL

- [ ] **Step 3: Implement the filter engine**

```rust
// src/filter/engine.rs
use crate::filter::parser::{ParsedRule, RuleAction};
use std::collections::HashMap;

#[derive(Debug)]
pub enum FilterResult {
    Allowed,
    Blocked { rule: String, list: String },
}

/// Trie node for reverse-domain matching.
/// Domain "sub.ads.example.com" is stored as ["com", "example", "ads", "sub"].
#[derive(Debug, Default)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    /// If Some, this node is a terminal that blocks (with provenance).
    block_rule: Option<(String, String)>, // (original_rule, list_name)
}

impl TrieNode {
    fn insert(&mut self, labels: &[&str], rule: String, list: String) {
        if labels.is_empty() {
            self.block_rule = Some((rule, list));
            return;
        }
        self.children
            .entry(labels[0].to_string())
            .or_default()
            .insert(&labels[1..], rule, list);
    }

    /// Walk the trie with the given labels. If any node along the path
    /// is a terminal, the domain is blocked (subdomain matching).
    fn check(&self, labels: &[&str]) -> Option<&(String, String)> {
        if labels.is_empty() {
            return self.block_rule.as_ref();
        }
        // Check if current node is a terminal (subdomain match)
        if self.block_rule.is_some() {
            return self.block_rule.as_ref();
        }
        if let Some(child) = self.children.get(labels[0]) {
            return child.check(&labels[1..]);
        }
        None
    }
}

pub struct FilterEngine {
    /// Exact domain matches: domain -> (rule, list_name)
    exact: HashMap<String, (String, String)>,
    /// Reverse-domain trie for subdomain matching
    trie: TrieNode,
    /// Allowlist: exact and subdomain matches (no provenance needed)
    allow_exact: std::collections::HashSet<String>,
    allow_trie: TrieNode,
}

impl FilterEngine {
    pub fn new(
        block_rules: Vec<(ParsedRule, String)>,
        allow_rules: Vec<ParsedRule>,
    ) -> Self {
        let mut exact = HashMap::new();
        let mut trie = TrieNode::default();

        for (rule, list_name) in block_rules {
            if rule.action != RuleAction::Block {
                continue;
            }
            if rule.is_subdomain {
                let labels: Vec<&str> = rule.domain.split('.').rev().collect();
                trie.insert(&labels, rule.domain.clone(), list_name);
            } else {
                exact.insert(rule.domain.clone(), (rule.domain.clone(), list_name));
            }
        }

        let mut allow_exact = std::collections::HashSet::new();
        let mut allow_trie = TrieNode::default();
        for rule in allow_rules {
            if rule.action != RuleAction::Allow {
                continue;
            }
            if rule.is_subdomain {
                let labels: Vec<&str> = rule.domain.split('.').rev().collect();
                allow_trie.insert(&labels, rule.domain.clone(), String::new());
            } else {
                allow_exact.insert(rule.domain.clone());
            }
        }

        Self {
            exact,
            trie,
            allow_exact,
            allow_trie,
        }
    }

    pub fn check(&self, domain: &str) -> FilterResult {
        let domain = domain.to_lowercase();

        // Priority 1: allowlist
        if self.allow_exact.contains(&domain) {
            return FilterResult::Allowed;
        }
        let labels: Vec<&str> = domain.split('.').rev().collect();
        if self.allow_trie.check(&labels).is_some() {
            return FilterResult::Allowed;
        }

        // Priority 2: exact blocklist
        if let Some((rule, list)) = self.exact.get(&domain) {
            return FilterResult::Blocked {
                rule: rule.clone(),
                list: list.clone(),
            };
        }

        // Priority 3: subdomain blocklist (trie)
        if let Some((rule, list)) = self.trie.check(&labels) {
            return FilterResult::Blocked {
                rule: rule.clone(),
                list: list.clone(),
            };
        }

        FilterResult::Allowed
    }

    pub fn blocked_domain_count(&self) -> usize {
        // Approximate: exact rules + trie terminals
        self.exact.len() + self.count_trie_terminals(&self.trie)
    }

    fn count_trie_terminals(&self, node: &TrieNode) -> usize {
        let mut count = if node.block_rule.is_some() { 1 } else { 0 };
        for child in node.children.values() {
            count += self.count_trie_terminals(child);
        }
        count
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test filter_engine_test`
Expected: all 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/filter/engine.rs tests/filter_engine_test.rs
git commit -m "feat: implement filter engine with trie-based subdomain matching"
```

---

### Task 5: Upstream Forwarder

**Files:**
- Modify: `src/upstream/forwarder.rs`
- Modify: `src/upstream/mod.rs`
- Create: `tests/upstream_test.rs`

- [ ] **Step 1: Write failing tests for upstream forwarder**

```rust
// tests/upstream_test.rs
use noadd::upstream::forwarder::{UpstreamForwarder, UpstreamConfig};
use hickory_proto::op::{Message, Query, MessageType, OpCode};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;

#[tokio::test]
async fn test_forward_resolves_known_domain() {
    let config = UpstreamConfig {
        servers: vec!["1.1.1.1:53".into()],
        timeout_ms: 5000,
    };
    let forwarder = UpstreamForwarder::new(config);

    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut query = Query::new();
    query.set_name(Name::from_str("example.com.").unwrap());
    query.set_query_type(RecordType::A);
    msg.add_query(query);

    let response = forwarder.forward(&msg).await.unwrap();
    assert!(!response.answers().is_empty());
}

#[tokio::test]
async fn test_forward_failover_on_bad_primary() {
    let config = UpstreamConfig {
        // First server is invalid, should failover to second
        servers: vec!["192.0.2.1:53".into(), "1.1.1.1:53".into()],
        timeout_ms: 2000,
    };
    let forwarder = UpstreamForwarder::new(config);

    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut query = Query::new();
    query.set_name(Name::from_str("example.com.").unwrap());
    query.set_query_type(RecordType::A);
    msg.add_query(query);

    let response = forwarder.forward(&msg).await.unwrap();
    assert!(!response.answers().is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test upstream_test`
Expected: FAIL

- [ ] **Step 3: Implement the upstream forwarder**

```rust
// src/upstream/forwarder.rs
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use thiserror::Error;
use tokio::net::UdpSocket;
use std::time::Duration;

#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("all upstreams failed")]
    AllFailed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("dns decode error: {0}")]
    Decode(#[from] hickory_proto::error::ProtoError),
}

#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub servers: Vec<String>,
    pub timeout_ms: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                "1.1.1.1:53".into(),
                "9.9.9.9:53".into(),
                "194.242.2.2:53".into(),
            ],
            timeout_ms: 2000,
        }
    }
}

pub struct UpstreamForwarder {
    config: UpstreamConfig,
}

impl UpstreamForwarder {
    pub fn new(config: UpstreamConfig) -> Self {
        Self { config }
    }

    pub async fn forward(&self, query: &Message) -> Result<Message, ForwardError> {
        let query_bytes = query.to_vec()?;
        let timeout = Duration::from_millis(self.config.timeout_ms);

        for server in &self.config.servers {
            match self.try_forward(server, &query_bytes, timeout).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::warn!(upstream = server, error = %e, "upstream failed, trying next");
                    continue;
                }
            }
        }

        Err(ForwardError::AllFailed)
    }

    /// Returns the address of the upstream that successfully responded.
    pub async fn forward_with_upstream(&self, query: &Message) -> Result<(Message, String), ForwardError> {
        let query_bytes = query.to_vec()?;
        let timeout = Duration::from_millis(self.config.timeout_ms);

        for server in &self.config.servers {
            match self.try_forward(server, &query_bytes, timeout).await {
                Ok(response) => return Ok((response, server.clone())),
                Err(e) => {
                    tracing::warn!(upstream = server, error = %e, "upstream failed, trying next");
                    continue;
                }
            }
        }

        Err(ForwardError::AllFailed)
    }

    async fn try_forward(
        &self,
        server: &str,
        query_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Message, ForwardError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(server).await?;
        socket.send(query_bytes).await?;

        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| ForwardError::AllFailed)??;

        let response = Message::from_bytes(&buf[..len])?;
        Ok(response)
    }
}
```

Update `src/upstream/mod.rs`:

```rust
pub mod forwarder;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test upstream_test`
Expected: 2 tests PASS (requires network access to 1.1.1.1)

- [ ] **Step 5: Commit**

```bash
git add src/upstream/ tests/upstream_test.rs
git commit -m "feat: implement upstream DNS forwarder with failover"
```

---

### Task 6: DNS Response Cache

**Files:**
- Modify: `src/cache.rs`
- Create: `tests/cache_test.rs`

- [ ] **Step 1: Write failing tests for the cache**

```rust
// tests/cache_test.rs
use noadd::cache::DnsCache;
use hickory_proto::op::{Message, Query, MessageType, OpCode};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;

#[tokio::test]
async fn test_cache_miss_returns_none() {
    let cache = DnsCache::new(100);
    let key = ("example.com".into(), RecordType::A);
    assert!(cache.get(&key).is_none());
}

#[tokio::test]
async fn test_cache_insert_and_get() {
    let cache = DnsCache::new(100);
    let key = ("example.com".to_string(), RecordType::A);

    let mut msg = Message::new();
    msg.set_id(1);
    msg.set_message_type(MessageType::Response);

    cache.insert(key.clone(), msg.clone(), 300);
    let cached = cache.get(&key);
    assert!(cached.is_some());
}

#[tokio::test]
async fn test_cache_invalidate_all() {
    let cache = DnsCache::new(100);
    let key = ("example.com".to_string(), RecordType::A);

    let msg = Message::new();
    cache.insert(key.clone(), msg, 300);
    assert!(cache.get(&key).is_some());

    cache.invalidate_all();
    assert!(cache.get(&key).is_none());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test cache_test`
Expected: FAIL

- [ ] **Step 3: Implement the DNS cache**

```rust
// src/cache.rs
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use moka::future::Cache;
use std::time::Duration;

type CacheKey = (String, RecordType);

#[derive(Clone)]
pub struct DnsCache {
    cache: Cache<CacheKey, Vec<u8>>,
}

impl DnsCache {
    pub fn new(max_capacity: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(max_capacity)
                .build(),
        }
    }

    pub fn get(&self, key: &CacheKey) -> Option<Message> {
        self.cache.get(key).and_then(|bytes| {
            use hickory_proto::serialize::binary::BinDecodable;
            Message::from_bytes(&bytes).ok()
        })
    }

    pub fn insert(&self, key: CacheKey, msg: Message, ttl_secs: u64) {
        let bytes = msg.to_vec().unwrap_or_default();
        if !bytes.is_empty() {
            self.cache
                .insert_with_ttl(key, bytes, Duration::from_secs(ttl_secs));
        }
    }

    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test cache_test`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/cache.rs tests/cache_test.rs
git commit -m "feat: implement TTL-based DNS response cache"
```

---

### Task 7: DNS Query Handler

**Files:**
- Modify: `src/dns/handler.rs`
- Modify: `src/dns/mod.rs`
- Create: `tests/handler_test.rs`

This is the core query processing pipeline: filter → cache → upstream → respond.

- [ ] **Step 1: Write failing tests for the handler**

```rust
// tests/handler_test.rs
use noadd::dns::handler::{DnsHandler, QueryContext};
use noadd::filter::engine::FilterEngine;
use noadd::filter::parser::parse_list;
use noadd::cache::DnsCache;
use noadd::upstream::forwarder::{UpstreamForwarder, UpstreamConfig};
use arc_swap::ArcSwap;
use std::sync::Arc;
use hickory_proto::op::{Message, Query, MessageType, OpCode};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;
use tokio::sync::mpsc;

fn make_handler(block_rules: &str) -> (DnsHandler, mpsc::Receiver<QueryContext>) {
    let rules = parse_list(block_rules);
    let engine = FilterEngine::new(
        rules.into_iter().map(|r| (r, "test".into())).collect(),
        vec![],
    );
    let filter = Arc::new(ArcSwap::from_pointee(engine));
    let cache = DnsCache::new(100);
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig {
        servers: vec!["1.1.1.1:53".into()],
        timeout_ms: 5000,
    }));
    let (log_tx, log_rx) = mpsc::channel(1000);
    let handler = DnsHandler::new(filter, cache, forwarder, log_tx);
    (handler, log_rx)
}

fn make_query(domain: &str, record_type: RecordType) -> Message {
    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut query = Query::new();
    query.set_name(Name::from_str(domain).unwrap());
    query.set_query_type(record_type);
    msg.add_query(query);
    msg
}

#[tokio::test]
async fn test_handler_blocks_domain() {
    let (handler, _rx) = make_handler("||ads.example.com^\n");
    let query = make_query("ads.example.com.", RecordType::A);
    let response = handler.handle(query, "127.0.0.1".parse().unwrap()).await.unwrap();
    // Should return 0.0.0.0
    let answers = response.answers();
    assert_eq!(answers.len(), 1);
    if let Some(rdata) = answers[0].data() {
        let a = rdata.clone().into_a().unwrap();
        assert_eq!(a.0, std::net::Ipv4Addr::UNSPECIFIED);
    }
}

#[tokio::test]
async fn test_handler_forwards_allowed_domain() {
    let (handler, _rx) = make_handler("");
    let query = make_query("example.com.", RecordType::A);
    let response = handler.handle(query, "127.0.0.1".parse().unwrap()).await.unwrap();
    assert!(!response.answers().is_empty());
}

#[tokio::test]
async fn test_handler_sends_log_event() {
    let (handler, mut rx) = make_handler("||ads.example.com^\n");
    let query = make_query("ads.example.com.", RecordType::A);
    handler.handle(query, "127.0.0.1".parse().unwrap()).await.unwrap();
    let ctx = rx.recv().await.unwrap();
    assert_eq!(ctx.domain, "ads.example.com");
    assert_eq!(ctx.action, "blocked");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test handler_test`
Expected: FAIL

- [ ] **Step 3: Implement the DNS handler**

```rust
// src/dns/handler.rs
use crate::cache::DnsCache;
use crate::filter::engine::{FilterEngine, FilterResult};
use crate::upstream::forwarder::UpstreamForwarder;
use arc_swap::ArcSwap;
use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("no queries in message")]
    NoQuery,
    #[error("upstream error: {0}")]
    Upstream(#[from] crate::upstream::forwarder::ForwardError),
    #[error("proto error: {0}")]
    Proto(#[from] hickory_proto::error::ProtoError),
}

#[derive(Debug, Clone)]
pub struct QueryContext {
    pub timestamp: i64,
    pub client_ip: String,
    pub domain: String,
    pub query_type: String,
    pub action: String,
    pub upstream: Option<String>,
    pub response_time_ms: i64,
    pub matched_rule: Option<String>,
    pub matched_list: Option<String>,
}

pub struct DnsHandler {
    filter: Arc<ArcSwap<FilterEngine>>,
    cache: DnsCache,
    forwarder: Arc<UpstreamForwarder>,
    log_tx: mpsc::Sender<QueryContext>,
}

impl DnsHandler {
    pub fn new(
        filter: Arc<ArcSwap<FilterEngine>>,
        cache: DnsCache,
        forwarder: Arc<UpstreamForwarder>,
        log_tx: mpsc::Sender<QueryContext>,
    ) -> Self {
        Self {
            filter,
            cache,
            forwarder,
            log_tx,
        }
    }

    pub async fn handle(
        &self,
        query: Message,
        client_ip: IpAddr,
    ) -> Result<Message, HandlerError> {
        let start = Instant::now();
        let q = query.queries().first().ok_or(HandlerError::NoQuery)?;
        let domain = q.name().to_string().trim_end_matches('.').to_string();
        let record_type = q.query_type();
        let query_type_str = format!("{record_type:?}");

        // Step 1: Check filter
        let filter = self.filter.load();
        let filter_result = filter.check(&domain);

        match filter_result {
            FilterResult::Blocked { rule, list } => {
                let response = self.build_blocked_response(&query, record_type);
                let elapsed = start.elapsed().as_millis() as i64;
                let _ = self.log_tx.try_send(QueryContext {
                    timestamp: now_unix(),
                    client_ip: client_ip.to_string(),
                    domain,
                    query_type: query_type_str,
                    action: "blocked".into(),
                    upstream: None,
                    response_time_ms: elapsed,
                    matched_rule: Some(rule),
                    matched_list: Some(list),
                });
                Ok(response)
            }
            FilterResult::Allowed => {
                // Step 2: Check cache
                let cache_key = (domain.clone(), record_type);
                if let Some(mut cached) = self.cache.get(&cache_key) {
                    cached.set_id(query.id());
                    let elapsed = start.elapsed().as_millis() as i64;
                    let _ = self.log_tx.try_send(QueryContext {
                        timestamp: now_unix(),
                        client_ip: client_ip.to_string(),
                        domain,
                        query_type: query_type_str,
                        action: "allowed".into(),
                        upstream: Some("cache".into()),
                        response_time_ms: elapsed,
                        matched_rule: None,
                        matched_list: None,
                    });
                    return Ok(cached);
                }

                // Step 3: Forward to upstream
                let (response, upstream_addr) =
                    self.forwarder.forward_with_upstream(&query).await?;

                // Cache the response
                let min_ttl = response
                    .answers()
                    .iter()
                    .map(|r| r.ttl())
                    .min()
                    .unwrap_or(60);
                self.cache
                    .insert(cache_key, response.clone(), min_ttl as u64);

                let elapsed = start.elapsed().as_millis() as i64;
                let _ = self.log_tx.try_send(QueryContext {
                    timestamp: now_unix(),
                    client_ip: client_ip.to_string(),
                    domain,
                    query_type: query_type_str,
                    action: "allowed".into(),
                    upstream: Some(upstream_addr),
                    response_time_ms: elapsed,
                    matched_rule: None,
                    matched_list: None,
                });

                Ok(response)
            }
        }
    }

    fn build_blocked_response(&self, query: &Message, record_type: RecordType) -> Message {
        let mut response = Message::new();
        response.set_id(query.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(query.op_code());
        response.set_response_code(ResponseCode::NoError);
        response.set_recursion_desired(true);
        response.set_recursion_available(true);

        // Copy the query section
        for q in query.queries() {
            response.add_query(q.clone());
        }

        let name = query.queries()[0].name().clone();
        match record_type {
            RecordType::A => {
                let mut record = Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::UNSPECIFIED)));
                response.add_answer(record);
            }
            RecordType::AAAA => {
                let mut record =
                    Record::from_rdata(name, 300, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
                response.add_answer(record);
            }
            _ => {
                // For other types, return empty response (no answers)
            }
        }

        response
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
```

Update `src/dns/mod.rs`:

```rust
pub mod doh;
pub mod handler;
pub mod tcp;
pub mod udp;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test handler_test`
Expected: 3 tests PASS (requires network for forwarding test)

- [ ] **Step 5: Commit**

```bash
git add src/dns/ tests/handler_test.rs
git commit -m "feat: implement DNS query handler with filter-cache-forward pipeline"
```

---

### Task 8: UDP DNS Listener

**Files:**
- Modify: `src/dns/udp.rs`

- [ ] **Step 1: Implement the UDP listener**

```rust
// src/dns/udp.rs
use crate::dns::handler::DnsHandler;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub async fn run_udp_listener(
    addr: SocketAddr,
    handler: Arc<DnsHandler>,
) -> std::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    tracing::info!(%addr, "UDP DNS listener started");

    let mut buf = vec![0u8; 4096];
    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let data = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        let handler = Arc::clone(&handler);

        tokio::spawn(async move {
            if let Err(e) = handle_udp_query(&socket, &handler, &data, src).await {
                tracing::debug!(error = %e, %src, "failed to handle UDP query");
            }
        });
    }
}

async fn handle_udp_query(
    socket: &UdpSocket,
    handler: &DnsHandler,
    data: &[u8],
    src: SocketAddr,
) -> anyhow::Result<()> {
    let query = Message::from_bytes(data)?;
    let response = handler.handle(query, src.ip()).await?;
    let response_bytes = response.to_vec()?;
    socket.send_to(&response_bytes, src).await?;
    Ok(())
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /home/nixos/Develop/claude/noadd && cargo check`
Expected: compiles (may need to add `anyhow` to deps — if so, add it)

- [ ] **Step 3: Commit**

```bash
git add src/dns/udp.rs
git commit -m "feat: implement UDP DNS listener"
```

---

### Task 9: TCP DNS Listener

**Files:**
- Modify: `src/dns/tcp.rs`

- [ ] **Step 1: Implement the TCP listener**

TCP DNS uses a 2-byte length prefix per RFC 1035 Section 4.2.2.

```rust
// src/dns/tcp.rs
use crate::dns::handler::DnsHandler;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn run_tcp_listener(
    addr: SocketAddr,
    handler: Arc<DnsHandler>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "TCP DNS listener started");

    loop {
        let (stream, src) = listener.accept().await?;
        let handler = Arc::clone(&handler);

        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(stream, &handler, src).await {
                tracing::debug!(error = %e, %src, "failed to handle TCP connection");
            }
        });
    }
}

async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
    handler: &DnsHandler,
    src: SocketAddr,
) -> anyhow::Result<()> {
    // Read 2-byte length prefix
    let len = stream.read_u16().await? as usize;
    if len > 65535 {
        return Ok(());
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    let query = Message::from_bytes(&buf)?;
    let response = handler.handle(query, src.ip()).await?;
    let response_bytes = response.to_vec()?;

    // Write 2-byte length prefix + response
    stream.write_u16(response_bytes.len() as u16).await?;
    stream.write_all(&response_bytes).await?;

    Ok(())
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /home/nixos/Develop/claude/noadd && cargo check`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add src/dns/tcp.rs
git commit -m "feat: implement TCP DNS listener (RFC 1035 length-prefixed)"
```

---

### Task 10: DoH Endpoint

**Files:**
- Modify: `src/dns/doh.rs`
- Create: `tests/doh_test.rs`

- [ ] **Step 1: Write failing tests for DoH**

```rust
// tests/doh_test.rs
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use noadd::dns::doh::doh_router;
use noadd::dns::handler::DnsHandler;
use noadd::filter::engine::FilterEngine;
use noadd::cache::DnsCache;
use noadd::upstream::forwarder::{UpstreamForwarder, UpstreamConfig};
use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::sync::mpsc;
use hickory_proto::op::{Message, Query, MessageType, OpCode};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn make_test_handler() -> Arc<DnsHandler> {
    let engine = FilterEngine::new(vec![], vec![]);
    let filter = Arc::new(ArcSwap::from_pointee(engine));
    let cache = DnsCache::new(100);
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig {
        servers: vec!["1.1.1.1:53".into()],
        timeout_ms: 5000,
    }));
    let (log_tx, _) = mpsc::channel(1000);
    Arc::new(DnsHandler::new(filter, cache, forwarder, log_tx))
}

fn make_dns_query_bytes() -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0); // DoH uses id=0
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut query = Query::new();
    query.set_name(Name::from_str("example.com.").unwrap());
    query.set_query_type(RecordType::A);
    msg.add_query(query);
    msg.to_vec().unwrap()
}

#[tokio::test]
async fn test_doh_get() {
    let handler = make_test_handler();
    let app = doh_router(handler);

    let query_bytes = make_dns_query_bytes();
    let encoded = URL_SAFE_NO_PAD.encode(&query_bytes);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/dns-query?dns={encoded}"))
                .header("accept", "application/dns-message")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/dns-message"
    );
}

#[tokio::test]
async fn test_doh_post() {
    let handler = make_test_handler();
    let app = doh_router(handler);

    let query_bytes = make_dns_query_bytes();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dns-query")
                .header("content-type", "application/dns-message")
                .body(Body::from(query_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test doh_test`
Expected: FAIL

- [ ] **Step 3: Implement the DoH endpoint**

```rust
// src/dns/doh.rs
use crate::dns::handler::DnsHandler;
use axum::body::Bytes;
use axum::extract::{Query as AxumQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct DohGetParams {
    dns: String,
}

pub fn doh_router(handler: Arc<DnsHandler>) -> Router {
    Router::new()
        .route("/dns-query", get(doh_get).post(doh_post))
        .with_state(handler)
}

async fn doh_get(
    State(handler): State<Arc<DnsHandler>>,
    AxumQuery(params): AxumQuery<DohGetParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let bytes = match URL_SAFE_NO_PAD.decode(&params.dns) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid base64").into_response(),
    };

    process_doh(handler, &bytes, &headers).await
}

async fn doh_post(
    State(handler): State<Arc<DnsHandler>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    process_doh(handler, &body, &headers).await
}

async fn process_doh(
    handler: Arc<DnsHandler>,
    query_bytes: &[u8],
    _headers: &HeaderMap,
) -> axum::response::Response {
    let query = match Message::from_bytes(query_bytes) {
        Ok(q) => q,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid DNS message").into_response(),
    };

    // In production, extract client IP from X-Forwarded-For or connection info
    let client_ip: IpAddr = "127.0.0.1".parse().unwrap();

    match handler.handle(query, client_ip).await {
        Ok(response) => {
            let bytes = response.to_vec().unwrap_or_default();
            (
                StatusCode::OK,
                [("content-type", "application/dns-message")],
                bytes,
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "DoH handler error");
            (StatusCode::INTERNAL_SERVER_ERROR, "DNS resolution failed").into_response()
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test doh_test`
Expected: 2 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/dns/doh.rs tests/doh_test.rs
git commit -m "feat: implement DNS-over-HTTPS endpoint (RFC 8484)"
```

---

### Task 11: Async Query Logger

**Files:**
- Modify: `src/logger.rs`
- Create: `tests/logger_test.rs`

- [ ] **Step 1: Write failing tests for the logger**

```rust
// tests/logger_test.rs
use noadd::logger::QueryLogger;
use noadd::dns::handler::QueryContext;
use noadd::db::Database;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_logger_flushes_on_threshold() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();
    let (logger, tx) = QueryLogger::new(db.clone(), 5, 60);

    // Spawn the logger task
    let handle = tokio::spawn(logger.run());

    // Send 5 entries (matches flush threshold)
    for i in 0..5 {
        tx.send(QueryContext {
            timestamp: 1000 + i,
            client_ip: "127.0.0.1".into(),
            domain: format!("test{i}.com"),
            query_type: "A".into(),
            action: "allowed".into(),
            upstream: Some("1.1.1.1".into()),
            response_time_ms: 10,
            matched_rule: None,
            matched_list: None,
        })
        .await
        .unwrap();
    }

    // Give it a moment to flush
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let logs = db.get_query_logs(None, None, None, 100, 0).await.unwrap();
    assert_eq!(logs.len(), 5);

    // Drop sender to stop the logger
    drop(tx);
    let _ = handle.await;
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test logger_test`
Expected: FAIL

- [ ] **Step 3: Implement the async query logger**

```rust
// src/logger.rs
use crate::db::Database;
use crate::dns::handler::QueryContext;
use crate::db::QueryLogEntry;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

pub struct QueryLogger {
    db: Database,
    rx: mpsc::Receiver<QueryContext>,
    flush_threshold: usize,
    flush_interval_secs: u64,
}

impl QueryLogger {
    pub fn new(
        db: Database,
        flush_threshold: usize,
        flush_interval_secs: u64,
    ) -> (Self, mpsc::Sender<QueryContext>) {
        let (tx, rx) = mpsc::channel(10_000);
        (
            Self {
                db,
                rx,
                flush_threshold,
                flush_interval_secs,
            },
            tx,
        )
    }

    pub async fn run(mut self) {
        let mut buffer: Vec<QueryContext> = Vec::with_capacity(self.flush_threshold);
        let mut ticker = interval(Duration::from_secs(self.flush_interval_secs));

        loop {
            tokio::select! {
                Some(ctx) = self.rx.recv() => {
                    buffer.push(ctx);
                    if buffer.len() >= self.flush_threshold {
                        self.flush(&mut buffer).await;
                    }
                }
                _ = ticker.tick() => {
                    if !buffer.is_empty() {
                        self.flush(&mut buffer).await;
                    }
                }
                else => {
                    // Channel closed, flush remaining
                    if !buffer.is_empty() {
                        self.flush(&mut buffer).await;
                    }
                    break;
                }
            }
        }
    }

    async fn flush(&self, buffer: &mut Vec<QueryContext>) {
        let entries: Vec<QueryLogEntry> = buffer
            .drain(..)
            .map(|ctx| QueryLogEntry {
                timestamp: ctx.timestamp,
                client_ip: ctx.client_ip,
                domain: ctx.domain,
                query_type: ctx.query_type,
                action: ctx.action,
                upstream: ctx.upstream,
                response_time_ms: ctx.response_time_ms,
                matched_rule: ctx.matched_rule,
                matched_list: ctx.matched_list,
            })
            .collect();

        if let Err(e) = self.db.insert_query_logs(&entries).await {
            tracing::error!(error = %e, "failed to flush query logs");
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test logger_test`
Expected: 1 test PASS

- [ ] **Step 5: Commit**

```bash
git add src/logger.rs tests/logger_test.rs
git commit -m "feat: implement async query logger with batch flushing"
```

---

### Task 12: Admin Authentication

**Files:**
- Modify: `src/admin/auth.rs`
- Modify: `src/admin/mod.rs`
- Create: `tests/admin_auth_test.rs`

- [ ] **Step 1: Write failing tests for auth**

```rust
// tests/admin_auth_test.rs
use noadd::admin::auth::{hash_password, verify_password, create_session, validate_session, SessionStore};

#[test]
fn test_password_hash_and_verify() {
    let hash = hash_password("test-password").unwrap();
    assert!(verify_password("test-password", &hash).unwrap());
    assert!(!verify_password("wrong-password", &hash).unwrap());
}

#[test]
fn test_session_create_and_validate() {
    let store = SessionStore::new();
    let token = create_session(&store);
    assert!(validate_session(&store, &token));
    assert!(!validate_session(&store, "bogus-token"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test admin_auth_test`
Expected: FAIL

- [ ] **Step 3: Implement auth module**

```rust
// src/admin/auth.rs
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::Rng;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

pub type SessionStore = Arc<Mutex<HashSet<String>>>;

pub fn new_session_store() -> SessionStore {
    Arc::new(Mutex::new(HashSet::new()))
}

pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

pub fn verify_password(
    password: &str,
    hash: &str,
) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

pub fn create_session(store: &SessionStore) -> String {
    let token: String = rand::rng()
        .sample_iter(&rand::distr::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    store.lock().unwrap().insert(token.clone());
    token
}

pub fn validate_session(store: &SessionStore, token: &str) -> bool {
    store.lock().unwrap().contains(token)
}
```

Update `src/admin/mod.rs`:

```rust
pub mod api;
pub mod auth;
pub mod stats;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test admin_auth_test`
Expected: 2 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/admin/ tests/admin_auth_test.rs
git commit -m "feat: implement admin authentication with argon2 + session tokens"
```

---

### Task 13: Admin API — Settings, Lists, Rules

**Files:**
- Modify: `src/admin/api.rs`
- Create: `tests/admin_api_test.rs`

- [ ] **Step 1: Write failing tests for settings and lists API endpoints**

```rust
// tests/admin_api_test.rs
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use noadd::admin::api::admin_router;
use noadd::admin::auth::{new_session_store, create_session, hash_password};
use noadd::db::Database;
use noadd::filter::engine::FilterEngine;
use noadd::cache::DnsCache;
use arc_swap::ArcSwap;
use std::sync::Arc;
use tempfile::NamedTempFile;

async fn setup() -> (axum::Router, String) {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();
    let session_store = new_session_store();
    let token = create_session(&session_store);
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![])));
    let cache = DnsCache::new(100);

    // Set up admin password
    let hash = hash_password("admin").unwrap();
    db.set_setting("admin_password_hash", &hash).await.unwrap();

    let router = admin_router(db, session_store, filter, cache);
    (router, token)
}

#[tokio::test]
async fn test_health_endpoint_no_auth() {
    let (app, _) = setup().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_settings_requires_auth() {
    let (app, _) = setup().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_settings_with_auth() {
    let (app, token) = setup().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/settings")
                .header("cookie", format!("session={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_login_success() {
    let (app, _) = setup().await;
    let body = serde_json::json!({"password": "admin"});
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // Should have Set-Cookie header
    assert!(response.headers().get("set-cookie").is_some());
}

#[tokio::test]
async fn test_login_wrong_password() {
    let (app, _) = setup().await;
    let body = serde_json::json!({"password": "wrong"});
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test admin_api_test`
Expected: FAIL

- [ ] **Step 3: Implement the admin API router**

```rust
// src/admin/api.rs
use crate::admin::auth::{
    create_session, hash_password, new_session_store, validate_session, verify_password,
    SessionStore,
};
use crate::cache::DnsCache;
use crate::db::Database;
use crate::filter::engine::FilterEngine;
use arc_swap::ArcSwap;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub sessions: SessionStore,
    pub filter: Arc<ArcSwap<FilterEngine>>,
    pub cache: DnsCache,
}

pub fn admin_router(
    db: Database,
    sessions: SessionStore,
    filter: Arc<ArcSwap<FilterEngine>>,
    cache: DnsCache,
) -> Router {
    let state = AppState {
        db,
        sessions,
        filter,
        cache,
    };

    Router::new()
        // Public endpoints
        .route("/api/health", get(health))
        .route("/api/auth/login", post(login))
        .route("/api/auth/setup", post(setup_password))
        // Protected endpoints
        .route("/api/settings", get(get_settings).put(put_settings))
        .route(
            "/api/lists",
            get(get_lists).post(add_list),
        )
        .route(
            "/api/lists/{id}",
            put(update_list).delete(delete_list),
        )
        .route("/api/lists/update", post(trigger_list_update))
        .route(
            "/api/rules/allowlist",
            get(get_allowlist).post(add_allowlist_rule),
        )
        .route("/api/rules/allowlist/{id}", delete(delete_allowlist_rule))
        .route(
            "/api/rules/blocklist",
            get(get_blocklist).post(add_blocklist_rule),
        )
        .route("/api/rules/blocklist/{id}", delete(delete_blocklist_rule))
        .with_state(state)
}

// --- Auth helpers ---

fn extract_session_token(jar: &CookieJar) -> Option<String> {
    jar.get("session").map(|c| c.value().to_string())
}

fn require_auth(state: &AppState, jar: &CookieJar) -> Result<(), StatusCode> {
    let token = extract_session_token(jar).ok_or(StatusCode::UNAUTHORIZED)?;
    if !validate_session(&state.sessions, &token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

// --- Handlers ---

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let hash = state
        .db
        .get_setting("admin_password_hash")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !verify_password(&req.password, &hash).unwrap_or(false) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = create_session(&state.sessions);
    let cookie = Cookie::build(("session", token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict);

    Ok((jar.add(cookie), Json(serde_json::json!({"ok": true}))))
}

#[derive(Deserialize)]
struct SetupRequest {
    password: String,
}

async fn setup_password(
    State(state): State<AppState>,
    Json(req): Json<SetupRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Only allow if no password is set yet
    let existing = state
        .db
        .get_setting("admin_password_hash")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if existing.is_some() {
        return Err(StatusCode::CONFLICT);
    }

    let hash = hash_password(&req.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .db
        .set_setting("admin_password_hash", &hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({"ok": true})))
}

async fn get_settings(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    // Return known settings
    let keys = ["dns_port", "doh_port", "admin_port", "upstream_servers", "log_retention_days"];
    let mut settings = serde_json::Map::new();
    for key in keys {
        if let Ok(Some(val)) = state.db.get_setting(key).await {
            settings.insert(key.to_string(), serde_json::Value::String(val));
        }
    }
    Ok(Json(serde_json::Value::Object(settings)))
}

#[derive(Deserialize)]
struct SettingsUpdate {
    #[serde(flatten)]
    values: std::collections::HashMap<String, String>,
}

async fn put_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<SettingsUpdate>,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    for (key, value) in &req.values {
        state
            .db
            .set_setting(key, value)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn get_lists(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    let lists = state
        .db
        .get_filter_lists()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(lists))
}

#[derive(Deserialize)]
struct AddListRequest {
    name: String,
    url: String,
}

async fn add_list(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<AddListRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    let id = state
        .db
        .add_filter_list(&req.name, &req.url, false)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"id": id})))
}

#[derive(Deserialize)]
struct UpdateListRequest {
    enabled: bool,
}

async fn update_list(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Json(req): Json<UpdateListRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    state
        .db
        .update_filter_list_enabled(id, req.enabled)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn delete_list(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    state
        .db
        .delete_filter_list(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn trigger_list_update() -> impl IntoResponse {
    // Will be implemented in Task 15
    Json(serde_json::json!({"ok": true, "message": "not yet implemented"}))
}

async fn get_allowlist(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    let rules = state
        .db
        .get_custom_rules("allow")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rules))
}

#[derive(Deserialize)]
struct AddRuleRequest {
    rule: String,
}

async fn add_allowlist_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<AddRuleRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    let id = state
        .db
        .add_custom_rule(&req.rule, "allow")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"id": id})))
}

async fn delete_allowlist_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    state
        .db
        .delete_custom_rule(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn get_blocklist(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    let rules = state
        .db
        .get_custom_rules("block")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rules))
}

async fn add_blocklist_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<AddRuleRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    let id = state
        .db
        .add_custom_rule(&req.rule, "block")
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"id": id})))
}

async fn delete_blocklist_rule(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    state
        .db
        .delete_custom_rule(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"ok": true})))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test admin_api_test`
Expected: 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/admin/ tests/admin_api_test.rs
git commit -m "feat: implement admin API with auth, settings, lists, and rules endpoints"
```

---

### Task 14: Admin API — Statistics & Logs

**Files:**
- Modify: `src/admin/stats.rs`
- Modify: `src/admin/api.rs`
- Create: `tests/admin_stats_test.rs`

- [ ] **Step 1: Write failing tests for stats queries**

```rust
// tests/admin_stats_test.rs
use noadd::admin::stats::{compute_summary, compute_top_domains, compute_top_clients};
use noadd::db::{Database, QueryLogEntry};
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_summary_stats() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let entries: Vec<QueryLogEntry> = (0..10)
        .map(|i| QueryLogEntry {
            timestamp: now - i * 60,
            client_ip: "192.168.1.1".into(),
            domain: format!("domain{i}.com"),
            query_type: "A".into(),
            action: if i % 3 == 0 { "blocked" } else { "allowed" }.into(),
            upstream: Some("1.1.1.1".into()),
            response_time_ms: 10,
            matched_rule: None,
            matched_list: None,
        })
        .collect();
    db.insert_query_logs(&entries).await.unwrap();

    let summary = compute_summary(&db, now).await.unwrap();
    assert_eq!(summary.total_today, 10);
    assert_eq!(summary.blocked_today, 4); // i=0,3,6,9
}

#[tokio::test]
async fn test_top_domains() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Insert repeated domains
    let mut entries = Vec::new();
    for _ in 0..5 {
        entries.push(QueryLogEntry {
            timestamp: now,
            client_ip: "192.168.1.1".into(),
            domain: "popular.com".into(),
            query_type: "A".into(),
            action: "allowed".into(),
            upstream: Some("1.1.1.1".into()),
            response_time_ms: 10,
            matched_rule: None,
            matched_list: None,
        });
    }
    for _ in 0..3 {
        entries.push(QueryLogEntry {
            timestamp: now,
            client_ip: "192.168.1.1".into(),
            domain: "other.com".into(),
            query_type: "A".into(),
            action: "allowed".into(),
            upstream: Some("1.1.1.1".into()),
            response_time_ms: 10,
            matched_rule: None,
            matched_list: None,
        });
    }
    db.insert_query_logs(&entries).await.unwrap();

    let top = compute_top_domains(&db, now, 10).await.unwrap();
    assert_eq!(top[0].domain, "popular.com");
    assert_eq!(top[0].count, 5);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test admin_stats_test`
Expected: FAIL

- [ ] **Step 3: Implement stats module**

```rust
// src/admin/stats.rs
use crate::db::{Database, DbResult};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Summary {
    pub total_today: i64,
    pub blocked_today: i64,
    pub total_7d: i64,
    pub blocked_7d: i64,
    pub block_ratio_today: f64,
}

#[derive(Debug, Serialize)]
pub struct TopDomain {
    pub domain: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct TopClient {
    pub client_ip: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct TimelinePoint {
    pub timestamp: i64,
    pub total: i64,
    pub blocked: i64,
}

const SECS_PER_DAY: i64 = 86400;

pub async fn compute_summary(db: &Database, now: i64) -> DbResult<Summary> {
    let today_start = now - SECS_PER_DAY;
    let week_start = now - 7 * SECS_PER_DAY;

    let (total_today, blocked_today) = db.count_queries_since(today_start).await?;
    let (total_7d, blocked_7d) = db.count_queries_since(week_start).await?;

    let block_ratio_today = if total_today > 0 {
        blocked_today as f64 / total_today as f64
    } else {
        0.0
    };

    Ok(Summary {
        total_today,
        blocked_today,
        total_7d,
        blocked_7d,
        block_ratio_today,
    })
}

pub async fn compute_top_domains(
    db: &Database,
    now: i64,
    limit: i64,
) -> DbResult<Vec<TopDomain>> {
    let since = now - SECS_PER_DAY;
    db.top_domains_since(since, limit).await
}

pub async fn compute_top_clients(
    db: &Database,
    now: i64,
    limit: i64,
) -> DbResult<Vec<TopClient>> {
    let since = now - SECS_PER_DAY;
    db.top_clients_since(since, limit).await
}

pub async fn compute_timeline(
    db: &Database,
    now: i64,
    hours: i64,
) -> DbResult<Vec<TimelinePoint>> {
    let since = now - hours * 3600;
    db.timeline_since(since, 3600).await
}
```

This requires additional DB methods. Add to `src/db.rs`:

```rust
use crate::admin::stats::{TopDomain, TopClient, TimelinePoint};

impl Database {
    // ... existing methods ...

    pub async fn count_queries_since(&self, since: i64) -> DbResult<(i64, i64)> {
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT COUNT(*), SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END)
                     FROM query_logs WHERE timestamp >= ?1",
                )?;
                let (total, blocked): (i64, i64) =
                    stmt.query_row([since], |row| Ok((row.get(0)?, row.get::<_, Option<i64>>(1)?.unwrap_or(0))))?;
                Ok((total, blocked))
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn top_domains_since(&self, since: i64, limit: i64) -> DbResult<Vec<TopDomain>> {
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT domain, COUNT(*) as cnt FROM query_logs
                     WHERE timestamp >= ?1 GROUP BY domain ORDER BY cnt DESC LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![since, limit], |row| {
                        Ok(TopDomain {
                            domain: row.get(0)?,
                            count: row.get(1)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn top_clients_since(&self, since: i64, limit: i64) -> DbResult<Vec<TopClient>> {
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT client_ip, COUNT(*) as cnt FROM query_logs
                     WHERE timestamp >= ?1 GROUP BY client_ip ORDER BY cnt DESC LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![since, limit], |row| {
                        Ok(TopClient {
                            client_ip: row.get(0)?,
                            count: row.get(1)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(DbError::from)
    }

    pub async fn timeline_since(
        &self,
        since: i64,
        bucket_secs: i64,
    ) -> DbResult<Vec<TimelinePoint>> {
        self.conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT (timestamp / ?1) * ?1 as bucket,
                            COUNT(*),
                            SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END)
                     FROM query_logs WHERE timestamp >= ?2
                     GROUP BY bucket ORDER BY bucket",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![bucket_secs, since], |row| {
                        Ok(TimelinePoint {
                            timestamp: row.get(0)?,
                            total: row.get(1)?,
                            blocked: row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(DbError::from)
    }
}
```

- [ ] **Step 4: Add stats and logs endpoints to admin_router**

Add these routes and handlers to `src/admin/api.rs`:

```rust
// Add to router in admin_router():
.route("/api/stats/summary", get(get_stats_summary))
.route("/api/stats/timeline", get(get_stats_timeline))
.route("/api/stats/top-domains", get(get_stats_top_domains))
.route("/api/stats/top-clients", get(get_stats_top_clients))
.route("/api/logs", get(get_logs).delete(delete_logs))

// Add handlers:
async fn get_stats_summary(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let summary = crate::admin::stats::compute_summary(&state.db, now)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(summary))
}

async fn get_stats_timeline(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let timeline = crate::admin::stats::compute_timeline(&state.db, now, 24)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(timeline))
}

async fn get_stats_top_domains(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let top = crate::admin::stats::compute_top_domains(&state.db, now, 20)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(top))
}

async fn get_stats_top_clients(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let top = crate::admin::stats::compute_top_clients(&state.db, now, 20)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(top))
}

#[derive(Deserialize)]
struct LogQuery {
    domain: Option<String>,
    action: Option<String>,
    client: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn get_logs(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Query(params): axum::extract::Query<LogQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    let logs = state
        .db
        .get_query_logs(
            params.domain.as_deref(),
            params.action.as_deref(),
            params.client.as_deref(),
            params.limit.unwrap_or(50),
            params.offset.unwrap_or(0),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(logs))
}

async fn delete_logs(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &jar)?;
    state
        .db
        .delete_all_logs()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({"ok": true})))
}
```

- [ ] **Step 5: Run all tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test admin_stats_test --test admin_api_test`
Expected: all tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/admin/ src/db.rs tests/admin_stats_test.rs
git commit -m "feat: implement admin stats and logs API endpoints"
```

---

### Task 15: Filter List Download & Update

**Files:**
- Modify: `src/filter/lists.rs`
- Create: `tests/filter_lists_test.rs`

- [ ] **Step 1: Write failing tests for list downloading and filter rebuilding**

```rust
// tests/filter_lists_test.rs
use noadd::filter::lists::ListManager;
use noadd::filter::engine::FilterEngine;
use noadd::db::Database;
use arc_swap::ArcSwap;
use std::sync::Arc;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_rebuild_filter_from_db() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();

    // Add a custom block rule
    db.add_custom_rule("||ads.test.com^", "block").await.unwrap();
    db.add_custom_rule("@@||safe.test.com^", "allow").await.unwrap();

    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![])));
    let manager = ListManager::new(db, filter.clone());
    manager.rebuild_filter().await.unwrap();

    let engine = filter.load();
    // Should block ads.test.com
    assert!(matches!(
        engine.check("ads.test.com"),
        noadd::filter::engine::FilterResult::Blocked { .. }
    ));
    // Should allow safe.test.com
    assert!(matches!(
        engine.check("safe.test.com"),
        noadd::filter::engine::FilterResult::Allowed
    ));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test filter_lists_test`
Expected: FAIL

- [ ] **Step 3: Implement list manager**

```rust
// src/filter/lists.rs
use crate::db::Database;
use crate::filter::engine::FilterEngine;
use crate::filter::parser::{parse_list, ParsedRule, RuleAction};
use arc_swap::ArcSwap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ListError {
    #[error("db error: {0}")]
    Db(#[from] crate::db::DbError),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

pub struct ListManager {
    db: Database,
    filter: Arc<ArcSwap<FilterEngine>>,
}

impl ListManager {
    pub fn new(db: Database, filter: Arc<ArcSwap<FilterEngine>>) -> Self {
        Self { db, filter }
    }

    pub async fn rebuild_filter(&self) -> Result<(), ListError> {
        let mut all_block_rules: Vec<(ParsedRule, String)> = Vec::new();
        let mut all_allow_rules: Vec<ParsedRule> = Vec::new();

        // Load from enabled filter lists (stored content in settings as list_content_{id})
        let lists = self.db.get_filter_lists().await?;
        for list in &lists {
            if !list.enabled {
                continue;
            }
            let key = format!("list_content_{}", list.id);
            if let Some(content) = self.db.get_setting(&key).await? {
                let rules = parse_list(&content);
                for rule in rules {
                    match rule.action {
                        RuleAction::Block => {
                            all_block_rules.push((rule, list.name.clone()));
                        }
                        RuleAction::Allow => {
                            all_allow_rules.push(rule);
                        }
                    }
                }
            }
        }

        // Load custom rules from DB
        let custom_blocks = self.db.get_custom_rules("block").await?;
        for cr in custom_blocks {
            if let Some(parsed) = crate::filter::parser::parse_rule(&cr.rule) {
                all_block_rules.push((parsed, "Custom Rules".into()));
            }
        }

        let custom_allows = self.db.get_custom_rules("allow").await?;
        for cr in custom_allows {
            if let Some(parsed) = crate::filter::parser::parse_rule(&cr.rule) {
                all_allow_rules.push(parsed);
            }
        }

        let engine = FilterEngine::new(all_block_rules, all_allow_rules);
        self.filter.store(Arc::new(engine));

        Ok(())
    }

    pub async fn download_and_update_list(&self, list_id: i64) -> Result<usize, ListError> {
        let lists = self.db.get_filter_lists().await?;
        let list = lists.iter().find(|l| l.id == list_id);
        let list = match list {
            Some(l) => l,
            None => return Ok(0),
        };

        let client = reqwest::Client::new();
        let content = client.get(&list.url).send().await?.text().await?;

        let rules = parse_list(&content);
        let rule_count = rules.len();

        // Store content in settings
        let key = format!("list_content_{}", list.id);
        self.db.set_setting(&key, &content).await?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        self.db
            .update_filter_list_stats(list.id, rule_count as i64, now)
            .await?;

        Ok(rule_count)
    }

    pub async fn update_all_lists(&self) -> Result<(), ListError> {
        let lists = self.db.get_filter_lists().await?;
        for list in &lists {
            if !list.enabled {
                continue;
            }
            match self.download_and_update_list(list.id).await {
                Ok(count) => {
                    tracing::info!(list = list.name, rules = count, "updated filter list");
                }
                Err(e) => {
                    tracing::error!(list = list.name, error = %e, "failed to update filter list");
                }
            }
        }
        self.rebuild_filter().await?;
        Ok(())
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test filter_lists_test`
Expected: 1 test PASS

- [ ] **Step 5: Commit**

```bash
git add src/filter/lists.rs tests/filter_lists_test.rs
git commit -m "feat: implement filter list manager with download and rebuild"
```

---

### Task 16: Build Script & Embedded Default Lists

**Files:**
- Create: `build.rs`
- Create: `lists/README.md` (placeholder so git tracks the directory)
- Modify: `src/filter/lists.rs` (add default list constants)

- [ ] **Step 1: Define default list URLs as constants**

Add to `src/filter/lists.rs`:

```rust
pub const DEFAULT_LISTS: &[(&str, &str)] = &[
    (
        "AdGuard DNS Filter",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    ),
    (
        "EasyList",
        "https://easylist.to/easylist/easylist.txt",
    ),
    (
        "Peter Lowe's List",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    ),
    (
        "OISD Basic",
        "https://basic.oisd.nl/",
    ),
    (
        "Steven Black Unified Hosts",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    (
        "URLhaus Malware Filter",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
    ),
];
```

- [ ] **Step 2: Create build.rs that downloads lists with fallback**

```rust
// build.rs
use std::fs;
use std::path::Path;

const LISTS: &[(&str, &str)] = &[
    ("adguard_dns", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"),
    ("peter_lowe", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
    ("steven_black", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/"),
];

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let lists_dir = Path::new(&out_dir).join("lists");
    fs::create_dir_all(&lists_dir).unwrap();

    let fallback_dir = Path::new("lists");

    for (name, url) in LISTS {
        let out_path = lists_dir.join(format!("{name}.txt"));
        let fallback_path = fallback_dir.join(format!("{name}.txt"));

        // Try to download; if that fails, use fallback snapshot
        if let Ok(content) = download(url) {
            fs::write(&out_path, &content).unwrap();
            // Also update the fallback snapshot
            let _ = fs::write(&fallback_path, &content);
        } else if fallback_path.exists() {
            println!("cargo:warning=Failed to download {name}, using fallback snapshot");
            fs::copy(&fallback_path, &out_path).unwrap();
        } else {
            println!("cargo:warning=Failed to download {name} and no fallback exists, using empty list");
            fs::write(&out_path, "").unwrap();
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=lists/");
}

fn download(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Use ureq (sync HTTP) for build script — reqwest is async and heavy for build.rs
    // For now, use a simple approach with std::process::Command and curl
    let output = std::process::Command::new("curl")
        .args(["-sL", "--max-time", "30", url])
        .output()?;
    if output.status.success() {
        Ok(String::from_utf8(output.stdout)?)
    } else {
        Err("curl failed".into())
    }
}
```

- [ ] **Step 3: Add method to load embedded lists on first run**

Add to `ListManager` in `src/filter/lists.rs`:

```rust
impl ListManager {
    // ... existing methods ...

    pub async fn seed_default_lists(&self) -> Result<(), ListError> {
        let existing = self.db.get_filter_lists().await?;
        if !existing.is_empty() {
            return Ok(()); // Already seeded
        }

        for (name, url) in DEFAULT_LISTS {
            let id = self.db.add_filter_list(name, url, true).await?;
            tracing::info!(name, "seeded default filter list");

            // Try to load embedded content
            let embedded = get_embedded_list(name);
            if let Some(content) = embedded {
                let rules = parse_list(&content);
                let key = format!("list_content_{id}");
                self.db.set_setting(&key, &content).await?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                self.db
                    .update_filter_list_stats(id, rules.len() as i64, now)
                    .await?;
            }
        }

        self.rebuild_filter().await?;
        Ok(())
    }
}

fn get_embedded_list(name: &str) -> Option<String> {
    let content = match name {
        "AdGuard DNS Filter" => include_str!(concat!(env!("OUT_DIR"), "/lists/adguard_dns.txt")),
        "Peter Lowe's List" => include_str!(concat!(env!("OUT_DIR"), "/lists/peter_lowe.txt")),
        "Steven Black Unified Hosts" => {
            include_str!(concat!(env!("OUT_DIR"), "/lists/steven_black.txt"))
        }
        "URLhaus Malware Filter" => include_str!(concat!(env!("OUT_DIR"), "/lists/urlhaus.txt")),
        _ => return None,
    };
    if content.is_empty() {
        None
    } else {
        Some(content.to_string())
    }
}
```

Note: EasyList and OISD are excluded from compile-time embedding to keep binary size reasonable. They will be downloaded on first update cycle.

- [ ] **Step 4: Verify it compiles**

Run: `cd /home/nixos/Develop/claude/noadd && cargo check`
Expected: compiles (build.rs may download lists or use empty fallbacks)

- [ ] **Step 5: Create lists directory with .gitkeep**

```bash
mkdir -p lists && touch lists/.gitkeep
```

- [ ] **Step 6: Commit**

```bash
git add build.rs src/filter/lists.rs lists/.gitkeep
git commit -m "feat: add build.rs for list embedding and default list seeding"
```

---

### Task 17: TLS / ACME

**Files:**
- Modify: `src/tls.rs`

- [ ] **Step 1: Implement TLS configuration helper**

```rust
// src/tls.rs
use rustls::ServerConfig;
use std::io;
use std::path::Path;
use std::sync::Arc;

pub fn load_tls_config(cert_path: &Path, key_path: &Path) -> io::Result<Arc<ServerConfig>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(Arc::new(config))
}
```

Note: `rustls-acme` integration will be added when the main server wiring is done (Task 21), as it hooks into the axum server directly. Add `rustls-pemfile` to Cargo.toml dependencies.

- [ ] **Step 2: Verify it compiles**

Run: `cd /home/nixos/Develop/claude/noadd && cargo check`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add src/tls.rs Cargo.toml
git commit -m "feat: add TLS configuration helper"
```

---

### Task 18: Admin Web UI

**Files:**
- Create: `admin-ui/` (frontend SPA)
- Modify: `src/admin/api.rs` (serve static files)

This task uses the **@frontend-design** skill for UI design and implementation.

- [ ] **Step 1: Invoke frontend-design skill**

Use the `frontend-design` skill to design and build the admin SPA. Requirements:

**Pages:**
1. **Dashboard** — stats summary (total queries, blocked, ratio), time-series chart (24h), top blocked domains, top clients
2. **Query Log** — paginated table with domain, client, action, time; search/filter by domain, action, client
3. **Filter Lists** — table of lists with name, URL, enabled toggle, rule count, last updated; add/remove custom lists; trigger update button
4. **Custom Rules** — two sections: allowlist and blocklist; add/remove rules
5. **Settings** — upstream DNS servers, DNS port, DoH port, admin port, log retention

**Tech constraints:**
- Must build to static files (HTML/CSS/JS)
- Will be embedded in Rust binary via `include_dir`
- Calls REST API at `/api/*`
- Uses session cookie for auth
- Login page shown when not authenticated

- [ ] **Step 2: Wire static file serving in axum**

Add to `src/admin/api.rs`:

```rust
use include_dir::{include_dir, Dir};
use axum::response::Html;

static ADMIN_UI: Dir = include_dir!("$CARGO_MANIFEST_DIR/admin-ui/dist");

// Add to admin_router:
.fallback(serve_static)

async fn serve_static(uri: axum::http::Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match ADMIN_UI.get_file(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                StatusCode::OK,
                [("content-type", mime.to_string())],
                file.contents().to_vec(),
            )
                .into_response()
        }
        None => {
            // SPA fallback: serve index.html for client-side routing
            match ADMIN_UI.get_file("index.html") {
                Some(file) => Html(String::from_utf8_lossy(file.contents()).to_string()).into_response(),
                None => (StatusCode::NOT_FOUND, "not found").into_response(),
            }
        }
    }
}
```

Add `mime_guess` to Cargo.toml.

- [ ] **Step 3: Verify it compiles**

Run: `cd /home/nixos/Develop/claude/noadd && cargo check`
Expected: compiles (with empty dist directory it may warn)

- [ ] **Step 4: Commit**

```bash
git add admin-ui/ src/admin/api.rs Cargo.toml
git commit -m "feat: add admin web UI with static file serving"
```

---

### Task 19: Graceful Shutdown

**Files:**
- Create: `src/shutdown.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Implement shutdown signal handler**

```rust
// src/shutdown.rs
use tokio::sync::broadcast;

pub fn shutdown_signal() -> (broadcast::Sender<()>, impl std::future::Future<Output = ()>) {
    let (tx, _) = broadcast::channel(1);
    let tx_clone = tx.clone();

    let signal = async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();

        #[cfg(unix)]
        tokio::select! {
            _ = ctrl_c => {},
            _ = sigterm.recv() => {},
        }

        #[cfg(not(unix))]
        ctrl_c.await.ok();

        tracing::info!("shutdown signal received");
        let _ = tx_clone.send(());
    };

    (tx, signal)
}
```

Add `pub mod shutdown;` to `src/lib.rs`.

- [ ] **Step 2: Verify it compiles**

Run: `cd /home/nixos/Develop/claude/noadd && cargo check`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add src/shutdown.rs src/lib.rs
git commit -m "feat: add graceful shutdown signal handler"
```

---

### Task 20: Integration Tests

**Files:**
- Create: `tests/integration_test.rs`

- [ ] **Step 1: Write integration test that boots the full stack**

```rust
// tests/integration_test.rs
use noadd::cache::DnsCache;
use noadd::db::Database;
use noadd::dns::handler::DnsHandler;
use noadd::filter::engine::FilterEngine;
use noadd::filter::lists::ListManager;
use noadd::filter::parser::parse_list;
use noadd::logger::QueryLogger;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};
use arc_swap::ArcSwap;
use std::sync::Arc;
use tempfile::NamedTempFile;
use hickory_proto::op::{Message, Query, MessageType, OpCode};
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;

#[tokio::test]
async fn test_full_query_pipeline_block() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();

    // Add a block rule
    db.add_custom_rule("||ads.blocked.com^", "block").await.unwrap();

    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![])));
    let manager = ListManager::new(db.clone(), filter.clone());
    manager.rebuild_filter().await.unwrap();

    let cache = DnsCache::new(1000);
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()));
    let (logger, log_tx) = QueryLogger::new(db.clone(), 500, 1);
    let logger_handle = tokio::spawn(logger.run());

    let handler = Arc::new(DnsHandler::new(filter, cache, forwarder, log_tx));

    // Test blocked query
    let mut msg = Message::new();
    msg.set_id(1);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut query = Query::new();
    query.set_name(Name::from_str("ads.blocked.com.").unwrap());
    query.set_query_type(RecordType::A);
    msg.add_query(query);

    let response = handler
        .handle(msg, "192.168.1.100".parse().unwrap())
        .await
        .unwrap();

    // Should return 0.0.0.0
    let a = response.answers()[0]
        .data()
        .unwrap()
        .clone()
        .into_a()
        .unwrap();
    assert_eq!(a.0, std::net::Ipv4Addr::UNSPECIFIED);

    // Wait for logger flush
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let logs = db.get_query_logs(None, None, None, 10, 0).await.unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].action, "blocked");
    assert_eq!(logs[0].domain, "ads.blocked.com");
}

#[tokio::test]
async fn test_full_query_pipeline_allow() {
    let tmp = NamedTempFile::new().unwrap();
    let db = Database::open(tmp.path()).await.unwrap();
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![])));
    let cache = DnsCache::new(1000);
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig {
        servers: vec!["1.1.1.1:53".into()],
        timeout_ms: 5000,
    }));
    let (logger, log_tx) = QueryLogger::new(db.clone(), 500, 1);
    tokio::spawn(logger.run());

    let handler = Arc::new(DnsHandler::new(filter, cache, forwarder, log_tx));

    let mut msg = Message::new();
    msg.set_id(2);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut query = Query::new();
    query.set_name(Name::from_str("example.com.").unwrap());
    query.set_query_type(RecordType::A);
    msg.add_query(query);

    let response = handler
        .handle(msg, "192.168.1.100".parse().unwrap())
        .await
        .unwrap();

    assert!(!response.answers().is_empty());
}
```

- [ ] **Step 2: Run integration tests**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test integration_test`
Expected: 2 tests PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration_test.rs
git commit -m "test: add integration tests for full query pipeline"
```

---

### Task 21: Main Entry Point Wiring

**Files:**
- Modify: `src/main.rs`
- Modify: `src/config.rs`

- [ ] **Step 1: Implement CLI args in config.rs**

```rust
// src/config.rs
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "noadd", about = "DNS ad-blocker with DoH support")]
pub struct CliArgs {
    /// Path to SQLite database
    #[arg(long, default_value = "noadd.db")]
    pub db_path: PathBuf,

    /// DNS listener address (UDP + TCP)
    #[arg(long, default_value = "0.0.0.0:53")]
    pub dns_addr: String,

    /// HTTP/DoH listener address
    #[arg(long, default_value = "0.0.0.0:3000")]
    pub http_addr: String,

    /// Admin UI listener address
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub admin_addr: String,

    /// TLS certificate file (enables HTTPS)
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file
    #[arg(long)]
    pub tls_key: Option<PathBuf>,
}
```

- [ ] **Step 2: Wire everything together in main.rs**

```rust
// src/main.rs
use clap::Parser;
use noadd::admin::api::admin_router;
use noadd::admin::auth::new_session_store;
use noadd::cache::DnsCache;
use noadd::config::CliArgs;
use noadd::db::Database;
use noadd::dns::doh::doh_router;
use noadd::dns::handler::DnsHandler;
use noadd::dns::tcp::run_tcp_listener;
use noadd::dns::udp::run_udp_listener;
use noadd::filter::engine::FilterEngine;
use noadd::filter::lists::ListManager;
use noadd::logger::QueryLogger;
use noadd::shutdown::shutdown_signal;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};
use arc_swap::ArcSwap;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "noadd=info".into()),
        )
        .init();

    let args = CliArgs::parse();
    tracing::info!("starting noadd");

    // Database
    let db = Database::open(&args.db_path).await?;

    // Filter engine
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![])));

    // Seed default lists on first run and rebuild filter
    let list_manager = ListManager::new(db.clone(), filter.clone());
    list_manager.seed_default_lists().await?;
    list_manager.rebuild_filter().await?;

    // Upstream forwarder
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()));

    // DNS cache
    let cache = DnsCache::new(10_000);

    // Query logger
    let (logger, log_tx) = QueryLogger::new(db.clone(), 500, 1);
    let logger_handle = tokio::spawn(logger.run());

    // DNS handler
    let handler = Arc::new(DnsHandler::new(filter.clone(), cache.clone(), forwarder, log_tx));

    // Shutdown signal
    let (shutdown_tx, shutdown_signal) = shutdown_signal();

    // Start UDP listener
    let dns_addr: std::net::SocketAddr = args.dns_addr.parse()?;
    let udp_handler = handler.clone();
    let udp_handle = tokio::spawn(async move {
        if let Err(e) = run_udp_listener(dns_addr, udp_handler).await {
            tracing::error!(error = %e, "UDP listener failed");
        }
    });

    // Start TCP listener
    let tcp_handler = handler.clone();
    let tcp_handle = tokio::spawn(async move {
        if let Err(e) = run_tcp_listener(dns_addr, tcp_handler).await {
            tracing::error!(error = %e, "TCP listener failed");
        }
    });

    // Start DoH + Admin HTTP server
    let doh_routes = doh_router(handler.clone());
    let session_store = new_session_store();
    let admin_routes = admin_router(db.clone(), session_store, filter.clone(), cache.clone());

    let app = doh_routes.merge(admin_routes);

    let http_addr: std::net::SocketAddr = args.http_addr.parse()?;
    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    tracing::info!(%http_addr, "HTTP server started (DoH + Admin)");

    // Background list update scheduler (every 24h)
    let update_db = db.clone();
    let update_filter = filter.clone();
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
        interval.tick().await; // Skip first immediate tick
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let manager = ListManager::new(update_db.clone(), update_filter.clone());
                    if let Err(e) = manager.update_all_lists().await {
                        tracing::error!(error = %e, "failed to update filter lists");
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    });

    // Background log pruning (every hour)
    let prune_db = db.clone();
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let retention_days: i64 = prune_db
                        .get_setting("log_retention_days")
                        .await
                        .ok()
                        .flatten()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(7);
                    let cutoff = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64
                        - retention_days * 86400;
                    match prune_db.prune_logs_before(cutoff).await {
                        Ok(count) if count > 0 => {
                            tracing::info!(count, "pruned old query logs");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to prune logs");
                        }
                        _ => {}
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    });

    // Serve HTTP with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    tracing::info!("shutting down...");

    // Cleanup
    udp_handle.abort();
    tcp_handle.abort();
    // Logger will flush on channel close (sender dropped with handler)
    drop(handler);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), logger_handle).await;

    tracing::info!("goodbye");
    Ok(())
}
```

- [ ] **Step 3: Add anyhow to dependencies**

Add `anyhow = "1"` to `[dependencies]` in Cargo.toml.

- [ ] **Step 4: Verify it compiles**

Run: `cd /home/nixos/Develop/claude/noadd && cargo check`
Expected: compiles

- [ ] **Step 5: Run all tests**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run`
Expected: all tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/main.rs src/config.rs Cargo.toml
git commit -m "feat: wire all components together in main entry point"
```
