# Programmatic API (API keys + OpenAPI docs) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let scripts/CI authenticate to noadd's existing REST API with long-lived, user-bound API keys, and ship an interactive OpenAPI (Scalar) reference for the core programmatic endpoints.

**Architecture:** A new hashed `api_keys` table (BLAKE2b, one key = one operator). A single `AuthedUser` axum extractor resolves either the existing `session` cookie or an `Authorization: Bearer` API key to a `user_id`, so every guarded handler drops its manual `require_auth` call and gains dual-source auth uniformly. `utoipa` annotations on a core subset feed a `#[derive(OpenApi)]` document served interactively by `utoipa-scalar`.

**Tech Stack:** Rust 2024, axum 0.8, `axum-extra` CookieJar, `tokio-rusqlite`, `blake2` (already transitive), `utoipa` 5.x, `utoipa-scalar` 0.3 (`axum` feature).

**Design doc:** `docs/superpowers/specs/2026-07-10-programmatic-api-design.md`.

## Global Constraints

- Rust edition 2024; do **not** change `rust-version` (MSRV) in `Cargo.toml`.
- Tests run with `cargo nextest run` (not `cargo test`). Run `cargo fmt` before every commit; `cargo clippy --all-targets -- -D warnings` must stay clean.
- All commits GPG-signed. Work on branch `feat/programmatic-api`. Stage files explicitly by name — never `git add -A`/`.`.
- Dependencies must be a version published ≥7 days before today (2026-07-10). Verify with `cargo info <crate>` before pinning: `utoipa` 5.5.0 (2026-05-04) and `utoipa-scalar` 0.3.0 (2025-01-16) both qualify.
- Token hashing uses **BLAKE2b** via the `blake2` crate (already in the tree via `argon2`); do **not** add `sha2`. Do **not** add `utoipa-axum` or `utoipa-swagger-ui`.
- API keys are stored hashed only; the full token is returned exactly once at creation. Keys inherit the full permissions of their owning operator; no independent scopes.
- Docs endpoints (`/api/docs`, `/api/openapi.json`) are intentionally unauthenticated (schema only, no data).

---

### Task 0: Branch setup

- [ ] **Step 1: Create the feature branch**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && pwd && git checkout -b feat/programmatic-api
```
Expected: `Switched to a new branch 'feat/programmatic-api'`.

---

### Task 1: Add dependencies

**Files:**
- Modify: `Cargo.toml` (`[dependencies]`)

**Interfaces:**
- Produces: `blake2`, `utoipa`, `utoipa-scalar` crates available to the codebase.

- [ ] **Step 1: Verify the versions clear the 7-day cooldown**

Run:
```bash
cargo info utoipa 2>/dev/null | grep -E '^version|^created' ; cargo info utoipa-scalar 2>/dev/null | grep -E '^version|^created'
```
Expected: `utoipa` ≥ 5.5.0 and `utoipa-scalar` ≥ 0.3.0, both created well before 2026-07-03. If a newer version is <7 days old, pin the newest that is ≥7 days old.

- [ ] **Step 2: Add the dependencies**

In `Cargo.toml`, under `[dependencies]`, add (keep the block's existing ordering style — append these lines):
```toml
blake2 = "0.10"
utoipa = "5"
utoipa-scalar = { version = "0.3", features = ["axum"] }
```

- [ ] **Step 3: Build to resolve and compile**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo build
```
Expected: builds successfully; `Cargo.lock` updated with the three crates.

- [ ] **Step 4: Supply-chain gate**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo deny check
```
Expected: passes (advisories, licenses, bans, sources). If `cargo deny` flags a new transitive license, resolve per existing `deny.toml` policy before continuing.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -S -m "build: add blake2, utoipa, utoipa-scalar for the programmatic API"
```

---

### Task 2: `api_keys` schema, migration, and CRUD

**Files:**
- Modify: `src/db.rs` (CREATE TABLE block ~line 359–370; `run_migrations` ~line 386–459; row structs ~line 94–105; add methods after the DoH-token section ~line 995)

**Interfaces:**
- Produces:
  - `pub struct ApiKeyRow { id: i64, name: String, prefix: String, created_at: i64, last_used_at: Option<i64>, expires_at: Option<i64> }` (Serialize)
  - `Database::insert_api_key(&self, user_id: i64, name: &str, token_hash: &str, prefix: &str, created_at: i64, expires_at: Option<i64>) -> Result<i64, DbError>`
  - `Database::list_api_keys_for_user(&self, user_id: i64) -> Result<Vec<ApiKeyRow>, DbError>`
  - `Database::delete_api_key(&self, id: i64, user_id: i64) -> Result<bool, DbError>` (true if a row was deleted)
  - `Database::validate_api_key(&self, token_hash: &str, now: i64) -> Result<Option<i64>, DbError>` (returns owner `user_id`; enforces expiry; throttled `last_used_at` write)

- [ ] **Step 1: Write the failing migration test**

Add to the `#[cfg(test)] mod tests` block in `src/db.rs`:
```rust
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
```

- [ ] **Step 2: Run it to verify it fails**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run migration_v8_adds_api_keys_table
```
Expected: FAIL to compile (`insert_api_key`/`list_api_keys_for_user` not found).

- [ ] **Step 3: Add the `ApiKeyRow` struct**

In `src/db.rs`, after `DohTokenRow` (~line 98):
```rust
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyRow {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub expires_at: Option<i64>,
}
```

- [ ] **Step 4: Add the table to the fresh-schema CREATE block**

In the top-level `execute_batch` (after the `users` table, ~line 369), add:
```sql
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
```

- [ ] **Step 5: Add the migration step and bump `LATEST_VERSION`**

In `run_migrations`, after the `if version < 7 { … }` block (~line 455), add:
```rust
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
```
Then change `const LATEST_VERSION: i64 = 7;` to `const LATEST_VERSION: i64 = 8;`.

- [ ] **Step 6: Add the CRUD + validate methods**

In `src/db.rs`, after the DoH-token section (after `has_doh_tokens`, ~line 995), add:
```rust
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
    pub async fn validate_api_key(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<i64>, DbError> {
        let token_hash = token_hash.to_string();
        let user_id = self
            .conn
            .call(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT id, user_id, expires_at, last_used_at
                         FROM api_keys WHERE token_hash = ?1",
                        params![token_hash],
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
                    conn.execute(
                        "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
                        params![now, id],
                    )?;
                }
                Ok(Some(user_id))
            })
            .await?;
        Ok(user_id)
    }
```

- [ ] **Step 7: Run the migration test — should pass**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run migration_v8_adds_api_keys_table
```
Expected: PASS.

- [ ] **Step 8: Write failing tests for expiry, throttle, delete-scoping, and cascade**

Add to the tests module:
```rust
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
        assert_eq!(db.validate_api_key("hash-live", 200).await.unwrap(), Some(1));

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
    async fn deleting_user_cascades_api_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cascade.db");
        let db = Database::open(path.to_str().unwrap()).await.unwrap();
        db.create_user("a", "x", 100).await.unwrap(); // id 1
        db.create_user("b", "y", 100).await.unwrap(); // id 2 (so delete isn't the last operator)
        db.insert_api_key(1, "k", "h", "noadd_cccc", 100, None)
            .await
            .unwrap();
        assert_eq!(db.delete_user(1).await.unwrap(), crate::db::DeleteUserOutcome::Deleted);
        assert!(db.list_api_keys_for_user(1).await.unwrap().is_empty());
    }
```

Note: `ON DELETE CASCADE` requires `PRAGMA foreign_keys = ON`. Verify it is already enabled at connection open (search `foreign_keys` in `src/db.rs`). If it is **not** set, add `PRAGMA foreign_keys = ON;` to the writer connection's pragma setup and to `open_read_conn`, and note it in the commit; the cascade test above is the guard.

- [ ] **Step 9: Run the new tests to confirm they pass**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run -E 'test(validate_api_key_respects_expiry_and_scoping) or test(deleting_user_cascades_api_keys) or test(migration_v8_adds_api_keys_table)'
```
Expected: all PASS.

- [ ] **Step 10: Format, lint, commit**

```bash
cd /Users/henry/Develop/claude/noadd && cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/db.rs
git commit -S -m "feat(db): add api_keys table, migration v8, and CRUD"
```

---

### Task 3: Token generation + BLAKE2b hashing helpers

**Files:**
- Modify: `src/admin/auth.rs`

**Interfaces:**
- Produces:
  - `hash_api_key(token: &str) -> String` (BLAKE2b-512, lower-hex)
  - `generate_api_key() -> (String, String, String)` returning `(full_token, display_prefix, token_hash)`

- [ ] **Step 1: Write failing tests**

Add to `src/admin/auth.rs` (create a `#[cfg(test)] mod tests` block if none exists at the file end):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_shape_and_prefix() {
        let (full, prefix, hash) = generate_api_key();
        assert!(full.starts_with("noadd_"));
        assert_eq!(full.len(), "noadd_".len() + 40);
        assert!(prefix.starts_with("noadd_"));
        assert_eq!(prefix.len(), "noadd_".len() + 4);
        assert!(full.starts_with(&prefix));
        // hash is deterministic hex of the full token
        assert_eq!(hash, hash_api_key(&full));
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_is_stable_and_distinct() {
        assert_eq!(hash_api_key("noadd_abc"), hash_api_key("noadd_abc"));
        assert_ne!(hash_api_key("noadd_abc"), hash_api_key("noadd_abd"));
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run api_key_shape_and_prefix
```
Expected: FAIL to compile (`generate_api_key` not found).

- [ ] **Step 3: Implement the helpers**

At the top of `src/admin/auth.rs`, add the import:
```rust
use blake2::{Blake2b512, Digest};
```
Then, after `generate_token` (~line 67), add:
```rust
/// Prefix identifying a noadd programmatic API key (useful for secret scanners).
const API_KEY_PREFIX: &str = "noadd_";
/// Random body length; 40 alphanumeric chars ≈ 238 bits of entropy.
const API_KEY_BODY_LEN: usize = 40;

/// BLAKE2b-512 hash of an API key, lower-hex encoded. Fast one-way hash — the
/// token is high-entropy random, so no salt/Argon2 is needed, and the hex digest
/// is directly indexable for lookup.
pub fn hash_api_key(token: &str) -> String {
    let mut hasher = Blake2b512::new();
    hasher.update(token.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Mint a fresh API key. Returns `(full_token, display_prefix, token_hash)`.
/// The full token is shown to the user exactly once; only the hash is stored.
pub fn generate_api_key() -> (String, String, String) {
    let body: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(API_KEY_BODY_LEN)
        .map(char::from)
        .collect();
    let full = format!("{API_KEY_PREFIX}{body}");
    let prefix = format!("{API_KEY_PREFIX}{}", &body[..4]);
    let hash = hash_api_key(&full);
    (full, prefix, hash)
}
```

- [ ] **Step 4: Run tests to verify pass**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run -E 'test(api_key_shape_and_prefix) or test(hash_is_stable_and_distinct)'
```
Expected: PASS.

- [ ] **Step 5: Format, lint, commit**

```bash
cd /Users/henry/Develop/claude/noadd && cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/admin/auth.rs
git commit -S -m "feat(auth): API key generation and BLAKE2b hashing"
```

---

### Task 4: `AuthedUser` extractor + migrate guarded handlers to dual-source auth

**Files:**
- Modify: `src/admin/api.rs` (auth helpers ~line 265–278; every handler that calls `require_auth`)
- Test: `tests/api_key_auth.rs` (create)

**Interfaces:**
- Consumes: `validate_session` (existing), `Database::validate_api_key` (Task 2), `hash_api_key` (Task 3).
- Produces: `pub struct AuthedUser { pub user_id: i64 }` implementing `FromRequestParts<AppState>`; used as a handler argument to require + resolve auth from cookie or bearer token. `require_auth` is removed.

- [ ] **Step 1: Write the failing integration test**

The crate already has a lib target (`src/lib.rs`); integration tests import `noadd::admin::api::{AppState, admin_router}`, `noadd::admin::auth::…`, and `noadd::db::Database` directly. `tower` (for `oneshot`) and `tempfile` are already dev-dependencies. `tests/admin_api_test.rs` already contains a `build_app` helper that seeds an operator (`user_id = 1`) and returns the router; this new file uses a self-contained variant that **also returns the `Database`** so tests can mint keys directly.

Create `tests/api_key_auth.rs`:
```rust
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::mpsc;
use tower::ServiceExt; // oneshot

use noadd::admin::api::{AppState, ServerInfo, admin_router};
use noadd::admin::auth::{RateLimiter, generate_api_key, new_session_store};
use noadd::cache::DnsCache;
use noadd::db::Database;
use noadd::dns::handler::DnsHandler;
use noadd::filter::engine::FilterEngine;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

/// Build the admin router with a seeded operator (user_id 1) and return the
/// router plus the backing Database. Mirrors `build_app` in admin_api_test.rs.
async fn build_app() -> (axum::Router, Database) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep().join("test.db");
    let db = Database::open(path.to_str().unwrap()).await.unwrap();
    let hash = noadd::admin::auth::hash_password("admin").unwrap();
    db.create_user("admin", &hash, noadd::now_unix()).await.unwrap(); // id 1

    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![], vec![])));
    let cache = DnsCache::new(100);
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);
    let (log_tx, _log_rx) = mpsc::channel(64);
    let handler = Arc::new(DnsHandler::new(filter.clone(), cache.clone(), forwarder.clone(), log_tx));

    let state = AppState {
        db: db.clone(),
        sessions: new_session_store(),
        filter,
        cache,
        rate_limiter: Arc::new(RateLimiter::new(5, 60)),
        forwarder,
        handler,
        server_info: ServerInfo {
            dns_addr: "127.0.0.1:5353".into(),
            http_addr: "127.0.0.1:3000".into(),
            tls_enabled: false,
        },
        list_manager: todo_list_manager().await,
        rebuild: todo_rebuild(),
        registry: todo_registry(),
        trusted_proxies: todo_trusted_proxies(),
    };
    (admin_router(state), db)
}
```

**Before finalizing the helper:** open `tests/admin_api_test.rs` and copy its exact `AppState { … }` construction (the `list_manager`, `rebuild`, `registry`, `trusted_proxies` fields need real constructors — the `todo_*()` placeholders above are stand-ins). Reuse the identical field initializers from `build_app` there so all twelve `AppState` fields are populated correctly; only the return type differs (also return `db`).

Then add the auth test to the same file:
```rust
#[tokio::test]
async fn bearer_api_key_authenticates_like_a_session() {
    let (app, db) = build_app().await;

    let (full, prefix, hash) = generate_api_key();
    db.insert_api_key(1, "test", &hash, &prefix, 0, None).await.unwrap();

    // Valid bearer key -> 200.
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/rules")
                .header("authorization", format!("Bearer {full}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // No credentials -> 401.
    let res = app
        .clone()
        .oneshot(Request::builder().uri("/api/rules").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Garbage bearer token -> 401.
    let res = app
        .oneshot(
            Request::builder()
                .uri("/api/rules")
                .header("authorization", "Bearer noadd_not_a_real_key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
```

- [ ] **Step 2: Run to verify failure**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run bearer_api_key_authenticates_like_a_session
```
Expected: FAIL to compile (no `AuthedUser`, `test_app` missing).

- [ ] **Step 3: Implement the `AuthedUser` extractor**

In `src/admin/api.rs`, update the auth-helper imports to include the bearer-token pieces and add the extractor. Replace the existing `current_session`/`require_auth` region (lines 265–278) with:
```rust
fn current_session(state: &AppState, jar: &CookieJar) -> Result<(i64, String), StatusCode> {
    let token = jar
        .get("session")
        .map(|c| c.value().to_string())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    match validate_session(&state.sessions, &token) {
        Some(user_id) => Ok((user_id, token)),
        None => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Extract a bearer token from the `Authorization` header, if present.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let v = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    v.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

/// An authenticated operator, resolved from either the browser `session` cookie
/// or an `Authorization: Bearer <api key>` header. Downstream handlers depend
/// only on `user_id`, so cookie and API-key requests are indistinguishable.
pub struct AuthedUser {
    pub user_id: i64,
}

impl axum::extract::FromRequestParts<AppState> for AuthedUser {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. Session cookie (browser path).
        let jar = CookieJar::from_headers(&parts.headers);
        if let Some(cookie) = jar.get("session")
            && let Some(user_id) = validate_session(&state.sessions, cookie.value())
        {
            return Ok(AuthedUser { user_id });
        }
        // 2. Bearer API key (programmatic path).
        if let Some(token) = bearer_token(&parts.headers) {
            let hash = crate::admin::auth::hash_api_key(&token);
            let now = crate::now_unix();
            if let Ok(Some(user_id)) = state.db.validate_api_key(&hash, now).await {
                return Ok(AuthedUser { user_id });
            }
        }
        Err(StatusCode::UNAUTHORIZED)
    }
}
```
Add `hash_api_key` to the `use crate::admin::auth::{…}` import list at the top of the file (alongside `generate_token`, etc.), or reference it fully-qualified as written above.

- [ ] **Step 4: Migrate every `require_auth` call site to the extractor**

`require_auth` is now gone; the compiler will flag each call site. For every guarded handler:
- Add `_auth: AuthedUser,` to the signature (place it after `State(state): State<AppState>` and before any `Json<…>` body extractor).
- Delete the `let … = require_auth(&state, &jar)?;` line.
- If `jar: CookieJar` is now unused in that handler, remove the `jar` parameter too.
- Handlers that need the caller's identity use `_auth.user_id` (rename `_auth` → `auth`).

Example — `get_rules` becomes:
```rust
async fn get_rules(
    State(state): State<AppState>,
    _auth: AuthedUser,
) -> Result<Json<Vec<crate::db::CustomRuleRow>>, StatusCode> {
    let rules = state
        .db
        .get_all_custom_rules()
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rules))
}
```
Example with a body — `add_rule` becomes:
```rust
async fn add_rule(
    State(state): State<AppState>,
    _auth: AuthedUser,
    Json(body): Json<AddRuleRequest>,
) -> Result<(StatusCode, Json<AddRuleResponse>), StatusCode> {
    // body unchanged from here …
```
Example that needs identity — `get_me` becomes (drop `current_session`, use the extractor):
```rust
async fn get_me(
    State(state): State<AppState>,
    auth: AuthedUser,
) -> Result<Json<MeResponse>, StatusCode> {
    let username = state
        .db
        .get_username(auth.user_id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(MeResponse { id: auth.user_id, username }))
}
```
**Keep `current_session`** — the session-token-specific handlers still use it: `logout` (revokes the current cookie token), the sessions list (`is_current`), and self-session revoke (cookie clearing). Do not convert those; they are session-only by nature.

To enumerate every site to convert, run:
```bash
cd /Users/henry/Develop/claude/noadd && grep -n 'require_auth' src/admin/api.rs
```
Convert each, then delete the `fn require_auth` definition. The build failing on any leftover `require_auth` is the completeness gate.

- [ ] **Step 5: Compile — the removed `require_auth` enforces full migration**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo build
```
Expected: compiles with zero references to `require_auth`. Fix any handler the compiler flags.

- [ ] **Step 6: Run the auth integration test**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run bearer_api_key_authenticates_like_a_session
```
Expected: PASS.

- [ ] **Step 7: Full suite + lint (guard against a broken migration)**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run && cargo clippy --all-targets -- -D warnings
```
Expected: all green — confirms no handler lost its auth guard.

- [ ] **Step 8: Format and commit**

```bash
cd /Users/henry/Develop/claude/noadd && cargo fmt
git add src/admin/api.rs tests/api_key_auth.rs
git commit -S -m "feat(auth): AuthedUser extractor for cookie + bearer API-key auth"
```

---

### Task 5: API-key management endpoints

**Files:**
- Modify: `src/admin/api.rs` (route registration ~line 111–112 area; new handlers + DTOs)
- Test: `tests/api_key_auth.rs` (extend)

**Interfaces:**
- Consumes: `AuthedUser`, `generate_api_key`, `Database::{insert_api_key,list_api_keys_for_user,delete_api_key}`.
- Produces routes: `GET /api/api-keys`, `POST /api/api-keys`, `DELETE /api/api-keys/{id}`.
  - `CreateApiKeyRequest { name: String, expires_at: Option<i64> }`
  - `CreateApiKeyResponse { id: i64, name: String, prefix: String, token: String }`

- [ ] **Step 1: Write the failing endpoint test**

Append to `tests/api_key_auth.rs`:
```rust
#[tokio::test]
async fn api_key_lifecycle_over_http() {
    use serde_json::json;
    let (app, db) = build_app().await;

    // Authenticate management calls with a bootstrap key for user 1.
    let (boot, prefix, hash) = generate_api_key();
    db.insert_api_key(1, "boot", &hash, &prefix, 0, None)
        .await
        .unwrap();
    let auth = format!("Bearer {boot}");

    // Create returns the full token exactly once.
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/api-keys")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(json!({"name": "ci"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let token = created["token"].as_str().unwrap();
    assert!(token.starts_with("noadd_"));
    let new_id = created["id"].as_i64().unwrap();

    // List never leaks a token/hash.
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/api-keys")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(!body.contains("token_hash"));
    assert!(!body.contains(token));

    // Delete the created key.
    let res = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/api-keys/{new_id}"))
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
```

- [ ] **Step 2: Run to verify failure**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run api_key_lifecycle_over_http
```
Expected: FAIL (routes 404 / handlers missing).

- [ ] **Step 3: Add DTOs + handlers**

In `src/admin/api.rs`, after the DoH-token handlers (~line 1254), add:
```rust
// --- API Keys ---

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub expires_at: Option<i64>,
}

#[derive(Serialize)]
pub struct CreateApiKeyResponse {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    /// Full secret — shown only in this create response, never again.
    pub token: String,
}

async fn list_api_keys(
    State(state): State<AppState>,
    auth: AuthedUser,
) -> Result<Json<Vec<crate::db::ApiKeyRow>>, StatusCode> {
    let keys = state
        .db
        .list_api_keys_for_user(auth.user_id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(keys))
}

async fn create_api_key(
    State(state): State<AppState>,
    auth: AuthedUser,
    Json(body): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), StatusCode> {
    let name = body.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (full, prefix, hash) = crate::admin::auth::generate_api_key();
    let now = crate::now_unix();
    let id = state
        .db
        .insert_api_key(auth.user_id, &name, &hash, &prefix, now, body.expires_at)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse { id, name, prefix, token: full }),
    ))
}

async fn delete_api_key(
    State(state): State<AppState>,
    auth: AuthedUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    let deleted = state
        .db
        .delete_api_key(id, auth.user_id)
        .await
        .map_err(|_err| StatusCode::INTERNAL_SERVER_ERROR)?;
    if deleted {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
```

- [ ] **Step 4: Register the routes**

In `admin_router`, after the `doh-tokens` routes (~line 112), add:
```rust
        .route("/api/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api/api-keys/{id}", delete(delete_api_key))
```

- [ ] **Step 5: Run the endpoint test — should pass**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run api_key_lifecycle_over_http
```
Expected: PASS.

- [ ] **Step 6: Format, lint, commit**

```bash
cd /Users/henry/Develop/claude/noadd && cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/admin/api.rs tests/api_key_auth.rs
git commit -S -m "feat(api): API-key management endpoints (list/create/revoke)"
```

---

### Task 6: OpenAPI document + Scalar docs endpoint

**Files:**
- Modify: `src/admin/api.rs` (annotate core handlers; add `ApiDoc`; register `/api/docs` + `/api/openapi.json`)
- Modify: `src/db.rs` (derive `ToSchema` on rows used in documented responses)
- Modify: `src/admin/stats.rs` (derive `ToSchema` on `Summary`)

**Interfaces:**
- Consumes: all annotated handlers + their request/response types.
- Produces: `GET /api/openapi.json` (the spec), `GET /api/docs` (Scalar UI), a `Bearer` security scheme named `api_key`.

Core subset to annotate (method — path — handler):
- GET `/api/health` — `health`
- GET `/api/server-info` — `get_server_info`
- GET `/api/settings` — `get_settings`; PUT `/api/settings` — `put_settings`
- GET `/api/lists` — `get_lists`; POST `/api/lists` — `add_list`; PUT `/api/lists/{id}` — `update_list`; DELETE `/api/lists/{id}` — `delete_list`
- GET `/api/rules` — `get_rules`; POST `/api/rules` — `add_rule`; DELETE `/api/rules/{id}` — `delete_rule`
- POST `/api/filter/check` — `filter_check`
- GET `/api/stats/summary` — `get_stats_summary`
- GET `/api/api-keys` — `list_api_keys`; POST `/api/api-keys` — `create_api_key`; DELETE `/api/api-keys/{id}` — `delete_api_key`

- [ ] **Step 1: Write the failing spec test**

Add a `#[cfg(test)] mod openapi_tests` at the end of `src/admin/api.rs`:
```rust
#[cfg(test)]
mod openapi_tests {
    use super::*;
    use utoipa::OpenApi;

    #[test]
    fn openapi_spec_covers_core_paths_and_bearer_scheme() {
        let doc = ApiDoc::openapi();
        let json = serde_json::to_value(&doc).unwrap();
        let paths = json["paths"].as_object().unwrap();
        for p in [
            "/api/health",
            "/api/rules",
            "/api/lists",
            "/api/filter/check",
            "/api/stats/summary",
            "/api/api-keys",
        ] {
            assert!(paths.contains_key(p), "spec missing path {p}");
        }
        // Bearer security scheme registered.
        let schemes = &json["components"]["securitySchemes"];
        assert!(schemes.get("api_key").is_some(), "missing api_key security scheme");
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run openapi_spec_covers_core_paths_and_bearer_scheme
```
Expected: FAIL to compile (`ApiDoc` not defined).

- [ ] **Step 3: Derive `ToSchema` on the documented data types**

- In `src/admin/api.rs`, add `utoipa::ToSchema` to the derive list of: `ServerInfo`, `HealthResponse`, `SettingsMap`, `AddListRequest`, `AddRuleRequest`, `AddRuleResponse`, `FilterCheckRequest`, `CreateApiKeyRequest`, `CreateApiKeyResponse`. Example:
  ```rust
  #[derive(Serialize, utoipa::ToSchema)]
  pub struct HealthResponse { /* … */ }
  ```
  Make `FilterCheckRequest` `pub` if utoipa requires it for schema visibility (it is currently private — change `struct FilterCheckRequest` to `pub struct`).
- In `src/db.rs`, add `utoipa::ToSchema` to `CustomRuleRow`, `FilterListRow`, and `ApiKeyRow`.
- In `src/admin/stats.rs`, add `utoipa::ToSchema` to `Summary`.

For handlers returning `Json<serde_json::Value>` (`filter_check`), document the response as a free-form object using `body = serde_json::Value` in the `#[utoipa::path]` responses (utoipa maps it to an open object). Do not invent a typed schema for it.

- [ ] **Step 4: Annotate the handlers**

Add a `#[utoipa::path(...)]` attribute above each core handler. Representative forms — apply the matching shape to every handler in the subset list above:

GET, no body:
```rust
#[utoipa::path(
    get, path = "/api/health", tag = "system",
    responses((status = 200, description = "Service health", body = HealthResponse))
)]
async fn health(/* … unchanged … */) { /* … */ }
```
GET returning a list:
```rust
#[utoipa::path(
    get, path = "/api/rules", tag = "rules",
    security(("api_key" = [])),
    responses((status = 200, description = "All custom rules", body = [crate::db::CustomRuleRow]))
)]
async fn get_rules(/* … */) { /* … */ }
```
POST with body:
```rust
#[utoipa::path(
    post, path = "/api/rules", tag = "rules",
    security(("api_key" = [])),
    request_body = AddRuleRequest,
    responses(
        (status = 201, description = "Rule created", body = AddRuleResponse),
        (status = 400, description = "Unparseable rule")
    )
)]
async fn add_rule(/* … */) { /* … */ }
```
DELETE with path param:
```rust
#[utoipa::path(
    delete, path = "/api/rules/{id}", tag = "rules",
    security(("api_key" = [])),
    params(("id" = i64, Path, description = "Rule id")),
    responses((status = 200, description = "Deleted"))
)]
async fn delete_rule(/* … */) { /* … */ }
```
Apply analogously: `get_server_info` (tag `system`), `get_settings`/`put_settings` (tag `settings`, PUT has `request_body = SettingsMap`), `get_lists`/`add_list`/`update_list`/`delete_list` (tag `lists`), `filter_check` (tag `filter`, `request_body = FilterCheckRequest`, `body = serde_json::Value`), `get_stats_summary` (tag `stats`, `body = crate::admin::stats::Summary`), `list_api_keys`/`create_api_key`/`delete_api_key` (tag `api-keys`). Every guarded endpoint gets `security(("api_key" = []))`; `health` does not.

- [ ] **Step 5: Define `ApiDoc` with the bearer security scheme**

Near the top of `src/admin/api.rs` (after the imports), add:
```rust
#[derive(utoipa::OpenApi)]
#[openapi(
    info(title = "noadd API", description = "Programmatic access to noadd."),
    paths(
        health, get_server_info,
        get_settings, put_settings,
        get_lists, add_list, update_list, delete_list,
        get_rules, add_rule, delete_rule,
        filter_check, get_stats_summary,
        list_api_keys, create_api_key, delete_api_key,
    ),
    components(schemas(
        ServerInfo, HealthResponse, SettingsMap,
        AddListRequest, AddRuleRequest, AddRuleResponse,
        FilterCheckRequest, CreateApiKeyRequest, CreateApiKeyResponse,
        crate::db::CustomRuleRow, crate::db::FilterListRow, crate::db::ApiKeyRow,
        crate::admin::stats::Summary,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "system"), (name = "settings"), (name = "lists"),
        (name = "rules"), (name = "filter"), (name = "stats"), (name = "api-keys"),
    )
)]
struct ApiDoc;

struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "api_key",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some("noadd API key: `Authorization: Bearer noadd_…`"))
                    .build(),
            ),
        );
    }
}
```

- [ ] **Step 6: Run the spec test — should pass**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run openapi_spec_covers_core_paths_and_bearer_scheme
```
Expected: PASS. If utoipa reports a missing schema for a documented `body`, add that type to `components(schemas(...))`.

- [ ] **Step 7: Serve the spec + Scalar UI**

In `src/admin/api.rs`, add the import near the top:
```rust
use utoipa_scalar::{Scalar, Servable};
```
Add a small handler:
```rust
async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    use utoipa::OpenApi;
    Json(ApiDoc::openapi())
}
```
In `admin_router`, register the JSON route with the others and merge the Scalar UI before `.fallback(serve_static)`:
```rust
        .route("/api/openapi.json", get(openapi_json))
        .merge(Scalar::with_url("/api/docs", ApiDoc::openapi()))
```
If the `.merge(...)` fails to typecheck against `Router<AppState>`, wrap via `Router::from(Scalar::with_url(...))` per `utoipa-scalar`'s axum docs; the `Servable` import provides the conversion.

- [ ] **Step 8: Write a failing test for the served endpoints, then confirm it passes**

Append to `tests/api_key_auth.rs`:
```rust
#[tokio::test]
async fn docs_endpoints_are_public() {
    let (app, _db) = build_app().await;
    for uri in ["/api/openapi.json", "/api/docs"] {
        let res = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{uri} should be public 200");
    }
}
```
Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run docs_endpoints_are_public
```
Expected: PASS (no auth header, still 200).

- [ ] **Step 9: Full suite, lint, format, commit**

```bash
cd /Users/henry/Develop/claude/noadd && cargo nextest run && cargo clippy --all-targets -- -D warnings && cargo fmt
git add src/admin/api.rs src/db.rs src/admin/stats.rs tests/api_key_auth.rs
git commit -S -m "feat(api): OpenAPI spec + Scalar docs for the core programmatic subset"
```

---

### Task 7: Admin UI — API Keys card on the Account page

**Files:**
- Modify: `admin-ui/dist/index.html`
- Regenerate: `docs/screenshots/` (via e2e)

**Interfaces:**
- Consumes: `GET/POST/DELETE /api/api-keys`.

- [ ] **Step 1: Locate the DoH Tokens UI to mirror**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && grep -n 'doh-tokens\|Account\|API Keys\|api-keys' admin-ui/dist/index.html | head
```
Use the DoH-tokens card and the Account page structure as the template.

- [ ] **Step 2: Add an "API Keys" card to the Account page**

In `admin-ui/dist/index.html`, add a card under the Account page mirroring the DoH-tokens card, reusing existing classes (`card`, `card-title`, `input-row`, `table-wrap`, `btn`/`btn-primary`/`btn-danger`/`btn-sm`, `.mono`):
- A table with columns: name / prefix (`.mono`) / created / last used / expires / revoke.
- A "Create API Key" form: a `name` text input (and an optional expiry input; leave blank = never).
- Fetch logic mirroring the DoH-tokens card:
  - Load: `fetch('/api/api-keys').then(r => r.json())` → render rows using `prefix`, `created_at`, `last_used_at`, `expires_at` (format timestamps with the file's existing date helper; show `—` for null `last_used_at`, `never` for null `expires_at`).
  - Create: `fetch('/api/api-keys', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({name, expires_at})})`. On success, show the returned `token` **once** in a copy-to-clipboard callout with a clear "you won't see this again" warning; re-list on dismiss.
  - Revoke: `fetch('/api/api-keys/' + id, {method:'DELETE'})` then re-list.
- Add a small link near the card: `<a href="/api/docs">Interactive API reference</a>`.

- [ ] **Step 3: Rebuild the binary to re-embed the UI**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo build
```
Expected: builds; the edited HTML is re-embedded via `include_dir!`.

- [ ] **Step 4: Manual smoke check**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && RUST_LOG=noadd=debug cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:3000
```
In a browser: complete setup/login, open the Account page, create a key (confirm the one-time reveal + copy), see it listed by prefix, revoke it. Then `curl -H "Authorization: Bearer <token>" http://127.0.0.1:3000/api/rules` returns `200`. Stop the server.

- [ ] **Step 5: Regenerate screenshots**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo build
cd e2e && npm ci && npx playwright install chromium && npm run screenshots
```
Expected: `docs/screenshots/` updated (Account page now shows the API Keys card).

- [ ] **Step 6: Commit**

```bash
cd /Users/henry/Develop/claude/noadd
git add admin-ui/dist/index.html docs/screenshots
git commit -S -m "feat(ui): API Keys management card on the Account page"
```

---

### Task 8: Documentation

**Files:**
- Modify: `ARCHITECTURE.md`, `README.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Update `ARCHITECTURE.md`**

- Add `api_keys` to the storage/table list in the storage section.
- In the admin/auth description, note the dual auth model: browser `session` cookie **or** `Authorization: Bearer` API key, unified by the `AuthedUser` extractor; keys are BLAKE2b-hashed at rest and inherit their operator's permissions.
- Mention the `/api/docs` (Scalar) + `/api/openapi.json` endpoints.

- [ ] **Step 2: Add a "Programmatic API" section to `README.md`**

Include: how to mint a key (Account page), the header form, an example call, and the docs link. Concretely:
````markdown
## Programmatic API

Every `/api/*` endpoint accepts an **API key** in addition to the browser
session. Create one on the **Account** page (the full token is shown once — copy
it then). A key inherits its operator's permissions.

```bash
curl -H "Authorization: Bearer noadd_XXXXXXXX…" \
     https://noadd.example.com/api/rules
```

Interactive reference (OpenAPI / Scalar): open **`/api/docs`** on your instance;
the raw spec is at **`/api/openapi.json`**.
````

- [ ] **Step 3: Commit**

```bash
cd /Users/henry/Develop/claude/noadd
git add ARCHITECTURE.md README.md
git commit -S -m "docs: document API-key auth and the OpenAPI/Scalar reference"
```

---

## Final verification

- [ ] **Full gate**

Run:
```bash
cd /Users/henry/Develop/claude/noadd && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo nextest run && cargo deny check
```
Expected: all green.

- [ ] **Open the PR (only when the user asks)** — do not open automatically; per project rules, PRs and merges require explicit user confirmation.
