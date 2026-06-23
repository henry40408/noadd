# Multi-user Admin Accounts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace noadd's single password-only admin login with multiple named operator accounts, each with an independent, manageable session.

**Architecture:** Add `users` and `sessions` tables (schema v5→v6). Login becomes username+password; the in-memory `SessionStore` maps a token to a `SessionInfo` carrying `user_id`. New REST endpoints provide operator CRUD, change-own-password, and session listing/revocation. The single-file admin UI gains a username field on login/setup and a new "Account" page. On upgrade the old credential is dropped so the instance re-runs first-boot setup (no default account); all other data is preserved.

**Tech Stack:** Rust 2024, axum, tokio-rusqlite (SQLite), argon2, arc-swap; vanilla-JS web components for the UI.

## Global Constraints

- Branch `feat/multi-user-accounts` is already checked out; do not branch again.
- Tests run with `cargo nextest run` (never `cargo test`).
- `cargo fmt` before every commit; `cargo clippy -- -D warnings` must pass.
- All commits GPG-signed (default config); end every commit message with:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- Stage files explicitly by name. Never `git add -A` / `git add .`.
- Keep Argon2 for password hashing (do NOT switch to bcrypt).
- `MIN_PASSWORD_LENGTH` is 8 (already defined in `src/admin/api.rs`).
- Username rules: trimmed, non-empty, ≤64 chars, unique.
- Tokens are NEVER returned to the client in any response body.
- All new endpoints require auth except none (they are all behind `require_auth`); `setup`/`login`/`health` remain public.

---

### Task 1: Users table + DB CRUD + migration v6

**Files:**
- Modify: `src/db.rs` (schema CREATE block ~248-296; `run_migrations` ~311-357; add CRUD methods near the DoH token methods ~820-860; add unit test in `#[cfg(test)] mod tests` ~1520)
- Test: `tests/db_test.rs`

**Interfaces:**
- Produces:
  - `pub struct UserRow { pub id: i64, pub username: String, pub created_at: i64 }` (derive `Debug, Clone, Serialize`)
  - `pub struct UserAuth { pub id: i64, pub password_hash: String }` (derive `Debug, Clone`)
  - `Database::create_user(&self, username: &str, password_hash: &str, created_at: i64) -> Result<i64, DbError>`
  - `Database::get_user_auth(&self, username: &str) -> Result<Option<UserAuth>, DbError>`
  - `Database::get_user_password_hash(&self, id: i64) -> Result<Option<String>, DbError>`
  - `Database::update_user_password(&self, id: i64, password_hash: &str) -> Result<(), DbError>`
  - `Database::list_users(&self) -> Result<Vec<UserRow>, DbError>`
  - `Database::count_users(&self) -> Result<i64, DbError>`
  - `Database::delete_user(&self, id: i64) -> Result<(), DbError>`
  - `Database::get_username(&self, id: i64) -> Result<Option<String>, DbError>`

- [ ] **Step 1: Add the `users` table to the fresh-schema block**

In the `conn.execute_batch("... CREATE TABLE IF NOT EXISTS doh_tokens (...);")` block (ends ~294), append before the closing `");`:

```sql

                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        created_at INTEGER NOT NULL
                    );
```

- [ ] **Step 2: Add migration v6 (users + sessions tables, drop old credential)**

In `run_migrations`, after the `if version < 5 { ... }` block and before `const LATEST_VERSION`, add:

```rust
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
```

Then change `const LATEST_VERSION: i64 = 5;` to `const LATEST_VERSION: i64 = 6;`.

(The `sessions` table is created here too so Task 2 only adds CRUD. `PRAGMA foreign_keys = ON` is already set at open time, so `ON DELETE CASCADE` is active.)

- [ ] **Step 3: Add the row structs and CRUD methods**

Add the structs near `DohTokenRow` (~73):

```rust
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
```

Add the methods inside `impl Database` (place after the DoH token methods, ~860):

```rust
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
                let mut stmt = conn
                    .prepare_cached("SELECT id, password_hash FROM users WHERE username = ?1")?;
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

    pub async fn update_user_password(
        &self,
        id: i64,
        password_hash: &str,
    ) -> Result<(), DbError> {
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
                let mut stmt = conn.prepare_cached(
                    "SELECT id, username, created_at FROM users ORDER BY id",
                )?;
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

    pub async fn delete_user(&self, id: i64) -> Result<(), DbError> {
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
                Ok(())
            })
            .await?;
        Ok(())
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
```

- [ ] **Step 4: Write integration tests for users CRUD**

Append to `tests/db_test.rs`:

```rust
#[tokio::test]
async fn test_users_crud() {
    let db = test_db().await;
    assert_eq!(db.count_users().await.unwrap(), 0);

    let id = db.create_user("alice", "hash-a", 1000).await.unwrap();
    assert_eq!(db.count_users().await.unwrap(), 1);

    let auth = db.get_user_auth("alice").await.unwrap().unwrap();
    assert_eq!(auth.id, id);
    assert_eq!(auth.password_hash, "hash-a");
    assert!(db.get_user_auth("nobody").await.unwrap().is_none());

    assert_eq!(db.get_username(id).await.unwrap().as_deref(), Some("alice"));

    db.update_user_password(id, "hash-b").await.unwrap();
    assert_eq!(
        db.get_user_password_hash(id).await.unwrap().as_deref(),
        Some("hash-b")
    );

    let users = db.list_users().await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "alice");

    db.delete_user(id).await.unwrap();
    assert_eq!(db.count_users().await.unwrap(), 0);
}

#[tokio::test]
async fn test_duplicate_username_rejected() {
    let db = test_db().await;
    db.create_user("bob", "h", 1).await.unwrap();
    assert!(db.create_user("bob", "h2", 2).await.is_err());
}
```

- [ ] **Step 5: Write the v5→v6 migration unit test**

Add to `src/db.rs` `#[cfg(test)] mod tests` (mirrors `migration_replaces_legacy_domain_index`):

```rust
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
        assert!(db.get_setting("admin_password_hash").await.unwrap().is_none());
        assert!(db.get_setting("sessions").await.unwrap().is_none());
        // Unrelated data preserved.
        assert_eq!(
            db.get_setting("log_retention_days").await.unwrap().as_deref(),
            Some("14")
        );
        // New tables exist and are empty.
        let tables = db.list_tables().await.unwrap();
        assert!(tables.contains(&"users".to_string()));
        assert!(tables.contains(&"sessions".to_string()));
        assert_eq!(db.count_users().await.unwrap(), 0);
    }
```

- [ ] **Step 6: Run tests**

Run: `cargo nextest run -E 'test(test_users_crud) | test(test_duplicate_username_rejected) | test(migration_v6_drops_credential_and_adds_tables)'`
Expected: 3 passed. (Run after Step 7 fmt if needed.)

- [ ] **Step 7: fmt, clippy, commit**

```bash
cargo fmt
cargo clippy -- -D warnings
git add src/db.rs tests/db_test.rs
git commit -m "feat(db): add users table, CRUD, and v6 migration"
```

---

### Task 2: Sessions table DB CRUD

**Files:**
- Modify: `src/db.rs` (add structs near `UserRow`; methods after the users methods)
- Test: `tests/db_test.rs`

**Interfaces:**
- Consumes: `users` table (Task 1), `sessions` table (created in Task 1 migration).
- Produces:
  - `pub struct SessionRow { pub id: i64, pub user_id: i64, pub username: String, pub created_at: i64, pub last_seen: i64, pub ip: Option<String>, pub user_agent: Option<String>, pub token: String }` (derive `Debug, Clone`; **NOT** `Serialize` — `token` must never leak)
  - `pub struct LoadedSession { pub token: String, pub id: i64, pub user_id: i64, pub created_at: i64, pub last_seen: i64 }` (derive `Debug, Clone`)
  - `Database::insert_session(&self, token: &str, user_id: i64, created_at: i64, last_seen: i64, ip: Option<&str>, user_agent: Option<&str>) -> Result<i64, DbError>`
  - `Database::delete_session_by_token(&self, token: &str) -> Result<(), DbError>`
  - `Database::delete_session_by_id(&self, id: i64) -> Result<Option<String>, DbError>` (returns the deleted token, so the caller can evict it from the in-memory store)
  - `Database::delete_all_sessions(&self) -> Result<(), DbError>`
  - `Database::list_sessions(&self) -> Result<Vec<SessionRow>, DbError>`
  - `Database::load_sessions(&self, max_age_secs: i64, now: i64) -> Result<Vec<LoadedSession>, DbError>` (also deletes expired rows)
  - `Database::flush_sessions_last_seen(&self, entries: &[(String, i64)]) -> Result<(), DbError>`

- [ ] **Step 1: Add the structs**

```rust
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
```

- [ ] **Step 2: Add the session methods**

```rust
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
                let tok: Option<String> = conn
                    .query_row(
                        "SELECT token FROM sessions WHERE id = ?1",
                        params![id],
                        |row| row.get(0),
                    )
                    .optional()?;
                if tok.is_some() {
                    conn.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
                }
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
                conn.execute("DELETE FROM sessions WHERE created_at < ?1", params![cutoff])?;
                let mut stmt = conn.prepare(
                    "SELECT token, id, user_id, created_at, last_seen FROM sessions",
                )?;
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

    pub async fn flush_sessions_last_seen(
        &self,
        entries: &[(String, i64)],
    ) -> Result<(), DbError> {
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
```

- [ ] **Step 3: Write sessions tests (incl. cascade)**

Append to `tests/db_test.rs`:

```rust
#[tokio::test]
async fn test_sessions_crud_and_cascade() {
    let db = test_db().await;
    let uid = db.create_user("carol", "h", 100).await.unwrap();

    let sid = db
        .insert_session("tok-1", uid, 100, 100, Some("1.2.3.4"), Some("UA"))
        .await
        .unwrap();

    let list = db.list_sessions().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].username, "carol");
    assert_eq!(list[0].token, "tok-1");
    assert_eq!(list[0].ip.as_deref(), Some("1.2.3.4"));

    // delete_session_by_id returns the token for in-memory eviction
    assert_eq!(
        db.delete_session_by_id(sid).await.unwrap().as_deref(),
        Some("tok-1")
    );
    assert!(db.list_sessions().await.unwrap().is_empty());
    assert!(db.delete_session_by_id(sid).await.unwrap().is_none());

    // Deleting the user cascades to their sessions.
    db.insert_session("tok-2", uid, 100, 100, None, None)
        .await
        .unwrap();
    db.delete_user(uid).await.unwrap();
    assert!(db.list_sessions().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_load_sessions_drops_expired() {
    let db = test_db().await;
    let uid = db.create_user("dave", "h", 0).await.unwrap();
    db.insert_session("fresh", uid, 1_000, 1_000, None, None)
        .await
        .unwrap();
    db.insert_session("stale", uid, 1, 1, None, None)
        .await
        .unwrap();

    // max_age 100, now 1100 → cutoff 1000; "stale" (created_at 1) is purged.
    let loaded = db.load_sessions(100, 1_100).await.unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].token, "fresh");
    assert!(db.list_sessions().await.unwrap().iter().all(|s| s.token == "fresh"));
}

#[tokio::test]
async fn test_flush_last_seen() {
    let db = test_db().await;
    let uid = db.create_user("erin", "h", 0).await.unwrap();
    db.insert_session("tok", uid, 0, 0, None, None).await.unwrap();
    db.flush_sessions_last_seen(&[("tok".to_string(), 555)])
        .await
        .unwrap();
    assert_eq!(db.list_sessions().await.unwrap()[0].last_seen, 555);
}
```

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -E 'test(test_sessions_crud_and_cascade) | test(test_load_sessions_drops_expired) | test(test_flush_last_seen)'`
Expected: 3 passed.

- [ ] **Step 5: fmt, clippy, commit**

```bash
cargo fmt
cargo clippy -- -D warnings
git add src/db.rs tests/db_test.rs
git commit -m "feat(db): add sessions table CRUD with user cascade"
```

---

### Task 3: Rework the in-memory session store (`auth.rs`)

**Files:**
- Modify: `src/admin/auth.rs`
- Test: `tests/admin_auth_test.rs` (rewrite session tests)

**Interfaces:**
- Consumes: `Database::{insert_session, delete_all_sessions, load_sessions, flush_sessions_last_seen}` (Task 2).
- Produces:
  - `pub struct SessionInfo { pub session_id: i64, pub user_id: i64, pub created_at: i64, pub last_seen: i64 }` (derive `Debug, Clone, Copy`)
  - `pub type SessionStore = Arc<Mutex<HashMap<String, SessionInfo>>>`
  - `pub fn new_session_store() -> SessionStore`
  - `pub fn generate_token() -> String` (64-char alphanumeric)
  - `pub fn store_session(store: &SessionStore, token: &str, info: SessionInfo)`
  - `pub fn validate_session(store: &SessionStore, token: &str) -> Option<i64>` (returns `user_id`; refreshes `last_seen` to now; drops expired)
  - `pub fn revoke_session(store: &SessionStore, token: &str)` (unchanged signature)
  - `pub async fn revoke_all_sessions(store: &SessionStore, db: &Database) -> Result<(), DbError>`
  - `pub async fn load_sessions_from_db(store: &SessionStore, db: &Database) -> Result<(), DbError>`
  - `pub async fn flush_last_seen(store: &SessionStore, db: &Database) -> Result<(), DbError>`
- Removed: `save_sessions_to_db` (replaced by direct table writes); `create_session` (replaced by `generate_token` + `store_session`).

- [ ] **Step 1: Replace the type + store helpers**

Replace the `SessionStore` type alias and `new_session_store` with:

```rust
/// In-memory session metadata. Persisted to the `sessions` table on creation
/// and revocation; `last_seen` is flushed periodically (see `flush_last_seen`).
#[derive(Debug, Clone, Copy)]
pub struct SessionInfo {
    pub session_id: i64,
    pub user_id: i64,
    pub created_at: i64,
    pub last_seen: i64,
}

/// Thread-safe session store. Maps token -> session metadata.
pub type SessionStore = Arc<Mutex<HashMap<String, SessionInfo>>>;

/// Create a new, empty session store.
pub fn new_session_store() -> SessionStore {
    Arc::new(Mutex::new(HashMap::new()))
}
```

- [ ] **Step 2: Replace token creation + validation**

Remove `create_session` and replace `validate_session` (and add `generate_token`/`store_session`):

```rust
/// Generate a fresh 64-character alphanumeric session token.
pub fn generate_token() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

/// Record a session in the in-memory store.
pub fn store_session(store: &SessionStore, token: &str, info: SessionInfo) {
    store.lock().insert(token.to_string(), info);
}

/// Validate a token. Returns the owning `user_id` and refreshes `last_seen`,
/// or `None` if missing/expired (expired entries are dropped).
pub fn validate_session(store: &SessionStore, token: &str) -> Option<i64> {
    let now = now_secs();
    let mut map = store.lock();
    if let Some(info) = map.get_mut(token) {
        if now - info.created_at < SESSION_MAX_AGE_SECS {
            info.last_seen = now;
            return Some(info.user_id);
        }
        map.remove(token);
    }
    None
}
```

- [ ] **Step 3: Replace persistence helpers**

Replace `load_sessions_from_db`, `save_sessions_to_db`, and `revoke_all_sessions` with:

```rust
/// Load persisted sessions from the `sessions` table into the store.
/// Expired rows are purged by `Database::load_sessions`.
pub async fn load_sessions_from_db(
    store: &SessionStore,
    db: &crate::db::Database,
) -> Result<(), crate::db::DbError> {
    let now = now_secs();
    let loaded = db.load_sessions(SESSION_MAX_AGE_SECS, now).await?;
    let mut map = store.lock();
    for s in loaded {
        map.insert(
            s.token,
            SessionInfo {
                session_id: s.id,
                user_id: s.user_id,
                created_at: s.created_at,
                last_seen: s.last_seen,
            },
        );
    }
    Ok(())
}

/// Flush in-memory `last_seen` values to the database.
pub async fn flush_last_seen(
    store: &SessionStore,
    db: &crate::db::Database,
) -> Result<(), crate::db::DbError> {
    let entries: Vec<(String, i64)> = store
        .lock()
        .iter()
        .map(|(token, info)| (token.clone(), info.last_seen))
        .collect();
    db.flush_sessions_last_seen(&entries).await
}

/// Revoke all sessions (logout everywhere): clear the store and the table.
pub async fn revoke_all_sessions(
    store: &SessionStore,
    db: &crate::db::Database,
) -> Result<(), crate::db::DbError> {
    store.lock().clear();
    db.delete_all_sessions().await
}
```

Keep `revoke_session` as-is (it already just removes the token from the store).

- [ ] **Step 4: Rewrite the affected auth unit tests**

In `tests/admin_auth_test.rs`, update the import line and replace `test_session_create_and_validate` and `test_revoke_session_removes_only_that_token`:

```rust
use noadd::admin::auth::{
    RateLimiter, SessionInfo, generate_token, hash_password, new_session_store, revoke_session,
    store_session, validate_session, verify_password,
};

fn info(user_id: i64) -> SessionInfo {
    SessionInfo { session_id: 1, user_id, created_at: noadd::now_unix(), last_seen: noadd::now_unix() }
}

#[test]
fn test_session_create_and_validate() {
    let store = new_session_store();
    let token = generate_token();
    assert_eq!(token.len(), 64);
    assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));

    store_session(&store, &token, info(42));
    assert_eq!(validate_session(&store, &token), Some(42));
    assert_eq!(validate_session(&store, "nope"), None);
}

#[test]
fn test_revoke_session_removes_only_that_token() {
    let store = new_session_store();
    let t1 = generate_token();
    let t2 = generate_token();
    store_session(&store, &t1, info(1));
    store_session(&store, &t2, info(2));
    revoke_session(&store, &t1);
    assert_eq!(validate_session(&store, &t1), None);
    assert_eq!(validate_session(&store, &t2), Some(2));
}
```

(Leave `test_password_hash_and_verify` and any rate-limiter tests untouched.)

- [ ] **Step 5: Build (call sites will break — expected) and run auth tests**

Run: `cargo nextest run -E 'test(test_session_create_and_validate) | test(test_revoke_session_removes_only_that_token) | test(test_password_hash_and_verify)' --no-fail-fast`
Expected: these 3 pass. The crate may still fail to compile until Task 4 updates `api.rs`/`main.rs` call sites — if so, proceed to Task 4 and run this then. Note in the commit that compilation completes in Task 4.

- [ ] **Step 6: fmt + commit (no clippy gate yet — crate compiles after Task 4)**

```bash
cargo fmt
git add src/admin/auth.rs tests/admin_auth_test.rs
git commit -m "feat(auth): session store carries user_id, persisted via sessions table"
```

---

### Task 4: Auth flow — setup, login, needs_setup, auth helpers (`api.rs`, `main.rs`)

**Files:**
- Modify: `src/admin/api.rs` (`login`, `setup`, `health`, `require_auth`, add `current_session`, `revoke_all`, `logout`)
- Modify: `src/main.rs` (periodic `last_seen` flush task)
- Modify: `tests/admin_api_test.rs` and `tests/stats_api_test.rs` (`build_app` helpers)
- Test: `tests/admin_api_test.rs`

**Interfaces:**
- Consumes: Task 1 (`create_user`, `get_user_auth`, `count_users`), Task 3 (`generate_token`, `store_session`, `validate_session`, `SessionInfo`).
- Produces:
  - `LoginRequest { username: String, password: String }`, `SetupRequest { username: String, password: String }`
  - `fn current_session(state: &AppState, jar: &CookieJar) -> Result<(i64, String), StatusCode>` (returns `(user_id, token)`)
  - `require_auth` unchanged signature: `Result<(), StatusCode>` (now implemented via `current_session`)

- [ ] **Step 1: Update imports + `require_auth` + add `current_session`**

In `src/admin/api.rs`, update the auth import (~21) to:

```rust
use crate::admin::auth::{
    RateLimiter, SessionInfo, SessionStore, generate_token, hash_password, store_session,
    validate_session, verify_password,
};
```

Replace `require_auth` (~254) with:

```rust
/// Returns `(user_id, token)` for the current authenticated session, or 401.
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

fn require_auth(state: &AppState, jar: &CookieJar) -> Result<(), StatusCode> {
    current_session(state, jar).map(|_| ())
}
```

- [ ] **Step 2: Rewrite `login` to take username + password and bind a session**

Replace `LoginRequest` and the `login` handler:

```rust
#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

async fn login(
    State(state): State<AppState>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), StatusCode> {
    let ip = client_ip(&state, connect.as_deref(), &headers);
    if !state.rate_limiter.check(ip) {
        tracing::warn!(%ip, "login rate limited");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    state.rate_limiter.record(ip);

    // Generic 401 whether the username is unknown or the password is wrong.
    let auth = state
        .db
        .get_user_auth(body.username.trim())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let valid = verify_password(&body.password, &auth.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !valid {
        tracing::warn!("login failed: invalid credentials");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let now = crate::now_unix();
    let token = generate_token();
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let session_id = state
        .db
        .insert_session(&token, auth.id, now, now, Some(&ip.to_string()), user_agent)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    store_session(
        &state.sessions,
        &token,
        SessionInfo { session_id, user_id: auth.id, created_at: now, last_seen: now },
    );
    tracing::info!(user_id = auth.id, "login successful");

    let cookie = Cookie::build(("session", token))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .max_age(time::Duration::seconds(crate::admin::auth::SESSION_MAX_AGE_SECS))
        .build();

    Ok((jar.add(cookie), Json(LoginResponse { success: true })))
}
```

- [ ] **Step 3: Rewrite `setup` to create the first operator**

Replace `SetupRequest` and the `setup` handler body. New struct:

```rust
#[derive(Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
}
```

Replace the `setup` handler with (validates username, gates on zero users):

```rust
async fn setup(
    State(state): State<AppState>,
    Json(body): Json<SetupRequest>,
) -> Result<Json<SetupResponse>, (StatusCode, Json<SetupErrorResponse>)> {
    let count = state.db.count_users().await.map_err(|_| setup_ise())?;
    if count > 0 {
        return Err((
            StatusCode::CONFLICT,
            Json(SetupErrorResponse { error: "already configured".to_string() }),
        ));
    }
    let username = body.username.trim();
    if username.is_empty() || username.chars().count() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(SetupErrorResponse { error: "invalid username".to_string() }),
        ));
    }
    if body.password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(SetupErrorResponse {
                error: format!("password must be at least {MIN_PASSWORD_LENGTH} characters"),
            }),
        ));
    }
    let hash = hash_password(&body.password).map_err(|_| setup_ise())?;
    state
        .db
        .create_user(username, &hash, crate::now_unix())
        .await
        .map_err(|_| setup_ise())?;
    Ok(Json(SetupResponse { success: true }))
}
```

- [ ] **Step 4: Update `health` needs_setup + `revoke_all`/`logout`**

In `health`, replace the `needs_setup` computation:

```rust
    let needs_setup = state
        .db
        .count_users()
        .await
        .map(|n| n == 0)
        .unwrap_or(false);
```

In `revoke_all`, the body already calls `revoke_all_sessions` — no change needed (its signature is unchanged).

In `logout`, replace the `save_sessions_to_db` call with a table delete:

```rust
    if let Some(c) = jar.get("session") {
        let token = c.value().to_string();
        crate::admin::auth::revoke_session(&state.sessions, &token);
        let _ = state.db.delete_session_by_token(&token).await;
    }
```

- [ ] **Step 5: Wire the periodic last_seen flush + startup load in `main.rs`**

`load_sessions_from_db(&session_store, &db)` (line ~155) keeps the same signature — no change. After the `admin_router(AppState { ... })` is built and `session_store` is moved in, we need the store handle for the flush task. Capture a clone BEFORE moving it into `AppState`:

Change line ~154-164 so a clone is kept:

```rust
    let session_store = new_session_store();
    load_sessions_from_db(&session_store, &db).await?;
    let session_store_for_flush = session_store.clone();
    let db_for_flush = db.clone();
    // ... rate_limiter / server_info ...
    let admin_routes = admin_router(AppState {
        db: db.clone(),
        sessions: session_store,
        // ... rest unchanged ...
    });

    // Periodically persist session last_seen so it survives restarts.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.tick().await; // skip immediate fire
        loop {
            tick.tick().await;
            let _ = noadd::admin::auth::flush_last_seen(&session_store_for_flush, &db_for_flush).await;
        }
    });
```

Add the `flush_last_seen` import or reference it fully-qualified as shown.

- [ ] **Step 6: Update test `build_app` helpers**

In `tests/admin_api_test.rs`, update the import and the `set_password` block so an operator + bound session exist:

```rust
use noadd::admin::auth::{RateLimiter, SessionInfo, generate_token, hash_password, new_session_store, store_session};
```

Replace the session/token + password setup inside `build_app` (~50-72):

```rust
    let sessions = new_session_store();
    // ... build filter/cache/etc unchanged ...

    let token = generate_token();
    if set_password {
        let hash = hash_password("admin").unwrap();
        let uid = db.create_user("admin", &hash, noadd::now_unix()).await.unwrap();
        let now = noadd::now_unix();
        let sid = db.insert_session(&token, uid, now, now, None, None).await.unwrap();
        store_session(&sessions, &token, SessionInfo { session_id: sid, user_id: uid, created_at: now, last_seen: now });
    }
```

Apply the same change to `tests/stats_api_test.rs` if it has an equivalent `build_app`/`setup` that sets `admin_password_hash` and `create_session`. (Grep: `rg -n "admin_password_hash|create_session" tests/`.)

- [ ] **Step 7: Update existing auth endpoint tests + add new ones**

In `tests/admin_api_test.rs`, find login/setup tests that post `{ "password": ... }` and update them to `{ "username": "admin", "password": ... }`. Add:

```rust
#[tokio::test]
async fn login_with_wrong_username_is_unauthorized() {
    let (app, _token) = setup().await;
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"ghost","password":"admin"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn setup_creates_first_operator_when_empty() {
    let app = unconfigured_app().await;
    let res = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/setup")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"root","password":"hunter2pass"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
```

- [ ] **Step 8: Build, fmt, clippy, run, commit**

Run: `cargo nextest run -E 'package(noadd) & test(login) | test(setup_creates_first_operator_when_empty)'` then the full auth/api suites.
Expected: PASS. Then:

```bash
cargo fmt
cargo clippy -- -D warnings
git add src/admin/api.rs src/main.rs tests/admin_api_test.rs tests/stats_api_test.rs tests/admin_auth_test.rs
git commit -m "feat(auth): username+password login/setup, session-bound auth, periodic flush"
```

---

### Task 5: Operator management endpoints (`api.rs`)

**Files:**
- Modify: `src/admin/api.rs` (add handlers + routes ~72-120)
- Test: `tests/admin_api_test.rs`

**Interfaces:**
- Consumes: Task 1 (`list_users`, `create_user`, `count_users`, `delete_user`, `get_username`, `get_user_password_hash`, `update_user_password`), Task 2 (`delete_session_by_token` for cascade-evict), `current_session` (Task 4).
- Produces routes: `GET /api/auth/me`, `GET/POST /api/users`, `DELETE /api/users/{id}`, `POST /api/users/me/password`.

- [ ] **Step 1: Add routes**

In `admin_router`, after the auth routes (~75), add:

```rust
        .route("/api/auth/me", get(get_me))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/{id}", delete(delete_user))
        .route("/api/users/me/password", post(change_own_password))
```

- [ ] **Step 2: Add `/api/auth/me`**

```rust
#[derive(Serialize)]
struct MeResponse {
    id: i64,
    username: String,
}

async fn get_me(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<MeResponse>, StatusCode> {
    let (user_id, _token) = current_session(&state, &jar)?;
    let username = state
        .db
        .get_username(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(MeResponse { id: user_id, username }))
}
```

- [ ] **Step 3: Add list/create operators**

```rust
async fn list_users(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<crate::db::UserRow>>, StatusCode> {
    require_auth(&state, &jar)?;
    let users = state
        .db
        .list_users()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(users))
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
}

async fn create_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<CreateUserRequest>,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;
    let username = body.username.trim();
    if username.is_empty() || username.chars().count() > 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if body.password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(StatusCode::BAD_REQUEST);
    }
    let hash = hash_password(&body.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match state.db.create_user(username, &hash, crate::now_unix()).await {
        Ok(_) => Ok(StatusCode::CREATED),
        // UNIQUE violation → duplicate username.
        Err(_) => Err(StatusCode::CONFLICT),
    }
}
```

- [ ] **Step 4: Add delete operator (last-user guard + session cascade-evict)**

```rust
async fn delete_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<StatusCode, StatusCode> {
    require_auth(&state, &jar)?;
    let count = state
        .db
        .count_users()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if count <= 1 {
        return Err(StatusCode::CONFLICT);
    }
    // Evict the deleted operator's sessions from the in-memory store before the
    // DB cascade removes the rows.
    let tokens: Vec<String> = state
        .sessions
        .lock()
        .iter()
        .filter(|(_, info)| info.user_id == id)
        .map(|(t, _)| t.clone())
        .collect();
    for t in &tokens {
        crate::admin::auth::revoke_session(&state.sessions, t);
    }
    state
        .db
        .delete_user(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}
```

(`Path` is already imported for other routes; if not, add `use axum::extract::Path;`.)

- [ ] **Step 5: Add change-own-password**

```rust
#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_own_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<StatusCode, StatusCode> {
    let (user_id, _token) = current_session(&state, &jar)?;
    if body.new_password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(StatusCode::BAD_REQUEST);
    }
    let hash = state
        .db
        .get_user_password_hash(user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let ok = verify_password(&body.current_password, &hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !ok {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let new_hash =
        hash_password(&body.new_password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .db
        .update_user_password(user_id, &new_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}
```

- [ ] **Step 6: Tests**

Append to `tests/admin_api_test.rs` (the authed `token` from `setup()` belongs to user "admin", id 1):

```rust
fn authed(method: &str, uri: &str, token: &str, body: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", format!("session={token}"));
    if body.is_some() {
        b = b.header("content-type", "application/json");
    }
    b.body(body.map(|s| Body::from(s.to_string())).unwrap_or(Body::empty()))
        .unwrap()
}

#[tokio::test]
async fn create_and_list_operators() {
    let (app, token) = setup().await;
    let res = app
        .clone()
        .oneshot(authed("POST", "/api/users", &token, Some(r#"{"username":"bob","password":"longpass1"}"#)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // Duplicate → 409
    let res = app
        .clone()
        .oneshot(authed("POST", "/api/users", &token, Some(r#"{"username":"bob","password":"longpass1"}"#)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cannot_delete_last_operator() {
    let (app, token) = setup().await;
    // Only "admin" (id 1) exists.
    let res = app
        .oneshot(authed("DELETE", "/api/users/1", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn change_own_password_requires_correct_current() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed(
            "POST",
            "/api/users/me/password",
            &token,
            Some(r#"{"current_password":"wrong","new_password":"brandnewpass"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}
```

- [ ] **Step 7: fmt, clippy, run, commit**

Run: `cargo nextest run -E 'test(create_and_list_operators) | test(cannot_delete_last_operator) | test(change_own_password_requires_correct_current)'`
Expected: PASS.

```bash
cargo fmt
cargo clippy -- -D warnings
git add src/admin/api.rs tests/admin_api_test.rs
git commit -m "feat(api): operator CRUD and change-own-password endpoints"
```

---

### Task 6: Session listing + revocation endpoints (`api.rs`)

**Files:**
- Modify: `src/admin/api.rs` (routes + handlers)
- Test: `tests/admin_api_test.rs`

**Interfaces:**
- Consumes: Task 2 (`list_sessions`, `delete_session_by_id`), `current_session` (Task 4).
- Produces routes: `GET /api/sessions`, `DELETE /api/sessions/{id}`.

- [ ] **Step 1: Add routes**

After the users routes:

```rust
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/{id}", delete(revoke_session_by_id))
```

- [ ] **Step 2: Add list sessions (token never serialized; compute is_current)**

```rust
#[derive(Serialize)]
struct SessionResponse {
    id: i64,
    username: String,
    created_at: i64,
    last_seen: i64,
    ip: Option<String>,
    user_agent: Option<String>,
    is_current: bool,
}

async fn list_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<SessionResponse>>, StatusCode> {
    let (_user_id, token) = current_session(&state, &jar)?;
    let rows = state
        .db
        .list_sessions()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Prefer the fresher in-memory last_seen when present.
    let live = state.sessions.lock();
    let out = rows
        .into_iter()
        .map(|r| {
            let last_seen = live.get(&r.token).map(|i| i.last_seen).unwrap_or(r.last_seen);
            SessionResponse {
                id: r.id,
                username: r.username,
                created_at: r.created_at,
                last_seen,
                ip: r.ip,
                user_agent: r.user_agent,
                is_current: r.token == token,
            }
        })
        .collect();
    Ok(Json(out))
}
```

- [ ] **Step 3: Add revoke-by-id (clears cookie if revoking own current session)**

```rust
async fn revoke_session_by_id(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<(CookieJar, StatusCode), StatusCode> {
    let (_user_id, current_token) = current_session(&state, &jar)?;
    let removed = state
        .db
        .delete_session_by_id(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match removed {
        Some(token) => {
            crate::admin::auth::revoke_session(&state.sessions, &token);
            if token == current_token {
                let removal = Cookie::build(("session", "")).path("/").build();
                return Ok((jar.remove(removal), StatusCode::NO_CONTENT));
            }
            Ok((jar, StatusCode::NO_CONTENT))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}
```

- [ ] **Step 4: Tests**

```rust
#[tokio::test]
async fn list_sessions_marks_current_and_hides_token() {
    let (app, token) = setup().await;
    let res = app
        .oneshot(authed("GET", "/api/sessions", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("\"is_current\":true"));
    assert!(!text.contains(&token), "raw token must never appear in the response");
}

#[tokio::test]
async fn revoke_current_session_clears_cookie() {
    let (app, token) = setup().await;
    // The seeded session has id 1.
    let res = app
        .oneshot(authed("DELETE", "/api/sessions/1", &token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let set_cookie = res.headers().get("set-cookie").map(|v| v.to_str().unwrap().to_string());
    assert!(set_cookie.unwrap_or_default().contains("session="));
}
```

- [ ] **Step 5: fmt, clippy, run, commit**

Run: `cargo nextest run -E 'test(list_sessions_marks_current_and_hides_token) | test(revoke_current_session_clears_cookie)'`
Expected: PASS.

```bash
cargo fmt
cargo clippy -- -D warnings
git add src/admin/api.rs tests/admin_api_test.rs
git commit -m "feat(api): list and revoke active sessions"
```

---

### Task 7: Admin UI — username fields + Account page (`admin-ui/dist/index.html`)

**Files:**
- Modify: `admin-ui/dist/index.html`

**Interfaces:**
- Consumes: all Task 4–6 endpoints. Uses existing `api` helper, `setPage`, `AppRouter.on`, `showFormError`, `esc`, `timeAgo`, `icons`.
- Reference mockups (real-CSS, approved): `.superpowers/brainstorm/*/content/account-real-style-v2.html` and `auth-screens.html`.

- [ ] **Step 1: Setup page — add username field**

In `SetupPage` (~1607), change the boot-log line `admin password ........... not set` to `admin account ............ <span class="warn">none</span>`, and add a username `login-line` above the password one:

```html
          <div class="login-line">
            <label for="setup-user">username:</label>
            <input type="text" id="setup-user" data-testid="setup-username" autofocus>
          </div>
```

Remove `autofocus` from `#setup-pw`. In `doSetup`, read username and send it; validate non-empty:

```javascript
      const user = this.querySelector('#setup-user').value.trim();
      if (!user) return showFormError(err, 'Username is required');
      if (!pw.value || pw.value.length < 8) return showFormError(err, 'Password must be at least 8 characters');
      if (pw.value !== pw2.value) return showFormError(err, 'Passwords do not match');
      try {
        await api.post('/api/auth/setup', { username: user, password: pw.value });
        await api.post('/api/auth/login', { username: user, password: pw.value });
```

- [ ] **Step 2: Login page — add username field**

In `LoginPage` (~1662), add above the password `login-line`:

```html
          <div class="login-line">
            <label for="li-user">username:</label>
            <input type="text" id="li-user" data-testid="login-username" autofocus>
          </div>
```

Remove `autofocus` from `#pw`. In `doLogin`, send username:

```javascript
        await api.post('/api/auth/login', { username: this.querySelector('#li-user').value.trim(), password: pw.value });
```

- [ ] **Step 3: Add the `account-page` component**

Add a new web component before `customElements.define('app-shell', ...)`:

```javascript
class AccountPage extends HTMLElement {
  connectedCallback() {
    this.innerHTML = `
      <div class="page-header fade-in"><h2>Account</h2><p>Operator accounts and active sessions</p></div>
      <div class="card fade-in">
        <div class="card-title">This Account</div>
        <p id="acct-whoami" style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:12px">Loading…</p>
        <div class="card-title" style="margin-top:4px">Change Password</div>
        <div class="login-error" id="pw-error" style="display:none"></div>
        <div class="input-row"><input type="password" id="pw-current" placeholder="current password" style="max-width:220px"></div>
        <div class="input-row" style="margin-top:8px"><input type="password" id="pw-new" placeholder="new password (min 8)" style="max-width:220px"></div>
        <div class="input-row" style="margin-top:8px"><input type="password" id="pw-confirm" placeholder="confirm new password" style="max-width:220px"></div>
        <button class="btn btn-primary btn-sm" id="pw-save" style="margin-top:12px">Change Password</button>
      </div>
      <div class="card fade-in" style="animation-delay:0.05s">
        <div class="card-title">Operators</div>
        <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:12px">All operators have full admin access. The last operator cannot be deleted; deleting one revokes all their sessions.</p>
        <div class="table-wrap"><table>
          <thead><tr><th>Username</th><th>Created</th><th></th></tr></thead>
          <tbody id="ops-body"></tbody>
        </table></div>
        <div class="card-title" style="margin-top:16px">Add Operator</div>
        <div class="login-error" id="op-error" style="display:none"></div>
        <div class="input-row"><input type="text" id="op-user" placeholder="username" style="max-width:200px"></div>
        <div class="input-row" style="margin-top:8px"><input type="password" id="op-pw" placeholder="password (min 8)" style="max-width:220px"></div>
        <div class="input-row" style="margin-top:8px"><input type="password" id="op-pw2" placeholder="confirm password" style="max-width:220px"></div>
        <button class="btn btn-primary btn-sm" id="op-add" style="margin-top:12px">Add Operator</button>
      </div>
      <div class="card fade-in" style="animation-delay:0.1s">
        <div class="card-title">Active Sessions</div>
        <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:12px">Tokens are never shown. Any operator can revoke any session. Sessions expire after 7 days.</p>
        <div class="table-wrap"><table>
          <thead><tr><th>Operator</th><th>IP</th><th>Browser</th><th>Signed in</th><th>Last seen</th><th></th></tr></thead>
          <tbody id="sess-body"></tbody>
        </table></div>
        <button class="btn btn-danger" id="revoke-all" data-testid="revoke-sessions" style="margin-top:14px">Revoke All Other Sessions</button>
      </div>`;

    this._me = null;
    this.load();

    this.querySelector('#pw-save').onclick = () => this.changePassword();
    this.querySelector('#op-add').onclick = () => this.addOperator();
    this.querySelector('#revoke-all').onclick = async () => {
      if (!confirm('Revoke all sessions and log out everywhere?')) return;
      await api.post('/api/auth/revoke-all');
      window.dispatchEvent(new CustomEvent('auth-required'));
    };
  }

  async load() {
    try {
      this._me = await api.get('/api/auth/me');
      this.querySelector('#acct-whoami').innerHTML =
        `Signed in as <code style="color:var(--accent);font-size:0.85rem">${esc(this._me.username)}</code>`;
    } catch (e) {}
    this.loadOperators();
    this.loadSessions();
  }

  async loadOperators() {
    const users = await api.get('/api/users');
    const body = this.querySelector('#ops-body');
    body.innerHTML = users.map(u => {
      const isYou = this._me && u.id === this._me.id;
      const last = users.length <= 1;
      const disabled = isYou || last;
      return `<tr>
        <td class="mono" style="color:var(--text-primary)">${esc(u.username)}${isYou ? ' <span class="badge badge-allowed">you</span>' : ''}</td>
        <td>${u.created_at ? timeAgo(u.created_at) : '—'}</td>
        <td style="text-align:right"><button class="btn btn-danger btn-sm del-op" data-id="${u.id}" ${disabled ? 'disabled style="opacity:.35"' : ''}>${icons.trash}</button></td>
      </tr>`;
    }).join('');
    body.querySelectorAll('.del-op:not([disabled])').forEach(btn => {
      btn.onclick = async () => {
        if (!confirm('Delete this operator and revoke their sessions?')) return;
        await api.del(`/api/users/${btn.dataset.id}`);
        this.loadOperators();
        this.loadSessions();
      };
    });
  }

  async loadSessions() {
    const sessions = await api.get('/api/sessions');
    const body = this.querySelector('#sess-body');
    body.innerHTML = sessions.map(s => `<tr>
      <td class="mono" style="color:var(--text-primary)">${esc(s.username)}${s.is_current ? ' <span class="badge badge-allowed">this device</span>' : ''}</td>
      <td class="mono">${esc(s.ip || '—')}</td>
      <td>${esc(s.user_agent || '—')}</td>
      <td>${s.created_at ? timeAgo(s.created_at) : '—'}</td>
      <td>${s.last_seen ? timeAgo(s.last_seen) : '—'}</td>
      <td style="text-align:right"><button class="btn btn-danger btn-sm rev-sess" data-id="${s.id}" data-current="${s.is_current}">${icons.trash}</button></td>
    </tr>`).join('');
    body.querySelectorAll('.rev-sess').forEach(btn => {
      btn.onclick = async () => {
        await api.del(`/api/sessions/${btn.dataset.id}`);
        if (btn.dataset.current === 'true') { window.dispatchEvent(new CustomEvent('auth-required')); return; }
        this.loadSessions();
      };
    });
  }

  async changePassword() {
    const err = this.querySelector('#pw-error');
    err.style.display = 'none';
    const cur = this.querySelector('#pw-current').value;
    const nw = this.querySelector('#pw-new').value;
    const cf = this.querySelector('#pw-confirm').value;
    if (nw.length < 8) return showFormError(err, 'New password must be at least 8 characters');
    if (nw !== cf) return showFormError(err, 'Passwords do not match');
    try {
      await api.post('/api/users/me/password', { current_password: cur, new_password: nw });
      this.querySelector('#pw-current').value = '';
      this.querySelector('#pw-new').value = '';
      this.querySelector('#pw-confirm').value = '';
      const btn = this.querySelector('#pw-save');
      btn.textContent = 'Changed!';
      setTimeout(() => { btn.textContent = 'Change Password'; }, 2000);
    } catch (e) {
      showFormError(err, 'Current password is incorrect');
    }
  }

  async addOperator() {
    const err = this.querySelector('#op-error');
    err.style.display = 'none';
    const user = this.querySelector('#op-user').value.trim();
    const pw = this.querySelector('#op-pw').value;
    const pw2 = this.querySelector('#op-pw2').value;
    if (!user) return showFormError(err, 'Username is required');
    if (pw.length < 8) return showFormError(err, 'Password must be at least 8 characters');
    if (pw !== pw2) return showFormError(err, 'Passwords do not match');
    try {
      await api.post('/api/users', { username: user, password: pw });
      this.querySelector('#op-user').value = '';
      this.querySelector('#op-pw').value = '';
      this.querySelector('#op-pw2').value = '';
      this.loadOperators();
    } catch (e) {
      showFormError(err, 'Could not add operator (username may already exist)');
    }
  }
}
customElements.define('account-page', AccountPage);
```

- [ ] **Step 4: Add nav entry + route**

In `AppShell` desktop nav (~1722), add after the settings button:

```html
            <button class="nav-item" data-route="#account" data-testid="nav-account"><b>6:</b>account</button>
```

In the mobile `fnbar` (~1742), add after the settings button:

```html
          <button class="nav-item" data-route="#account"><span class="fk">F6</span><b>acct</b></button>
```

In the router chain (~3718), add:

```javascript
  .on('#account', () => setPage('account-page'))
```

- [ ] **Step 5: Remove the old Sessions card from Settings**

In `SettingsPage` (~3528), delete the entire `<div class="card fade-in" style="animation-delay:0.25s"> ... Revoke All Sessions ... </div>` block (the "Sessions" card). The revoke-all action now lives on the Account page. Remove any now-dead `#revoke-sessions` handler code in `SettingsPage` if present.

- [ ] **Step 6: Rebuild + manual smoke check**

```bash
cargo build
RUST_LOG=noadd=debug cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:3000
```

Open `http://127.0.0.1:3000`: complete setup with a username, log in, visit Account, add an operator, see two sessions, change password. Stop the server.

- [ ] **Step 7: Commit**

```bash
git add admin-ui/dist/index.html
git commit -m "feat(admin-ui): username login/setup and Account management page"
```

---

### Task 8: Docs + e2e + screenshots

**Files:**
- Modify: `ARCHITECTURE.md`, `README.md`
- Modify: `e2e/features/*`, `e2e/steps/*` (login/setup steps)
- Regenerate: `docs/screenshots/*`

**Interfaces:** none (documentation/tests).

- [ ] **Step 1: ARCHITECTURE.md**

In the storage table list (~99-107), add rows:

```markdown
| `users` | Operator accounts (username, Argon2 password hash) |
| `sessions` | Active admin sessions (token, user_id, ip, user agent, timestamps) |
```

Update the `settings` row to drop the "sessions" mention. Update the "Admin" bullet (~auth) and DoH/Admin sections to describe multi-operator auth: "Login is username + password; sessions are bound to a user and individually revocable."

- [ ] **Step 2: README.md**

Update any first-run / login wording to reflect creating a named operator account (username + password) and that additional operators and sessions are managed from the Account page. (Grep `rg -ni "password|login|admin" README.md` and adjust the relevant lines.)

- [ ] **Step 3: e2e steps**

In `e2e/`, update setup/login step definitions and features to supply a username (e.g. a `testuser`) alongside the password. Run:

```bash
cargo build
cd e2e && npm ci && npx playwright install chromium && npm test
```

Expected: suite passes (fix any step that posts password-only login/setup).

- [ ] **Step 4: Screenshots**

```bash
cd e2e && npm run screenshots
```

Commit the regenerated `docs/screenshots/*.png` (login, setup, and the new Account page).

- [ ] **Step 5: Commit**

```bash
git add ARCHITECTURE.md README.md e2e docs/screenshots
git commit -m "docs(multi-user): update architecture, README, e2e steps, screenshots"
```

---

## Self-Review

**Spec coverage:**
- Data model (users/sessions, v6) → Tasks 1–2. ✓
- Migration drops credential, preserves data, re-enters setup → Task 1 (migration + test), Task 4 (`needs_setup`). ✓
- In-memory store carries user_id, last_seen lazy, no DNS-path impact → Task 3 (store only touched by `validate_session`, used only on admin routes). ✓
- Auth flow (setup/login username+password, generic 401) → Task 4. ✓
- Endpoints `/api/auth/me`, `/api/users` CRUD, change-own-password → Task 5. ✓
- `/api/sessions` list + revoke, keep revoke-all/logout → Task 6 + Task 4 (logout). ✓
- Last-user guard + cascade evict → Task 5 (delete_user) + Task 2 (cascade). ✓
- Tokens never returned → Task 2 (`SessionRow` not Serialize), Task 6 (`SessionResponse` excludes token; test asserts absence). ✓
- UI: username on login/setup, Account page, remove Settings Sessions card → Task 7. ✓
- Argon2 retained → Global Constraints + Task 1 uses existing `hash_password`. ✓
- Docs + screenshots + e2e → Task 8. ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code. ✓

**Type consistency:** `SessionInfo { session_id, user_id, created_at, last_seen }` used identically in Tasks 3–6. `validate_session -> Option<i64>` consumed by `current_session`/`require_auth` (Task 4) consistently. `delete_session_by_id -> Result<Option<String>, _>` (Task 2) consumed in Task 6. `UserRow`/`UserAuth` (Task 1) consumed in Tasks 4–5. `generate_token`/`store_session` (Task 3) consumed in Task 4 and test helpers. ✓
