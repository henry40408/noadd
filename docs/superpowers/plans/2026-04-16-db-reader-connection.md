# Database Reader Connection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `Database` a second read-only `tokio_rusqlite::Connection` so admin SELECT queries run in parallel with the query-log writer under WAL, removing single-worker-thread contention under multi-client load.

**Architecture:** Add a `read_conn` field to `Database` opened with `SQLITE_OPEN_READ_ONLY` flags against the same DB file. Route all pure-SELECT methods to `read_conn`; keep all writes + schema init on the existing connection. No API surface change — callers see the same public methods.

**Tech Stack:** Rust, `rusqlite = "0.37"`, `tokio-rusqlite = "0.7"` (both pinned in `Cargo.toml`). Tests run with `cargo nextest run` (per project CLAUDE.md).

**Spec:** `docs/superpowers/specs/2026-04-16-db-reader-connection-design.md`

**Branch:** `feat/dns-concurrency-limit` (do NOT create a new branch — this is the last P1 item on the in-flight multi-client hardening branch, commit `8e7259c` added the spec).

**Per-commit conventions:**
- Sign every commit with GPG (`-S`). Never pass `--no-verify` or `--no-gpg-sign`.
- Stage files explicitly by path; never `git add -A` / `git add .`.
- Run `cargo fmt` before every commit.
- Commit messages in English.
- Non-docs commits: let CI run (no `[skip ci]`).

---

## File Structure

**Modified files:**

- `src/db.rs` — adds `open_read_conn` helper, adds `read_conn` field, re-routes ~28 read methods.

**New files:**

- `tests/db_concurrency_test.rs` — concurrent reader + writer integration test.

**Touched tests (non-structural):**

- `tests/db_test.rs` — one new smoke test appended at the end of the file.

No changes to:
- `src/main.rs`, `src/logger.rs`, `src/admin/**`, anything under `admin-ui/`.
- `Cargo.toml` / `Cargo.lock` (no new deps).
- `ARCHITECTURE.md` (unchanged at the granularity it describes).

---

### Task 1: Add `read_conn` infrastructure to `Database`

Adds the second connection and opens it from `Database::open` without yet routing any methods to it. Smoke test confirms startup and basic reads/writes still work.

**Files:**
- Modify: `src/db.rs` (add field + helper; wire `Database::open`)
- Modify: `tests/db_test.rs` (append one smoke test)

- [ ] **Step 1: Add `OpenFlags` import to `src/db.rs`**

At the top of `src/db.rs`, extend the existing `rusqlite` import to include `OpenFlags`. Change line 1:

```rust
use rusqlite::{OpenFlags, OptionalExtension, params};
```

- [ ] **Step 2: Add `read_conn` field to the `Database` struct**

In `src/db.rs`, change the `Database` struct (around line 14–17):

```rust
#[derive(Clone)]
pub struct Database {
    conn: Connection,
    read_conn: Connection,
}
```

- [ ] **Step 3: Add `open_read_conn` helper function**

In `src/db.rs`, add a new private helper immediately after the `Database` struct declaration and before the large `impl Database` block. Place it at the module level:

```rust
/// Open a second connection to the same SQLite file in read-only mode.
/// Used for admin SELECT queries so they run concurrently with the writer
/// under WAL without blocking on a single worker thread.
async fn open_read_conn(path: &str) -> Result<Connection, DbError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    let conn = Connection::open_with_flags(path, flags).await?;
    conn.call(|conn| {
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
```

- [ ] **Step 4: Update `Database::open` to open both connections**

In `src/db.rs`, change the `open` method (around line 109–114). The write connection and schema init must run first so `journal_mode = WAL` is persisted on the file before the read connection attaches:

```rust
pub async fn open(path: &str) -> Result<Self, DbError> {
    let conn = Connection::open(path).await?;
    let db_init = Self {
        conn: conn.clone(),
        // Placeholder — replaced below. We need schema init to run on
        // the write conn before opening the read conn so WAL is in effect.
        read_conn: conn.clone(),
    };
    db_init.init_schema().await?;
    let read_conn = open_read_conn(path).await?;
    Ok(Self { conn, read_conn })
}
```

Note: `tokio_rusqlite::Connection` is `Clone` (it wraps an `Arc` to the worker). The intermediate `db_init` is only used to call `init_schema`, then dropped. The returned `Self` holds the real `read_conn`.

- [ ] **Step 5: Run existing tests to confirm no regression**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run`

Expected: all existing tests pass. The write path is unchanged; the read path still uses `self.conn`; `read_conn` is opened but not yet referenced by any method.

- [ ] **Step 6: Append smoke test to `tests/db_test.rs`**

Append to the end of `tests/db_test.rs`:

```rust
#[tokio::test]
async fn test_read_conn_opens_and_basic_roundtrip_works() {
    // Verifies that Database::open successfully opens both connections
    // against the same file and that a write followed by a read still
    // works end-to-end after the read_conn infrastructure is wired.
    let db = test_db().await;
    let entry = QueryLogEntry {
        timestamp: 1_700_000_000_000,
        domain: "example.com".to_string(),
        query_type: "A".to_string(),
        client_ip: "127.0.0.1".to_string(),
        blocked: false,
        cached: false,
        response_ms: 1,
        upstream: None,
        doh_token: None,
        result: None,
    };
    db.insert_query_logs(std::slice::from_ref(&entry))
        .await
        .unwrap();
    let rows = db
        .query_logs(10, 0, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].domain, "example.com");
}
```

- [ ] **Step 7: Run the new smoke test**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test db_test test_read_conn_opens_and_basic_roundtrip_works`

Expected: PASS.

- [ ] **Step 8: Run `cargo fmt` and full test suite**

Run:
```bash
cd /home/nixos/Develop/claude/noadd && cargo fmt && cargo nextest run
```

Expected: formatter produces no diff beyond this task's changes; all tests green.

- [ ] **Step 9: Stage, verify, and commit**

```bash
cd /home/nixos/Develop/claude/noadd
git add src/db.rs tests/db_test.rs
git status
git diff --cached --stat
git commit -S -m "feat(db): add read-only connection alongside writer

Opens a second tokio_rusqlite::Connection with SQLITE_OPEN_READ_ONLY
flags against the same SQLite file. Not yet wired into any read
method — this commit adds the infrastructure and a smoke test so the
subsequent routing change is a pure substitution.

Part of feat/dns-concurrency-limit P1 #6.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
git log --show-signature -1 | head -6
```

Expected: commit recorded; `gpg: Good signature from "Heng-Yi Wu ..."`.

---

### Task 2: Route all pure-SELECT methods to `read_conn`

Re-routes every read-only method from `self.conn.call(...)` to `self.read_conn.call(...)`. Existing test suite must still pass — this is a behaviour-preserving change for non-concurrent callers.

**Files:**
- Modify: `src/db.rs` (swap the receiver on 28 methods)

- [ ] **Step 1: Re-route `list_tables`**

In `src/db.rs`, in the `list_tables` method (line ~266), change `self.conn.call` to `self.read_conn.call`. Keep the closure body unchanged.

- [ ] **Step 2: Re-route `get_setting`**

In `src/db.rs`, in `get_setting` (line ~284), change `self.conn.call` to `self.read_conn.call`.

- [ ] **Step 3: Re-route the query-log read methods**

In `src/db.rs`, change `self.conn.call` to `self.read_conn.call` in each of these methods (line numbers approximate):

- `query_logs` (~347)
- `count_logs` (~411)
- `earliest_log_timestamp` (~784)
- `total_log_count` (~1204)

- [ ] **Step 4: Re-route the window-count stats methods**

In `src/db.rs`, change `self.conn.call` to `self.read_conn.call` in:

- `count_queries_since` (~800)
- `count_queries_multi_since` (~842)

- [ ] **Step 5: Re-route the cache-stats methods**

In `src/db.rs`, change `self.conn.call` to `self.read_conn.call` in:

- `cache_stats_since` (~819)
- `cache_stats_multi_since` (~880)

- [ ] **Step 6: Re-route the top-N methods**

In `src/db.rs`, change `self.conn.call` to `self.read_conn.call` in:

- `top_domains_since` (~931)
- `top_clients_since` (~957)
- `top_upstreams_since` (~984)

- [ ] **Step 7: Re-route the timeline / heatmap / breakdown methods**

In `src/db.rs`, change `self.conn.call` to `self.read_conn.call` in:

- `timeline_since` (~1216)
- `timeline_multi_since` (~1011)
- `hourly_heatmap_since` (~1047)
- `query_type_breakdown_since` (~1079)
- `outcome_breakdown_since` (~1105)
- `unique_domains_since` (~1135)
- `latency_summary_since` (~1151)

- [ ] **Step 8: Re-route `db_file_size`**

In `src/db.rs`, in `db_file_size` (line ~1192), change `self.conn.call` to `self.read_conn.call`. The two `PRAGMA page_count` / `PRAGMA page_size` queries are read-only and safe on a `SQLITE_OPEN_READ_ONLY` connection.

- [ ] **Step 9: Re-route the filter-list read methods**

In `src/db.rs`, change `self.conn.call` to `self.read_conn.call` in:

- `get_filter_lists` (~502)
- `get_filter_list_content` (~679)

- [ ] **Step 10: Re-route the custom-rule read methods**

In `src/db.rs`, change `self.conn.call` to `self.read_conn.call` in:

- `has_custom_rule` (~589)
- `get_all_custom_rules` (~620)
- `get_custom_rules_by_type` (~641)

- [ ] **Step 11: Re-route the DoH-token read methods**

In `src/db.rs`, change `self.conn.call` to `self.read_conn.call` in:

- `get_doh_tokens` (~714)
- `validate_doh_token` (~755)
- `has_doh_tokens` (~769)

- [ ] **Step 12: Grep sanity-check the routing**

Run:
```bash
cd /home/nixos/Develop/claude/noadd
grep -n 'self\.conn\.call' src/db.rs
grep -n 'self\.read_conn\.call' src/db.rs
```

Expected: `self.conn.call` appears **only** in the methods listed in the spec's "stay on write_conn" set (15 methods: schema init, settings write, query-log inserts/deletes/prune, filter-list writes, filter-list content writer, custom-rule writes, DoH-token writes). `self.read_conn.call` appears exactly 28 times, matching the re-routed list above.

If the counts don't match, re-check against the spec's routing table before proceeding.

- [ ] **Step 13: Run `cargo fmt` and full test suite**

Run:
```bash
cd /home/nixos/Develop/claude/noadd && cargo fmt && cargo nextest run
```

Expected: all 153+ tests pass including the smoke test added in Task 1. The change is behaviour-preserving for non-concurrent callers; existing tests should not flake.

- [ ] **Step 14: Stage and commit**

```bash
cd /home/nixos/Develop/claude/noadd
git add src/db.rs
git diff --cached --stat
git commit -S -m "feat(db): route read-only methods to the reader connection

All pure-SELECT Database methods (28 of them, covering query-log
pagination, stats windows, top-N, timeline/heatmap, filter-list
reads, custom-rule reads, DoH token lookups, and settings reads)
now dispatch through self.read_conn. Writes, schema init, and
migrations continue to use self.conn.

Under WAL, SQLite lets the reader run concurrently with the writer,
so admin dashboard scans no longer block query-log inserts.

Part of feat/dns-concurrency-limit P1 #6.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
git log --show-signature -1 | head -6
```

Expected: commit recorded with a valid GPG signature.

---

### Task 3: Concurrent reader-writer integration test

Adds the test that directly exercises the isolation property: a heavy reader task and a streaming writer task must both complete independently without error.

**Files:**
- Create: `tests/db_concurrency_test.rs`

- [ ] **Step 1: Create the test file**

Create `tests/db_concurrency_test.rs` with the following content:

```rust
use std::time::Duration;

use noadd::db::{Database, QueryLogEntry};
use tempfile::tempdir;
use tokio::time::timeout;

fn sample_entry(i: i64) -> QueryLogEntry {
    QueryLogEntry {
        timestamp: 1_700_000_000_000 + i,
        domain: format!("host-{}.example.com", i % 1024),
        query_type: "A".to_string(),
        client_ip: format!("10.0.{}.{}", (i / 256) % 256, i % 256),
        blocked: i % 7 == 0,
        cached: i % 3 == 0,
        response_ms: (i % 50) + 1,
        upstream: Some("1.1.1.1".to_string()),
        doh_token: None,
        result: None,
    }
}

async fn open_db() -> Database {
    let dir = tempdir().unwrap();
    let path = dir.path().join("concurrency.db");
    let path_str = path.to_str().unwrap().to_string();
    // Leak the dir so the file lives for the duration of the test.
    std::mem::forget(dir);
    Database::open(&path_str).await.unwrap()
}

/// Concurrently run a heavy reader (latency_summary_since, which uses
/// window functions and scans query_logs) alongside a streaming writer
/// (insert_query_logs). With the reader connection in place, WAL allows
/// both paths to proceed in parallel on their own worker threads. The
/// assertion is existence: both tasks must complete without error.
///
/// No timing assertion beyond a generous 5s ceiling — speedup vs. the
/// single-connection baseline is machine-dependent and would make the
/// test flaky.
#[tokio::test]
async fn reader_and_writer_run_concurrently_without_error() {
    let db = open_db().await;

    // Pre-populate ~10_000 rows so latency_summary_since does real work.
    let seed: Vec<QueryLogEntry> = (0..10_000).map(sample_entry).collect();
    db.insert_query_logs(&seed).await.unwrap();

    let writer_db = db.clone();
    let writer = tokio::spawn(async move {
        for round in 0..10 {
            let batch: Vec<QueryLogEntry> = (0..500)
                .map(|i| sample_entry(100_000 + round * 500 + i))
                .collect();
            writer_db.insert_query_logs(&batch).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let reader_db = db.clone();
    let reader = tokio::spawn(async move {
        let since_seconds = 1_000_000_000_i64; // epoch seconds; well before any row
        for _ in 0..10 {
            let summary = reader_db.latency_summary_since(since_seconds).await.unwrap();
            assert!(summary.sample_count > 0);
        }
    });

    let joined = async {
        writer.await.unwrap();
        reader.await.unwrap();
    };
    timeout(Duration::from_secs(5), joined)
        .await
        .expect("writer + reader must both complete within 5s");

    // Sanity check: final row count matches pre-population + 10 * 500 writes.
    let total = db.total_log_count().await.unwrap();
    assert_eq!(total, 10_000 + 10 * 500);
}

/// Smoke check for the spec's "defence-in-depth" claim: the read
/// connection is opened with SQLITE_OPEN_READ_ONLY, so any write
/// attempt would be rejected by SQLite. We can only observe this
/// indirectly through the public API — `Database` routes all writes
/// to the writer connection by construction. This test asserts the
/// positive: a write followed by a read works, which means Database
/// correctly chose each connection for each operation.
#[tokio::test]
async fn read_only_routing_does_not_break_writes() {
    let db = open_db().await;
    db.insert_query_logs(&[sample_entry(1)]).await.unwrap();
    let rows = db.query_logs(10, 0, None, None, None, None).await.unwrap();
    assert_eq!(rows.len(), 1);
}
```

- [ ] **Step 2: Run the new test file**

Run:
```bash
cd /home/nixos/Develop/claude/noadd && cargo nextest run --test db_concurrency_test
```

Expected: both tests PASS within seconds.

- [ ] **Step 3: Run the full test suite**

Run:
```bash
cd /home/nixos/Develop/claude/noadd && cargo fmt && cargo nextest run
```

Expected: all tests pass (existing + new concurrency tests).

- [ ] **Step 4: Stage and commit**

```bash
cd /home/nixos/Develop/claude/noadd
git add tests/db_concurrency_test.rs
git diff --cached --stat
git commit -S -m "test(db): cover concurrent reader + writer isolation

Spawns a 10k-row latency_summary_since reader loop alongside a
500-row-per-batch insert_query_logs writer loop, asserting both
complete within 5s without error. Exercises the WAL isolation
provided by the new read-only connection.

Part of feat/dns-concurrency-limit P1 #6.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
git log --show-signature -1 | head -6
```

Expected: commit recorded with a valid GPG signature.

---

### Task 4: Branch verification and memory update

Confirms the feature branch state matches the project-memory roadmap's expectation for P1 #6 and records completion.

**Files:** (no code changes)

- [ ] **Step 1: Verify branch state**

Run:
```bash
cd /home/nixos/Develop/claude/noadd
git log --oneline main..HEAD
```

Expected: exactly six commits on top of `main`:

1. `db87386` feat(dns): bound concurrent in-flight queries with semaphore  *(pre-existing)*
2. `c95db65` feat(admin): real client IP in rate limiter, expose log drop metric  *(pre-existing)*
3. `c200638` feat(dns): per-client-IP token-bucket rate limiting  *(pre-existing)*
4. `5adc4a1` feat(dns): coalesce concurrent cold-miss upstream queries  *(pre-existing)*
5. `8e7259c` docs(spec): add db-reader-connection design for P1 #6  *(from this session, already pushed)*
6. Task 1 commit: feat(db): add read-only connection alongside writer
7. Task 2 commit: feat(db): route read-only methods to the reader connection
8. Task 3 commit: test(db): cover concurrent reader + writer isolation

(Commits 6–8 are added by this plan. Commit count above reflects order on branch.)

- [ ] **Step 2: Run the full test suite once more**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run`

Expected: green. Record the final test count in the summary for the user.

- [ ] **Step 3: Update project memory**

Edit `/home/nixos/.claude/projects/-home-nixos-Develop-claude-noadd/memory/project_multi_client_hardening.md`:

- Flip the `[ ]` on P1 #6 to `[x]` and append the commit SHA triple (Task 1/2/3 hashes, obtained from `git log --oneline main..HEAD`).
- Update the first paragraph's commit count from "4 GPG-signed commits" to the new total, and update the "latest verified" date.
- Leave the "User-facing follow-ups" section untouched — PR decision is still open.

- [ ] **Step 4: Stop here. Do not push or open a PR.**

PR strategy (single bundle vs. split-by-P-level) is an explicit open decision in `project_multi_client_hardening.md` under "User-facing follow-ups". Summarise branch state for the user and wait for their PR instruction.

---

## Self-Review

**Spec coverage:**

- Architecture — Task 1 Steps 1–4 add `read_conn` + helper + open order. ✓
- Method routing table — Task 2 covers all 28 read methods + the grep sanity-check in Step 12 guards the split. ✓
- Error handling (`Database::open` fails hard if read_conn fails) — Task 1 Step 4 propagates the `?` from `open_read_conn`. ✓
- Testing (smoke + concurrency + positive routing check) — Task 1 Step 6 (smoke), Task 3 (concurrency + positive routing). ✓
- Non-goals (no batch/interval/channel changes, no CLI flags) — plan touches none of those files. ✓
- Files changed match spec's "Files Changed" list (`src/db.rs`, `tests/db_concurrency_test.rs`, plus the appended smoke test in `tests/db_test.rs` which the spec implicitly permits as an existing test file). ✓

**Placeholder scan:** no TBD / TODO / "similar to" references. Every code-bearing step shows the code. Every command shows the expected outcome.

**Type consistency:** `Database::open`, `Connection`, `OpenFlags`, `DbError`, `QueryLogEntry` names match the existing codebase and the spec. Field name `read_conn` is used consistently across the plan. Method names in the Task 2 routing list match `src/db.rs` definitions (spot-checked the complete 28-item list against the actual file).
