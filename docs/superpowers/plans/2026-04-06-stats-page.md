# Statistics Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Statistics" admin page that surfaces long-term timeline (7d/30d/90d), weekday×hour heatmap, query-type/result breakdowns, and DB health — all derived from the existing `query_logs` schema with no migrations.

**Architecture:** Pure additive change. New aggregation methods on `Database`, new compute functions in `admin::stats`, four new Axum routes under `/api/stats/...` (matching existing route prefix — note: spec mentioned `/api/v1/stats` but the codebase uses `/api/stats`; this plan uses the existing prefix), and a new "Statistics" tab in the single-file SPA at `admin-ui/dist/index.html`. Backend follows the patterns of existing methods like `count_queries_since` and `compute_timeline`.

**Tech Stack:** Rust (axum, tokio_rusqlite, serde), SQLite, single-file HTML/JS SPA. Tests via `cargo nextest run`.

**Conventions to respect:**
- `query_logs.timestamp` is stored in **milliseconds**, but all aggregation functions take a `since` argument in **seconds (epoch)** and convert internally (`since_ms = since * 1000`).
- Run `cargo fmt` before each commit. Sign all commits with GPG (default config). Use `[skip ci]` only for docs-only commits.
- Stage files explicitly by name; never `git add -A` / `git add .`.
- Tests live in `tests/*.rs`; helper `test_db()` lives in `tests/db_test.rs` — duplicate it locally in new test files (do not refactor existing tests).

---

## File Structure

**Modify:**
- `src/db.rs` — add 5 new aggregation methods + 2 new struct types
- `src/admin/stats.rs` — add 4 new compute functions + supporting types
- `src/admin/api.rs` — add 4 new route handlers and register them
- `admin-ui/dist/index.html` — add a new "Statistics" tab and its render logic

**Create:**
- `tests/stats_db_test.rs` — unit tests for new `db.rs` methods
- `tests/stats_api_test.rs` — integration tests for new HTTP endpoints

---

## Task 1: DB type — `TimelineMultiPoint`

**Files:**
- Modify: `src/db.rs` (near existing `TimelinePoint` at line ~76)

- [ ] **Step 1: Add the struct**

In `src/db.rs`, just below the existing `TimelinePoint` struct, add:

```rust
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
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /home/nixos/Develop/claude/noadd && cargo check`
Expected: clean build, no warnings about unused (Serialize derive is used by serde).

- [ ] **Step 3: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
cargo fmt
git add src/db.rs
git commit -m "feat(db): add TimelineMultiPoint and HeatmapCell types"
```

---

## Task 2: DB method — `timeline_multi_since`

**Files:**
- Modify: `src/db.rs`
- Test: `tests/stats_db_test.rs` (create)

- [ ] **Step 1: Create the test file with a failing test**

Create `tests/stats_db_test.rs`:

```rust
use noadd::db::{Database, QueryLogEntry};
use tempfile::tempdir;

async fn test_db() -> Database {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.db");
    let path_str = path.to_str().unwrap().to_string();
    std::mem::forget(dir); // keep tempdir alive for the test
    Database::open(&path_str).await.unwrap()
}

fn entry(ts_secs: i64, qtype: &str, blocked: bool, cached: bool, result: Option<&str>) -> QueryLogEntry {
    QueryLogEntry {
        timestamp: ts_secs * 1000, // column is in ms
        domain: "example.com".to_string(),
        query_type: qtype.to_string(),
        client_ip: "1.2.3.4".to_string(),
        blocked,
        cached,
        upstream: None,
        doh_token: None,
        result: result.map(|s| s.to_string()),
        response_ms: 5,
    }
}

#[tokio::test]
async fn timeline_multi_buckets_total_blocked_cached() {
    let db = test_db().await;
    // Three entries inside one 60s bucket starting at t=600
    let entries = vec![
        entry(600, "A", false, false, Some("NOERROR")),
        entry(610, "A", true,  false, Some("NXDOMAIN")),
        entry(620, "A", false, true,  Some("NOERROR")),
        // One entry in the next 60s bucket
        entry(700, "AAAA", false, false, Some("NOERROR")),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let points = db.timeline_multi_since(0, 60).await.unwrap();
    assert_eq!(points.len(), 2);
    assert_eq!(points[0].total, 3);
    assert_eq!(points[0].blocked, 1);
    assert_eq!(points[0].cached, 1);
    assert_eq!(points[1].total, 1);
    assert_eq!(points[1].blocked, 0);
    assert_eq!(points[1].cached, 0);
}

#[tokio::test]
async fn timeline_multi_empty_db() {
    let db = test_db().await;
    let points = db.timeline_multi_since(0, 60).await.unwrap();
    assert!(points.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_db_test timeline_multi`
Expected: compile error — `timeline_multi_since` not found.

- [ ] **Step 3: Implement `timeline_multi_since` in `src/db.rs`**

Add right after the existing `timeline_since` method (around line ~895). Note that the existing code stores `timestamp` in **milliseconds** but bucketing should be done in seconds; mirror the conversion pattern from `timeline_since`.

```rust
pub async fn timeline_multi_since(
    &self,
    since: i64,        // unix seconds
    bucket_secs: i64,
) -> Result<Vec<TimelineMultiPoint>, DbError> {
    let since_ms = since * 1000;
    let bucket_ms = bucket_secs * 1000;
    let result = self
        .conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
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
```

- [ ] **Step 4: Run tests, expect pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_db_test`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
cargo fmt
git add src/db.rs tests/stats_db_test.rs
git commit -m "feat(db): add timeline_multi_since aggregating total/blocked/cached"
```

---

## Task 3: DB method — `hourly_heatmap_since`

**Files:**
- Modify: `src/db.rs`
- Test: `tests/stats_db_test.rs`

- [ ] **Step 1: Add failing test**

Append to `tests/stats_db_test.rs`:

```rust
#[tokio::test]
async fn heatmap_groups_by_weekday_and_hour() {
    let db = test_db().await;
    // 2024-01-01 00:00:00 UTC = Monday, hour 0; epoch = 1704067200
    // Add 2 entries that hour, 1 entry one hour later same day.
    let monday_midnight = 1704067200;
    let entries = vec![
        entry(monday_midnight + 10, "A", false, false, None),
        entry(monday_midnight + 20, "A", false, false, None),
        entry(monday_midnight + 3600 + 5, "A", false, false, None),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let cells = db.hourly_heatmap_since(0).await.unwrap();
    // Expect two cells (mon/0 with count 2, mon/1 with count 1).
    let mon_0 = cells.iter().find(|c| c.weekday == 1 && c.hour == 0).expect("mon 0");
    let mon_1 = cells.iter().find(|c| c.weekday == 1 && c.hour == 1).expect("mon 1");
    assert_eq!(mon_0.count, 2);
    assert_eq!(mon_1.count, 1);
}

#[tokio::test]
async fn heatmap_empty_db() {
    let db = test_db().await;
    let cells = db.hourly_heatmap_since(0).await.unwrap();
    assert!(cells.is_empty());
}
```

- [ ] **Step 2: Run, expect failure**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_db_test heatmap`
Expected: compile error — method missing.

- [ ] **Step 3: Implement in `src/db.rs`**

Add below `timeline_multi_since`:

```rust
pub async fn hourly_heatmap_since(
    &self,
    since: i64, // unix seconds
) -> Result<Vec<HeatmapCell>, DbError> {
    let since_ms = since * 1000;
    let result = self
        .conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
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
```

- [ ] **Step 4: Run tests, expect pass**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_db_test heatmap`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
cargo fmt
git add src/db.rs tests/stats_db_test.rs
git commit -m "feat(db): add hourly_heatmap_since for weekday/hour aggregation"
```

---

## Task 4: DB methods — query type & result breakdowns

**Files:**
- Modify: `src/db.rs`
- Test: `tests/stats_db_test.rs`

- [ ] **Step 1: Add failing tests**

Append to `tests/stats_db_test.rs`:

```rust
#[tokio::test]
async fn query_type_breakdown_sorts_desc() {
    let db = test_db().await;
    let entries = vec![
        entry(1000, "A",     false, false, Some("NOERROR")),
        entry(1001, "A",     false, false, Some("NOERROR")),
        entry(1002, "AAAA",  false, false, Some("NOERROR")),
        entry(1003, "HTTPS", false, false, Some("NOERROR")),
        entry(1004, "A",     false, false, Some("NOERROR")),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let rows = db.query_type_breakdown_since(0).await.unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0], ("A".to_string(), 3));
    // Tiebreak between AAAA and HTTPS not asserted; both should have count 1.
    assert!(rows[1].1 == 1 && rows[2].1 == 1);
}

#[tokio::test]
async fn result_breakdown_buckets_null_as_unknown() {
    let db = test_db().await;
    let entries = vec![
        entry(1000, "A", false, false, Some("NOERROR")),
        entry(1001, "A", true,  false, Some("NXDOMAIN")),
        entry(1002, "A", false, false, None),
        entry(1003, "A", false, false, Some("NOERROR")),
    ];
    db.insert_query_logs(&entries).await.unwrap();

    let rows = db.result_breakdown_since(0).await.unwrap();
    let map: std::collections::HashMap<String, i64> = rows.into_iter().collect();
    assert_eq!(map.get("NOERROR"), Some(&2));
    assert_eq!(map.get("NXDOMAIN"), Some(&1));
    assert_eq!(map.get("unknown"), Some(&1));
}
```

- [ ] **Step 2: Run, expect failure**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_db_test breakdown`
Expected: compile error — methods missing.

- [ ] **Step 3: Implement in `src/db.rs`**

```rust
pub async fn query_type_breakdown_since(
    &self,
    since: i64,
) -> Result<Vec<(String, i64)>, DbError> {
    let since_ms = since * 1000;
    let result = self
        .conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
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

pub async fn result_breakdown_since(
    &self,
    since: i64,
) -> Result<Vec<(String, i64)>, DbError> {
    let since_ms = since * 1000;
    let result = self
        .conn
        .call(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT COALESCE(result, 'unknown') AS r, COUNT(*) AS cnt \
                 FROM query_logs \
                 WHERE timestamp >= ?1 \
                 GROUP BY r \
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
```

- [ ] **Step 4: Run tests**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_db_test breakdown`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
cargo fmt
git add src/db.rs tests/stats_db_test.rs
git commit -m "feat(db): add query_type and result breakdown aggregations"
```

---

## Task 5: DB methods — file size & total log count

**Files:**
- Modify: `src/db.rs`
- Test: `tests/stats_db_test.rs`

- [ ] **Step 1: Add failing tests**

```rust
#[tokio::test]
async fn db_file_size_is_positive() {
    let db = test_db().await;
    let size = db.db_file_size().await.unwrap();
    assert!(size > 0);
}

#[tokio::test]
async fn total_log_count_matches_inserts() {
    let db = test_db().await;
    assert_eq!(db.total_log_count().await.unwrap(), 0);
    db.insert_query_logs(&[entry(1000, "A", false, false, None)])
        .await
        .unwrap();
    assert_eq!(db.total_log_count().await.unwrap(), 1);
}
```

- [ ] **Step 2: Run, expect failure**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_db_test db_file_size total_log_count`
Expected: compile error.

- [ ] **Step 3: Implement in `src/db.rs`**

```rust
pub async fn db_file_size(&self) -> Result<i64, DbError> {
    let result = self
        .conn
        .call(|conn| {
            let page_count: i64 =
                conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
            let page_size: i64 =
                conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
            Ok(page_count * page_size)
        })
        .await?;
    Ok(result)
}

pub async fn total_log_count(&self) -> Result<i64, DbError> {
    let result = self
        .conn
        .call(|conn| {
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM query_logs", [], |row| row.get(0))?;
            Ok(count)
        })
        .await?;
    Ok(result)
}
```

- [ ] **Step 4: Run tests**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_db_test`
Expected: all stats_db_test tests pass.

- [ ] **Step 5: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
cargo fmt
git add src/db.rs tests/stats_db_test.rs
git commit -m "feat(db): add db_file_size and total_log_count helpers"
```

---

## Task 6: `admin::stats` compute layer

**Files:**
- Modify: `src/admin/stats.rs`

- [ ] **Step 1: Add types and Range enum**

Append to `src/admin/stats.rs`:

```rust
use crate::db::{HeatmapCell, TimelineMultiPoint};

#[derive(Debug, Clone, Copy)]
pub enum StatsRange {
    Days7,
    Days30,
    Days90,
}

impl StatsRange {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "7d" => Some(Self::Days7),
            "30d" => Some(Self::Days30),
            "90d" => Some(Self::Days90),
            _ => None,
        }
    }

    /// (since_seconds_offset, bucket_secs)
    fn window(self) -> (i64, i64) {
        match self {
            Self::Days7  => (7  * 86400, 3600),         // 1h buckets
            Self::Days30 => (30 * 86400, 6 * 3600),     // 6h buckets
            Self::Days90 => (90 * 86400, 86400),        // 1d buckets
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Breakdowns {
    pub query_types: Vec<(String, i64)>,
    pub results: Vec<(String, i64)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DbHealth {
    pub db_size_bytes: i64,
    pub total_log_count: i64,
    pub oldest_log_timestamp: Option<i64>, // unix seconds
    pub log_retention_days: Option<i64>,
    pub avg_new_rows_per_day: f64,
}

pub async fn compute_stats_timeline(
    db: &Database,
    now: i64,
    range: StatsRange,
) -> Result<Vec<TimelineMultiPoint>, DbError> {
    let (window_secs, bucket_secs) = range.window();
    db.timeline_multi_since(now - window_secs, bucket_secs).await
}

pub async fn compute_heatmap(
    db: &Database,
    now: i64,
) -> Result<Vec<HeatmapCell>, DbError> {
    // Fixed 30-day window per spec.
    db.hourly_heatmap_since(now - 30 * 86400).await
}

pub async fn compute_breakdowns(
    db: &Database,
    now: i64,
    range: StatsRange,
) -> Result<Breakdowns, DbError> {
    let (window_secs, _) = range.window();
    let since = now - window_secs;
    let query_types = db.query_type_breakdown_since(since).await?;
    let results = db.result_breakdown_since(since).await?;
    Ok(Breakdowns { query_types, results })
}

pub async fn compute_db_health(db: &Database, now: i64) -> Result<DbHealth, DbError> {
    let db_size_bytes = db.db_file_size().await?;
    let total_log_count = db.total_log_count().await?;
    let earliest_ms = db.earliest_log_timestamp().await?;
    let oldest_log_timestamp = earliest_ms.map(|ms| ms / 1000);
    let log_retention_days = db
        .get_setting("log_retention_days")
        .await?
        .and_then(|s| s.parse::<i64>().ok());

    let avg_new_rows_per_day = match oldest_log_timestamp {
        Some(oldest) if now > oldest => {
            let span_days = ((now - oldest) as f64 / 86400.0).max(1.0);
            total_log_count as f64 / span_days
        }
        _ => 0.0,
    };

    Ok(DbHealth {
        db_size_bytes,
        total_log_count,
        oldest_log_timestamp,
        log_retention_days,
        avg_new_rows_per_day,
    })
}
```

Also add at the top of the file (if not already imported):
```rust
use crate::db::Database;
```
(Existing file already has the relevant `use` lines — only add what is missing.)

- [ ] **Step 2: Verify compilation**

Run: `cd /home/nixos/Develop/claude/noadd && cargo check`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
cargo fmt
git add src/admin/stats.rs
git commit -m "feat(stats): add compute layer for timeline/heatmap/breakdowns/health"
```

---

## Task 7: API endpoints

**Files:**
- Modify: `src/admin/api.rs`
- Test: `tests/stats_api_test.rs` (create)

- [ ] **Step 1: Add failing integration test**

Look at `tests/admin_api_test.rs` for the existing pattern (how `AppState` is built, how the test client authenticates). Mirror that exactly. Create `tests/stats_api_test.rs` with at minimum:

```rust
// Mirror tests/admin_api_test.rs setup helpers (test_app(), authed_client(), etc).
// Keep it self-contained — duplicate helpers rather than refactoring the
// existing test file.

#[tokio::test]
async fn stats_timeline_unauthenticated_returns_401() {
    let app = test_app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/stats/v2/timeline?range=7d")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stats_timeline_invalid_range_returns_400() {
    let (app, jar) = authed_app().await;
    let resp = send(&app, &jar, "/api/stats/v2/timeline?range=bogus").await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn stats_timeline_empty_db_returns_empty_array() {
    let (app, jar) = authed_app().await;
    let resp = send(&app, &jar, "/api/stats/v2/timeline?range=7d").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = read_json(resp).await;
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn stats_health_returns_expected_fields() {
    let (app, jar) = authed_app().await;
    let resp = send(&app, &jar, "/api/stats/v2/health").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = read_json(resp).await;
    assert!(body.get("db_size_bytes").is_some());
    assert!(body.get("total_log_count").is_some());
    assert!(body.get("oldest_log_timestamp").is_some());
    assert!(body.get("log_retention_days").is_some());
    assert!(body.get("avg_new_rows_per_day").is_some());
}
```

> Implementer note: copy the helper functions (`test_app`, `authed_app`, `send`, `read_json`) from `tests/admin_api_test.rs`. The route prefix for new endpoints is `/api/stats/v2/...` to avoid clashing with the existing `/api/stats/...` routes — see Step 3 for the rationale.

- [ ] **Step 2: Run, expect failure**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_api_test`
Expected: compile error or 404 (route not registered).

- [ ] **Step 3: Add the four endpoints in `src/admin/api.rs`**

Route prefix decision: existing routes already use `/api/stats/{summary,timeline,top-domains,...}`. To keep this additive and avoid breaking the existing dashboard, register the new routes under `/api/stats/v2/...`. Add to the router builder near line ~93:

```rust
        // Stats v2 — statistics page
        .route("/api/stats/v2/timeline", get(get_stats_v2_timeline))
        .route("/api/stats/v2/heatmap", get(get_stats_v2_heatmap))
        .route("/api/stats/v2/breakdown", get(get_stats_v2_breakdown))
        .route("/api/stats/v2/health", get(get_stats_v2_health))
```

Then add the handlers (place near the other `get_stats_*` handlers, around line ~800):

```rust
#[derive(Deserialize)]
pub struct StatsRangeQuery {
    pub range: Option<String>,
}

fn parse_range(q: &StatsRangeQuery) -> Result<stats::StatsRange, StatusCode> {
    let raw = q.range.as_deref().unwrap_or("7d");
    stats::StatsRange::parse(raw).ok_or(StatusCode::BAD_REQUEST)
}

async fn get_stats_v2_timeline(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<StatsRangeQuery>,
) -> Result<Json<Vec<crate::db::TimelineMultiPoint>>, StatusCode> {
    require_auth(&state, &jar)?;
    let range = parse_range(&query)?;
    let now = now_epoch();
    let timeline = stats::compute_stats_timeline(&state.db, now, range)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(timeline))
}

async fn get_stats_v2_heatmap(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Vec<crate::db::HeatmapCell>>, StatusCode> {
    require_auth(&state, &jar)?;
    let now = now_epoch();
    let cells = stats::compute_heatmap(&state.db, now)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(cells))
}

async fn get_stats_v2_breakdown(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<StatsRangeQuery>,
) -> Result<Json<stats::Breakdowns>, StatusCode> {
    require_auth(&state, &jar)?;
    let range = parse_range(&query)?;
    let now = now_epoch();
    let b = stats::compute_breakdowns(&state.db, now, range)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(b))
}

async fn get_stats_v2_health(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<stats::DbHealth>, StatusCode> {
    require_auth(&state, &jar)?;
    let now = now_epoch();
    let h = stats::compute_db_health(&state.db, now)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(h))
}
```

- [ ] **Step 4: Run tests**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_api_test`
Expected: 4 passed.

- [ ] **Step 5: Run full test suite**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run`
Expected: all tests pass (sanity check that nothing else broke).

- [ ] **Step 6: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
cargo fmt
git add src/admin/api.rs tests/stats_api_test.rs
git commit -m "feat(api): add /api/stats/v2 endpoints for statistics page"
```

---

## Task 8: Frontend — Statistics tab

**Files:**
- Modify: `admin-ui/dist/index.html`

This task is the visual layer. **Invoke the `frontend-design` skill** at the start of this task and let it drive the implementation. Constraints to give the skill:

- Single-file SPA — all changes go in `admin-ui/dist/index.html`. No new dependencies, no separate build step. Use whatever chart library the existing dashboard already loads (inspect the file first).
- Add a new top-level tab labelled **Statistics**, alongside the existing Dashboard tab. Use the existing tab/router pattern in the file.
- Page sections (top to bottom):
  1. Range switcher: `7d / 30d / 90d`, segmented control. Default `7d`. Drives sections 2, 4, 5.
  2. Multi-period timeline chart, three series: `total`, `blocked`, `cached`. Data from `GET /api/stats/v2/timeline?range=<range>`. Each point: `{ timestamp, total, blocked, cached }`, timestamp is unix seconds.
  3. Weekday × hour heatmap, fixed 30-day window. Data from `GET /api/stats/v2/heatmap`. Each cell: `{ weekday (0=Sun..6=Sat), hour (0..23), count }`. Render as 7×24 grid; missing cells = 0.
  4. Query type breakdown — horizontal bar chart, sorted by count desc. Data: `GET /api/stats/v2/breakdown?range=<range>` → `query_types: [[label, count], ...]`.
  5. Result breakdown — horizontal bar chart. Data from same endpoint → `results: [[label, count], ...]`.
  6. DB Health card. Data from `GET /api/stats/v2/health`. Fields:
     - `db_size_bytes` (format as KB/MB/GB)
     - `total_log_count`
     - `oldest_log_timestamp` (unix seconds, format as locale date or "n days ago")
     - `log_retention_days` (may be null → show "—")
     - `avg_new_rows_per_day` (round to 1 decimal)
- State: range switcher updates a single piece of local state; sections 2, 4, 5 re-fetch when it changes. Heatmap and Health load once on tab mount.
- Re-use existing card / typography / colour tokens. Match the visual weight of the existing Dashboard.
- Auth: same cookie-based auth as Dashboard — fetch with `credentials: 'same-origin'` (or whatever the existing dashboard fetches use; mirror that pattern).

- [ ] **Step 1: Read the existing index.html structure**

Run: `cd /home/nixos/Develop/claude/noadd && wc -l admin-ui/dist/index.html`
Then open the file and locate: tab definitions, the dashboard tab content, the chart library being used, and the existing fetch helper.

- [ ] **Step 2: Invoke `frontend-design` skill**

Hand it the constraints listed above plus the file contents you just read. Let the skill produce the markup, styles, and JS for the new tab.

- [ ] **Step 3: Manual smoke test**

Run: `cd /home/nixos/Develop/claude/noadd && cargo run`
Then open the admin UI in a browser, log in, click the Statistics tab. Verify:
- All 6 sections render without console errors.
- Range switcher refetches sections 2, 4, 5 (check Network tab).
- Heatmap and Health load on mount and do not refetch on range change.
- Empty DB case: visit on a fresh DB or after clearing logs — page renders without crashing.

- [ ] **Step 4: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
git add admin-ui/dist/index.html
git commit -m "feat(ui): add Statistics tab with timeline/heatmap/breakdown/health"
```

---

## Task 9: Documentation update

**Files:**
- Modify: `README.md` (if it documents admin endpoints) and/or `ARCHITECTURE.md`

- [ ] **Step 1: Check current docs**

Run: `cd /home/nixos/Develop/claude/noadd && grep -l "/api/stats" README.md ARCHITECTURE.md docs/`
If any file lists API endpoints or admin features, add entries for:
- The Statistics page
- The four new `/api/stats/v2/*` endpoints (one-line description each)

- [ ] **Step 2: Update the relevant file(s)**

Make minimal additive edits — do not rewrite existing sections.

- [ ] **Step 3: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
git add <files>
git commit -m "docs: document statistics page and /api/stats/v2 endpoints [skip ci]"
```

---

## Task 10: Final verification & PR

- [ ] **Step 1: Run the full test suite**

Run: `cd /home/nixos/Develop/claude/noadd && cargo nextest run`
Expected: all green.

- [ ] **Step 2: Run formatter and clippy**

Run: `cd /home/nixos/Develop/claude/noadd && cargo fmt --check && cargo clippy --all-targets -- -D warnings`
Expected: no diffs, no warnings. Fix and re-commit if needed.

- [ ] **Step 3: Push and open PR**

```bash
cd /home/nixos/Develop/claude/noadd
git push -u origin feat/stats-page
gh pr create --title "feat: add Statistics admin page" --body "$(cat <<'EOF'
## Summary
- Adds a Statistics tab to the admin UI with long-term timeline (7d/30d/90d), weekday×hour heatmap, query-type and result breakdowns, and DB health card.
- Pure additive change: no schema migration, no changes to existing Dashboard.
- New endpoints under `/api/stats/v2/*`.

## Test plan
- [ ] `cargo nextest run` passes
- [ ] Statistics tab renders with seeded data
- [ ] Empty DB renders without errors
- [ ] Range switcher refetches timeline and breakdowns

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Out of Scope (do not implement)

- Filter-list / custom-rule attribution for blocked queries
- Upstream latency percentiles or failure rate
- Per-client / per-token analytics
- Cache internals (entry count, TTL distribution, evictions)
- Schema changes of any kind
- Modifying the existing Dashboard
