# Statistics Page Design

**Date:** 2026-04-06
**Status:** Approved (design phase)

## Goal

Add a "Statistics" page to the admin UI that provides long-term, breakdown,
and operational views which do **not** overlap with the existing Dashboard.
The Dashboard already covers today/7d/30d totals, block ratio, cache hit
rate, average response time, QPS, 24h top domains/clients/upstreams, and a
24h timeline. The Statistics page focuses on a different time horizon
(7d/30d/90d), behavioural patterns (weekday × hour heatmap), traffic
breakdowns (query type, result code), and DB health.

## Non-Goals

- Blocked-source breakdown by filter list / custom rule (requires schema
  change to record which rule matched).
- Upstream latency percentiles or failure rate (requires new metrics
  source).
- Per-client deep analysis or DoH token usage stats.
- Cache internals (entry count, evictions, TTL distribution).
- Any modification to existing Dashboard behaviour.

These are explicitly deferred and may become follow-up work.

## Page Layout

Top to bottom inside a new "Statistics" tab in `admin-ui/dist/index.html`:

1. **Range switcher** — segmented control: `7d / 30d / 90d`. Drives
   sections A1, B1, B2. Default: `7d`.
2. **A1 — Multi-period timeline.** Stacked or multi-line chart with three
   series: `total`, `blocked`, `cached`. Bucket size depends on range:
   - 7d → 1h buckets
   - 30d → 6h buckets
   - 90d → 1d buckets
3. **A3 — Weekday × hour heatmap.** Fixed 30-day window (independent of
   the range switcher). 7 rows (Mon–Sun) × 24 columns (00–23). Cell colour
   encodes query count.
4. **B1 — Query type breakdown.** Horizontal bar chart sorted by count.
5. **B2 — Result breakdown.** Horizontal bar chart sorted by count
   (NOERROR / NXDOMAIN / SERVFAIL / …).
6. **D3 — DB health card.** Five fields:
   - DB file size
   - Total log row count
   - Oldest log timestamp
   - Log retention setting (days, from `settings` table)
   - Average new rows per day (derived: total ÷ age in days, or by retention)

## Backend

### `src/db.rs` — new aggregation methods

All methods are read-only and operate on the existing `query_logs` schema —
no schema changes required.

- `timeline_multi_since(since: i64, bucket_secs: i64) -> Vec<TimelineMultiPoint>`
  - Returns `(bucket, total, blocked, cached)` per bucket.
  - Single SQL: `SELECT (timestamp/?) * ? AS bucket, COUNT(*),
    COALESCE(SUM(blocked),0), COALESCE(SUM(cached),0) FROM query_logs
    WHERE timestamp >= ? GROUP BY bucket ORDER BY bucket`.
- `hourly_heatmap_since(since: i64) -> Vec<HeatmapCell>`
  - Returns `(weekday 0–6, hour 0–23, count)`.
  - Use `strftime('%w', timestamp, 'unixepoch')` and `strftime('%H', ...)`.
- `query_type_breakdown_since(since: i64) -> Vec<(String, i64)>`
  - `GROUP BY query_type ORDER BY COUNT(*) DESC`.
- `result_breakdown_since(since: i64) -> Vec<(String, i64)>`
  - `GROUP BY result ORDER BY COUNT(*) DESC`. Rows with NULL `result`
    are bucketed as `"unknown"`.
- `db_file_size() -> Result<i64, DbError>`
  - `PRAGMA page_count` × `PRAGMA page_size`.
- `total_log_count() -> Result<i64, DbError>`
  - `SELECT COUNT(*) FROM query_logs`.
- `earliest_log_timestamp` — already exists, reuse.

### `src/admin/stats.rs` — new compute functions

- `compute_stats_timeline(db, now, range) -> Vec<TimelineMultiPoint>`
  - Maps `range` enum (`Range7d | Range30d | Range90d`) to `(since,
    bucket_secs)` pairs as in the layout section.
- `compute_heatmap(db, now) -> Vec<HeatmapCell>` — fixed 30-day window.
- `compute_breakdowns(db, now, range) -> Breakdowns` — bundle of
  `query_types` and `results`, both windowed by `range`.
- `compute_db_health(db) -> DbHealth`
  - Reads `db_file_size`, `total_log_count`, `earliest_log_timestamp`,
    `get_setting("log_retention_days")` (default if absent), derives
    `avg_new_rows_per_day`.

### `src/admin/api.rs` — new endpoints

All under existing auth middleware, JSON responses, same error-handling
style as current stats endpoints:

- `GET /api/v1/stats/timeline?range=7d|30d|90d`
- `GET /api/v1/stats/heatmap`
- `GET /api/v1/stats/breakdown?range=7d|30d|90d`
- `GET /api/v1/stats/health`

Range parsing: invalid or missing `range` → 400 with a clear message.

## Frontend

`admin-ui/dist/index.html` is a single-file SPA. Add a new top-level tab
labelled "Statistics" next to the existing Dashboard tab. Reuse:

- Existing tab/router pattern.
- Existing chart library already loaded by the dashboard (do not introduce
  new dependencies — confirm during implementation which library is in
  use).
- Existing card / typography / colour tokens.

Visual design will be iterated on with the `frontend-design` skill during
implementation. The skill is invoked only for the visual layer; the
backend and data contracts are fixed by this spec.

State management:

- Range switcher updates a single piece of local state; sections A1, B1,
  B2 re-fetch when it changes.
- Heatmap and DB health load once on tab mount.

## Testing

### Unit tests (`src/db.rs`)

For each new aggregation method, add a test that:

1. Opens an in-memory SQLite DB and runs migrations.
2. Inserts a small fixture set of `query_logs` rows with known
   timestamps, query types, results, blocked/cached flags.
3. Calls the method and asserts exact expected output.

Cases to cover:

- Empty table → empty/zero result, no panic.
- Bucket boundary correctness for `timeline_multi_since`.
- Heatmap weekday/hour extraction matches a known timestamp.
- Breakdowns sort order and NULL handling for `result`.

### Integration tests (`src/admin/api.rs` or `tests/`)

For each of the four new endpoints:

- Unauthenticated request → 401.
- Authenticated request against an empty DB → 200 with empty/zero shape.
- Authenticated request against a seeded DB → 200 with expected values.
- For `timeline` and `breakdown`: invalid `range` parameter → 400.

## Open Questions

None. All design decisions are settled; visual specifics are deferred to
implementation with the `frontend-design` skill.

## Out of Scope (Explicit)

See "Non-Goals" above. Anything requiring schema changes, new metrics
sources, or modification to existing dashboard behaviour is excluded from
this spec.
