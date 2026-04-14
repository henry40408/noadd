# Dashboard Rate KPIs — 7d / 30d Windows

## Overview

Extend the Dashboard's three rate-based KPI cards (Block Rate, Cache Hit Rate, Avg Response) to show 7-day and 30-day values alongside today, matching the visual pattern already used by the Queries Today and Blocked Today cards on the same page.

## UI Changes

On the Dashboard, the existing Queries Today / Blocked Today cards render `today` as the main value and a sub line `7d: X / 30d: Y` (`admin-ui/dist/index.html:1361-1362`). The three rate cards currently show only today. Apply the same pattern to them:

- **Block Rate** — main: `block_ratio_today` as `%`; sub: `7d: X% / 30d: Y%`
- **Cache Hit Rate** — main: `cache_hit_rate_today` as `%`; sub: `7d: X% / 30d: Y%`
- **Avg Response** — main: `avg_response_ms_today` in ms; sub: `7d: X ms / 30d: Y ms`

Percentages use one decimal place (matching the existing Block Rate format). Avg Response uses the existing ms formatter. When the underlying window has no qualifying queries, the value is `0` (same fallback the backend already uses for today).

No new toggles or controls. No layout changes to the grid.

## Backend Changes

### `Summary` struct (`src/admin/stats.rs`)

Add six fields to `Summary`:

- `block_ratio_7d: f64`, `block_ratio_30d: f64`
- `cache_hit_rate_7d: f64`, `cache_hit_rate_30d: f64`
- `avg_response_ms_7d: f64`, `avg_response_ms_30d: f64`

### `compute_summary`

`block_ratio_{7d,30d}` can be derived from the existing `total_{7d,30d}` and `blocked_{7d,30d}` counts — no extra queries.

`cache_hit_rate_{7d,30d}` and `avg_response_ms_{7d,30d}` require two additional calls to `db.cache_stats_since` (one for `since_7d`, one for `since_30d`). These run in parallel with the existing calls via `tokio::try_join!` so the summary endpoint stays responsive.

The DB helper `cache_stats_since` uses the existing `idx_query_logs_timestamp` index; a 30-day scan on a homelab-sized log table is acceptable and matches the cost already paid by the Stats page for its 30d/90d ranges.

### API contract

`GET /api/stats/summary` continues to return `Summary` as JSON. The response gains six new fields; no fields are removed or renamed.

## Frontend Changes

In the Dashboard render path (`admin-ui/dist/index.html`, `DashboardPage` component), update the three rate cards to include a `stat-sub` line in the same shape as the count cards:

```
<div class="stat-sub">7d: ${fmt(s.X_7d)} / 30d: ${fmt(s.X_30d)}</div>
```

Reuse the existing number formatter for ms values and the existing percent formatter for ratios. No new CSS.

## Testing

- `stats_api_test` / `stats_db_test`: extend the summary test to assert the six new fields are present and correctly computed from a seeded log set spanning > 30 days.
- Unit: `block_ratio_7d` and `block_ratio_30d` match `blocked_Nd / total_Nd` with the same zero-division fallback as today.
- Unit: `cache_hit_rate_Nd` and `avg_response_ms_Nd` come from `cache_stats_since(now - N*86400)`.
- Manual: load `/` on the admin UI with populated logs, confirm the three rate cards show `7d: … / 30d: …` sub lines in the same visual style as Queries Today.

## Out of Scope

- No new time-range toggle on the Dashboard.
- No changes to the Stats page (it already supports 7d / 30d / 90d).
- No schema or index changes.
