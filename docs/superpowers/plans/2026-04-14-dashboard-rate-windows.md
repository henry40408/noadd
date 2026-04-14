# Dashboard Rate KPIs — 7d / 30d Windows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 7-day and 30-day sub-line values to the Dashboard's three rate-based KPI cards (Block Rate, Cache Hit Rate, Avg Response), matching the existing Queries Today / Blocked Today visual pattern.

**Architecture:** Extend the backend `Summary` struct with six new `f64` fields (`block_ratio_{7d,30d}`, `cache_hit_rate_{7d,30d}`, `avg_response_ms_{7d,30d}`). `compute_summary` derives the block ratios from existing counts and makes two additional `cache_stats_since` calls for 7d and 30d, issued in parallel with the existing today call via `tokio::try_join!`. The Dashboard renderer reads the new fields and appends a `<div class="stat-sub">` line to each of the three rate cards.

**Tech Stack:** Rust (axum + tokio + rusqlite via async wrapper), Serde JSON, vanilla JS web components (single-file compiled admin UI), cargo nextest.

---

## File Structure

**Modified:**

- `src/admin/stats.rs` — add six `f64` fields to `Summary`; extend `compute_summary` to fetch 7d/30d cache stats and populate the new fields.
- `admin-ui/dist/index.html` — inside `DashboardPage.renderStats`, compute six new formatted strings and append a `stat-sub` div to each of the three rate cards (`data-i="2"`, `"3"`, `"4"`).
- `tests/stats_db_test.rs` — add a new `#[tokio::test]` exercising `noadd::admin::stats::compute_summary` over a seeded log set that spans >30 days, asserting the six new fields.

**Not modified:**

- `src/db.rs` — `cache_stats_since` / `count_queries_since` unchanged; existing `idx_query_logs_timestamp` index covers the 30-day scan.
- `src/admin/api.rs` — `/api/stats/summary` handler returns `Summary` unchanged; new fields flow through Serde automatically.
- Stats page — already has its own 7d/30d/90d range; untouched.

---

## Task 1: Backend — extend `Summary` and `compute_summary`

**Files:**
- Modify: `src/admin/stats.rs:8-59`
- Test: `tests/stats_db_test.rs` (append at end of file)

- [ ] **Step 1: Write the failing test**

Append to `tests/stats_db_test.rs`:

```rust
#[tokio::test]
async fn compute_summary_populates_7d_and_30d_rates() {
    use noadd::admin::stats::compute_summary;

    let db = test_db().await;
    // "now" is 40 days past the epoch so all windows have room.
    let now: i64 = 40 * 86400;
    let one_day: i64 = 86400;

    // Today window (now - 86400 .. now): 2 total, 1 blocked, 1 allowed+cached.
    // Allowed row in today: response_ms=5, cached=true.
    let today_blocked = entry(now - 100, "A", true, false, Some("NXDOMAIN"));
    let today_allowed_cached = entry(now - 200, "A", false, true, Some("NOERROR"));

    // 7d window adds one allowed+uncached entry 3 days ago (response_ms=5, cached=false).
    let three_days_ago = entry(now - 3 * one_day, "A", false, false, Some("NOERROR"));

    // 30d window adds one blocked entry 20 days ago.
    let twenty_days_ago = entry(now - 20 * one_day, "A", true, false, Some("NXDOMAIN"));

    db.insert_query_logs(&[
        today_blocked,
        today_allowed_cached,
        three_days_ago,
        twenty_days_ago,
    ])
    .await
    .unwrap();

    let s = compute_summary(&db, now).await.unwrap();

    // today: 2 total, 1 blocked -> 0.5
    assert!((s.block_ratio_today - 0.5).abs() < 1e-9);
    // 7d: 3 total, 1 blocked -> 1/3
    assert!((s.block_ratio_7d - (1.0 / 3.0)).abs() < 1e-9);
    // 30d: 4 total, 2 blocked -> 0.5
    assert!((s.block_ratio_30d - 0.5).abs() < 1e-9);

    // today cache_hit_rate: 1 allowed row, cached=true -> 1.0
    assert!((s.cache_hit_rate_today - 1.0).abs() < 1e-9);
    // 7d cache_hit_rate: 2 allowed rows (one cached, one not) -> 0.5
    assert!((s.cache_hit_rate_7d - 0.5).abs() < 1e-9);
    // 30d cache_hit_rate: 2 allowed rows (same as 7d; the 20d-old is blocked) -> 0.5
    assert!((s.cache_hit_rate_30d - 0.5).abs() < 1e-9);

    // avg_response_ms across allowed rows. entry() hardcodes response_ms=5.
    assert!((s.avg_response_ms_today - 5.0).abs() < 1e-9);
    assert!((s.avg_response_ms_7d - 5.0).abs() < 1e-9);
    assert!((s.avg_response_ms_30d - 5.0).abs() < 1e-9);
}
```

- [ ] **Step 2: Run test to verify it fails**

```
cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_db_test compute_summary_populates_7d_and_30d_rates
```

Expected: FAIL — compile error on `s.block_ratio_7d`, `s.cache_hit_rate_7d`, `s.avg_response_ms_7d`, `s.block_ratio_30d`, `s.cache_hit_rate_30d`, `s.avg_response_ms_30d` (fields do not exist on `Summary`).

- [ ] **Step 3: Implement — extend `Summary` struct**

Replace `src/admin/stats.rs:8-20` with:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub total_today: i64,
    pub blocked_today: i64,
    pub total_7d: i64,
    pub blocked_7d: i64,
    pub total_30d: i64,
    pub blocked_30d: i64,
    pub block_ratio_today: f64,
    pub block_ratio_7d: f64,
    pub block_ratio_30d: f64,
    pub cache_hit_rate_today: f64,
    pub cache_hit_rate_7d: f64,
    pub cache_hit_rate_30d: f64,
    pub avg_response_ms_today: f64,
    pub avg_response_ms_7d: f64,
    pub avg_response_ms_30d: f64,
    pub queries_1m: i64,
}
```

- [ ] **Step 4: Implement — extend `compute_summary`**

Replace `src/admin/stats.rs:22-59` with:

```rust
pub async fn compute_summary(db: &Database, now: i64) -> Result<Summary, DbError> {
    let one_day = 86400;
    let since_today = now - one_day;
    let since_7d = now - 7 * one_day;
    let since_30d = now - 30 * one_day;
    let since_1m = now - 60;

    let (queries_1m, _) = db.count_queries_since(since_1m).await?;
    let (total_today, blocked_today) = db.count_queries_since(since_today).await?;
    let (total_7d, blocked_7d) = db.count_queries_since(since_7d).await?;
    let (total_30d, blocked_30d) = db.count_queries_since(since_30d).await?;

    let (cache_today, cache_7d, cache_30d) = tokio::try_join!(
        db.cache_stats_since(since_today),
        db.cache_stats_since(since_7d),
        db.cache_stats_since(since_30d),
    )?;
    let (cache_hits_today, allowed_total_today, avg_response_ms_today) = cache_today;
    let (cache_hits_7d, allowed_total_7d, avg_response_ms_7d) = cache_7d;
    let (cache_hits_30d, allowed_total_30d, avg_response_ms_30d) = cache_30d;

    let ratio = |blocked: i64, total: i64| -> f64 {
        if total > 0 {
            blocked as f64 / total as f64
        } else {
            0.0
        }
    };
    let hit_rate = |hits: i64, allowed: i64| -> f64 {
        if allowed > 0 {
            hits as f64 / allowed as f64
        } else {
            0.0
        }
    };

    Ok(Summary {
        total_today,
        blocked_today,
        total_7d,
        blocked_7d,
        total_30d,
        blocked_30d,
        block_ratio_today: ratio(blocked_today, total_today),
        block_ratio_7d: ratio(blocked_7d, total_7d),
        block_ratio_30d: ratio(blocked_30d, total_30d),
        cache_hit_rate_today: hit_rate(cache_hits_today, allowed_total_today),
        cache_hit_rate_7d: hit_rate(cache_hits_7d, allowed_total_7d),
        cache_hit_rate_30d: hit_rate(cache_hits_30d, allowed_total_30d),
        avg_response_ms_today,
        avg_response_ms_7d,
        avg_response_ms_30d,
        queries_1m,
    })
}
```

- [ ] **Step 5: Run test to verify it passes**

```
cd /home/nixos/Develop/claude/noadd && cargo nextest run --test stats_db_test compute_summary_populates_7d_and_30d_rates
```

Expected: PASS.

- [ ] **Step 6: Run the full test suite**

```
cd /home/nixos/Develop/claude/noadd && cargo nextest run
```

Expected: all tests PASS (existing `stats_api_test` is unaffected because the new fields are additive JSON keys).

- [ ] **Step 7: Format and commit**

```
cd /home/nixos/Develop/claude/noadd && cargo fmt
git add src/admin/stats.rs tests/stats_db_test.rs
git commit -S -m "feat(stats): add 7d/30d rates to summary endpoint"
```

---

## Task 2: Frontend — render sub lines on rate cards

**Files:**
- Modify: `admin-ui/dist/index.html:1349-1366` (inside `DashboardPage.renderStats`)

- [ ] **Step 1: Extend the formatted-values block**

Replace `admin-ui/dist/index.html:1349-1353` with:

```javascript
  renderStats(s) {
    const pct = (v) => ((v || 0) * 100).toFixed(1);
    const ms = (v) => (v || 0).toFixed(1);

    const ratio = s.total_today > 0 ? ((s.blocked_today / s.total_today) * 100).toFixed(1) : '0.0';
    const ratio7d = pct(s.block_ratio_7d);
    const ratio30d = pct(s.block_ratio_30d);
    const cacheRate = pct(s.cache_hit_rate_today);
    const cacheRate7d = pct(s.cache_hit_rate_7d);
    const cacheRate30d = pct(s.cache_hit_rate_30d);
    const avgMs = ms(s.avg_response_ms_today);
    const avgMs7d = ms(s.avg_response_ms_7d);
    const avgMs30d = ms(s.avg_response_ms_30d);
    const qps = ((s.queries_1m || 0) / 60).toFixed(1);
```

- [ ] **Step 2: Update the three rate cards to include `stat-sub` lines**

Replace `admin-ui/dist/index.html:1363-1365` with:

```html
      <div class="stat-card" data-i="2"><div class="stat-label">Block Rate</div><div class="stat-value green">${ratio}%</div><div class="stat-sub">7d: ${ratio7d}% / 30d: ${ratio30d}%</div></div>
      <div class="stat-card" data-i="3"><div class="stat-label">Cache Hit Rate</div><div class="stat-value accent">${cacheRate}%</div><div class="stat-sub">7d: ${cacheRate7d}% / 30d: ${cacheRate30d}%</div></div>
      <div class="stat-card" data-i="4"><div class="stat-label">Avg Response</div><div class="stat-value" style="color:var(--orange)">${avgMs}<span style="font-size:0.9rem;color:var(--text-dim)">ms</span></div><div class="stat-sub">7d: ${avgMs7d} ms / 30d: ${avgMs30d} ms</div></div>
```

Leave `data-i="0"`, `data-i="1"`, `data-i="5"` unchanged. Leave the `vals` array on line 1355 unchanged — it drives the flash-on-change animation using only the today values, which is the desired behavior (we flash the main number, not the sub line).

- [ ] **Step 3: Manually verify**

```
cd /home/nixos/Develop/claude/noadd && cargo run
```

Then in a browser, open the admin UI (default `http://localhost:3000/` or whatever the instance exposes), log in, and confirm the Dashboard shows:

- Block Rate card: main `X%`, sub `7d: Y% / 30d: Z%`
- Cache Hit Rate card: main `X%`, sub `7d: Y% / 30d: Z%`
- Avg Response card: main `X ms`, sub `7d: Y ms / 30d: Z ms`

Refresh a few times; confirm only the main value flashes, not the sub line.

Stop the server (Ctrl+C) when done.

- [ ] **Step 4: Commit**

```
cd /home/nixos/Develop/claude/noadd
git add admin-ui/dist/index.html
git commit -S -m "feat(dashboard): show 7d/30d values under rate KPIs"
```

---

## Task 3: Final verification and PR

- [ ] **Step 1: Run the full test suite one more time**

```
cd /home/nixos/Develop/claude/noadd && cargo nextest run
```

Expected: all tests PASS.

- [ ] **Step 2: Confirm lint is clean**

```
cd /home/nixos/Develop/claude/noadd && cargo clippy --all-targets -- -D warnings
```

Expected: no warnings.

- [ ] **Step 3: Push and open PR (English)**

```
cd /home/nixos/Develop/claude/noadd
git push -u origin feat/dashboard-rate-windows
gh pr create --base main --title "feat(dashboard): show 7d/30d values under rate KPIs" --body "$(cat <<'EOF'
## Summary
- Extend `Summary` with `block_ratio_{7d,30d}`, `cache_hit_rate_{7d,30d}`, and `avg_response_ms_{7d,30d}`.
- `compute_summary` derives the block ratios from existing counts and fetches 7d/30d cache stats via `tokio::try_join!` alongside the existing today call.
- Dashboard UI renders a `stat-sub` line under Block Rate, Cache Hit Rate, and Avg Response, matching the Queries Today / Blocked Today pattern.

## Test plan
- [ ] `cargo nextest run` (new `compute_summary_populates_7d_and_30d_rates` test plus the existing suite)
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] Manual: load the Dashboard, confirm all three rate cards show `7d: … / 30d: …` sub lines
EOF
)"
```

Expected: PR URL returned by `gh`.
