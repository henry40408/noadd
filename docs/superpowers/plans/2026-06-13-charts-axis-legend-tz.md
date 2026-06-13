# Plan: Charts — axis labels, legends, browser timezone, no squashing

Branch: `fix/charts-axis-legend-tz`
Scope: admin UI only. **All product changes live in one file: `admin-ui/dist/index.html`** (the
entire admin UI is a single hand-written HTML file with inline CSS/JS, embedded into the binary
via `include_dir!` in `src/admin/api.rs:119` — a rebuild is required for the server to serve edits).

## 1. Discovery — where the three charts live

Charting approach: **hand-rolled inline SVG line charts** stretched with
`preserveAspectRatio="none"` over a fixed `600×{180,140}` viewBox. No JS chart library.
Text must NEVER live inside these stretched SVGs (non-uniform scaling distorts glyphs) — the
codebase already solves this with HTML overlays (`.tl-yticks`) and an HTML label row
(`.chart-labels`). See the comment block at `admin-ui/dist/index.html:493-498` and `2164-2167`.

| # | Chart | Container | Renderer (index.html) | Data source |
|---|-------|-----------|------------------------|-------------|
| 1 | Dashboard "Queries (24h)" | `#chart` inside `#chart-card` (line ~2255) | `DashboardPage.renderChart` (~2418) → shared `renderTimelineChart` (~2138) | `GET /api/stats/timeline` → `stats::compute_timeline` → `Db::timeline_since` (`src/db.rs:1308`). **Timestamps in epoch milliseconds**; dynamic bucket (1m–1h). |
| 2 | Statistics "Queries (last Nd)" | `#timeline-chart` inside `#timeline-card` (~2485) | `StatsPage._renderTimeline` (~2593) → shared `renderTimelineChart` | `GET /api/stats/v2/timeline?range=7d|30d|90d` → `Db::timeline_multi_since` (`src/db.rs:1113`). **Timestamps in epoch seconds**; buckets: 7d→1h, 30d→6h, 90d→1d (`src/admin/stats.rs:170-176`). |
| 3 | Statistics "Block & Cache rate (last Nd)" | `#rate-trend-chart` inside `#rate-trend-card` (~2489) | `StatsPage._renderRateTrend` (~2744), **bespoke** (not shared) | Same `/api/stats/v2/timeline` payload as #2. |

Shared helper relationships: charts 1+2 share `renderTimelineChart(el, data, series, fmtX, fmtTooltip)`
— one change there covers both. Chart 3 is standalone but was the model for the shared helper
(same tooltip/cursor interaction, `.rate-tooltip`, `.rate-cursor`).

Relevant time helpers (index.html ~1505-1531): `normalizeTs(ts)` (handles s vs ms),
`formatTime(ts)` (`toLocaleTimeString`, browser tz), `absTime`, `esc`.

### Current state vs. the four requirements

| Requirement | Chart 1 (24h) | Chart 2 (Nd queries) | Chart 3 (Nd rates) |
|---|---|---|---|
| 1. Axis date/time | ✅ time labels via `formatTime` in `.chart-labels` | ✅ date labels via `toLocaleDateString([], {month:'short', day:'numeric'})` | ❌ **no x-axis labels at all** |
| 2. Legend | ❌ none | ❌ none | ✅ `.rate-legend` ("blocked %", "cached %") |
| 3. Browser tz | ✅ `toLocaleTimeString` with no `timeZone` option = browser tz | ✅ `toLocaleDateString` | ✅ tooltip already local; axis must use same local formatting when added |
| 4. No squashing | ✅ y-ticks are HTML overlay `.tl-yticks`; x labels are HTML | ✅ same | ❌ **`25%/50%/75%` `<text>` elements live inside the `preserveAspectRatio="none"` SVG** (line ~2780) → glyphs are non-uniformly scaled (squashed) |

So the real gaps are: legends for charts 1+2, x-axis date labels for chart 3, and de-squashing
chart 3's percent tick labels. Timezone is already browser-local everywhere (all formatting goes
through `toLocale*` with no explicit `timeZone`); the plan adds no UTC formatting anywhere.

### Existing conventions to honor

- Legend markup/style: `.rate-legend` (CSS ~1077-1091) — mono font, `0.7rem`, lowercase series
  names, `<span><i style="background:VAR"></i>name</span>`.
- X labels: `.chart-labels` flex row (CSS ~554-568), one `.chart-label` per
  `labelEvery = max(1, floor(len/6))` data points, `space-between`.
- Y tick text: HTML overlay (`.tl-yticks` / `.tl-ytick`, CSS ~510-527), `top:` as a percentage of
  the SVG box, `aria-hidden="true"`, `pointer-events:none`.
- Colors: total=`var(--accent)`, blocked=`var(--red)`, cached=`var(--orange)` in chart 2's lines
  (note: chart 3's legend uses `var(--green)` for cached % — leave chart 3's colors as-is).
- Selectors relied on by tooling (do NOT break): `#chart .tl-svg`, `#timeline-chart .tl-svg`,
  `#rate-trend-chart svg` (used by `e2e/screenshots/capture.mjs:61-67`). No `data-testid`s exist
  on charts today; don't add any unless a test needs one.
- HTML injected into labels/tooltips must be pre-escaped with `esc()`.

## 2. Implementation steps (all in `admin-ui/dist/index.html`)

### Step A — Legend support in the shared `renderTimelineChart` (fixes req. 2 for charts 1 & 2)

1. **Extend the series descriptor** with a `label` field. Update the doc comment above
   `renderTimelineChart` (~2128-2137) to document it.
2. In `renderTimelineChart`, after building `labels`, build a legend and append it to the
   container HTML (after `${labels}`):

   ```js
   const legend = '<div class="rate-legend tl-legend">' +
     series.map(s => `<span><i style="background:${s.color}"></i>${s.label}</span>`).join('') +
     '</div>';
   ```

   and render `...${labels}${legend}` in `el.innerHTML`.
3. **CSS — reserve room inside the fixed 200px `.chart-container`** so nothing overlaps
   (this is the "no squashing" guard for the new legend). In the `/* Chart */` block (~486-527):
   - `.tl-svg { height: calc(100% - 28px); }` → `calc(100% - 50px)`
   - `.tl-yticks { bottom: 28px; }` → `bottom: 50px`
   - add: `.tl-legend { height: 14px; margin-top: 8px; align-items: center; }`
     (14px legend + 8px margin = 22px; 28px labels row + 22px legend = 50px reserved)
   - Update the two explanatory CSS comments (lines ~493-498 and ~506-509) that currently say
     "28px" so the math stays documented.
4. **Call sites:**
   - `DashboardPage.renderChart` (~2421): `{ key: 'total', color: 'var(--accent)', label: 'total' }`,
     `{ key: 'blocked', color: 'var(--red)', label: 'blocked' }`.
   - `StatsPage._renderTimeline` (~2600): labels `'total'`, `'cached'`, `'blocked'` on the
     existing three series.

Nothing changes for the empty-data path (`No data yet`) — legend only renders with data.

### Step B — X-axis date labels for chart 3 (fixes req. 1 for the rate chart)

In `StatsPage._renderRateTrend` (~2744):

1. Reuse the exact `.chart-labels` pattern from `renderTimelineChart` (~2184-2187):

   ```js
   const fmtDay = (d) => esc(new Date(d.timestamp * 1000)
     .toLocaleDateString([], { month: 'short', day: 'numeric' }));   // browser tz
   const labelEvery = Math.max(1, Math.floor(len / 6));
   let labels = '<div class="chart-labels">';
   for (let i = 0; i < len; i += labelEvery) labels += `<div class="chart-label">${fmtDay(rawData[i])}</div>`;
   labels += '</div>';
   ```

   (`fmtDay` matches the formatting already used in this function's tooltip at ~2826 — consider
   reusing the new `fmtDay` there to deduplicate.)
2. Insert `${labels}` into `el.innerHTML` between the closing `</svg>` and
   `<div class="rate-tooltip">`, so the visual order is: svg → y-tick overlay (Step C) → labels →
   legend. `.rate-chart-container` has no fixed height (CSS ~1060-1063), so the extra ~28px just
   grows the card — no height juggling needed here.

### Step C — De-squash chart 3's percent tick labels (fixes req. 4)

Same fix the codebase already applied to the timeline charts
(see `docs/superpowers/plans/2026-06-13-admin-ui-fix-yaxis-label-squish.md`):

1. In the `ticks` builder (~2778-2781), **delete the `<text …>${p}%</text>` part**, keeping only
   the gridline `<line>`s.
2. Build an HTML overlay (mirrors `renderTimelineChart` ~2172-2176, reusing the `.tl-ytick`
   span styling):

   ```js
   const yTicks = '<div class="rate-yticks" aria-hidden="true">' +
     [25, 50, 75].map(p =>
       `<span class="tl-ytick" style="top:${((ys(p) / h) * 100).toFixed(2)}%">${p}%</span>`
     ).join('') + '</div>';
   ```

   Render it immediately after the `</svg>`.
3. CSS: add next to `.rate-svg` (~1064):

   ```css
   /* Tracks the 160px .rate-svg box exactly so % labels are real HTML and
      never distorted by preserveAspectRatio="none" (same fix as .tl-yticks). */
   .rate-yticks { position: absolute; top: 0; left: 0; right: 0; height: 160px; pointer-events: none; }
   ```

   (`.rate-chart-container` is already `position:relative`; `.rate-svg` is fixed `height:160px`,
   so `top%`-of-160px positions land on the gridlines; `.tl-ytick`'s
   `translateY(calc(-100% - 2px))` puts the text just above each line, same as the other charts.)

### Step D — Timezone (req. 3): verify, don't change

All three charts already format with `toLocaleTimeString`/`toLocaleDateString` and no `timeZone`
option ⇒ browser timezone. Keep it that way in all new code (Steps A–C use the same helpers).
Mind the **s-vs-ms asymmetry**: chart 1 rows carry epoch **ms** (`Db::timeline_since` returns the
raw ms bucket) and go through `formatTime`→`normalizeTs`; charts 2/3 carry epoch **seconds** and
multiply by 1000 inline. Do not "fix" either path; just don't mix them.

### Step E — Tests & docs (per repo rules: update existing files, no new docs)

- **README screenshots** (`docs/screenshots/dashboard.png`, `statistics.png`, …) show these
  charts and are the user-facing documentation of this UI. Regenerate them after the change:
  `cd /home/nixos/Develop/claude/noadd && cargo build && cd e2e && npm run screenshots`.
- **e2e** (`e2e/`, playwright-bdd): `dashboard.feature` scenarios run against a shared instance
  with **no query traffic**, so the charts render the "No data yet" branch there — chart
  internals (legend/labels) cannot be asserted in the existing fixtures without seeding traffic.
  No existing test asserts chart internals, so there is nothing to update;
  `cd e2e && npm test` must still pass (it exercises login/nav around these pages).
  The screenshot pipeline's waits (`capture.mjs:61-67`) double as a smoke test that the charts
  still render with seeded data.
- **Rust**: no Rust changes planned ⇒ `tests/stats_api_test.rs` etc. are untouched; the full
  suite must still pass.

## 3. Verification

Per repo rules: `pwd` before build/test commands; tests via `cargo nextest run`; `cargo fmt`
before committing (no .rs edits expected, but run it anyway).

1. `pwd && cargo build` — required because `index.html` is compile-time-embedded
   (`include_dir!`); the screenshot pipeline runs `target/debug/noadd`.
2. `pwd && cargo nextest run` — full suite green (sanity: nothing server-side changed).
3. `cd /home/nixos/Develop/claude/noadd/e2e && npm test` — playwright-bdd suite green.
4. `cd /home/nixos/Develop/claude/noadd/e2e && npm run screenshots` — then **visually inspect**
   `docs/screenshots/dashboard.png` and `docs/screenshots/statistics.png`:
   - Chart 1: time-of-day x labels (e.g. `14:00`), legend `— total — blocked` under the chart,
     no overlap between svg/labels/legend inside the 200px container.
   - Chart 2: date x labels (e.g. `Jun 12`), legend `total / cached / blocked`.
   - Chart 3: date x labels now present; `25% 50% 75%` labels crisp and undistorted (compare
     glyph shape with the y-ticks of chart 2 above it); legend unchanged.
5. **Timezone check** (manual, via the seeded DB the screenshot run leaves behind):
   run `./target/debug/noadd --db-path e2e/.tmp/screenshots.db --http-addr 127.0.0.1:14150 --dns-addr 127.0.0.1:15150`,
   then view the UI in browsers pinned to two zones (e.g. launch with `TZ=UTC` and
   `TZ=Asia/Taipei`, or Playwright `timezoneId`). Axis labels and tooltips must shift by the
   zone offset (24h chart hours differ by +8; Nd tooltips/labels shift date at local midnight).
6. **No-squash check at odd sizes**: resize the window (e.g. 960px breakpoint where
   `.stats-row-2col` collapses) and zoom 90–120%; x/y labels must keep their aspect (they are
   HTML, so they will), and the legend must not clip inside `.chart-container`.
7. Hover each chart: tooltip + cursor still work (pointer handlers untouched; y-tick overlays are
   `pointer-events:none`).

## 4. Risks & notes

- **Fixed-height container math (charts 1+2).** `.chart-container` is hard-coded 200px (twice:
  line ~488 and `stats-page .chart-container` ~1101). The 28px→50px reserve in `.tl-svg` /
  `.tl-yticks` must match the actual legend box (14px + 8px margin) or labels/legend will
  overlap or the plot area shrinks asymmetrically. Verify visually (step 4/6); adjust the
  reserve, not the container height, if off by a pixel or two.
- **Don't put any `<text>` in the stretched SVGs** — that is the original squash bug class.
- **UTC-aligned buckets (known limitation, out of scope).** The server buckets rows by
  `timestamp / bucket * bucket` (UTC-epoch-aligned). For the 90d range (1-day buckets), a viewer
  west of UTC sees each bucket's *start instant* rendered as the previous local date, and bucket
  boundaries don't fall on local midnight. Requirement 3 (render in browser tz) is satisfied;
  truly tz-aware *bucketing* would need the client to pass its offset to
  `/api/stats/v2/timeline` and a SQL change — list as an optional follow-up, do not do it now.
- **7d range tooltips are date-only for hourly buckets** (24 buckets share one date in the
  tooltip of charts 2/3). Axis requirement (date) is met; adding `HH:mm` to sub-day-bucket
  tooltips is an optional follow-up, not part of this fix.
- **`.chart-labels` uses `justify-content:space-between`**, so the last label is pinned to the
  right edge even when `len % labelEvery !== 0` — labels are evenly spaced, not exactly aligned
  to their data x-positions. Pre-existing behavior for charts 1+2; chart 3 inherits it by reusing
  the same pattern (consistency over precision). Out of scope to change.
- **Selector stability**: keep `.tl-svg`, `.rate-svg`, `#chart`, `#timeline-chart`,
  `#rate-trend-chart` exactly as-is (screenshot pipeline waits on them).
- The `_flashIfChanged` signature for chart 1 (`total + ',' + blocked`) is unaffected.

## 5. Optional follow-ups (NOT in this change)

1. Sub-day tooltip time for the 7d range (charts 2 & 3).
2. Client-tz-aware day bucketing for the 90d range (API + SQL change).
3. Align `.chart-labels` to true data x-positions (absolute positioning) instead of
   `space-between`.
4. Seeded-traffic e2e fixture so chart internals (legend text, label count) become assertable.

## 6. Follow-up / correction (post-implementation)

This plan's "Current state vs. the four requirements" table (§1) marked requirement 4
("No squashing") as ✅ for charts 1 & 2. **That assessment was incomplete.** It only audited
the y-tick *text* glyphs (already moved to the `.tl-yticks` HTML overlay) and missed that the
hover **marker dots** — and the single-point static dots — are SVG `<circle>`s rendered *inside*
the `preserveAspectRatio="none"` timeline SVG. Non-uniform scaling stretches them into ellipses
just like text. Worse, Step A's `.tl-svg` reserve change (28px → 50px) shrank the plot height
(sy/sx ≈ 0.43 at 1280px wide), which **amplified** the latent dot squash into a visible bug.

Fixed in a follow-up commit (`3d5d353`): the marker dots were moved out of the stretched SVG into
an HTML overlay (`.tl-dots`) positioned with `left/top` as a % of the SVG box — the same overlay
technique already used for `.tl-yticks`. This covers both charts sharing `renderTimelineChart`
(dashboard 24h + statistics Nd). Verified with a Playwright probe (hover → `.tl-dot` renders 6×6,
round, at any container aspect).

**Lesson:** the squash bug class is broader than "no `<text>` in the stretched SVG" (Risk §4) — it
covers *any* element meant to keep a fixed shape (round markers included). Anything shape-sensitive
belongs in an HTML overlay.

**Still latent (optional follow-up):** chart 3's `rate-dot-cached` / `rate-dot-blocked` markers
(`index.html`, the `_renderRateTrend` cursor group) are still SVG `<circle>`s with the same issue.
Not reported, so left as-is per smallest-change.
