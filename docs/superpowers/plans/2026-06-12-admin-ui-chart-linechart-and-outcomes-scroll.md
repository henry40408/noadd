# Admin UI: convert query timelines to SVG line charts + kill the Outcomes phantom scrollbar

> Status: planned — investigation complete, fix verified against prototypes in a real browser.
> Single file under change: `admin-ui/dist/index.html` (~3573 lines, vanilla JS light-DOM web
> components, no build step). Everything below uses line numbers from commit `e522927`
> (current `main`); apply edits by the quoted anchor snippets, line numbers are orientation only.
> Work on a new branch, e.g. `fix/admin-ui-line-charts-and-outcomes-scroll`.

## What this fixes

- **Issue A** — the Dashboard "Queries (24h)" chart and the Statistics "Queries (last Nd)"
  timeline (up to 90 stacked bars) are too dense to read. Replace both with hand-written
  inline-SVG **line charts**, matching the existing in-house SVG chart
  (`StatsPage._renderRateTrend`, the "Block & Cache rate" card) in style and interaction.
- **Issue B** — the Statistics "Outcomes" panel shows a vertical scrollbar with only 3 rows.
  Root cause found and reproduced (see below): sub-pixel rounding at fractional browser zoom
  turns the unconditional `overflow-y: auto` on `stats-page .bar-list` into a 1px-scrollable
  phantom scrollbar. Fix: only long lists become scroll containers (`:has()`-gated), so Top
  Domains / Top Sources / Query Types (10 rows) keep their legitimate scroll.

## Hard constraints (do not violate)

- Vanilla JS only. No libraries, no build step. SVG is hand-assembled into `innerHTML`,
  exactly like `_renderRateTrend` (line 2711).
- All colors via existing CSS custom properties (`--accent`, `--red`, `--orange`, `--border`,
  `--text-dim`, `--bg-panel`) so dark **and** light themes work. Never hardcode hex.
  ⚠ In the dark theme `--accent` **equals** `--green` (#41f586), so the cached series must be
  `var(--orange)` (as the cached bars already are), *not* green, or it would be
  indistinguishable from the total line.
- Responsive: `viewBox` + `preserveAspectRatio="none"` + `width:100%` (same approach as
  `.rate-svg`); must look right at 375px.
- Preserve every `data-testid` (inventory below). **None live inside the edited regions**, so
  the rule is simply: do not touch markup outside the snippets quoted here.
- e2e suite (`e2e/`, playwright-bdd, 24 scenarios) must stay green.
- Smallest change: no legends, no new features. (Optional follow-up, NOT in scope: a
  `.rate-legend`-style legend under the stats timeline.)

## Investigation findings (verbatim, for zero-context implementer)

### Issue A — current bar-chart code

| What | Where |
|---|---|
| Dashboard card markup | line 2156–2159: `<div class="card fade-in" ... id="chart-card"><div class="card-title">Queries (24h)</div><div class="chart-container" id="chart"></div></div>` |
| Dashboard renderer | `DashboardPage.renderChart(rawData)`, lines 2319–2362. Data rows: `{timestamp, total, blocked}` (24 hourly buckets from `/api/stats/timeline`). Emits `.chart-area > .chart-col × N`, each with `.chart-tooltip` + `.chart-bar.total` + `.chart-bar.blocked`, then a `.chart-labels` row (~6 labels). Has a mobile merge block (lines 2323–2336) that halves bar count at ≤768px — obsolete for lines, delete it. |
| Stats timeline markup | lines 2417–2420: `#timeline-card` / `#timeline-title` / `<div class="chart-container" id="timeline-chart">` |
| Stats renderer | `StatsPage._renderTimeline(rawData)`, lines 2525–2582. Data rows: `{timestamp (sec), total, blocked, cached}` from `/api/stats/v2/timeline?range=7d|30d|90d` (up to ~90 rows). Same bar markup + `.chart-bar.cached`; same mobile merge block (lines 2532–2544). |
| Template to copy | `StatsPage._renderRateTrend`, lines 2711–2810: SVG `viewBox 600×140`, `preserveAspectRatio="none"`, paths stroked with CSS vars, 25/50/75 dashed gridlines, `.rate-cursor` group + `.rate-tooltip` div repositioned on `pointermove` to the nearest point, `pointerleave`/`pointercancel` to hide. |
| Bar CSS (will become dead) | `.chart-area` 493–498, `.chart-col` 500–508, `.chart-bar` 510–514, `.chart-bar.total/.blocked` 516–517, hover 519–520, `.chart-tooltip` parts of 522–555, edge-anchoring 557–567, `.chart-bar.cached` 934–935, stats-page overrides 1114–1120 (`gap:1px`, `min-width:3px`, `.chart-bar.total` recolor + 4-line comment). |
| CSS to KEEP | `.chart-container` (487–491, 200px tall, `position:relative` — the tooltip anchors to it), `.chart-labels`/`.chart-label` (569–583), `stats-page .chart-container { height: 200px; }` (1113, redundant but harmless), the overflow escapes `#chart-card, stats-page #timeline-card... { overflow: visible; }` (1133–1136 — lets the hover tooltip escape the card). |
| Tooltip CSS shared with other charts | The grouped selectors at 522–555 also style `.heatmap-tooltip` and `.rate-tooltip` — those two must keep working; only strip `.chart-tooltip` out of the groups. |

`grep` confirms `chart-area|chart-col|chart-bar|chart-tooltip` appear **nowhere else** in the
file or repo (e2e tests reference none of them).

### Issue B — Outcomes phantom scrollbar: measured root cause

- Scroll container: `stats-page .bar-list { max-height: 220px; overflow-y: auto; padding-right: 4px; }`
  — **line 1128**. Rows are emitted by `StatsPage._renderBarChart` (lines 2637–2661) as
  `.bar-list > .bar-row × N`; Outcomes (`#outcomes-chart`, populated at line 2666) has 2–3 rows.
- Measured in headless Chromium and Firefox against the real file + real render code:
  each `.bar-row` is **24.5px** tall (count cell: 12.59px number line + 10.91px pct line +
  1px margin), flex `gap: 6px` ⇒ 3 rows = **85.5px** content (fractional!), far below the
  220px cap. At zoom 1 there is no overflow (scrollHeight 86 == clientHeight 86): the panel
  does *not* scroll.
- **Reproduced** the phantom scrollbar in two real conditions:
  - Chromium, webfont unavailable (fallback metrics) at browser zoom 0.9 / 1.1 / 1.2:
    `scrollHeight 86 > clientHeight 85` → 1px-scrollable scrollbar appears.
  - Firefox, webfont loaded, zoom 1.1: `scrollHeight 87 > clientHeight 86` → same.
- Mechanism: the list's auto height is fractional (85.5px and scales fractionally with zoom);
  `scrollHeight` is rounded **up** while `clientHeight` snaps **down**, and because the element
  is unconditionally `overflow-y: auto` it becomes a scroll container and renders a scrollbar
  for that phantom 1px. The earlier `.bar-row-count` line-height 1.15→1.2 tweak (comment on
  line 1055) only shifted the metrics at zoom 1 — any zoom/font/DPI combination can re-break it.
- Fix principle: **a 3-row list must never be a scroll container at all.** Gate
  `max-height`/`overflow-y` on row count with `:has()`: 7 rows ≈ 207.5px < 220px (never needs
  scrolling), 8 rows ≈ 238px > 220px (genuinely overflows). Top Domains / Top Sources /
  Query Types render 10 rows → still scroll (verified: scrollHeight 299–300 vs clientHeight
  220 with the fix applied, in both browsers, all zooms). `:has()` is fine here — the file
  already requires `color-mix()` (line 994), a newer baseline than `:has()`.

### `data-testid` inventory (must all survive — none are inside edited regions)

Full set in the file (45 occurrences, unique ids):
`setup-error, setup-password, setup-password-confirm, setup-submit, setup-welcome,
setup-welcome-dismiss, login-error, login-password, login-submit, app-shell, nav-dashboard,
nav-stats, nav-logs, nav-filters, nav-settings, topbar-logout, next-step-banner,
next-step-banner-addr, next-step-banner-dismiss, live-toggle, dashboard-empty-state,
top-domains-card, stat-blocked-today, stat-block-rate, db-health-card, logs-empty-state,
domain-test-input, domain-test-submit, domain-test-result, filters-all-disabled-warning,
filters-enable-recommended, list-name-input, list-url-input, list-add-submit, rule-input,
rule-submit, rules-list, filter-list-row, filter-list-toggle, rule-row, rule-delete,
revoke-sessions`.

The two charts and the outcomes panel contain **zero** testids. The closest neighbors that
must not be disturbed: `live-toggle` + `dashboard-empty-state` (Dashboard header/empty state,
lines 2152–2154), `top-domains-card` (2161), `db-health-card` (2450). The e2e steps reference
charts only indirectly via these.

---

## Implementation steps

Apply in order. Steps 1–6 are CSS (all inside the single `<style>` block), 7–9 are JS.

### Step 1 — CSS: replace the bar-column rules with the line-chart SVG rule

Delete lines 493–520 (everything from `.chart-area {` through
`.chart-col:hover .chart-bar.blocked { opacity: 1; }`, keeping the preceding
`.chart-container` rule untouched) and put in their place:

```css
/* Timeline line-chart SVG (Dashboard 24h + Statistics Nd). Sits inside the
   200px .chart-container; 28px is the .chart-labels row (20px + 4px margin
   + 4px padding). preserveAspectRatio="none" stretches the 600×180 viewBox
   to the container, same approach as .rate-svg. */
.tl-svg {
  width: 100%;
  height: calc(100% - 28px);
  display: block;
  touch-action: none;
}
```

### Step 2 — CSS: strip `.chart-tooltip` from the shared tooltip rules

In the block currently at 522–555:

- Change the comment + group selector
  `/* Shared tooltip base — also styles .heatmap-tooltip and .rate-tooltip (Statistics page) */`
  `.chart-tooltip,` `.heatmap-tooltip,` `.rate-tooltip {` →
  `/* Shared tooltip base — .heatmap-tooltip and .rate-tooltip */`
  `.heatmap-tooltip,` `.rate-tooltip {`
- Change `.chart-tooltip,` `.rate-tooltip {` (lines 538–539, the padding/font block) →
  `.rate-tooltip {`
- Delete the `.chart-tooltip { bottom: calc(100% + 8px); left: 50%; transform: translateX(-50%); }`
  rule (545–549).
- Change `.chart-tooltip, .rate-tooltip { box-shadow: ... }` inside the light-scheme media
  query (552) → `.rate-tooltip { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }`
- Delete `.chart-col:hover .chart-tooltip { display: block; }` (555).

### Step 3 — CSS: delete the edge-anchoring block

Delete lines 557–567 in full (the comment
`/* Edge anchoring so tooltips don't overflow the chart horizontally */` and both
`.chart-col:nth-child(-n+3)` / `.chart-col:nth-last-child(-n+3)` rules). Do NOT touch the
similar `.heatmap-cell.edge-*` rules near line 1001 — those belong to the heatmap.

### Step 4 — CSS: delete the cached-bar rules

Delete lines 934–935 (keep the `/* Statistics page */` section comment on 933):

```css
.chart-bar.cached { background: var(--orange); opacity: 0.85; }
.chart-col:hover .chart-bar.cached { opacity: 1; }
```

### Step 5 — CSS: delete the stats-page bar overrides

Delete lines 1114–1120 (4-line comment beginning `/* Statistics timeline has up to 90 bars`
plus the three rules `stats-page .chart-area { gap: 1px; }`,
`stats-page .chart-col { min-width: 3px; }`, `stats-page .chart-bar.total { ... }`). Keep
line 1113 `stats-page .chart-container { height: 200px; }` and line 1121
`stats-page .heatmap-cell { height: 14px; }`.

### Step 6 — CSS: Issue B fix — gate `.bar-list` scrolling on row count

Replace line 1128:

```css
stats-page .bar-list { max-height: 220px; overflow-y: auto; padding-right: 4px; }
```

with:

```css
/* Only long lists become scroll containers. Short lists (Outcomes has 3 rows
   ≈ 85.5px) must never own a scrollbar: their fractional auto height rounds
   so scrollHeight exceeds clientHeight by 1px at fractional browser zoom,
   and overflow-y:auto then shows a phantom, 1px-scrollable bar (reproduced
   in Chromium and Firefox at 90–120% zoom). Rows are ~24.5px + 6px gap:
   7 rows ≈ 207px < 220px cap, 8 rows ≈ 238px > 220px — so gating on the 8th
   row enables scrolling exactly when content can actually exceed the cap.
   Top Domains / Top Sources / Query Types (10 rows) keep their scrollbar. */
stats-page .bar-list:has(> .bar-row:nth-child(8)) { max-height: 220px; overflow-y: auto; padding-right: 4px; }
```

Also update the now-stale comment on line 1055 inside `.bar-row-count` from
`line-height: 1.2; /* 1.15 produced a 1px sub-pixel overflow -> phantom scrollbar in .bar-list */`
to
`line-height: 1.2; /* compact two-line cell; phantom-scrollbar guard lives on the stats-page .bar-list:has(...) rule */`

### Step 7 — JS: add the shared line-chart renderer

Insert immediately after `customElements.define('registry-modal', RegistryModal);` (line 2132),
right before the `// --- Dashboard Page ---` comment. This code was prototyped and
screenshot-verified (dark + light + 375px, hover tooltip working) before planning:

```js
// --- Shared SVG line chart for query-volume timelines ---
// Used by Dashboard "Queries (24h)" and Statistics "Queries (last Nd)".
// Modeled on StatsPage._renderRateTrend (same cursor/tooltip interaction).
// el      — a .chart-container (position:relative, 200px tall)
// data    — raw API rows; series[0].key must be 'total': it sets the y-scale
//           and gets the area fill
// series  — [{ key, color }] drawn in order (total first, underneath)
// fmtX    — (row) => x-axis label HTML (must be pre-escaped)
// fmtTooltip — (row) => tooltip HTML (must be pre-escaped)
function renderTimelineChart(el, data, series, fmtX, fmtTooltip) {
  const len = data.length;
  const w = 600, h = 180, padX = 8, padY = 12;
  const innerW = w - padX * 2, innerH = h - padY * 2;
  const max = Math.max(...data.map(d => d[series[0].key] || 0), 1);
  const xs = (i) => padX + (len === 1 ? innerW / 2 : (i / (len - 1)) * innerW);
  const ys = (v) => padY + innerH - (v / max) * innerH;

  const points = [];
  const paths = series.map(() => []);
  for (let i = 0; i < len; i++) {
    const d = data[i];
    const x = xs(i);
    const yByKey = {};
    series.forEach((s, si) => {
      const y = ys(d[s.key] || 0);
      yByKey[s.key] = y;
      paths[si].push(`${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`);
    });
    points.push({ x, d, yByKey });
  }
  const baseline = (padY + innerH).toFixed(1);
  const totalArea = `${paths[0].join(' ')} L${xs(len - 1).toFixed(1)},${baseline} L${xs(0).toFixed(1)},${baseline} Z`;
  const ticks = [0.25, 0.5, 0.75].map(p => {
    const y = ys(max * p).toFixed(1);
    return `<line x1="${padX}" y1="${y}" x2="${padX + innerW}" y2="${y}" stroke="var(--border)" stroke-dasharray="2 4" stroke-width="0.5"/>` +
      `<text x="${padX + 2}" y="${(parseFloat(y) - 2).toFixed(1)}" fill="var(--text-dim)" font-size="8" font-family="var(--font-sans)">${formatNum(Math.round(max * p))}</text>`;
  }).join('');
  const lines = series.map((s, si) =>
    `<path d="${paths[si].join(' ')}" fill="none" stroke="${s.color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>`
  ).join('');
  const dots = series.map(s => `<circle class="tl-dot" data-key="${s.key}" cx="0" cy="0" r="3" fill="${s.color}" stroke="var(--bg-panel)" stroke-width="1"/>`).join('');
  // A single data point draws no path — mark it with static dots instead.
  const single = len === 1 ? series.map(s => `<circle cx="${xs(0).toFixed(1)}" cy="${points[0].yByKey[s.key].toFixed(1)}" r="2.5" fill="${s.color}"/>`).join('') : '';

  const labelEvery = Math.max(1, Math.floor(len / 6));
  let labels = '<div class="chart-labels">';
  for (let i = 0; i < len; i += labelEvery) labels += `<div class="chart-label">${fmtX(data[i])}</div>`;
  labels += '</div>';

  el.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" class="tl-svg">
      ${ticks}
      <path d="${totalArea}" fill="${series[0].color}" fill-opacity="0.10"/>
      ${lines}${single}
      <g class="rate-cursor">
        <line x1="0" y1="${padY}" x2="0" y2="${padY + innerH}" stroke="var(--text-dim)" stroke-width="0.5" stroke-dasharray="2 3"/>
        ${dots}
      </g>
    </svg>
    <div class="rate-tooltip"></div>
    ${labels}`;

  const svg = el.querySelector('.tl-svg');
  const cursor = el.querySelector('.rate-cursor');
  const cursorLine = cursor.querySelector('line');
  const tooltip = el.querySelector('.rate-tooltip');
  const dotEls = [...cursor.querySelectorAll('.tl-dot')];
  const onMove = (evt) => {
    const rect = svg.getBoundingClientRect();
    if (rect.width === 0) return;
    const svgX = ((evt.clientX - rect.left) / rect.width) * w;
    let best = points[0];
    for (const p of points) if (Math.abs(p.x - svgX) < Math.abs(best.x - svgX)) best = p;
    cursorLine.setAttribute('x1', best.x.toFixed(1));
    cursorLine.setAttribute('x2', best.x.toFixed(1));
    dotEls.forEach(c => { c.setAttribute('cx', best.x.toFixed(1)); c.setAttribute('cy', best.yByKey[c.dataset.key].toFixed(1)); });
    cursor.classList.add('active');
    tooltip.innerHTML = fmtTooltip(best.d);
    const containerRect = el.getBoundingClientRect();
    const pxX = (best.x / w) * rect.width;
    const topY = Math.min(...series.map(s => best.yByKey[s.key]));
    const pxY = (rect.top - containerRect.top) + (topY / h) * rect.height;
    tooltip.style.left = `${pxX}px`;
    tooltip.style.top = `${pxY}px`;
    tooltip.classList.add('active');
  };
  const onLeave = () => { cursor.classList.remove('active'); tooltip.classList.remove('active'); };
  svg.addEventListener('pointermove', onMove);
  svg.addEventListener('pointerleave', onLeave);
  svg.addEventListener('pointercancel', onLeave);
}
```

Notes that make this fit the codebase:
- `.rate-cursor` / `.rate-tooltip` CSS classes are intentionally reused (they're generic:
  display-toggled by `.active`, positioned absolutely inside the `position:relative`
  container). No new tooltip CSS needed.
- `vector-effect="non-scaling-stroke"` keeps the 1.5px strokes crisp despite the non-uniform
  `preserveAspectRatio="none"` scaling (the dots/tick text still scale like in the existing
  rate chart — accepted there, accepted here).
- Re-rendering (Dashboard polls every 10s) replaces `innerHTML`, so the old listeners are
  garbage-collected with the old SVG — same lifecycle as `_renderRateTrend`.

### Step 8 — JS: rewrite `DashboardPage.renderChart`

Replace the whole method, lines 2319–2362 (from `renderChart(rawData) {` through its closing
`}` right before `renderTopDomains(data) {`) with:

```js
  renderChart(rawData) {
    if (!rawData || !rawData.length) { this.querySelector('#chart').innerHTML = '<p style="color:var(--text-dim);text-align:center;padding:40px">No data yet</p>'; this._prevChart = null; return; }
    this._flashIfChanged('_prevChart', rawData.map(d => d.total + ',' + d.blocked).join(';'), '#chart-card');
    renderTimelineChart(this.querySelector('#chart'), rawData, [
      { key: 'total', color: 'var(--accent)' },
      { key: 'blocked', color: 'var(--red)' },
    ],
    (d) => formatTime(d.timestamp),
    (d) => {
      const pct = d.total > 0 ? ((d.blocked / d.total) * 100).toFixed(0) : '0';
      return `${formatTime(d.timestamp)}<br><span style="color:var(--accent)">${formatFull(d.total)} total</span> · <span style="color:var(--red)">${formatFull(d.blocked)} blocked</span> (${pct}%)`;
    });
  }
```

This intentionally drops the ≤768px two-bar merge (lines 2323–2336): it existed solely to
reduce bar density, which lines don't suffer from. Tooltip text is byte-identical to the old
`.chart-tooltip` content. Empty-state and flash behavior unchanged.

### Step 9 — JS: rewrite `StatsPage._renderTimeline`

Replace the whole method, lines 2525–2582 (from `_renderTimeline(rawData) {` through its
closing `}` right before `_renderHeatmap(rawData) {`) with:

```js
  _renderTimeline(rawData) {
    const el = this.querySelector('#timeline-chart');
    if (!rawData || !rawData.length) {
      el.innerHTML = '<p style="color:var(--text-dim);text-align:center;padding:40px">No data yet</p>';
      return;
    }
    const fmtDay = (d) => esc(new Date(d.timestamp * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' }));
    renderTimelineChart(el, rawData, [
      { key: 'total', color: 'var(--accent)' },
      { key: 'cached', color: 'var(--orange)' },
      { key: 'blocked', color: 'var(--red)' },
    ],
    fmtDay,
    (d) => {
      const blocked = d.blocked || 0;
      const cached = d.cached || 0;
      const blockedPct = formatPct(blocked, d.total);
      const cachedPct = formatPct(cached, d.total);
      const blockedStr = blockedPct ? `${formatFull(blocked)} blocked (${blockedPct})` : `${formatFull(blocked)} blocked`;
      const cachedStr = cachedPct ? `${formatFull(cached)} cached (${cachedPct})` : `${formatFull(cached)} cached`;
      return `${fmtDay(d)}<br><span style="color:var(--accent)">${formatFull(d.total)} total</span> · <span style="color:var(--red)">${blockedStr}</span> · <span style="color:var(--orange)">${cachedStr}</span>`;
    });
  }
```

Two deliberate deltas from the old tooltip/bars:
- The cached tooltip span changes `var(--green)` → `var(--orange)` to match the cached line
  color (the old code already painted cached *bars* orange but the tooltip green — an
  inconsistency, and green would now collide with the accent-colored total line in dark mode).
- The mobile merge block (2532–2544) is dropped, same rationale as Step 8.
- Note the line semantics change vs the bars: bars were *stacked* (allowed+cached+blocked
  segments summing to total); the lines plot **absolute** total / cached / blocked values,
  which is the standard reading for a line chart and matches the tooltip numbers.

---

## Verification

All commands: run `pwd` first; the repo root is `/home/nixos/Develop/claude/noadd`.

1. **Syntax sanity** — the file is a single HTML page; quickest check is loading it:
   `node -e "const s=require('fs').readFileSync('admin-ui/dist/index.html','utf8'); console.log(s.length)"`
   then the browser checks below (any JS syntax error kills every component — the pages would
   render empty).

2. **e2e (playwright-bdd, 24 scenarios)** — requires the binary:
   ```sh
   cd /home/nixos/Develop/claude/noadd && cargo build
   cd /home/nixos/Develop/claude/noadd/e2e && npm test
   ```
   Expect 24/24 green. No test touches chart internals (verified: the only stats-related
   selector is `nav-stats`; dashboard steps use `live-toggle`, `stat-blocked-today`,
   `stat-block-rate`, `db-health-card`) — failures would indicate a JS error, not a selector
   change.

3. **Visual + behavioral, no server needed** (the components are light-DOM and the real
   functions are callable against `file://`). Use the e2e project's playwright
   (`e2e/node_modules`, chromium installed). Script pattern (proven during planning):
   - `page.goto('file:///home/nixos/Develop/claude/noadd/admin-ui/dist/index.html')`
   - `page.evaluate`: clear `document.body`, append `<div class="main-content">` containing a
     `document.createElement('stats-page')` (its API calls fail silently — the skeleton still
     renders), then drive the real renderers with mock data:
     - `sp._renderTimeline(Array.from({length:90},(_,i)=>({timestamp: 1750000000+i*86400, total: 8000+((i*37)%4000), blocked: 900+((i*13)%500), cached: 2000+((i*17)%700)})))`
     - `sp._renderBarChart('#outcomes-chart', [['allowed',1234],['blocked',567],['cached',89]], 'var(--orange)')`
     - `sp._renderBarChart('#qtypes-chart', Array.from({length:10},(_,i)=>['TYPE'+i, 1000-i*50]), 'var(--accent)')`
     - Same for the dashboard: mount `dashboard-page`… or simpler, mount a bare
       `<div class="card" id="chart-card"><div class="chart-container" id="chart"></div></div>`
       and call `renderTimelineChart` directly with 24 hourly rows.
   - Checks:
     - [ ] `#timeline-chart svg.tl-svg` exists; **no** `.chart-bar` elements remain anywhere.
     - [ ] Hover middle of each SVG → `.rate-tooltip.active` visible with correct text/colors.
     - [ ] Screenshots at viewport 1280×900 **and** 375×800, with `colorScheme: 'dark'` and
       `'light'` (4 shots) — lines green/orange/red on both themes, x-labels readable, nothing
       overflowing the card frame.
     - [ ] **Outcomes (Issue B)**: `getComputedStyle(outcomesList).overflowY === 'visible'`
       and `outcomesList.scrollHeight - outcomesList.clientHeight <= 1` with **no scrollbar**;
       Query Types (10 rows): `overflowY === 'auto'`, `clientHeight === 220`,
       `scrollHeight ≈ 299` → still scrolls.
     - [ ] **Zoom regression (the actual repro)**: with `ctx.route('**fonts.bunny.net**', r => r.abort())`
       and `document.documentElement.style.zoom = '1.1'`, the outcomes list must show no
       scrollbar (it cannot — it is no longer a scroll container), while qtypes still scrolls.
4. **Manual smoke (optional but recommended)**: `cargo run` with an existing DB, open the
   Dashboard and Statistics pages, flip 7d/30d/90d (the 90d line must stay smooth and the
   tooltip must track the pointer), and toggle the OS theme.

## Out of scope / optional follow-ups (do not implement unbidden)

- Legend row (`.rate-legend` style) under the two new line charts.
- Removing the redundant `stats-page .chart-container { height: 200px; }` (line 1113).
- De-duplicating the two `fmtDay`-style date formatters used across stats renderers.
