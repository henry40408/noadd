# Fix: Dashboard/Stats timeline chart Y-axis numbers are squished

**Date:** 2026-06-13
**File under change:** `admin-ui/dist/index.html` (single-file admin UI, vanilla JS + inline SVG, no build step)

## Root cause (confirmed)

The Y-axis numeric labels are SVG `<text>` elements rendered **inside** an SVG that is
non-uniformly stretched by `preserveAspectRatio="none"`.

Evidence, all in `admin-ui/dist/index.html`:

- **Line 2127** (inside `renderTimelineChart`, the shared helper used by both the
  Dashboard "Queries (24h)" chart and the Statistics "Queries (last Nd)" chart):

  ```js
  `<text x="${padX + 2}" y="${(parseFloat(y) - 2).toFixed(1)}" fill="var(--text-dim)" font-size="8" font-family="var(--font-sans)">${formatNum(Math.round(max * p))}</text>`
  ```

- **Line 2142** — the SVG template those `<text>` nodes live in:

  ```html
  <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" ... class="tl-svg">
  ```

  with `w = 600, h = 180` (line 2103).

- **Lines 497–502** — `.tl-svg { width: 100%; height: calc(100% - 28px); ... }`
  inside the 200 px `.chart-container` (lines 487–491), so the SVG box is always
  *container-width × 172 px*.

**Mechanism:** `preserveAspectRatio="none"` maps the 600×180 viewBox onto the
rendered box with independent X and Y scale factors:

- `scaleY = 172 / 180 ≈ 0.956` (always ~1)
- `scaleX = containerWidth / 600` — on the Dashboard at 1280 px viewport the chart
  card is roughly full content width (~900–1150 px), so `scaleX ≈ 1.5–1.9`; at
  375 px mobile the chart is ~330 px, so `scaleX ≈ 0.55`.

Every glyph in the `<text>` nodes is scaled by that non-uniform transform: at
desktop the numbers are stretched ~1.5–1.9× wide while staying ~1× tall (looks
vertically flattened / 壓扁), at mobile they are horizontally crushed. The
polylines don't show this because strokes use
`vector-effect="non-scaling-stroke"` (line 2130) and a stretched *path geometry*
is exactly what we want — but `vector-effect` has no equivalent for glyph shapes.

**Is the Statistics timeline affected too?** Yes, structurally — `StatsPage._renderTimeline`
(lines 2544–2566) calls the same `renderTimelineChart`. It is *less visibly* distorted at
desktop because it sits in `.stats-row-2col` (half width → chart ≈ 540 px → `scaleX ≈ 0.9`,
close to `scaleY 0.956`), which is why the Dashboard was noticed first. Below 960 px the
grid collapses to one column (line 1097) and the stats chart gets the same full-width
distortion. **The fix lives in the shared helper, so both charts are fixed by one change.**

**The older `_renderRateTrend` chart** (lines 2695–2794) has the *same latent bug*: its
"25% / 50% / 75%" `<text>` ticks (line 2731) sit inside a `preserveAspectRatio="none"`
SVG (line 2734, viewBox 600×140, `.rate-svg` 160 px tall → `scaleY ≈ 1.14`). At desktop
half-width it's near-uniform so it has passed unnoticed. Fixing it is **optional Task 3**
(recommended for visual consistency on the Statistics page, where it renders side-by-side
with the fixed timeline).

## Fix design (minimal)

Keep the polyline/area/gridlines in the stretched SVG (they *should* stretch).
Move only the numeric tick labels out of the SVG into an absolutely-positioned
HTML overlay inside `.chart-container` (which is already `position: relative`,
line 489). HTML text is never subjected to the SVG's non-uniform transform, so
the glyphs render at native proportions at any width, in both themes
(`var(--text-dim)` adapts), with IBM Plex Mono via `var(--font-mono)`.

Vertical placement: each gridline's viewBox `y` converts to a percentage of the
SVG box — `top: (y / h) * 100%` — on an overlay whose box exactly matches
`.tl-svg` (`inset: 0 0 28px 0`, mirroring `height: calc(100% - 28px)`). A
`translateY(calc(-100% - 2px))` reproduces the old "baseline 2 units above the
gridline" placement. `pointer-events: none` keeps the existing
pointermove/tooltip interaction on the SVG intact.

No `data-testid` exists inside either chart container (`#chart`, `#timeline-chart`);
nearby testids `dashboard-empty-state` (line 2204), `live-toggle` (2202),
`top-domains-card` (2211) are untouched.

---

## Task 1 — JS: move Y tick labels out of the SVG (`renderTimelineChart`)

**Anchor:** lines 2124–2128 of `admin-ui/dist/index.html`.

Replace:

```js
  const ticks = [0.25, 0.5, 0.75].map(p => {
    const y = ys(max * p).toFixed(1);
    return `<line x1="${padX}" y1="${y}" x2="${padX + innerW}" y2="${y}" stroke="var(--border)" stroke-dasharray="2 4" stroke-width="0.5"/>` +
      `<text x="${padX + 2}" y="${(parseFloat(y) - 2).toFixed(1)}" fill="var(--text-dim)" font-size="8" font-family="var(--font-sans)">${formatNum(Math.round(max * p))}</text>`;
  }).join('');
```

with:

```js
  // Gridlines stay inside the stretched SVG (geometry should stretch). The
  // numeric labels are real HTML in a .tl-yticks overlay so they are never
  // distorted by preserveAspectRatio="none" (SVG <text> glyphs get the same
  // non-uniform scale as paths; vector-effect can't opt text out of it).
  const ticks = [0.25, 0.5, 0.75].map(p => {
    const y = ys(max * p).toFixed(1);
    return `<line x1="${padX}" y1="${y}" x2="${padX + innerW}" y2="${y}" stroke="var(--border)" stroke-dasharray="2 4" stroke-width="0.5"/>`;
  }).join('');
  const yTicks = '<div class="tl-yticks" aria-hidden="true">' +
    [0.25, 0.5, 0.75].map(p =>
      `<span class="tl-ytick" style="top:${((ys(max * p) / h) * 100).toFixed(2)}%">${formatNum(Math.round(max * p))}</span>`
    ).join('') +
    '</div>';
```

**Anchor:** lines 2150–2152 (end of the `el.innerHTML` template). Replace:

```js
    </svg>
    <div class="rate-tooltip"></div>
    ${labels}`;
```

with:

```js
    </svg>
    ${yTicks}
    <div class="rate-tooltip"></div>
    ${labels}`;
```

(`yTicks` goes *after* the SVG and *before* the tooltip; the tooltip already has
`z-index: 20` (line 514), so stacking is unchanged.)

## Task 2 — CSS: the overlay + label style

**Anchor:** insert immediately after the `.tl-svg` rule closing brace (line 502),
before the `/* Shared tooltip base */` comment (line 504). Also update the
explanatory comment at lines 493–496.

Replace the comment block (lines 493–496):

```css
/* Timeline line-chart SVG (Dashboard 24h + Statistics Nd). Sits inside the
   200px .chart-container; 28px is the .chart-labels row (20px + 4px margin
   + 4px padding). preserveAspectRatio="none" stretches the 600×180 viewBox
   to the container, same approach as .rate-svg. */
```

with:

```css
/* Timeline line-chart SVG (Dashboard 24h + Statistics Nd). Sits inside the
   200px .chart-container; 28px is the .chart-labels row (20px + 4px margin
   + 4px padding). preserveAspectRatio="none" stretches the 600×180 viewBox
   to the container, same approach as .rate-svg. Y-axis numbers must NOT live
   inside this SVG (non-uniform scaling distorts glyphs) — they render in the
   .tl-yticks HTML overlay below. */
```

Then insert after line 502 (`}` of `.tl-svg`):

```css
/* Y-axis tick labels as real HTML so preserveAspectRatio="none" never
   distorts the digits. The overlay tracks the .tl-svg box exactly
   (bottom 28px = the .chart-labels row). pointer-events:none keeps the
   SVG's hover/tooltip interaction working underneath. */
.tl-yticks {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 28px;
  pointer-events: none;
}

.tl-ytick {
  position: absolute;
  left: 6px;
  transform: translateY(calc(-100% - 2px)); /* bottom edge 2px above gridline */
  font-family: var(--font-mono);
  font-size: 0.65rem;
  line-height: 1;
  color: var(--text-dim);
}
```

Notes:
- `var(--text-dim)` is theme-aware (same var the old SVG fill used) — works in
  dark and light without extra rules.
- The highest gridline (75 % of max) sits at viewBox y = 51 → 28.3 % from the
  overlay top, so `translateY(-100% - 2px)` can never clip at the top edge.
- Labels are inside the container box (left 6 px), so no horizontal overflow at
  375 px and no interference with the card's box-drawing frame.
- Helper doc comment (lines 2092–2100) needs no change, but if touched, do not
  alter the `el` / `series` contract.

## Task 3 (OPTIONAL, recommended) — same fix for `_renderRateTrend`

Skippable if strictly minimal scope is wanted; the rate chart's distortion is mild at
desktop but real (scaleY ≈ 1.14 vs scaleX ≈ 0.9), and after Task 1 it will sit next to
a crisp-labeled timeline on the Statistics page.

**Anchor:** lines 2729–2732. Replace:

```js
    const ticks = [25, 50, 75].map(p => {
      const y = ys(p).toFixed(1);
      return `<line x1="${padX}" y1="${y}" x2="${padX + innerW}" y2="${y}" stroke="var(--border)" stroke-dasharray="2 4" stroke-width="0.5"/><text x="${padX + 2}" y="${(parseFloat(y) - 2).toFixed(1)}" fill="var(--text-dim)" font-size="8" font-family="var(--font-sans)">${p}%</text>`;
    }).join('');
```

with:

```js
    const ticks = [25, 50, 75].map(p => {
      const y = ys(p).toFixed(1);
      return `<line x1="${padX}" y1="${y}" x2="${padX + innerW}" y2="${y}" stroke="var(--border)" stroke-dasharray="2 4" stroke-width="0.5"/>`;
    }).join('');
    const yTicks = '<div class="rate-yticks" aria-hidden="true">' +
      [25, 50, 75].map(p => `<span class="tl-ytick" style="top:${((ys(p) / h) * 100).toFixed(2)}%">${p}%</span>`).join('') +
      '</div>';
```

**Anchor:** line 2745–2746. Insert `${yTicks}` between `</svg>` and
`<div class="rate-tooltip"></div>`.

**CSS:** the rate SVG is a fixed 160 px tall (line 1035) with the legend *below* it in
normal flow, so the overlay must match the SVG box, not the container. Add next to
`.rate-svg` (after line 1038):

```css
/* Same HTML-label approach as .tl-yticks: matches the 160px .rate-svg box. */
.rate-yticks {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 160px;
  pointer-events: none;
}
```

(`.tl-ytick` is reused for the label style itself.)

## data-testids to preserve

No testids exist inside `#chart`, `#timeline-chart`, or `#rate-trend-chart`. Do not
touch: `live-toggle` (line 2202), `dashboard-empty-state` (2204),
`top-domains-card` (2211), `nav-dashboard`/`nav-stats` (1645–1646). The change is
confined to `renderTimelineChart`'s generated innerHTML, (optionally)
`_renderRateTrend`'s, and the CSS block — no component markup changes.

## Verification

Run from repo root; e2e lives in `/home/nixos/Develop/claude/noadd/e2e`.

1. **Structural assertion (the load-bearing one).** With the app running and the
   Dashboard showing data, in the browser console / `browser_evaluate`:
   - `document.querySelectorAll('.tl-svg text').length === 0` — no `<text>`
     remains inside the stretched SVG (distortion is impossible by construction
     for HTML labels).
   - `document.querySelectorAll('.tl-yticks .tl-ytick').length === 3` and each
     label's text equals `formatNum(Math.round(max * p))` for p ∈ {.25, .5, .75}.
   - Repeat on `#stats` page for `#timeline-chart` (and `.rate-svg text` /
     `.rate-yticks` if Task 3 was done).
2. **Visual acceptance — "the Y-axis numbers are not distorted".** Screenshot the
   chart card at:
   - 1280×800 dark, 1280×800 light (Playwright `colorScheme` emulation),
   - 375×812 dark and light.
   Acceptance: the digits' stroke proportions match surrounding UI text (e.g. the
   x-axis `.chart-label` times below the same chart) — same font, no wide/flat or
   narrow/tall glyphs. Objective cross-check: a `.tl-ytick` containing e.g. "1.2K"
   has `getBoundingClientRect()` width/height ratio identical at 1280 and 375
   (HTML text does not change shape with container width; the old SVG text did).
3. **No layout regressions.**
   - `#chart-card` and `#timeline-card`: `el.scrollWidth <= el.clientWidth` at
     375 px (no horizontal overflow, box-drawing frame intact).
   - Labels do not collide with the topmost gridline or the card title (75 % line
     is at ~28 % height; visually confirm the gap).
4. **Interaction regression.** Hover/touch-drag across the Dashboard chart: the
   cursor line + dots follow and `.rate-tooltip` appears (`pointer-events: none`
   on the overlay must not block this). Same on the stats timeline.
5. **E2E suite.** `cd /home/nixos/Develop/claude/noadd/e2e && npm test`
   (playwright-bdd). Existing features only reference the chart indirectly
   (onboarding empty-state), so all green = no regression.
6. **Both charts consistent.** On the Statistics page at 1280, the timeline
   (fixed) and rate-trend chart render side by side — if Task 3 was skipped,
   note the rate chart's labels are mildly distorted by design decision; if
   done, both must pass check 2.
