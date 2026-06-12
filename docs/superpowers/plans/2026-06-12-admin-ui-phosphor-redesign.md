# Admin UI "Phosphor" Terminal Redesign — Implementation Plan

> **For the implementing engineer (Opus):** This is a one-pass **visual reskin**. Functionality is frozen. The only deliverable file is `admin-ui/dist/index.html`. Everything you need to decide is decided below; if something appears ambiguous, the Invariants section wins over the Visual spec.

**Goal:** Reskin the noadd web admin UI from the generic dark "sidebar + cards" look to the approved **"Phosphor"** terminal/TUI operator-console aesthetic (IBM Plex Mono everywhere, tmux-style top tab bar, vim-style bottom status bar, box-drawing panel frames, inverse-video active states, CRT scanlines in dark mode, "paper terminal" light mode) — with zero functional change.

**Architecture:** The whole UI is one file, `/home/nixos/Develop/claude/noadd/admin-ui/dist/index.html` (~3405 lines): an inline `<style>` block (lines ~11–1310), then vanilla-JS web components in one `<script>`. It is embedded into the Rust binary at compile time via `include_dir!` in `src/admin/api.rs`, so the binary must be rebuilt after editing. All page components emit HTML using a fixed vocabulary of CSS class names and CSS custom properties; the reskin therefore consists of:

1. Rewriting the `<style>` block (repaint the existing class/variable vocabulary).
2. Swapping the `<head>` font `<link>` to IBM Plex Mono.
3. Rewriting the `innerHTML` template of exactly **three** shell-level components: `SetupPage` (~line 1455), `LoginPage` (~line 1497), `AppShell` (~line 1529).

No other component template (`rebuild-banner`, `next-step-banner`, `registry-modal`, `dashboard-page` ~1967, `stats-page` ~2231, `logs-page` ~2647, `filters-page` ~2824, `settings-page` ~3131) may be modified — they are restyled purely via CSS.

**Tech Stack:** Plain HTML + inline CSS + native Web Components. Font via Bunny Fonts CDN (same loader, new family). No frameworks, no build step, no npm packages.

**Visual source of truth:** `admin-ui/mockups/direction-1-terminal-phosphor.html` (read it in full before starting) and screenshots `admin-ui/mockups/shot-terminal-phosphor-{dark,light}-{login,dash,logs}.png`.

---

## 1. Invariants (breaking any of these fails the task)

### 1.1 `data-testid` set — preserve verbatim, no additions, no removals

The e2e suite (`e2e/`, playwright-bdd) selects on these. The file currently contains exactly these **40 unique values** as `data-testid="…"` literals:

```
app-shell  nav-dashboard nav-stats nav-logs nav-filters nav-settings
setup-error setup-password setup-password-confirm setup-submit setup-welcome-dismiss
login-error login-password login-submit
dashboard-empty-state top-domains-card stat-blocked-today stat-block-rate db-health-card
live-toggle next-step-banner next-step-banner-addr next-step-banner-dismiss
logs-empty-state domain-test-input domain-test-submit domain-test-result
filters-all-disabled-warning filters-enable-recommended
list-name-input list-url-input list-add-submit filter-list-row filter-list-toggle
rule-input rule-submit rules-list rule-row rule-delete revoke-sessions
```

Plus **`setup-welcome`**, set via `welcome.setAttribute('data-testid', 'setup-welcome')` inside `AppShell` — keep that code path intact.

Only `app-shell`, `nav-*`, `setup-*` (error/password/password-confirm/submit), and `login-*` live inside the three templates you rewrite. All others live in untouched components and are safe by construction.

**Uniqueness rule:** each `nav-*` testid must resolve to exactly **one** element. The new chrome has two nav groups (desktop tab strip + mobile F-key bar) that both use `.nav-item` + `data-route`; put `data-testid` **only on the desktop tab strip** buttons.

### 1.2 e2e behavioral couplings (verified against `e2e/steps/*.js`)

- `goToTab` clicks `getByTestId('nav-…')` and then asserts `toHaveClass(/active/)` on that same element → the active nav class must remain literally **`active`** (not `on` as in the mockup) and `updateActive()` must keep applying it to the testid-bearing buttons.
- `live-toggle` is asserted with `toContainText('LIVE')` / `toContainText('PAUSED')` → its DOM text is JS-emitted (frozen); do not replace its text via CSS `content` tricks that remove the original text node.
- Section/card titles are found with `getByText('Database Health')`, `'Filter Lists'`, `'Blocked Today'`, `'Block Rate'`, `'Top Queried Domains'`, `'Database Size'`, `'Total Logs'` etc. These are in untouched templates; your CSS may `text-transform` them (DOM text is unaffected) but must keep them **visible** (no `display:none`, no zero-size clipping of `.card-title`/`.stat-label`).
- Tests run in desktop-viewport Chromium → desktop tab strip is the visible nav during tests.

### 1.3 CSS class vocabulary — every selector below must still exist and be styled

JS in frozen components emits these classes. Repaint them; do not rename or drop:

- Layout/chrome: `.app-shell .main-content .page-header .fade-in .flash .hide-mobile .hide-mobile-block .show-mobile`
- Cards/stats: `.card .card-title .stat-grid .stat-card .stat-label .stat-value` (+ `.green .red .accent` modifiers) `.stat-sub .dashboard-grid-2col .stats-row-2col`
- Tables: `.table-wrap .top-table .truncate-cell .mono` + bare `table/th/td` rules + namespaced hooks `logs-page table|th|td`, `logs-page .log-card-domain`, `logs-page .log-card-row2`, `stats-page .chart-container|.heatmap-cell|.heatmap-table|.heatmap-col-labels|.heatmap-wrap|.bar-list|.card|.stat-grid`, `#chart-card`, `stats-page #timeline-card|#heatmap-card|#rate-trend-card` (overflow:visible escapes for tooltips — keep)
- Badges/buttons/inputs: `.badge .badge-blocked .badge-allowed .badge-cached .badge-off` · `.btn .btn-primary .btn-danger .btn-allow .btn-sm` · `input[type=text|password|url], select` rules · `.input-row .filters-row .pagination`
- Toggle: `.toggle .toggle-track .toggle-thumb` (checkbox-driven; structure frozen, CSS drives the visual)
- Charts: `.chart-container .chart-area .chart-col .chart-bar` (+ `.total .blocked .cached`) `.chart-tooltip` (incl. the `:nth-child(-n+3)` / `:nth-last-child(-n+3)` edge-anchoring rules) `.chart-labels .chart-label`
- Stats page: `.range-switcher` (+ `button.active`) `.heatmap-wrap .heatmap-table .heatmap-row-label .heatmap-col-labels .heatmap-col-label .heatmap-cell` (+ `.edge-top .edge-left .edge-right`, the `--cell-op` opacity mechanism via `color-mix`) `.heatmap-tooltip` · `.bar-list .bar-row .bar-row-label .bar-row-track .bar-row-fill .bar-row-count .bar-row-pct` · `.rate-chart-container .rate-svg .rate-cursor` (+ `.active`) `.rate-tooltip` (+ `.active`) `.rate-legend` `.rate-dot-cached .rate-dot-blocked` (SVG attrs, no CSS needed but vars they reference must exist)
- Live: `.live-toggle` (+ `.paused`) `.live-dot`
- Banners/dialogs: `.rebuild-banner` (+ `.show .active .done`, children `.icon .spin .check .text .label .meta`) · `.dialog-overlay .dialog .dialog-title .dialog-actions .dialog-health` · `.registry-overlay .registry-dialog .registry-head .registry-toolbar .registry-body .registry-empty .registry-row` (children `.info .name-row .name .desc .group-pill` (+ `.general .security .regional`) `.added-pill .dep-pill .home`) `.registry-summary .registry-foot .registry-loading .registry-error` and `.close-btn`
- Mobile cards: `.log-card .log-card-row1 .log-card-domain .log-card-row2`
- Auth: `.login-container .login-box .login-error`
- Keyframes used by JS-emitted markup: `fadeIn`, `rebuild-spin` (the inline "Adding…"/registry spinners reference `.spin`), `rebuild-strip-in`, `breathe` (or replacement animation for `.live-dot`), `registry-fade`/`registry-rise` (may be simplified but `.spin` and `.fade-in`/`.flash` must keep working)

Old sidebar-only classes (`.sidebar .sidebar-brand .sidebar-nav .sidebar-version .tagline`) become dead with the new AppShell markup — delete their CSS. New chrome classes you add: `.topbar .brand .v .nav-strip .topbar-meta .statusbar .fnbar .fk` (names are your call as long as `.nav-item` semantics in 1.5 hold).

### 1.4 CSS custom properties — all must be defined in `:root` AND the light override

Inline `style="…var(--X)…"` strings inside frozen JS reference these directly; an undefined var silently breaks colors:

```
--text-primary --text-secondary --text-dim
--accent --green --red --orange
--accent-glow --green-dim --red-dim --orange-dim
--bg-root --bg-panel --bg-card --bg-input --bg-hover --bg-secondary
--border --border-focus --flash-bg
--font-sans --font-mono --radius --transition
```

⚠ **`--bg-secondary` is referenced today but never defined** (Filters page: all-disabled warning box, syntax-reference box). The new `:root` must define it in both themes.

New helper vars you should add (additions are safe): `--inverse-fg`, `--glow`, `--glow-red`, `--scan`.

### 1.5 AppShell structural hooks (markup is rewritten, these survive)

- Root element keeps `data-testid="app-shell"`.
- Exactly one `<main class="main-content">` containing, in order: `<rebuild-banner></rebuild-banner>`, `<next-step-banner></next-step-banner>`, `<div id="page-content"></div>`. (The setup-welcome code does `main.insertBefore(welcome, main.firstChild)` against `.main-content` — class name is load-bearing.)
- `get pageContent() { return this.querySelector('#page-content'); }` unchanged.
- Five desktop nav buttons: `class="nav-item"`, `data-route` ∈ `#dashboard #stats #logs #filters #settings`, matching `data-testid="nav-…"`.
- Existing wiring stays: `this.querySelectorAll('.nav-item').forEach(btn => btn.onclick = () => { location.hash = btn.dataset.route; })` and `updateActive()` toggling `.active` where `data-route === hash`. Both loops automatically cover the mobile F-key buttons too if those are also `.nav-item` + `data-route` — that is the intended design (no new wiring).
- Version string `${window.__noadd_version || ''}` rendered somewhere visible (topbar brand).
- The entire setup-welcome block (sessionStorage `noadd_just_setup` read/clear, `div.rebuild-banner show done`, `data-testid="setup-welcome"`, dismiss button `data-testid="setup-welcome-dismiss"` with `onclick` remove) is kept byte-for-byte.

### 1.6 LoginPage / SetupPage hooks (markup is rewritten, these survive)

- LoginPage: `#pw` (with `data-testid="login-password"`, `autofocus`), `#login-btn` (`login-submit`), error div `#login-error` with **class `login-error`** and `data-testid="login-error"`; `doLogin` flow, Enter-to-submit on `#pw`, `login-success` event — all unchanged.
- SetupPage: `#setup-pw` (`setup-password`, `autofocus`), `#setup-pw2` (`setup-password-confirm`), `#setup-btn` (`setup-submit`), error div `#setup-error` class `login-error` + `data-testid="setup-error"`; `doSetup` flow with the exact validation messages (`'Password must be at least 8 characters'`, `'Passwords do not match'` — e2e asserts `/at least 8|too short/i` and `/do not match/i`), `sessionStorage.setItem('noadd_just_setup','1')`, auto-login, `login-success` event, Enter on `#setup-pw2` — all unchanged.
- Both keep `.login-container` as the outer full-viewport centering wrapper and `.login-box` as the inner column (restyled as the boot panel).

### 1.7 Functional JS is frozen

No changes to `api.*` calls, routing (`AppRouter`, `router.on(...)`), bootstrap, polling/timers, event wiring, data formatting (`formatNum` etc.), or the `icons` object (some icons go visually unused after the redesign — leave them; other components still reference `icons.check/close/trash/refresh/plus/search/external/dashboard`).

---

## 2. Design tokens — Phosphor → existing variables (authoritative mapping)

Dark is the default `:root`; light values go in one consolidated `@media (prefers-color-scheme: light)` block (fold today's three scattered light blocks into it). **Do not ship** the mockup's `[data-theme]` manual override or the reviewer `.demo` pill.

| Variable | Dark (CRT phosphor) | Light (paper terminal) | Notes |
|---|---|---|---|
| `--bg-root` | `#070a08` | `#f3efe2` | page background |
| `--bg-panel` | `#0b110c` | `#faf7ec` | topbar/statusbar/frames/tooltips |
| `--bg-card` | `#0b110c` | `#faf7ec` | = panel; terminal is flat |
| `--bg-input` | `#070a08` | `#f3efe2` | inputs recessed to root tone |
| `--bg-hover` | `#101b12` | `#ece6d4` | row/tab hover |
| `--bg-secondary` | `#0d150f` | `#efe9d8` | **newly defined** (warning/syntax boxes) |
| `--border` | `#1f3526` | `#c9c1a6` | the "line" color, all frames |
| `--border-focus` | `#41f586` | `#0b7a36` | focus = green |
| `--text-primary` | `#c2e8c9` | `#25301f` | phosphor text |
| `--text-secondary` | `#8fb89a` | `#4a5540` | between primary and dim |
| `--text-dim` | `#5e7d66` | `#79806a` | labels, meta |
| `--accent` | `#41f586` | `#0b7a36` | **green is the accent** (was blue) |
| `--green` | `#41f586` | `#0b7a36` | success/allowed (= accent) |
| `--red` | `#ff6b5e` | `#b3261e` | blocked/danger |
| `--orange` | `#ffb454` | `#99560a` | amber: cached/warn/latency |
| `--accent-glow` | `rgba(65,245,134,0.14)` | `rgba(11,122,54,0.10)` | bg tints (active nav, focus rings, pills) |
| `--green-dim` | `rgba(65,245,134,0.14)` | `rgba(11,122,54,0.10)` | allowed/positive bg tint |
| `--red-dim` | `rgba(255,107,94,0.14)` | `rgba(179,38,30,0.09)` | blocked bg tint |
| `--orange-dim` | `rgba(255,180,84,0.16)` | `rgba(153,86,10,0.10)` | cached/warn bg tint |
| `--flash-bg` | `rgba(65,245,134,0.10)` | `rgba(11,122,54,0.08)` | live-update flash |
| `--font-sans` | `'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace` | same | **all type is mono now** |
| `--font-mono` | same stack | same | |
| `--radius` | `0` | `0` | square corners everywhere |
| `--transition` | `120ms ease` | same | snappier than 150ms |
| `--inverse-fg` (new) | `#04130a` | `#f6f3e6` | text on inverse-video green |
| `--glow` (new) | `0 0 9px rgba(65,245,134,0.38)` | `none` | green text-shadow/box-shadow |
| `--glow-red` (new) | `0 0 9px rgba(255,107,94,0.35)` | `none` | red glow |
| `--scan` (new) | `0.4` | `0` | CRT overlay opacity |

Where `--glow`/`--glow-red` are used as `text-shadow`/`box-shadow` values, `none` is valid for both properties, so a single var works across themes.

**Font link** (`<head>` line ~10): replace
`https://fonts.bunny.net/css?family=geist:400,500,600,700|geist-mono:400,500&display=swap`
with
`https://fonts.bunny.net/css?family=ibm-plex-mono:400,500,600,700&display=swap`.
No other `<head>` change (title, favicon, viewport untouched). After this, zero occurrences of "Geist" may remain in the file.

**Literal-radius sweep:** the old CSS hardcodes radii outside `--radius` (`3px` badges, `10px` toggle track, `50%` thumbs/dots, `2px` heatmap cells/bar tracks, `10px` registry dialog/pills, `4px` close-btn). Set all to `0` except: keep `50%` on `.rebuild-banner .icon`, `.spin` spinners, and `.live-dot`/blink pips (circular spinners/dots stay circular — terminal cursors are blocky but spinner geometry needs round).

---

## 3. Repaint spec by cluster (rewrite the `<style>` block to realize this)

Work selector-compatible: keep every selector from §1.3, change declarations. Mockup line references are to `direction-1-terminal-phosphor.html`.

1. **Global / CRT.** `body { font-family: var(--font-sans); background: var(--bg-root); color: var(--text-primary); font-variant-ligatures: none; font-variant-numeric: tabular-nums; overflow-x: hidden; }`. Add the CRT overlay exactly as mockup lines 68–78: `body::after` fixed inset-0, `repeating-linear-gradient(0deg, rgba(0,0,0,.22) 0 1px, transparent 1px 3px)` + radial vignette, `pointer-events:none; opacity:var(--scan); z-index:90;`. `::selection { background: var(--green); color: var(--inverse-fg); }`. Scrollbars: 8px square, thumb `var(--border)`, track transparent. Keep `html { font-size: 14px; }`.
   z-order note: scanlines at z-90 sit above page content (z≤50) but below `.registry-overlay` (z-100) and `.dialog-overlay` (z-200) — matches mockup intent; leave those overlay z-indexes as-is.

2. **App chrome (pairs with the AppShell rewrite, §4.1).**
   - `.app-shell`: plain block (delete the old `display:flex` sidebar layout).
   - `.topbar`: `position:sticky; top:0; z-index:50; display:flex; align-items:stretch; background:var(--bg-panel); border-bottom:1px solid var(--border); white-space:nowrap; overflow-x:auto;` (mockup 88–96). `.brand`: green, `font-weight:700`, `text-shadow:var(--glow)`, right border; `.brand .v`: dim, weight 400, no glow.
   - Topbar `.nav-item`: reset button chrome (`border:none; background:none;`), mono, `color:var(--text-dim)`, `padding:8px 14px`, `border-right:1px solid var(--border)`, hover → `color:var(--text-primary)`. `.nav-item b` (the `1:` numeral) → `color:var(--text-primary); font-weight:600`. **`.nav-item.active` = inverse video:** `background:var(--green); color:var(--inverse-fg);` and `.nav-item.active b { color:var(--inverse-fg); }`.
   - `.topbar-meta`: `margin-left:auto; padding:8px 14px; color:var(--text-dim); border-left:1px solid var(--border);`.
   - `.statusbar` (desktop only): `position:fixed; bottom:0; left:0; right:0; z-index:50; display:flex; gap:18px; background:var(--bg-panel); border-top:1px solid var(--border); padding:6px 14px; font-size:0.82rem; color:var(--text-dim);`. `.statusbar .live`: green, glow, `::before { content:'●'; margin-right:6px; animation: blink 1.6s steps(2,start) infinite; }`. `.statusbar .right { margin-left:auto; }`. Add `@keyframes blink { 0%,100%{opacity:1} 50%{opacity:.25} }`.
   - `.main-content`: `max-width:1240px; margin:0 auto; padding:22px 18px 64px;` (bottom padding clears the fixed statusbar). Delete the `margin-left:220px` sidebar offset.
   - `.fnbar` (mobile F-key bar): `display:none` by default; inside `@media (max-width:768px)` becomes `display:flex; position:fixed; bottom:0; left:0; right:0; z-index:60; background:var(--bg-panel); border-top:1px solid var(--border);` with each `.fnbar .nav-item` as `flex:1; flex-direction:column; padding:9px 2px 10px; font-size:0.72rem; border-right:1px solid var(--border);` (`:last-child` no border), `.fk` (the F1 label) dim small, label `b` block-level primary; `.fnbar .nav-item.active` inverse-green like the tabs (mockup 375–389).

3. **`.page-header` as shell prompt (pure CSS — page JS emits `<h2>` + `<p>` unchanged).**
   `.page-header h2 { font-size:0.95rem; font-weight:400; color:var(--text-primary); text-transform: lowercase; }` and `.page-header h2::before { content:'operator@noadd:~$ '; color: var(--green); font-weight:600; text-shadow: var(--glow); }` plus a blinking block cursor `.page-header h2::after { content:''; display:inline-block; width:0.6em; height:1.05em; margin-left:6px; background:var(--green); vertical-align:-0.18em; animation: blink 1.1s steps(2,start) infinite; }`. `.page-header p { color: var(--text-dim); font-size:0.8rem; margin-top:4px; }`. Keep `.page-header { margin-bottom: 24px; }` so the inline flex layouts (dashboard/stats headers with right-side controls) keep working.

4. **`.card` as box-drawing frame.** `border:1px solid var(--border); background: var(--bg-card); border-radius:0; padding:18px 16px 14px;` — keep `min-width:0; overflow:hidden` (**load-bearing**: it contains wide tables). `.card-title` stays **in-flow** (do NOT absolute-position it: `.card{overflow:hidden}` would clip a border-straddling label, and Filters/Settings render multiple `.card-title`s mid-card as section headers): `font-size:0.78rem; font-weight:600; letter-spacing:0.08em; text-transform: lowercase; color:var(--text-dim); margin-bottom:14px;` with box-drawing decoration `.card-title::before { content:'┤ '; color:var(--text-dim); }` / `.card-title::after { content:' ├'; color:var(--text-dim); }` — this approximates the mockup's floating `┤ title ├` tab inside the frame. (Accepted deviation; recorded as a trade-off.)

5. **Stat readouts (`.stat-card` cluster).** `.stat-card`: `border:1px solid var(--border); background:var(--bg-card); border-radius:0; padding:14px 14px 12px;`. `.stat-label`: `font-size:0.72rem; letter-spacing:0.12em; text-transform:uppercase; color:var(--text-dim);` with the readout glyph `.stat-label::before { content:'▌'; color:var(--green); margin-right:6px; }`. Tint the glyph by the card's value color using `:has()` (Chromium/modern-only is fine — this is a self-hosted admin UI and e2e runs Chromium):
   `.stat-card:has(.stat-value.red) .stat-label::before { color: var(--red); }`
   `.stat-card:has(.stat-value[style*="--orange"]) .stat-label::before { color: var(--orange); }` (the Avg-Response card sets its color inline).
   `.stat-value`: `font-family:var(--font-mono); font-size:2rem; font-weight:700; color:var(--green); text-shadow:var(--glow); font-variant-numeric:tabular-nums;`. `.stat-value.red { color:var(--red); text-shadow:var(--glow-red); }` `.stat-value.green { color:var(--green); }` `.stat-value.accent { color:var(--accent); }` (accent = green now). `.stat-sub`: dim mono 0.72rem. Keep `.stat-grid` responsive grid and the smaller mobile sizes.

6. **Tables.** `th`: dim, uppercase, `letter-spacing:0.12em`, `font-size:0.7rem`, `border-bottom:1px solid var(--border)`, keep `position:sticky; top:0; background:var(--bg-card);`. `td`: `border-bottom:1px dashed var(--border)` (**dashed rows are the signature move**), `color:var(--text-secondary)`, tabular-nums. `tr:hover td { background: var(--bg-hover); }`. Keep `.top-table` fixed layout + `.truncate-cell` ellipsis + `.table-wrap{overflow-x:auto}` exactly as-is functionally. Keep the `logs-page table/th/td` font-size bumps (restyle values, keep the selectors and the size hierarchy).

7. **Badges → bracketed/bordered status tags.** `.badge { display:inline-block; padding:0 7px; border:1px solid currentColor; background:transparent; border-radius:0; font-size:0.7rem; font-weight:600; letter-spacing:0.1em; text-transform:uppercase; font-family:var(--font-mono); }`. `.badge-blocked { color:var(--red); text-shadow:var(--glow-red); }` `.badge-allowed { color:var(--green); text-shadow:var(--glow); }` `.badge-cached { color:var(--orange); }` (explicit — do not let it inherit the old accent-glow background) `.badge-off { color:var(--text-dim); }`.

8. **Buttons.** `.btn { font-family:var(--font-mono); font-size:0.82rem; font-weight:600; border:1px solid var(--border); background:var(--bg-panel); color:var(--text-primary); border-radius:0; padding:6px 12px; }` hover → `border-color:var(--green); color:var(--green);`. Bracket the labels in CSS (JS text is frozen): `.btn::before { content:'[ '; }` `.btn::after { content:' ]'; }` with `color:inherit; opacity:0.55;` — pseudo-elements become flex items in the existing `display:inline-flex; gap:6px` box, which reads as `[ icon label ]`. `.btn-primary { background:var(--green); border-color:var(--green); color:var(--inverse-fg); box-shadow:var(--glow); }` hover: slightly translucent green is fine. `.btn-danger { background:transparent; color:var(--red); }` hover → `border-color:var(--red); background:var(--red-dim);`. `.btn-allow { color:var(--green); }` hover → green border/dim bg. `.btn-sm` smaller paddings. Keep `.btn svg` sizing rules and `white-space:nowrap`.
   `.live-toggle` (not a `.btn`): restyle as a bordered terminal pill — `border:1px solid var(--green); color:var(--green); background:transparent; border-radius:0; text-shadow:var(--glow);` `.live-toggle.paused { color:var(--text-dim); border-color:var(--border); text-shadow:none; }`; `.live-dot` stays a small green dot with the blink (`steps`) animation instead of `breathe`, `.paused .live-dot` static dim. Do not alter its text content.

9. **Inputs / selects.** `input[type=text|password|url], select`: `background:var(--bg-input); border:1px solid var(--border); border-radius:0; font-family:var(--font-mono); color:var(--text-primary);` focus → `border-color:var(--border-focus); box-shadow:var(--glow);`. Keep `.input-row`/`.filters-row` flex layouts and max-widths. (The mockup's `.field` label-wrapper does not exist in production markup — style the bare controls instead.) `.range-switcher`: `border:1px solid var(--border); border-radius:0;` buttons mono dim, `button.active` inverse green (`background:var(--green); color:var(--inverse-fg);`).

10. **Toggle.** Square: `.toggle-track { border-radius:0; background:var(--bg-input); border:1px solid var(--border); }` checked → `border-color:var(--green); background:var(--green-dim);`. `.toggle-thumb { border-radius:0; background:var(--text-dim); }` checked → `left:19px; background:var(--green);` (keep geometry/offsets so the thumb stays inside the 36×20 track).

11. **Charts.** `.chart-bar.total { background: var(--border); opacity:1; border-radius:0; }` hover col → `background: var(--text-dim);` (character-cell "allowed" bars). `.chart-bar.blocked { background: var(--red); opacity:1; box-shadow: var(--glow-red); }`. `.chart-bar.cached { background: var(--orange); opacity:0.85; }`. `.chart-area { gap:3px; }` (mockup uses chunky 3px gaps; keep `gap:1px` on mobile if it overflows — optional). `.chart-label`/`.chart-labels`: dim 0.72rem with `border-top:1px dashed var(--border); padding-top:4px;` on `.chart-labels`. Tooltips (`.chart-tooltip .heatmap-tooltip .rate-tooltip`): `background:var(--bg-panel); border:1px solid var(--border); border-radius:0; font-family:var(--font-mono);` keep all positioning/edge-anchoring rules and `display` toggling untouched. Heatmap: keep `color-mix(in srgb, var(--accent) calc(var(--cell-op,1)*100%), transparent)` — accent is now green, no change needed; `border-radius:0; height` rules kept. Rate-trend SVG strokes/fills reference `var(--red)/var(--green)/var(--border)/var(--text-dim)/var(--bg-panel)` from frozen JS — they recolor automatically. `.rate-legend` dim mono. `.bar-row-track { background:var(--bg-hover); border-radius:0; }` `.bar-row-fill { border-radius:0; }` (its color comes inline from JS as `var(--accent)`/`var(--green)`/`var(--orange)` — already on-palette).

12. **Dashboard top lists stay tables.** `_renderTopTable` emits `<table class="top-table">` — the mockup's dot-leader `<ol>` ranked list is a different DOM and **must not** be chased by editing JS. The terminal table style from item 6 is the approved rendering for top domains/sources/upstreams.

13. **Banners.** `.rebuild-banner.show`: flat terminal strip — `background:var(--bg-panel); border:1px solid var(--border); border-left:3px solid var(--border); border-radius:0;` `.active` → left border + icon green/accent with `--accent-glow` tint; `.done` → green. Keep `.icon .spin .check .text .label .meta` styling roles and both keyframes. This also styles `next-step-banner` and the setup-welcome strip (same classes).

14. **Dialogs & registry modal.** `.dialog`, `.registry-dialog`: `background:var(--bg-card); border:1px solid var(--border); border-radius:0;` square heavy shadow is fine in dark (`0 24px 48px rgba(0,0,0,.5)`), lighter in light mode. Registry head/toolbar/foot keep their flex layouts; restyle pills (`.group-pill .added-pill .dep-pill`) as mini bracketed tags (`border:1px solid currentColor; border-radius:0; background:transparent;` with group colors: general→green, security→red, regional→amber, default dim). `.registry-row { border-bottom:1px dashed var(--border); }` hover `var(--bg-hover)`. Backdrop blur may stay or go (keep `rgba` dim layer either way).

15. **Misc.** `.pagination span` dim mono. `.login-error { color:var(--red); display:none; }` (display toggled by JS — keep `display:none` default!). `.fade-in`/`.flash` keep mechanics, flash now tints green via `--flash-bg`. `.log-card` mobile cards: dashed bottom borders, mono meta row. `.show-mobile { display:none; }` default with the existing `@media` flips. Light-mode extras block: consolidate the old three light `@media` blocks into the main one; drop card box-shadows entirely (paper terminal is flat) or keep a faint `0 1px 3px rgba(0,0,0,0.05)`.

16. **Responsive (`@media (max-width:768px)`).** Keep every existing behavior: `html{font-size:13px}` (mockup) is optional — keep current sizing rules for `.stat-grid` 2-col, smaller `.stat-value`, `.table-wrap` negative margins, `.hide-mobile/.hide-mobile-block/.show-mobile` flips, `.truncate-cell{max-width:180px}`, `.dashboard-grid-2col` → 1 col, `.stats-row-2col` → 1 col (at 960px), `.bar-row` narrower grid, `.registry-*` mobile rules. New chrome rules: hide `.nav-strip` (desktop tabs), `.topbar-meta`, and `.statusbar`; show `.fnbar`; `.main-content { padding:18px 12px 76px; }` (clears the fnbar). The topbar brand may remain visible as a slim header.

---

## 4. Markup rewrites (the only three templates you touch)

### 4.1 `AppShell.connectedCallback()` (~line 1531)

Replace only the `this.innerHTML = \`…\`` template; keep every line of JS after it (nav wiring loop, `updateActive`, hashchange listener, setup-welcome block) and the `pageContent` getter byte-for-byte. New template:

```js
this.innerHTML = `
  <div class="app-shell" data-testid="app-shell">
    <header class="topbar">
      <div class="brand">noadd <span class="v">${window.__noadd_version || ''}</span></div>
      <nav class="nav-strip">
        <button class="nav-item" data-route="#dashboard" data-testid="nav-dashboard"><b>1:</b>dashboard</button>
        <button class="nav-item" data-route="#stats" data-testid="nav-stats"><b>2:</b>statistics</button>
        <button class="nav-item" data-route="#logs" data-testid="nav-logs"><b>3:</b>query-log</button>
        <button class="nav-item" data-route="#filters" data-testid="nav-filters"><b>4:</b>filters</button>
        <button class="nav-item" data-route="#settings" data-testid="nav-settings"><b>5:</b>settings</button>
      </nav>
      <div class="topbar-meta">dns sinkhole</div>
    </header>
    <main class="main-content">
      <rebuild-banner></rebuild-banner>
      <next-step-banner></next-step-banner>
      <div id="page-content"></div>
    </main>
    <footer class="statusbar">
      <span class="live">ONLINE</span>
      <span>noadd ${window.__noadd_version || ''}</span>
      <span class="right">${esc(location.host)}</span>
    </footer>
    <nav class="fnbar">
      <button class="nav-item" data-route="#dashboard"><span class="fk">F1</span><b>dash</b></button>
      <button class="nav-item" data-route="#stats"><span class="fk">F2</span><b>stats</b></button>
      <button class="nav-item" data-route="#logs"><span class="fk">F3</span><b>logs</b></button>
      <button class="nav-item" data-route="#filters"><span class="fk">F4</span><b>filt</b></button>
      <button class="nav-item" data-route="#settings"><span class="fk">F5</span><b>conf</b></button>
    </nav>
  </div>`;
```

Rules embodied above (do not regress them): testids only on the desktop strip; both nav groups share `.nav-item` + `data-route` so the existing wiring and `updateActive()` cover them with zero JS changes; statusbar shows only client-side data (version + `location.host` + a CSS-blinking ONLINE pip — **no new API calls, no clock timers, no uptime/qps fabrication**); the dropped nav SVG icons stay in the `icons` object untouched.

### 4.2 `LoginPage.connectedCallback()` (~line 1499) — boot screen

Replace only the template; `doLogin`, wiring, and event code below it stay byte-for-byte. New template:

```js
this.innerHTML = `
  <div class="login-container">
    <div class="login-box boot fade-in">
      <pre class="boot-logo" aria-hidden="true">
███╗   ██╗ ██████╗  █████╗ ██████╗ ██████╗
████╗  ██║██╔═══██╗██╔══██╗██╔══██╗██╔══██╗
██╔██╗ ██║██║   ██║███████║██║  ██║██║  ██║
██║╚██╗██║██║   ██║██╔══██║██║  ██║██║  ██║
██║ ╚████║╚██████╔╝██║  ██║██████╔╝██████╔╝
╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═════╝</pre>
      <div class="boot-log">
        noadd dns sinkhole${window.__noadd_version ? ' · ' + window.__noadd_version : ''}<br>
        admin console ............ <span class="ok">ok</span><br>
        session .................. <span class="ok">awaiting operator</span><br>
      </div>
      <div class="login-error" id="login-error" data-testid="login-error"></div>
      <div class="login-line">
        <label for="pw">password:</label>
        <input type="password" id="pw" data-testid="login-password" autofocus>
      </div>
      <button class="btn btn-primary boot-submit" id="login-btn" data-testid="login-submit">authenticate</button>
    </div>
  </div>`;
```

Supporting CSS (new classes): `.login-container` keeps full-viewport flex centering; `.login-box.boot { width:560px; max-width:100%; background:transparent; border:none; padding:24px; }`; `.boot-logo { color:var(--green); text-shadow:var(--glow); font-size:clamp(0.5rem,1.6vw,0.8rem); line-height:1.25; font-weight:600; user-select:none; margin-bottom:20px; }`; `.boot-log { font-size:0.86rem; line-height:1.8; color:var(--text-dim); margin-bottom:22px; }` `.boot-log .ok { color:var(--green); }`; `.login-line { display:flex; align-items:center; gap:10px; border:1px solid var(--border); background:var(--bg-panel); padding:10px 14px; margin-bottom:14px; }` with `label { color:var(--green); text-shadow:var(--glow); }` and a borderless transparent flexing input (`letter-spacing:0.3em` for password dots); `.boot-submit { width:100%; justify-content:center; padding:10px; }`. The `[ ]` brackets come free from the `.btn::before/::after` rule → renders `[ authenticate ]`.
Boot-log lines are **decorative but truthful** — no fabricated rule counts, listener addresses, or retention numbers (the mockup's sample numbers must not ship). `.login-error` keeps `display:none` default and turns red when JS shows it.

### 4.3 `SetupPage.connectedCallback()` (~line 1457) — first-boot screen

Same boot dressing; `doSetup`, validations, sessionStorage flag, wiring stay byte-for-byte. New template:

```js
this.innerHTML = `
  <div class="login-container">
    <div class="login-box boot fade-in">
      <pre class="boot-logo" aria-hidden="true">
███╗   ██╗ ██████╗  █████╗ ██████╗ ██████╗
████╗  ██║██╔═══██╗██╔══██╗██╔══██╗██╔══██╗
██╔██╗ ██║██║   ██║███████║██║  ██║██║  ██║
██║╚██╗██║██║   ██║██╔══██║██║  ██║██║  ██║
██║ ╚████║╚██████╔╝██║  ██║██████╔╝██████╔╝
╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═════╝</pre>
      <div class="boot-log">
        noadd dns sinkhole · first boot<br>
        admin password ........... <span class="warn">not set</span><br>
        create operator credentials to continue_
      </div>
      <div class="login-error" id="setup-error" data-testid="setup-error"></div>
      <div class="login-line">
        <label for="setup-pw">password:</label>
        <input type="password" id="setup-pw" data-testid="setup-password" autofocus>
      </div>
      <div class="login-line">
        <label for="setup-pw2">confirm:</label>
        <input type="password" id="setup-pw2" data-testid="setup-password-confirm">
      </div>
      <button class="btn btn-primary boot-submit" id="setup-btn" data-testid="setup-submit">create account</button>
      <div class="boot-hint">minimum 8 characters</div>
    </div>
  </div>`;
```

Add `.boot-log .warn { color: var(--orange); }` and `.boot-hint { margin-top:16px; font-size:0.75rem; color:var(--text-dim); text-align:center; }`.

---

## 5. Out of scope — do NOT do any of this

- No changes to `src/**`, `e2e/**`, `build.rs`, `Cargo.toml`, `Cargo.lock`, version fields, or `CHANGELOG.md`.
- No changes to `admin-ui/mockups/**` (reference material only) and do not commit mockups.
- No new API endpoints, no new polling/timers, no live data in the status bar beyond what's already client-side.
- Do not ship the mockup's reviewer `.demo` theme pill or any `[data-theme]` manual theme switcher — `prefers-color-scheme` only.
- Do not refactor page-component JS to chase mockup-only flourishes (dot-leader `<ol>` lists, per-hour "max" corner labels, fake boot-log statistics, uptime/qps topbar meta).
- No packages, no build step, no local font files — CDN link swap only.
- No swipe gestures, no new keyboard shortcuts (the `1:`/`F1` labels are visual hints only — do not add key handlers).

---

## 6. Execution steps

- [ ] **Step 0 — Branch.** `cd /home/nixos/Develop/claude/noadd && git switch -c refactor/admin-ui-phosphor-redesign` (skip if already on a dedicated redesign branch; never work on `main`).
- [ ] **Step 1 — Read sources.** Read `admin-ui/mockups/direction-1-terminal-phosphor.html` (651 lines) and `admin-ui/dist/index.html` in full. Confirm landmarks: `<link>` font at line ~10, `<style>` lines ~11–1310, `SetupPage` ~1455, `LoginPage` ~1497, `AppShell` ~1529. Keep a pristine copy for diffing: `git show HEAD:admin-ui/dist/index.html > /tmp/index-before.html`.
- [ ] **Step 2 — Swap the font link** per §2.
- [ ] **Step 3 — Rewrite `:root` + light `@media` block** with the §2 token table (every §1.4 var defined in both, including `--bg-secondary`, plus the four new helper vars). Consolidate the three existing light-mode `@media` blocks into one.
- [ ] **Step 4 — Repaint the rest of the `<style>` block** cluster by cluster per §3, in file order: global/CRT → chrome (topbar/statusbar/fnbar/nav-item) → page-header prompt → cards → stats → tables → badges → buttons/live-toggle → inputs/range-switcher → toggle → charts/tooltips/heatmap/bars/rate → banners → dialogs/registry → log-cards/pagination/misc → responsive block. Delete dead `.sidebar*` rules. Run the literal-radius sweep (§2 last paragraph).
- [ ] **Step 5 — Rewrite `AppShell` template** per §4.1 (template string only; JS below unchanged).
- [ ] **Step 6 — Rewrite `LoginPage` and `SetupPage` templates** per §4.2/§4.3 and add their supporting CSS classes (`.boot .boot-logo .boot-log .login-line .boot-submit .boot-hint`).
- [ ] **Step 7 — Static self-audit** (all from repo root; every check must pass before building):
  - testid set unchanged: `rg -o 'data-testid="[a-z-]+"' admin-ui/dist/index.html | sort -u | wc -l` → `40`, and `diff <(rg -o 'data-testid="([a-z-]+)"' -r '$1' admin-ui/dist/index.html | sort -u) <(rg -o 'data-testid="([a-z-]+)"' -r '$1' /tmp/index-before.html | sort -u)` → empty. Also `rg -c "setup-welcome'" admin-ui/dist/index.html` ≥ 1 (the setAttribute path survived).
  - nav testids unique: `for t in dashboard stats logs filters settings; do echo "nav-$t: $(rg -c "data-testid=\"nav-$t\"" admin-ui/dist/index.html)"; done` → all `1`.
  - every var defined: `for v in text-primary text-secondary text-dim accent green red orange accent-glow green-dim red-dim orange-dim bg-root bg-panel bg-card bg-input bg-hover bg-secondary border border-focus flash-bg font-sans font-mono radius transition inverse-fg glow glow-red scan; do rg -q -- "--$v:" admin-ui/dist/index.html || echo "MISSING --$v"; done` → no output (vars must appear with definitions in both the `:root` and light blocks — spot-check `--bg-secondary` and `--accent` appear ≥2 times as definitions).
  - no font leftovers: `rg -i geist admin-ui/dist/index.html` → empty; `rg -c 'ibm-plex-mono' admin-ui/dist/index.html` ≥ 1.
  - class vocabulary intact: spot-check survivors `rg -c '\.(card-title|stat-value|badge-cached|toggle-thumb|chart-bar\.cached|heatmap-cell|bar-row-fill|rate-tooltip|rebuild-banner|registry-row|log-card-row2|live-toggle|login-error|range-switcher|truncate-cell)' admin-ui/dist/index.html` — each selector still present in the `<style>` block.
  - frozen-JS diff guard: `diff /tmp/index-before.html admin-ui/dist/index.html` — confirm changed hunks are confined to (a) the `<link>` font line, (b) the `<style>` block, (c) the three `this.innerHTML` template literals of SetupPage/LoginPage/AppShell. Any hunk in other script regions is a violation — revert it.
- [ ] **Step 8 — Build.** `cd /home/nixos/Develop/claude/noadd && cargo build` → must succeed (re-embeds the HTML; no Rust changes expected, so no `cargo fmt` needed).
- [ ] **Step 9 — e2e.** `cd /home/nixos/Develop/claude/noadd/e2e && npm test` (builds a debug binary and launches three noadd instances across the `setup-app`/`auth`/`onboarding`/`app` projects automatically). If Chromium is missing: `npx playwright install chromium` once, then re-run. All scenarios must pass. If a failure traces to the reskin, fix the CSS/markup — never edit tests.
- [ ] **Step 10 — Visual sanity (manual, brief).** Serve the debug binary (the e2e harness shows the invocation, or `./target/debug/noadd` with its usual flags), open the admin UI in dark and light (`prefers-color-scheme` emulation in devtools), and eyeball against the six mockup screenshots: login boot screen, dashboard readouts/frames, query log table with bracketed badges, mobile width (≤768px) showing the F1–F5 bar. Check no fixed bar overlaps page content.
- [ ] **Step 11 — Verify scope and commit.** `git status` must show `admin-ui/dist/index.html` as the only modified tracked file (pre-existing untracked `localhost*.pem` may remain; do not stage them). Then stage explicitly and commit GPG-signed (default signing; never `--no-gpg-sign`, never `git add -A`):
  ```bash
  cd /home/nixos/Develop/claude/noadd
  git add admin-ui/dist/index.html
  git commit -m "refactor(admin-ui): reskin to Phosphor terminal aesthetic"
  ```

---

## 7. Verification gates (all must hold before declaring done)

1. **Build green:** `cargo build` succeeds.
2. **e2e green:** `cd e2e && npm test` — every scenario in all four Playwright projects passes.
3. **Self-audit green (Step 7):** 40-value testid set identical to baseline (plus the `setup-welcome` setAttribute path); each `nav-*` testid count = 1; all 24 contract vars + 4 helpers defined; zero `Geist` references; class-vocabulary spot-checks present; diff confined to font link + `<style>` + the three templates.
4. **Scope green:** `git status` shows no modified file other than `admin-ui/dist/index.html`; no new files created.

---

## Appendix — recorded design trade-offs (deviations from the mockup, all intentional)

| Mockup detail | Shipped as | Why |
|---|---|---|
| Floating `┤ title ├` label straddling the frame border | In-flow `.card-title` with `┤ ├` via `::before/::after` | `.card{overflow:hidden}` is load-bearing (wide-table containment) and would clip a border-straddling label; Filters/Settings also reuse `.card-title` mid-card as section dividers |
| Dot-leader `<ol>` ranked lists for top domains/clients | Terminal-styled tables | Dashboard JS emits `<table class="top-table">` and JS is frozen |
| Topbar meta `▲ up 18d · 3.2 q/s`, statusbar query counts/clock | Static `dns sinkhole` meta; statusbar = blinking ONLINE pip + version + `location.host` | No new API calls or timers allowed |
| Boot log with rule counts / listener / retention figures | Decorative boot lines without numbers | Real values aren't available pre-auth; fabricating them would mislead |
| `[ allow ]` / `[ block ]` dashed `.act` buttons | Existing `.btn`/`.btn-sm` classes with CSS-injected `[ ]` brackets | Log-row buttons are JS-emitted with frozen classes; bracket pseudo-elements give the same read |
| Tab active class `.on` | `.active` | e2e asserts `toHaveClass(/active/)` on nav buttons |
| Reviewer theme pill / `[data-theme]` override | Not shipped | Review affordance only; production follows `prefers-color-scheme` |
| `.field` labeled filter wrappers on the logs page | Bare styled inputs/selects | Logs-page markup is frozen and has no `.field` wrapper |
| Stat readout glyph color per metric class (`r-red`/`r-amber`) | `:has()`-based tinting from the existing `.stat-value` modifiers | Cannot add classes to frozen stat-card markup; `:has()` is supported by every targeted browser |
