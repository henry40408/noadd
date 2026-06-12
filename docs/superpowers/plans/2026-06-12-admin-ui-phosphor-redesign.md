# Admin UI "Phosphor" Terminal Redesign — Implementation Plan

> **For the implementing agent (Opus):** Execute this whole plan in one pass. It is a **visual reskin only** — DOM-emitting JavaScript logic, API calls, routing, and every `data-testid` MUST stay functionally identical. The deliverable is a single edited file: `admin-ui/dist/index.html`. After implementation, run the verification gates at the end. Do NOT change any `src/**` Rust, any `e2e/**` test, or any feature behavior.

**Goal:** Replace the generic dark "sidebar + cards" admin dashboard with the approved **"Phosphor" terminal/TUI operator-console** aesthetic, keeping all functionality, tests, and accessibility intact.

**Architecture:** The entire UI is one file, `admin-ui/dist/index.html` (inline `<style>` + vanilla-JS web components), embedded into the Rust binary via `include_dir!` at compile time (`src/admin/api.rs:118`). Every page component (`dashboard-page`, `stats-page`, `logs-page`, `filters-page`, `settings-page`) renders HTML using a **fixed vocabulary of CSS class names and CSS custom properties**. We therefore reskin by **rewriting the `<style>` block to render those existing class names in the terminal aesthetic**, plus rewriting the markup of only three shell-level components (`AppShell`, `LoginPage`, `SetupPage`) whose structure changes (sidebar → tmux-style top tab bar + vim-style status bar + mobile function-key bar; login → boot screen). No other component's `innerHTML` template is touched.

**Tech Stack:** Plain HTML + inline CSS + native Web Components. Font: IBM Plex Mono via Bunny Fonts CDN (already the loader mechanism — swap the family). No frameworks, no build step, no npm.

**Visual source of truth:** `admin-ui/mockups/direction-1-terminal-phosphor.html` (open it / read it). Reference screenshots: `admin-ui/mockups/shot-terminal-phosphor-{dark,light}-{login,dash,logs}.png`.

---

## The Contract (invariants you MUST NOT break)

These are the reasons the reskin is "CSS + 3 components" and not a rewrite. Violating any of these breaks the app or its tests.

### C1. Preserve every `data-testid` verbatim
The e2e suite (`e2e/steps/*.js`) selects on these. Full set currently in the file (keep all, spelled identically):

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
Note: `setup-welcome` (on the post-setup strip) is also referenced — keep it. Only `app-shell`, `nav-*`, `setup-*`, `login-*` live inside components you rewrite; the rest live in components you only restyle, so they are safe as long as you don't touch those templates.

### C2. Keep the CSS **class-name** vocabulary working
JS in untouched components emits these classes; your new `<style>` must define/style all of them so rendered HTML looks right:
`.card .card-title .stat-grid .stat-card .stat-label .stat-value (.green/.red/.accent) .stat-sub`
`.btn (.btn-primary/.btn-danger/.btn-allow/.btn-sm) .badge (.badge-blocked/.badge-allowed/.badge-cached/.badge-off)`
`.toggle .toggle-track .toggle-thumb .table-wrap .top-table .truncate-cell .mono`
`.chart-container .chart-area .chart-col .chart-bar (.total/.blocked/.cached) .chart-tooltip .chart-labels .chart-label`
`.range-switcher .heatmap-wrap .heatmap-table .heatmap-col-labels .heatmap-col-label .heatmap-row-label .heatmap-cell (.edge-top/.edge-left/.edge-right) .heatmap-tooltip`
`.bar-list .bar-row .bar-row-label .bar-row-track .bar-row-fill .bar-row-count .bar-row-pct`
`.rate-chart-container .rate-svg .rate-cursor .rate-tooltip .rate-legend`
`.filters-row .input-row .pagination .live-toggle .live-dot .page-header`
`.dialog-overlay .dialog .dialog-title .dialog-actions .dialog-health`
`.registry-overlay .registry-dialog .registry-head .registry-toolbar .registry-body .registry-row .registry-summary .registry-foot .registry-loading .registry-error (.name/.desc/.group-pill[.general/.security/.regional]/.added-pill/.dep-pill/.home)`
`.rebuild-banner (.show/.active/.done, .icon/.spin/.check/.text/.label/.meta)`
`.log-card .log-card-row1 .log-card-domain .log-card-row2`
`.fade-in .flash .hide-mobile .hide-mobile-block .show-mobile .login-container .login-box .login-error`
Keep `logs-page`/`stats-page` element-selector style hooks (e.g. `logs-page table { ... }`, `stats-page .heatmap-cell { ... }`) — restyle, don't delete.

### C3. Keep the CSS **custom-property** vocabulary defined
Inline `style="...var(--X)..."` attributes in untouched JS reference these. All MUST remain defined in `:root` (and the light override), or inline-styled text/areas lose their color:
`--text-primary --text-secondary --text-dim --accent --green --red --orange`
`--accent-glow --green-dim --red-dim --orange-dim`
`--bg-root --bg-panel --bg-card --bg-input --bg-hover --bg-secondary --border --border-focus --flash-bg`
`--font-sans --font-mono --radius --transition`
**`--bg-secondary` is currently referenced but undefined** (Filters warning box, syntax-reference box, rules box). Define it now (= panel tone) so those surfaces render correctly.

### C4. Keep these structural hooks in `AppShell` (you rewrite its markup, but must retain):
- Root element carries `data-testid="app-shell"`.
- A `<main class="main-content">` (class name reused by the setup-welcome insertion code) containing, in order: `<rebuild-banner></rebuild-banner>`, `<next-step-banner></next-step-banner>`, `<div id="page-content"></div>`.
- `get pageContent()` returns `this.querySelector('#page-content')` (unchanged).
- Five nav controls, each `class="nav-item"` with `data-route="#dashboard|#stats|#logs|#filters|#settings"` and the matching `data-testid="nav-..."`. The existing click wiring (`location.hash = btn.dataset.route`) and `updateActive()` (toggles `.active` by `data-route === hash`) must keep working against `.nav-item`.
- Version string `${window.__noadd_version || ''}` shown somewhere.
- The post-setup welcome strip code (reads `sessionStorage 'noadd_just_setup'`, builds a `div.rebuild-banner show done` with `data-testid="setup-welcome"` + a `[data-testid="setup-welcome-dismiss"]` button, inserts before `.main-content` firstChild) must stay and still target `.main-content`.

### C5. Functional JS is frozen
Do not alter any `api.*` call, event wiring, polling, routing (`router.on(...)`), bootstrap, or data formatting. If a markup rewrite in C4/Login/Setup references element ids, keep the same ids the surrounding wiring already queries, OR update both the template and its wiring together within that one component method.

---

## Design System → existing tokens (authoritative mapping)

Set these in the new `<style>`. Dark is default; light via `@media (prefers-color-scheme: light)`. (The mockup also supports a manual `[data-theme]` override for the reviewer pill — that pill is NOT shipped; only ship the `prefers-color-scheme` behavior. Do not add the reviewer `.demo` pill.)

| Existing var | Dark value | Light value | Notes |
|---|---|---|---|
| `--bg-root` | `#070a08` | `#f3efe2` | CRT black / paper |
| `--bg-panel` | `#0b110c` | `#faf7ec` | topbar/statusbar/frames |
| `--bg-card` | `#0b110c` | `#faf7ec` | same as panel (terminal = flat) |
| `--bg-input` | `#0b110c` | `#faf7ec` | inputs sit on panel tone |
| `--bg-hover` | `#070a08` | `#ece6d4` | row/nav hover = bg tone |
| `--bg-secondary` | `#0b110c` | `#faf7ec` | **define it** (was missing) |
| `--border` | `#1f3526` | `#c9c1a6` | the "line" color |
| `--border-focus` | `#41f586` | `#0b7a36` | green focus |
| `--text-primary` | `#c2e8c9` | `#25301f` | phosphor text |
| `--text-secondary` | `#8fb89a` | `#3f4a34` | between primary & dim |
| `--text-dim` | `#5e7d66` | `#79806a` | labels, meta |
| `--accent` | `#41f586` | `#0b7a36` | **green is the accent now** |
| `--green` | `#41f586` | `#0b7a36` | allowed/success (= accent) |
| `--red` | `#ff6b5e` | `#b3261e` | blocked |
| `--orange` | `#ffb454` | `#99560a` | amber: cached/warn |
| `--accent-glow` | `rgba(65,245,134,0.14)` | `rgba(11,122,54,0.10)` | badge/active bg tint |
| `--green-dim` | `rgba(65,245,134,0.14)` | `rgba(11,122,54,0.10)` | allowed badge bg |
| `--red-dim` | `rgba(255,107,94,0.14)` | `rgba(179,38,30,0.09)` | blocked badge bg |
| `--orange-dim` | `rgba(255,180,84,0.16)` | `rgba(153,86,10,0.10)` | cached badge bg |
| `--flash-bg` | `rgba(65,245,134,0.16)` | `rgba(11,122,54,0.12)` | update-flash |
| `--font-sans` | `'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace` | same | **all type is mono now** |
| `--font-mono` | same as `--font-sans` | same | |
| `--radius` | `0` | `0` | terminal has square corners |
| `--transition` | `120ms ease` | same | |

Add two helper vars used by glow effects (optional but recommended): `--glow: 0 0 9px rgba(65,245,134,0.38)` (dark) → `none` (light); `--glow-red: 0 0 9px rgba(255,107,94,0.35)` (dark) → `none` (light).

Font loader: change the `<link href="https://fonts.bunny.net/css?family=...">` in `<head>` to load `ibm-plex-mono:400,500,600,700` (drop Geist + Geist Mono).

---

## Per-class restyle spec (apply the terminal language onto existing classes)

Rewrite the `<style>` block to realize the look below. Keep selectors/classes from C2; change their painting. Concrete intent per cluster:

1. **Global / CRT**: `body { font-family: var(--font-sans); background: var(--bg-root); color: var(--text-primary); font-variant-ligatures: none; }`. Add a fixed full-viewport `body::after` scanline+vignette overlay (`repeating-linear-gradient(0deg, rgba(0,0,0,.22) 0 1px, transparent 1px 3px)` + radial vignette), `pointer-events:none; z-index:90;` with opacity ~`0.4` dark and `0` in light (gate via a `--scan` var or a light-mode override). `::selection { background: var(--green); color: #04130a; }`. Square, thin scrollbars using `--border`.

2. **App chrome (AppShell — see markup rewrite below)**: a sticky `.topbar` on `--bg-panel` with bottom `1px solid var(--border)`: left brand `noadd <span class="v">version</span>` (brand green w/ glow, version dim); a horizontal `.nav-item` tab strip; an optional right `.topbar-meta` (dim). Active tab = **inverse video** (`background: var(--green); color: #04130a;`). A fixed bottom `.statusbar` (desktop) on `--bg-panel`, top border, small dim mono text with a blinking green `LIVE` dot (CSS `@keyframes blink`) — populate only with already-available data (version + a CSS-blinking LIVE indicator; no new API calls, no clock required). On mobile the topbar tabs and statusbar hide and a fixed bottom **function-key bar** (`.nav-item`s laid out as F1–F5 cells) shows instead.

3. **`.page-header`**: render as a shell prompt. Keep `h2`/`p` as emitted. Use CSS to prefix the heading, e.g. `.page-header h2::before { content: 'operator@noadd:~$ '; color: var(--green); font-weight: 600; }` and tone `h2` mono/regular. (Pure CSS — page JS untouched.)

4. **`.card`**: a box-drawing **frame** — `border: 1px solid var(--border); background: var(--bg-card); border-radius: 0;`. Give `.card-title` the floating-label feel: small, lowercase, letter-spacing, dim, sitting on the top border (e.g. position the title to overlap the top edge with a `--bg-card` background patch, or render a `┤ title ├`-style inline label). Acceptable to approximate the floating `┤ ├` look with a top-aligned label that has side padding and panel background. Don't break cards whose first child isn't `.card-title` (some cards inject content directly).

5. **`.stat-grid` / `.stat-card` (readouts)**: square bordered cells. `.stat-label` uppercase dim with a leading block glyph (`::before { content:'▌'; color: var(--green); }`; red for `stat-blocked-today`'s card and amber where appropriate — but keep it simple/global green is fine since you can't easily per-card vary without new classes; use the existing `.stat-value.red/.green/.accent` modifiers to tint the leading glyph via sibling selectors if practical, otherwise a single green glyph is acceptable). `.stat-value` large, tabular-nums, green with `text-shadow: var(--glow)`; `.stat-value.red` red + `--glow-red`; `.stat-value.green` green; `.stat-value.accent` green. `.stat-sub` dim.

6. **Tables**: `th` dim uppercase letter-spaced with `1px solid var(--border)` underline; `td` with **dashed** bottom border (`1px dashed var(--border)`), tabular-nums; `tr:hover td { background: var(--bg-hover); }`. Keep `.top-table` fixed layout + `.truncate-cell` ellipsis behavior.

7. **`.badge` (status tags)**: bracketed, bordered, uppercase — `border: 1px solid currentColor; background: transparent; padding: 0 7px; letter-spacing: .1em; border-radius: 0;`. `.badge-blocked` red(+glow-red text-shadow), `.badge-allowed` green(+glow), `.badge-cached` amber, `.badge-off` dim. (A subtle dim background tint via the `*-dim` vars is fine too — keep legible in both themes.)

8. **`.btn`**: mono, square, `border: 1px solid var(--border); background: var(--bg-panel); color: var(--text-primary);` hover → border+text green. `.btn-primary` = inverse green (`background: var(--green); border-color: var(--green); color:#04130a; box-shadow: var(--glow);`). `.btn-danger` red text/border on hover. `.btn-allow` green. `.btn-sm` smaller. Consider rendering action labels bracket-style via existing text (don't inject brackets in JS; optional `::before/::after { content:'[' / ']' }` on `.btn-sm.log-action` only if it stays legible — optional, skip if risky).

9. **Inputs / selects / `.input-row` / `.filters-row` / `.field`**: transparent or panel bg, `1px solid var(--border)`, mono, `border-radius:0`; focus → green border + faint glow. Keep `.range-switcher` as bordered segmented control with inverse-green `.active`.

10. **`.toggle`**: keep functional checkbox-driven switch; restyle to terminal (square track, green when checked). Must keep `.toggle-track`/`.toggle-thumb` structure (JS relies on markup, CSS drives the visual).

11. **Charts**: `.chart-bar.total` → `background: var(--border)` (allowed = dim bars); hover col → `var(--text-dim)`. `.chart-bar.blocked` → `var(--red)` + `box-shadow: var(--glow-red)`. `.chart-bar.cached` → `var(--orange)`. `.chart-labels/.axis` dim with dashed top rule. `.chart-tooltip`/`.rate-tooltip`/`.heatmap-tooltip` → panel bg, square, `1px solid var(--border)`, mono. Heatmap cells already use `color-mix(... var(--accent) ...)` → now green; keep `--cell-op` mechanic. Rate-trend SVG uses `var(--red)`/`var(--green)` strokes — inherits automatically.

12. **`.bar-list`/`.bar-row`** (stats breakdowns): keep grid; `.bar-row-track` on `--bg-hover`, `.bar-row-fill` uses inline `background:var(--accent|--green|--orange)` from JS (now green/amber) — fine. Square corners.

13. **Ranked lists**: the dashboard top-domains/clients/upstreams render as **tables** (via `_renderTopTable`), not `<ol>`. So you do NOT get the mockup's dot-leader `<ol>` for free. Style those tables in the terminal table look (item 6). (Dot-leader list is a mockup flourish on different markup; do not refactor the JS to achieve it — table look is acceptable and on-aesthetic.)

14. **`.login-container/.login-box` + boot screen**: see LoginPage/SetupPage rewrite. `.login-error` stays display-toggled by JS; style it red.

15. **`.rebuild-banner`, `.registry-*`, `.dialog-*`, `.pagination`, `.log-card*`, `.fade-in`, `.flash`**: restyle to terminal tones (panel bg, `--border` lines, square corners, green/red/amber accents, glow on green where it reads well). Keep all class names and the `.fade-in`/`.flash` animations functional. The registry modal backdrop blur can stay or be dropped; keep it readable in light mode.

16. **Responsive (`@media (max-width: 768px)`)**: topbar tab strip + statusbar hide; the function-key bottom bar (the `.nav-item`s) shows as 5 equal cells with F-key labels; `.main-content` gets bottom padding to clear it; keep existing mobile rules for `.stat-grid` (2-col), `.hide-mobile`/`.show-mobile`, table→card swaps, `.dashboard-grid-2col` single-col, `.stats-row-2col` single-col. Preserve `.show-mobile { display:none }` default and the `@media` flip.

---

## Markup rewrites (only these three component templates)

### R1. `AppShell.connectedCallback()` — chrome
Replace the `.app-shell`/`.sidebar` markup with the terminal chrome. Required skeleton (fill class styling in `<style>`):

```js
this.innerHTML = `
  <div class="app-shell" data-testid="app-shell">
    <header class="topbar">
      <div class="brand">noadd<span class="v">${window.__noadd_version ? ' ' + window.__noadd_version : ''}</span></div>
      <nav class="nav-strip">
        <button class="nav-item" data-route="#dashboard" data-testid="nav-dashboard"><b>1:</b>dashboard</button>
        <button class="nav-item" data-route="#stats"     data-testid="nav-stats"><b>2:</b>statistics</button>
        <button class="nav-item" data-route="#logs"      data-testid="nav-logs"><b>3:</b>query-log</button>
        <button class="nav-item" data-route="#filters"   data-testid="nav-filters"><b>4:</b>filters</button>
        <button class="nav-item" data-route="#settings"  data-testid="nav-settings"><b>5:</b>settings</button>
      </nav>
      <div class="topbar-meta">${icons.dashboard ? '' : ''}<span class="live-pip"></span> live</div>
    </header>
    <main class="main-content">
      <rebuild-banner></rebuild-banner>
      <next-step-banner></next-step-banner>
      <div id="page-content"></div>
    </main>
    <footer class="statusbar">
      <span class="live"><span class="live-pip"></span>LIVE</span>
      <span class="sb-brand">noadd${window.__noadd_version ? ' ' + window.__noadd_version : ''}</span>
      <span class="right">dns sinkhole</span>
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
- Keep the existing wiring loop but it must bind **all** `.nav-item` (both the top strip and the fnbar): `this.querySelectorAll('.nav-item').forEach(btn => { btn.onclick = () => { location.hash = btn.dataset.route; }; });`
- Keep `updateActive()` toggling `.active` on every `.nav-item` whose `data-route === hash` (works for both bars).
- The fnbar buttons are display-controlled by CSS media query (hidden ≥769px, shown ≤768px); the top `.nav-strip` is the inverse. Both carry the same `data-route`; only the top strip carries `data-testid` (avoid duplicate testids — e2e uses `getByTestId('nav-dashboard')` which must resolve to exactly one element; keep `data-testid` ONLY on the top strip buttons).
- Keep the setup-welcome block unchanged (it targets `.main-content` and builds `data-testid="setup-welcome"` / `setup-welcome-dismiss`).
- Keep `get pageContent()`.
- The `.live-pip` is a CSS-blinking dot; no JS. The statusbar/topbar-meta carry no live data beyond decoration (no new API).

### R2. `LoginPage.connectedCallback()` — boot screen
Keep the same input/button/error **ids and data-testids and wiring** (`#pw`, `#login-btn`, `#login-error`, `data-testid` login-password/login-submit/login-error; `doLogin`, Enter-key handler, `login-success` event). Re-dress the markup as a boot screen inside `.login-container > .login-box` (or a new `.boot` wrapper — your choice, but keep `.login-container` as the outer centering element so existing centering CSS applies, and keep `.login-error` class on the error node). Add an ASCII-art `noadd` logo (`<pre>`, `user-select:none`, green + glow) and a short faux boot log (dim, with green `ok`/`listening` spans) above a terminal `password:` input line. Keep the brand spelled with the `no<span>add</span>` accent if you keep the `<h1>`, or fold it into the ASCII logo. Button label may read `[ authenticate ]`. Do not remove `autofocus`.

Use this exact ASCII logo (matches the mockup):
```
███╗   ██╗ ██████╗  █████╗ ██████╗ ██████╗
████╗  ██║██╔═══██╗██╔══██╗██╔══██╗██╔══██╗
██╔██╗ ██║██║   ██║███████║██║  ██║██║  ██║
██║╚██╗██║██║   ██║██╔══██║██║  ██║██║  ██║
██║ ╚████║╚██████╔╝██║  ██║██████╔╝██████╔╝
╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═════╝
```

### R3. `SetupPage.connectedCallback()` — boot screen (first-run)
Same treatment as R2. Keep ids/testids/wiring: `#setup-pw`, `#setup-pw2`, `#setup-btn`, `#setup-error`, `data-testid` setup-password/setup-password-confirm/setup-submit/setup-error; the `doSetup` flow (≥8 char + match validation, `sessionStorage 'noadd_just_setup'`, auto-login, `login-success`). Dress as a "first boot — set operator password" screen with the same ASCII logo. Keep the two labeled password inputs and submit button; keep `autofocus` on the first field.

---

## Execution steps

- [ ] **Step 1 — Baseline & branch.** You're on branch `feat/redesign-admin-ui` (already created). Confirm with `git -C /home/nixos/Develop/claude/noadd branch --show-current` → expect `feat/redesign-admin-ui`. Capture the current file for reference: `git -C /home/nixos/Develop/claude/noadd show HEAD:admin-ui/dist/index.html > /tmp/index-before.html` (so you can diff JS-bearing regions later).

- [ ] **Step 2 — Read the two sources fully.** Read `admin-ui/dist/index.html` (all 3406 lines) and `admin-ui/mockups/direction-1-terminal-phosphor.html`. Identify the `<style>` block (lines ~11–1310), the `<head>` font `<link>` (line ~10), and the three component methods to rewrite (`SetupPage` ~1455, `LoginPage` ~1497, `AppShell` ~1529). Everything else is restyle-only.

- [ ] **Step 3 — Swap the font link** in `<head>` to `ibm-plex-mono:400,500,600,700`.

- [ ] **Step 4 — Rewrite the `<style>` block** per the token mapping + per-class restyle spec above. Work top-down: `:root` (dark) + light `@media` override first (C3 — every var defined in both), then base/global + CRT overlay, then each class cluster (C2). Keep all existing selectors that target JS-emitted classes; only change their declarations. Add the new chrome selectors (`.topbar .brand .v .nav-strip .topbar-meta .statusbar .live .live-pip .fnbar .fk`) and restyle `.nav-item` for the topbar/fnbar contexts. Keep the responsive `@media (max-width:768px)` behaviors and add topbar-hide / fnbar-show.

- [ ] **Step 5 — Rewrite `AppShell` markup (R1)**, keeping all C4 hooks and the nav wiring/`updateActive`/`pageContent`/setup-welcome logic.

- [ ] **Step 6 — Rewrite `LoginPage` (R2) and `SetupPage` (R3) markup**, keeping all ids/testids/wiring.

- [ ] **Step 7 — Self-audit against the Contract.** Grep the edited file to prove invariants:
  - `rg -o 'data-testid="[a-z0-9-]+"' admin-ui/dist/index.html | sort -u` → must equal the C1 set (40 unique values; `setup-welcome` appears via JS string so also present).
  - For each var in C3, `rg -- '--bg-secondary'` etc. resolves (define-check): confirm each appears in `:root`. Quick check: `for v in text-primary text-secondary text-dim accent green red orange accent-glow green-dim red-dim orange-dim bg-root bg-panel bg-card bg-input bg-hover bg-secondary border border-focus flash-bg font-sans font-mono radius transition; do rg -q -- "--$v:" admin-ui/dist/index.html || echo "MISSING --$v"; done` → no output.
  - Confirm no stray Geist reference remains: `rg -i geist admin-ui/dist/index.html` → empty.
  - Confirm single source of each nav testid: `rg -c 'data-testid="nav-dashboard"' admin-ui/dist/index.html` → `1`.

- [ ] **Step 8 — Build the binary** (embeds the new HTML): `cd /home/nixos/Develop/claude/noadd && cargo build` → expect success. (Rust isn't changed, but `include_dir!` re-embeds the asset.)

- [ ] **Step 9 — Run the e2e suite** (functional + testid regression gate). Ensure no stale dev server is reusing the old binary, then:
  `cd /home/nixos/Develop/claude/noadd/e2e && npm test`
  Expect all projects (`setup-app`, `auth`, `onboarding`, `app`) green. If a Playwright browser is missing, run `npx playwright install chromium` once and re-run. If failures trace to a renamed class/testid you changed, fix the CSS/markup (not the test).

- [ ] **Step 10 — Commit** (GPG-signed; stage only the intended files):
  ```bash
  cd /home/nixos/Develop/claude/noadd
  git add admin-ui/dist/index.html
  git commit -m "refactor(admin-ui): redesign to Phosphor terminal aesthetic"
  ```
  Do NOT commit `admin-ui/mockups/` in this commit (kept for the review loop; can be removed later).

---

## Verification gates (must all pass before declaring done)

1. `cargo build` succeeds.
2. `cd e2e && npm test` — all scenarios pass (proves data-testid + functional integrity).
3. Step-7 self-audit greps all clean (testid set intact, every CSS var defined, no Geist, single nav testid).
4. No file other than `admin-ui/dist/index.html` is modified (check `git status`).

## Out of scope (do NOT do)
- No changes to `src/**`, `e2e/**`, `build.rs`, `Cargo.toml`, version fields, or `CHANGELOG.md`.
- No new API endpoints, no new polling, no live-data wiring in the status bar.
- No refactor of page-component JS to chase mockup-only flourishes (dot-leader lists, etc.).
- Do not ship the reviewer `.demo` theme pill from the mockup.
- Do not add libraries, a build step, or non-CDN assets.
