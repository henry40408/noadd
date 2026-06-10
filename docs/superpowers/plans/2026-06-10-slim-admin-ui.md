# Admin UI CSS/JS Slimming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove dead code and consolidate duplicated CSS/JS patterns in `admin-ui/dist/index.html` with zero behavior/appearance change.

**Architecture:** The admin UI is a single self-contained `admin-ui/dist/index.html` (~131 KB, one `<style>` block + one `<script>` block, no build step) embedded into the Rust binary via `include_dir!` in `src/admin/api.rs:118`. Because the file is embedded at compile time, **every e2e run after editing `index.html` must be preceded by `cargo build`**. Verification relies on the existing Playwright e2e suite; this is a behavior-preserving refactor with no new tests.

**Tech Stack:** Vanilla HTML/CSS/JS (web components), Rust (axum, `include_dir`), Playwright + playwright-bdd e2e suite in `e2e/`.

**Spec:** `docs/superpowers/specs/2026-06-10-slim-admin-ui-design.md`

**Branch:** `refactor/slim-admin-ui` (already created)

---

## Context for the implementer

- The only file being modified is `admin-ui/dist/index.html`. Line numbers below refer to the file **before any edits**; they shift as tasks complete, so always locate code by content, not line number.
- e2e suite: `cd /home/nixos/Develop/claude/noadd/e2e && npm test` (runs `bddgen && playwright test`). It spawns three `../target/debug/noadd` instances itself — you only need `cargo build` first. Do not run e2e in parallel with itself.
- e2e selectors use `data-testid` attributes only — never change or remove `data-testid`.
- Commits MUST be GPG-signed (the default; never pass `--no-gpg-sign`), and files MUST be staged explicitly by name (`git add <file>`, never `-A` or `.`).
- Every commit message body MUST end with the trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` (omitted from the snippets below for brevity).
- Zero behavior/appearance change is a hard requirement. CSS merges must use grouped selectors that keep every declaration's effective value identical; do not "fix" styling inconsistencies you notice (note them in the final report instead).

---

### Task 1: Baseline verification and measurement

**Files:**
- No modifications. Build + test only.

- [ ] **Step 1: Build the debug binary**

Run:
```bash
cd /home/nixos/Develop/claude/noadd && cargo build
```
Expected: compiles without errors.

- [ ] **Step 2: Run the e2e suite to confirm a green baseline**

Run:
```bash
cd /home/nixos/Develop/claude/noadd/e2e && npm test
```
Expected: all scenarios pass. If anything fails here, STOP — the baseline is broken and slimming must not start; report to the user.

- [ ] **Step 3: Record baseline size**

Run:
```bash
wc -c -l /home/nixos/Develop/claude/noadd/admin-ui/dist/index.html
```
Expected output (baseline): `3463` lines, `130872` bytes. Save these numbers for the final report.

---

### Task 2: CSS audit and dead-selector removal

**Files:**
- Modify: `admin-ui/dist/index.html` (CSS block, lines ~11–1342)

- [ ] **Step 1: Run a class-usage audit script**

Run:
```bash
cd /home/nixos/Develop/claude/noadd
awk '/<style>/{f=1;next} /<\/style>/{f=0} f' admin-ui/dist/index.html > /tmp/style.css
awk '/<style>/{f=1} /<\/style>/{f=0;next} !f' admin-ui/dist/index.html > /tmp/rest.txt
grep -o '\.[A-Za-z_][A-Za-z0-9_-]*' /tmp/style.css | sed 's/^\.//' | sort -u | while read c; do
  grep -q -F "$c" /tmp/rest.txt || echo "UNUSED: $c"
done
```
Expected: at minimum `UNUSED: badge-on` and `UNUSED: rules-grid`. The script is substring-based, so it can produce false *negatives* but few false positives; still, manually verify every reported class in the next step.

- [ ] **Step 2: Manually verify each reported class before deleting**

For each `UNUSED: <name>` from Step 1, run:
```bash
rg -n '<name>' /home/nixos/Develop/claude/noadd/admin-ui/dist/index.html /home/nixos/Develop/claude/noadd/e2e/features /home/nixos/Develop/claude/noadd/e2e/steps /home/nixos/Develop/claude/noadd/e2e/support
```
A class is safe to delete only when every match is inside the `<style>` block (and not in e2e files). Known-verified dead: `.badge-on` (line 311), `.rules-grid` (line 807, inside the `@media (max-width: 768px)` block). If the audit reports additional classes that pass verification, delete them too and list them in the commit message.

- [ ] **Step 3: Delete the dead selectors**

Remove this line (in the badge block, ~line 311):
```css
.badge-on { background: var(--green-dim); color: var(--green); }
```

Remove these lines (inside `@media (max-width: 768px)`, ~lines 806–807):
```css
  /* Filters: stack block/allow columns */
  .rules-grid { grid-template-columns: 1fr !important; }
```

- [ ] **Step 4: Re-run the audit script to confirm the deletions are clean**

Re-run the Step 1 script. Expected: `badge-on` and `rules-grid` no longer appear in `/tmp/style.css` (the `UNUSED` list shrinks accordingly; no new entries).

- [ ] **Step 5: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
git add admin-ui/dist/index.html
git commit -m "refactor(admin-ui): drop unused .badge-on and .rules-grid selectors"
```

---

### Task 3: Merge tooltip CSS into a shared base

**Files:**
- Modify: `admin-ui/dist/index.html` (`.chart-tooltip` ~467–490, `.heatmap-tooltip` ~892–909, `.rate-tooltip` ~971–991)

The three tooltips share 10 identical declarations. Merge them with grouped selectors, keeping each tooltip's unique declarations in its original location so the cascade is unchanged. Note: `.heatmap-tooltip` intentionally has NO light-mode box-shadow override today — do not add one.

- [ ] **Step 1: Replace the `.chart-tooltip` rule and its light-mode override**

Find:
```css
.chart-tooltip {
  display: none;
  position: absolute;
  bottom: calc(100% + 8px);
  left: 50%;
  transform: translateX(-50%);
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 6px 10px;
  font-family: var(--font-sans);
  font-size: 0.7rem;
  color: var(--text-primary);
  white-space: nowrap;
  z-index: 20;
  pointer-events: none;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
}

@media (prefers-color-scheme: light) {
  .chart-tooltip { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
}
```

Replace with:
```css
.chart-tooltip,
.heatmap-tooltip,
.rate-tooltip {
  display: none;
  position: absolute;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text-primary);
  white-space: nowrap;
  z-index: 20;
  pointer-events: none;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
}

.chart-tooltip,
.rate-tooltip {
  padding: 6px 10px;
  font-family: var(--font-sans);
  font-size: 0.7rem;
}

.chart-tooltip {
  bottom: calc(100% + 8px);
  left: 50%;
  transform: translateX(-50%);
}

@media (prefers-color-scheme: light) {
  .chart-tooltip, .rate-tooltip { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
}
```

- [ ] **Step 2: Shrink the `.heatmap-tooltip` rule to its unique declarations**

Find:
```css
.heatmap-tooltip {
  display: none;
  position: absolute;
  bottom: calc(100% + 4px);
  left: 50%;
  transform: translateX(-50%);
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 4px 8px;
  font-family: var(--font-mono);
  font-size: 0.65rem;
  color: var(--text-primary);
  white-space: nowrap;
  z-index: 20;
  pointer-events: none;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
}
```

Replace with:
```css
.heatmap-tooltip {
  bottom: calc(100% + 4px);
  left: 50%;
  transform: translateX(-50%);
  padding: 4px 8px;
  font-family: var(--font-mono);
  font-size: 0.65rem;
}
```

(The `.heatmap-cell.edge-*` rules just above have higher specificity than the shared base, so leaving them before this rule is safe.)

- [ ] **Step 3: Shrink the `.rate-tooltip` rule and drop its now-merged light-mode override**

Find:
```css
.rate-tooltip {
  display: none;
  position: absolute;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 6px 10px;
  font-family: var(--font-sans);
  font-size: 0.7rem;
  color: var(--text-primary);
  white-space: nowrap;
  z-index: 20;
  pointer-events: none;
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  transform: translate(-50%, -100%);
  margin-top: -8px;
}
.rate-tooltip.active { display: block; }
@media (prefers-color-scheme: light) {
  .rate-tooltip { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
}
```

Replace with:
```css
.rate-tooltip {
  transform: translate(-50%, -100%);
  margin-top: -8px;
}
.rate-tooltip.active { display: block; }
```

- [ ] **Step 4: Sanity-check declaration equivalence**

Run:
```bash
rg -n 'chart-tooltip|heatmap-tooltip|rate-tooltip' /home/nixos/Develop/claude/noadd/admin-ui/dist/index.html
```
Confirm: the shared base appears once; each tooltip's positioning/padding/font declarations are present exactly once; `.rate-tooltip.active` and all `.heatmap-cell.edge-*` rules are untouched.

- [ ] **Step 5: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
git add admin-ui/dist/index.html
git commit -m "refactor(admin-ui): merge shared tooltip declarations into grouped rule"
```

---

### Task 4: Merge registry pill CSS

**Files:**
- Modify: `admin-ui/dist/index.html` (`.registry-row .group-pill` / `.added-pill` / `.dep-pill`, ~lines 1253–1287)

- [ ] **Step 1: Replace the three pill rules with a grouped base + variants**

Find:
```css
.registry-row .group-pill {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 10px;
  font-size: 0.65rem;
  font-family: var(--font-sans);
  letter-spacing: 0.05em;
  text-transform: uppercase;
  background: var(--bg-input);
  color: var(--text-secondary);
  border: 1px solid var(--border);
}
.registry-row .group-pill.general { background: var(--accent-glow); color: var(--accent); border-color: transparent; }
.registry-row .group-pill.security { background: var(--red-dim); color: var(--red); border-color: transparent; }
.registry-row .group-pill.regional { background: var(--orange-dim); color: var(--orange); border-color: transparent; }
.registry-row .added-pill {
  background: var(--green-dim);
  color: var(--green);
  font-family: var(--font-sans);
  font-size: 0.65rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding: 1px 8px;
  border-radius: 10px;
}
.registry-row .dep-pill {
  background: var(--red-dim);
  color: var(--red);
  font-family: var(--font-sans);
  font-size: 0.65rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding: 1px 8px;
  border-radius: 10px;
}
```

Replace with:
```css
.registry-row .group-pill,
.registry-row .added-pill,
.registry-row .dep-pill {
  padding: 1px 8px;
  border-radius: 10px;
  font-size: 0.65rem;
  font-family: var(--font-sans);
  text-transform: uppercase;
}
.registry-row .group-pill {
  display: inline-block;
  letter-spacing: 0.05em;
  background: var(--bg-input);
  color: var(--text-secondary);
  border: 1px solid var(--border);
}
.registry-row .group-pill.general { background: var(--accent-glow); color: var(--accent); border-color: transparent; }
.registry-row .group-pill.security { background: var(--red-dim); color: var(--red); border-color: transparent; }
.registry-row .group-pill.regional { background: var(--orange-dim); color: var(--orange); border-color: transparent; }
.registry-row .added-pill,
.registry-row .dep-pill { letter-spacing: 0.06em; }
.registry-row .added-pill { background: var(--green-dim); color: var(--green); }
.registry-row .dep-pill { background: var(--red-dim); color: var(--red); }
```

Important: `display: inline-block` stays on `.group-pill` only — `.added-pill`/`.dep-pill` never had it and adding it would change their layout.

- [ ] **Step 2: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
git add admin-ui/dist/index.html
git commit -m "refactor(admin-ui): consolidate registry pill styles into grouped rules"
```

---

### Task 5: Remove no-op `btn-secondary` / `btn-ghost` class names, then verify all CSS work

**Files:**
- Modify: `admin-ui/dist/index.html` (two HTML strings, ~lines 1619 and 1761)

`btn-secondary` and `btn-ghost` appear only as class names in two HTML template strings; no CSS rule and no JS/e2e selector references them (verified: `rg -n 'btn-secondary|btn-ghost'` across `admin-ui/` and `e2e/` matches only these two lines). The buttons are styled by `.btn` alone, so dropping the dead class names changes nothing.

- [ ] **Step 1: Re-verify there are no other references**

Run:
```bash
rg -n 'btn-secondary|btn-ghost' /home/nixos/Develop/claude/noadd/admin-ui /home/nixos/Develop/claude/noadd/e2e --glob '!e2e/node_modules' --glob '!e2e/test-results'
```
Expected: exactly two matches, both `class="btn btn-..."` in `index.html`. If anything else matches, STOP and report instead of deleting.

- [ ] **Step 2: Remove the dead class names**

Change (in the setup-welcome card template):
```html
<button class="btn btn-secondary" data-testid="setup-welcome-dismiss"
```
to:
```html
<button class="btn" data-testid="setup-welcome-dismiss"
```

Change (in the next-step banner template):
```html
<button class="btn btn-ghost" data-testid="next-step-banner-dismiss" title="Dismiss" style="margin-left:auto">${icons.close}</button>
```
to:
```html
<button class="btn" data-testid="next-step-banner-dismiss" title="Dismiss" style="margin-left:auto">${icons.close}</button>
```

- [ ] **Step 3: Build and run the full e2e suite (verifies Tasks 2–5)**

Run:
```bash
cd /home/nixos/Develop/claude/noadd && cargo build && cd e2e && npm test
```
Expected: all scenarios pass, same as baseline. If any scenario fails, bisect the CSS commits (`git stash` / `git revert` one at a time) to find the culprit — do not proceed to JS tasks with red e2e.

- [ ] **Step 4: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
git add admin-ui/dist/index.html
git commit -m "refactor(admin-ui): drop unstyled btn-secondary/btn-ghost class names"
```

---

### Task 6: JS dead-code audit

**Files:**
- No modifications expected; audit only (delete only if something is proven dead).

- [ ] **Step 1: Audit top-level functions for references**

Run:
```bash
cd /home/nixos/Develop/claude/noadd
grep -o 'function [A-Za-z_][A-Za-z0-9_]*' admin-ui/dist/index.html | awk '{print $2}' | sort -u | while read f; do
  n=$(grep -c -F "$f" admin-ui/dist/index.html)
  [ "$n" -le 1 ] && echo "POSSIBLY UNUSED: $f (refs: $n)"
done
```
Expected: no output (prior analysis found all functions referenced). A function counted once is defined but never called.

- [ ] **Step 2: Audit class methods for references**

Run:
```bash
cd /home/nixos/Develop/claude/noadd
grep -oE '^  (async )?[a-zA-Z_][A-Za-z0-9_]*\(' admin-ui/dist/index.html | sed -E 's/^  (async )?//; s/\($//' | sort -u | grep -vE '^(constructor|connectedCallback|disconnectedCallback)$' | while read m; do
  n=$(grep -c -F "$m" admin-ui/dist/index.html)
  [ "$n" -le 1 ] && echo "POSSIBLY UNUSED METHOD: $m (refs: $n)"
done
```
Expected: no output. For any hit, manually verify with `rg -n '<name>' admin-ui/dist/index.html` — check string references too (`onclick="..."`, template literals, bracket access) before concluding it is dead. Delete only proven-dead code; otherwise just note findings for the final report.

- [ ] **Step 3: Commit (only if something was deleted)**

```bash
cd /home/nixos/Develop/claude/noadd
git add admin-ui/dist/index.html
git commit -m "refactor(admin-ui): remove dead JS code found by audit"
```
If nothing was deleted, skip the commit and move on.

---

### Task 7: Consolidate the three `renderTop*` methods and flash tracking

**Files:**
- Modify: `admin-ui/dist/index.html` (DashboardPage class: `_flashCard` ~2092, `renderChart` ~2175, `renderTopDomains`/`renderTopClients`/`renderTopUpstreams` ~2222–2273; module-level helpers near `function formatPct`)

- [ ] **Step 1: Add the `sharePctSpan` module-level helper**

Locate `function formatPct` (search: `rg -n 'function formatPct' admin-ui/dist/index.html`) and insert immediately after its closing brace:

```js
function sharePctSpan(count, sum) {
  const pct = formatPct(count, sum);
  return pct ? ` <span style="color:var(--text-dim);font-size:0.75em">(${pct})</span>` : '';
}
```

- [ ] **Step 2: Add `_flashIfChanged` and `_renderTopTable` to DashboardPage**

Locate the `_flashCard(id)` method in the DashboardPage class and insert immediately after it:

```js
  _flashIfChanged(prevKey, sig, card) {
    if (this[prevKey] && sig !== this[prevKey]) this._flashCard(card);
    this[prevKey] = sig;
  }

  _renderTopTable(data, { target, card, prevKey, sig, limit, head, row }) {
    this._flashIfChanged(prevKey, data.map(sig).join(';'), card);
    if (!data.length) { this.querySelector(target).innerHTML = '<p style="color:var(--text-dim)">No data</p>'; return; }
    const visible = limit ? data.slice(0, limit) : data;
    const sumVal = visible.reduce((a, d) => a + d.count, 0);
    let html = head;
    for (const d of visible) html += row(d, sumVal);
    this.querySelector(target).innerHTML = html + '</tbody></table>';
  }
```

- [ ] **Step 3: Rewrite the three `renderTop*` methods as thin configs**

Replace `renderTopDomains` / `renderTopClients` / `renderTopUpstreams` (currently three near-identical ~15-line methods) with:

```js
  renderTopDomains(data) {
    this._renderTopTable(data, {
      target: '#top-domains', card: '#domains-card', prevKey: '_prevDomains',
      sig: d => d.domain + d.count, limit: 10,
      head: '<table class="top-table"><colgroup><col><col style="width:140px"></colgroup><thead><tr><th>Domain</th><th style="text-align:right">Count</th></tr></thead><tbody>',
      row: (d, sum) => `<tr><td><div class="truncate-cell" title="${esc(d.domain)}">${esc(d.domain)}</div></td><td class="mono" style="text-align:right;white-space:nowrap">${formatFull(d.count)}${sharePctSpan(d.count, sum)}</td></tr>`,
    });
  }

  renderTopClients(data) {
    this._renderTopTable(data, {
      target: '#top-clients', card: '#clients-card', prevKey: '_prevClients',
      sig: d => d.client_ip + (d.doh_token || '') + d.count, limit: 10,
      head: '<table class="top-table"><colgroup><col><col style="width:140px"></colgroup><thead><tr><th>Client</th><th style="text-align:right">Count</th></tr></thead><tbody>',
      row: (d, sum) => {
        const tokenLine = d.doh_token
          ? `<div class="truncate-cell" title="${esc(d.doh_token)}" style="color:var(--accent);font-size:0.7rem">${esc(d.doh_token)}</div>`
          : '';
        return `<tr><td><div class="truncate-cell mono" title="${esc(d.client_ip)}">${esc(d.client_ip)}</div>${tokenLine}</td><td class="mono" style="text-align:right;white-space:nowrap">${formatFull(d.count)}${sharePctSpan(d.count, sum)}</td></tr>`;
      },
    });
  }

  renderTopUpstreams(data) {
    this._renderTopTable(data, {
      target: '#top-upstreams', card: '#upstreams-card', prevKey: '_prevUpstreams',
      sig: d => d.upstream + d.count,
      head: '<table class="top-table"><thead><tr><th>Upstream</th><th style="text-align:right;width:140px">Queries</th><th class="hide-mobile" style="text-align:right;width:120px">Avg Latency</th></tr></thead><tbody>',
      row: (d, sum) => `<tr><td><div class="truncate-cell mono" title="${esc(d.upstream)}">${esc(d.upstream)}</div></td><td class="mono" style="text-align:right;white-space:nowrap">${formatFull(d.count)}${sharePctSpan(d.count, sum)}</td><td class="mono hide-mobile" style="text-align:right;white-space:nowrap">${d.avg_ms.toFixed(1)}ms</td></tr>`,
    });
  }
```

Behavioral notes that MUST hold (compare against the originals before deleting them):
- `renderTopUpstreams` has NO `limit` — it renders all rows and sums over all rows (the originals sliced only domains/clients).
- The empty-state HTML, signature strings, and flash-card targets are byte-identical to the originals.

- [ ] **Step 4: Switch `renderChart`'s flash tracking to `_flashIfChanged`**

In `renderChart`, replace:
```js
    const sig = rawData.map(d => d.total + ',' + d.blocked).join(';');
    if (this._prevChart && sig !== this._prevChart) this._flashCard('#chart-card');
    this._prevChart = sig;
```
with:
```js
    this._flashIfChanged('_prevChart', rawData.map(d => d.total + ',' + d.blocked).join(';'), '#chart-card');
```
Note: the early-return for empty data (`this._prevChart = null`) above this line stays unchanged.

- [ ] **Step 5: Syntax check the script block**

Run:
```bash
cd /home/nixos/Develop/claude/noadd
awk '/<script>/{f=1;next} /<\/script>/{f=0} f' admin-ui/dist/index.html > /tmp/app.js && node --check /tmp/app.js && echo SYNTAX-OK
```
Expected: `SYNTAX-OK`.

- [ ] **Step 6: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
git add admin-ui/dist/index.html
git commit -m "refactor(admin-ui): extract shared top-table renderer and flash tracking"
```

---

### Task 8: Form error helper, then verify all JS work

**Files:**
- Modify: `admin-ui/dist/index.html` (module-level helper near `function esc`; SetupPage `doSetup` ~1497–1521; LoginPage `doLogin` ~1545–1554)

- [ ] **Step 1: Add the `showFormError` module-level helper**

Locate `function esc(s)` and insert immediately after its closing brace:

```js
function showFormError(el, msg) {
  el.textContent = msg;
  el.style.display = 'block';
}
```

- [ ] **Step 2: Rewrite SetupPage's `doSetup` to use it**

Replace:
```js
    const doSetup = async () => {
      err.style.display = 'none';
      if (!pw.value || pw.value.length < 8) {
        err.textContent = 'Password must be at least 8 characters';
        err.style.display = 'block';
        return;
      }
      if (pw.value !== pw2.value) {
        err.textContent = 'Passwords do not match';
        err.style.display = 'block';
        return;
      }
      try {
        await api.post('/api/auth/setup', { password: pw.value });
        // Auto-login after setup
        await api.post('/api/auth/login', { password: pw.value });
        // Mark this session as just-set-up so the dashboard shows a one-time
        // welcome message. Set before dispatching so AppShell sees it on render.
        try { sessionStorage.setItem('noadd_just_setup', '1'); } catch (e) {}
        this.dispatchEvent(new CustomEvent('login-success', { bubbles: true }));
      } catch (e) {
        err.textContent = 'Setup failed. A password may already be set.';
        err.style.display = 'block';
      }
    };
```
with:
```js
    const doSetup = async () => {
      err.style.display = 'none';
      if (!pw.value || pw.value.length < 8) return showFormError(err, 'Password must be at least 8 characters');
      if (pw.value !== pw2.value) return showFormError(err, 'Passwords do not match');
      try {
        await api.post('/api/auth/setup', { password: pw.value });
        // Auto-login after setup
        await api.post('/api/auth/login', { password: pw.value });
        // Mark this session as just-set-up so the dashboard shows a one-time
        // welcome message. Set before dispatching so AppShell sees it on render.
        try { sessionStorage.setItem('noadd_just_setup', '1'); } catch (e) {}
        this.dispatchEvent(new CustomEvent('login-success', { bubbles: true }));
      } catch (e) {
        showFormError(err, 'Setup failed. A password may already be set.');
      }
    };
```

- [ ] **Step 3: Rewrite LoginPage's `doLogin` to use it**

Replace:
```js
    const doLogin = async () => {
      try {
        err.style.display = 'none';
        await api.post('/api/auth/login', { password: pw.value });
        this.dispatchEvent(new CustomEvent('login-success', { bubbles: true }));
      } catch (e) {
        err.textContent = 'Invalid password';
        err.style.display = 'block';
      }
    };
```
with:
```js
    const doLogin = async () => {
      try {
        err.style.display = 'none';
        await api.post('/api/auth/login', { password: pw.value });
        this.dispatchEvent(new CustomEvent('login-success', { bubbles: true }));
      } catch (e) {
        showFormError(err, 'Invalid password');
      }
    };
```

- [ ] **Step 4: Syntax check, build, and run the full e2e suite (verifies Tasks 6–8)**

Run:
```bash
cd /home/nixos/Develop/claude/noadd
awk '/<script>/{f=1;next} /<\/script>/{f=0} f' admin-ui/dist/index.html > /tmp/app.js && node --check /tmp/app.js && echo SYNTAX-OK
cargo build && cd e2e && npm test
```
Expected: `SYNTAX-OK`, build succeeds, all e2e scenarios pass. The `@auth` and `@onboarding` features exercise the setup/login forms (including error paths) and the dashboard features exercise the top tables — these directly cover Tasks 7–8.

- [ ] **Step 5: Commit**

```bash
cd /home/nixos/Develop/claude/noadd
git add admin-ui/dist/index.html
git commit -m "refactor(admin-ui): extract showFormError helper for setup/login forms"
```

---

### Task 9: Final measurement and report

**Files:**
- No modifications.

- [ ] **Step 1: Measure the result**

Run:
```bash
wc -c -l /home/nixos/Develop/claude/noadd/admin-ui/dist/index.html
git -C /home/nixos/Develop/claude/noadd log --oneline main..HEAD
```
Compute the delta against the Task 1 baseline (3463 lines / 130872 bytes).

- [ ] **Step 2: Confirm no documentation refers to the removed/renamed internals**

Run:
```bash
rg -n 'badge-on|rules-grid|btn-secondary|btn-ghost|renderTopDomains|renderTopClients|renderTopUpstreams' /home/nixos/Develop/claude/noadd/README.md /home/nixos/Develop/claude/noadd/ARCHITECTURE.md /home/nixos/Develop/claude/noadd/docs --glob '!docs/superpowers/**'
```
Expected: no matches (these are internal names). If something matches, update that doc to stay accurate and amend the relevant commit message context in the report.

- [ ] **Step 3: Report**

Summarize for the user: baseline vs final lines/bytes, list of commits, any extra dead code found by the audits (Tasks 2/6), any anomalies skipped to preserve zero-change (e.g., `.heatmap-tooltip` lacking a light-mode shadow override — a candidate follow-up, not done here).
