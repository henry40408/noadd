# Fix: timeline-chart area fills + visible wrong-password login error

**Date:** 2026-06-13
**Files under change:**
- `admin-ui/dist/index.html` (single-file admin UI, vanilla JS + inline SVG, no build step)
- `e2e/features/setup-and-auth.feature` + `e2e/steps/auth.steps.js` (e2e coverage for the login error)
- **No Rust changes.** `src/admin/api.rs` already returns the right statuses (see Issue 2 findings).

**Branch:** `fix/admin-ui-chart-fill-and-login-error`

---

## ISSUE 1 — Timeline line charts need per-series area fills (like the rate chart)

### Findings (confirmed, with line anchors)

**Reference chart** — `StatsPage._renderRateTrend`, `admin-ui/dist/index.html:2729`.
Its fill mechanism is **NOT a gradient**: each series' line path is closed down to the
baseline and painted as a flat translucent fill with `fill-opacity="0.12"`:

- Lines 2761–2762 build the closed area paths:

  ```js
  const blockedArea = `${blockedPath.join(' ')} L${xs(len - 1).toFixed(1)},${(padY + innerH).toFixed(1)} L${xs(0).toFixed(1)},${(padY + innerH).toFixed(1)} Z`;
  const cachedArea = `${cachedPath.join(' ')} L${xs(len - 1).toFixed(1)},${(padY + innerH).toFixed(1)} L${xs(0).toFixed(1)},${(padY + innerH).toFixed(1)} Z`;
  ```

- Lines 2770–2773 render *area-then-stroke* per series, **both** series filled:

  ```html
  <path d="${cachedArea}" fill="var(--green)" fill-opacity="0.12"/>
  <path d="${cachedPath.join(' ')}" fill="none" stroke="var(--green)" stroke-width="1.5" .../>
  <path d="${blockedArea}" fill="var(--red)" fill-opacity="0.12"/>
  <path d="${blockedPath.join(' ')}" fill="none" stroke="var(--red)" stroke-width="1.5" .../>
  ```

There are **no `<linearGradient>`/`<defs>` anywhere** in `_renderRateTrend`. Because we
mirror this flat `fill-opacity` approach, **no SVG ids are introduced and the
gradient-id-collision concern is eliminated by construction.** (Do NOT introduce
gradients — the colors are CSS custom properties that differ per theme, and flat
fills inherit theme switching for free.)

**Current state of the shared helper** — `renderTimelineChart`, `admin-ui/dist/index.html:2126`.
It already fills **only** `series[0]` ("total") at a slightly different opacity:

- Lines 2147–2148:

  ```js
  const baseline = (padY + innerH).toFixed(1);
  const totalArea = `${paths[0].join(' ')} L${xs(len - 1).toFixed(1)},${baseline} L${xs(0).toFixed(1)},${baseline} Z`;
  ```

- Line 2177 inside the SVG template:

  ```html
  <path d="${totalArea}" fill="${series[0].color}" fill-opacity="0.10"/>
  ```

- Lines 2162–2164 render every series as a stroke-only line:

  ```js
  const lines = series.map((s, si) =>
    `<path d="${paths[si].join(' ')}" fill="none" stroke="${s.color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>`
  ).join('');
  ```

**Callers (no changes needed, listed for context):**
- `DashboardPage.renderChart` — line 2406 — series `total: var(--accent)`, `blocked: var(--red)`.
- `StatsPage._renderTimeline` — line 2585 — series `total: var(--accent)`,
  `cached: var(--orange)`, `blocked: var(--red)`.

### Decision: ALL series get area fills (not just "total")

Justification:
1. The reference chart (`_renderRateTrend`) fills **all** of its series; "only total"
   is essentially the status quo the user is complaining about (total is already
   filled at 0.10).
2. Legibility holds because the secondary series are strict subsets of total
   (`blocked ≤ total`, `cached ≤ total`), so their fills nest *inside* the total
   fill instead of crossing it. At `fill-opacity 0.12` per layer the worst-case
   stack (total + cached + blocked near the baseline) is ≈ 0.3 effective alpha —
   still a tint, not a mud pool — and the rate chart already proves two overlapping
   0.12 fills read cleanly in both themes.
3. Draw order: **all areas first (series order, total underneath), then all strokes**,
   so no fill ever occludes another series' line. (The rate chart interleaves
   area/stroke per series; areas-first is strictly safer for 3 series.)

Use `fill-opacity="0.12"` for every series — identical to the rate chart, so all
three charts share one visual language. Colors stay the callers' CSS custom
properties (`var(--accent)`, `var(--red)`, `var(--orange)`), which adapt to the
light theme automatically (`:root` dark values lines 26–41; light overrides
lines 58–69).

### Edits (all in `admin-ui/dist/index.html`)

**Edit 1a — doc comment, lines 2121–2123.** Replace:

```js
// data    — raw API rows; series[0].key must be 'total': it sets the y-scale
//           and gets the area fill
// series  — [{ key, color }] drawn in order (total first, underneath)
```

with:

```js
// data    — raw API rows; series[0].key must be 'total': it sets the y-scale
// series  — [{ key, color }] drawn in order (total first, underneath); every
//           series gets a translucent area fill (same flat fill-opacity style
//           as StatsPage._renderRateTrend — no gradients, theme-safe)
```

**Edit 1b — area construction, lines 2147–2148.** Replace:

```js
  const baseline = (padY + innerH).toFixed(1);
  const totalArea = `${paths[0].join(' ')} L${xs(len - 1).toFixed(1)},${baseline} L${xs(0).toFixed(1)},${baseline} Z`;
```

with:

```js
  const baseline = (padY + innerH).toFixed(1);
  const areaClose = ` L${xs(len - 1).toFixed(1)},${baseline} L${xs(0).toFixed(1)},${baseline} Z`;
  const areas = series.map((s, si) =>
    `<path d="${paths[si].join(' ')}${areaClose}" fill="${s.color}" fill-opacity="0.12"/>`
  ).join('');
```

(`len === 1` degenerates to a zero-width area exactly as `totalArea` does today —
harmless; the static dots at line 2167 still mark the point.)

**Edit 1c — SVG template, line 2177.** Replace:

```js
      <path d="${totalArea}" fill="${series[0].color}" fill-opacity="0.10"/>
```

with:

```js
      ${areas}
```

(The strokes `${lines}` at line 2178 already render after the fills; keep them and
everything else — `${ticks}`, `${single}`, the `.rate-cursor` group — untouched.)

**That's the whole of Issue 1.** No CSS changes, no caller changes, no ids, no defs.

---

## ISSUE 2 — Wrong password shows no visible error on login

### Root cause (confirmed)

**Backend is correct.** `login()` in `src/admin/api.rs:207` returns
`401 UNAUTHORIZED` on a bad password (line 233) and `429 TOO_MANY_REQUESTS` when
rate-limited (line 217). Covered by `tests/admin_api_test.rs::test_login_wrong_password`
(line 494) and `::test_login_rate_limit_is_per_connect_info_ip` (line 370).
**No Rust changes needed.**

**Frontend bug:** the global API client treats *every* 401 as "session expired",
including the failed login POST itself. `admin-ui/dist/index.html:1434–1438`:

```js
    const res = await fetch(path, opts);
    if (res.status === 401) {
      window.dispatchEvent(new CustomEvent('auth-required'));
      throw new Error('Unauthorized');
    }
```

`auth-required` is bound to `showLogin` (line 3568), and `showLogin` (lines
3540–3544) does `app.innerHTML = ''` and mounts a **fresh** `<login-page>`. So by
the time `doLogin`'s `catch` (lines 1652–1654) calls
`showFormError(err, 'Invalid password')`, `err` is the `#login-error` div of the
**old, detached** DOM tree — the message is written into a node nobody can see.
Observable behavior: the form silently resets. The e2e feature even documents the
bug (`e2e/features/setup-and-auth.feature:48–50`: "A rejected login re-renders the
sign-in screen rather than showing an inline error").

Secondary problem: even when `.login-error` does show (setup page uses it), its
styling (lines 678–683) is a bare small red text line — too timid:

```css
.login-error {
  color: var(--red);
  font-size: 0.8rem;
  margin-bottom: 12px;
  display: none;
}
```

### Fix design

Three parts, frontend only. Per the UI guidance, make the error block aggressively
visible on the first pass (bordered alert panel, not a thin text line).

**Edit 2a — `admin-ui/dist/index.html:1435`: don't treat a failed login as an
expired session.** Replace:

```js
    if (res.status === 401) {
```

with:

```js
    if (res.status === 401 && path !== '/api/auth/login') {
```

A 401 from `/api/auth/login` now falls through to line 1439
(`if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)`) and is caught
by `doLogin` with the login page still mounted. All other endpoints keep the
existing expired-session redirect. (Bootstrap/logout paths are unaffected; the
worst prior side effect — double `showLogin` from `bootstrap()` — also goes away
for the login path.)

**Edit 2b — `admin-ui/dist/index.html:1647–1655`: clear, specific messages +
refocus.** Replace `doLogin`:

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

with:

```js
    const doLogin = async () => {
      try {
        err.style.display = 'none';
        await api.post('/api/auth/login', { password: pw.value });
        this.dispatchEvent(new CustomEvent('login-success', { bubbles: true }));
      } catch (e) {
        const limited = /^429\b/.test((e && e.message) || '');
        showFormError(err, limited
          ? 'ERR: too many attempts — wait a minute, then retry'
          : 'ERR: incorrect password — access denied');
        pw.focus();
        pw.select();
      }
    };
```

Notes: message stays generic ("incorrect password" — the app has a single admin
password, so this reveals nothing; do **not** distinguish missing-hash vs bad
password). The `ERR:` prefix fits the boot-log terminal aesthetic. `pw.select()`
lets the operator retype immediately.

**Edit 2c — `admin-ui/dist/index.html:678–683`: make `.login-error` an obvious
alert panel.** Replace the block quoted above with:

```css
.login-error {
  display: none;
  margin-bottom: 12px;
  padding: 8px 10px;
  font-family: var(--font-mono);
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--red);
  background: var(--red-dim);
  border: 1px solid var(--red);
  box-shadow: var(--glow-red);
}
```

Why this works in both themes: `--red`/`--red-dim` have dark-theme values at lines
30–31 and light-theme overrides at lines 62–63; `--glow-red` is `none` in light
theme (line 69), so the glow is dark-theme-only by design. The same class styles
`#setup-error` (`data-testid="setup-error"`, line 1579) — the setup page gets the
same upgrade for free, which is consistent, desirable, and changes no testids.

**Edit 2d — accessibility (small, same render template, line 1636).** Replace:

```html
          <div class="login-error" id="login-error" data-testid="login-error"></div>
```

with:

```html
          <div class="login-error" id="login-error" data-testid="login-error" role="alert"></div>
```

(Keep `id` and `data-testid` exactly as-is.)

**Edit 2e — e2e: assert the inline error.** In
`e2e/features/setup-and-auth.feature`, scenario "Sign in fails with an incorrect
password" (lines 44–50), replace:

```gherkin
    And I sign in with the password "wrong password"
    # A rejected login re-renders the sign-in screen rather than showing an
    # inline error, so the observable outcome is simply staying signed out.
    Then I remain on the sign-in screen
```

with:

```gherkin
    And I sign in with the password "wrong password"
    Then I see a sign-in error telling me the password is incorrect
    And I remain on the sign-in screen
```

In `e2e/steps/auth.steps.js`, after the existing
`Then('I remain on the sign-in screen', ...)` (line 58), add:

```js
Then('I see a sign-in error telling me the password is incorrect', async ({ page }) => {
  const err = page.getByTestId('login-error');
  await expect(err).toBeVisible();
  await expect(err).toContainText(/incorrect password/i);
});
```

(`I remain on the sign-in screen` still passes: the login page is no longer
re-mounted, but `login-submit` remains visible, which is all the step asserts.
The existing fixture login flow in `e2e/steps/fixtures.js:35–44` uses the correct
password and is unaffected.)

---

## data-testids that MUST be preserved (all are)

`login-error`, `login-password`, `login-submit`, `setup-error`, plus all chart-page
ids (`live-toggle`, `dashboard-empty-state`, `top-domains-card`, nav/topbar ids).
No testid is renamed or removed by this plan.

## Explicitly out of scope

- No `<linearGradient>`s (so no SVG id scheme is needed — flat fills only).
- No Rust source changes; no version/CHANGELOG bumps.
- No change to the rate chart itself, the bar charts, heatmap, tooltips, or cursor
  interaction code.

---

## Verification

Run from the repo root unless noted; `pwd` first per workflow rules.

### Automated

1. `cd /home/nixos/Develop/claude/noadd && cargo nextest run` — must stay green
   (no Rust changed; this guards against accidental edits). `cargo fmt` is not
   required since no `.rs` file changes, but running it is harmless.
2. e2e suite (Playwright/cucumber, see `e2e/`): run the auth feature —
   the updated "Sign in fails with an incorrect password" scenario must pass
   (error visible + text matches), and "Sign in succeeds with the correct
   password" must still pass.

### Manual / visual (use `mcp` Playwright or a browser against a running server)

**Issue 1 — charts.** For each of: Dashboard "Queries (24h)", Statistics
"Queries (last Nd)", Statistics "Block & cache rate (last Nd)":
- [ ] Every plotted line has a translucent area fill beneath it down to the
      baseline, visually matching the rate chart's fill weight.
- [ ] Dashboard: accent (total) fill + red (blocked) fill nested inside; lines
      remain crisp on top of fills.
- [ ] Stats timeline: accent + orange (cached) + red (blocked) fills all visible
      and distinguishable; overlap region near the baseline is tinted, not muddy.
- [ ] Hover tooltip + cursor dots still track correctly (interaction code untouched).
- [ ] Single-data-point edge case still renders dots without console errors.
- [ ] Check all of the above in **dark and light** themes (light = system
      preference; toggle via DevTools emulation `prefers-color-scheme`).
- [ ] Check at desktop (~1280px) and mobile (~390px) widths — fills stretch with
      `preserveAspectRatio="none"` like the existing strokes; y-tick labels still
      unsquished.

**Issue 2 — login.**
- [ ] With a password set, submit a **wrong** password: the form does NOT reset;
      a bordered red alert appears above the password line reading
      `ERR: incorrect password — access denied`; the password field is focused
      with its text selected. `data-testid="login-error"` is visible.
- [ ] Submit the **correct** password: login succeeds and lands on the dashboard
      (no regression from the `api.request` change).
- [ ] Hammer 6+ wrong attempts quickly: alert switches to the
      `too many attempts` message (backend 429).
- [ ] Expired-session behavior unchanged: while logged in, revoke all sessions
      (Settings) → next API call still redirects to the sign-in screen.
- [ ] Error panel contrast is obvious in **both** themes (red border + `--red-dim`
      background; glow only in dark theme).
- [ ] Mobile width: alert panel wraps cleanly inside `.login-box`.

### Acceptance criteria

1. All three SVG charts share the same area-fill style (`fill-opacity 0.12`, flat,
   per series), in both themes, desktop and mobile.
2. A wrong password produces an immediately visible, high-contrast inline error in
   the login form without re-rendering/clearing the form; correct password still
   logs in; rate-limited attempts show a distinct message.
3. `cargo nextest run` green; e2e auth scenarios green; no `data-testid` changes.
