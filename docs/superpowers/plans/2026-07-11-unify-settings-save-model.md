# Unify Settings Save Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (this is a single cohesive frontend change, executed in-session). Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make every control on the admin Settings page use one consistent "change = saved" model, removing the ambiguous "Save Settings" button, so users never have to guess which settings auto-save and which need a button click.

**Architecture:** The Settings page (`admin-ui/dist/index.html`, `SettingsPage` web component) already auto-saves 3 of its selects on `change`. This plan extends auto-save to the two text fields (Log Retention, Public URL) and the block-mode controls, routes every save through one shared helper that flashes inline "✔ Saved / ✗ error" feedback, adds client-side validation so invalid/partial values never hit the network, and deletes the `#save-settings` button. Upstream DNS keeps its own "Save & apply" button (multi-line, validated, triggers reconfigure + health recheck — a genuinely different operation).

**Tech Stack:** Vanilla-JS web components in a single embedded HTML file (no build step; `cargo build` re-embeds). Playwright (standalone spec) for the regression test.

## Global Constraints

- Single-file admin UI at `admin-ui/dist/index.html`; no framework, no new deps. `cargo build` re-embeds it.
- Event choice matters: text inputs use **`onchange`** (fires on blur / Enter), **never `oninput`** (per-keystroke) — mid-typing must fire zero requests.
- Invalid or partial values MUST NOT produce a network request: validate client-side first, flash an inline error, and return without PUT.
- Commits GPG-signed (default git config; no `--no-gpg-sign`). Stage files explicitly by name; never `git add -A` / `.`.
- Continue on the existing branch `feat/configurable-block-mode` (integrate into PR #138). Do NOT create a new branch.
- Settings page is NOT in the screenshot capture set (`e2e/screenshots/capture.mjs` SHOTS = #dashboard/#stats/#logs/#filters) — no screenshot regeneration.
- Rust is untouched; `cargo nextest run` must remain green (297/3) as a no-regression check.

## Current-state reference (verified)

- Settings route hash: `#settings`; nav testid `nav-settings`; page element `settings-page`.
- Login testids: `login-username`, `login-password`, `login-submit`; shell testid `app-shell`.
- Auto-save today (onchange → PUT): `#s-strategy`, `#s-dnssec`, `#s-doh-policy`, and (from the in-progress block-mode fix) `#s-block-mode` / `#s-block-ipv4` / `#s-block-ipv6`.
- Button-only today: `#s-retention` (log_retention_days), `#s-public-url` (public_url), via `#save-settings`.
- `#save-settings` onclick currently PUTs: `upstream_strategy, log_retention_days, doh_access_policy, public_url, block_mode, block_custom_ipv4, block_custom_ipv6`.
- Backend `put_settings` validates `block_custom_ipv4/ipv6` whenever the key is present and non-empty, **regardless of `block_mode`** — so the UI must not send a stale/invalid custom IP under a non-`custom_ip` mode (it would 400).
- `api.put` throws on non-2xx (`if (!res.ok) throw`).

---

### Task 1: Add the failing Playwright regression spec

**Files:**
- Create: `e2e/specs/settings-autosave.spec.js`
- Modify: `e2e/playwright.config.js` (register a `settings` project — the existing `touch` project matches only `chart-touch.spec.js`, so a new spec is otherwise never collected)

**Interfaces:**
- Consumes: the noadd debug binary (`../target/debug/noadd`), `ADMIN_USERNAME`/`ADMIN_PASSWORD` from `../screenshots/seed.mjs`.
- Produces: a self-contained spec on dedicated ports 14104/15104 (disjoint from app/auth/onboarding/chart-touch which use 14100-14103), run via `--project=settings`.

- [ ] **Step 1: Write the spec**

Create `e2e/specs/settings-autosave.spec.js`:

```javascript
// e2e/specs/settings-autosave.spec.js
// Regression: the Settings page must use ONE consistent "change = saved" model.
// Every control auto-saves on change/blur; there is no "Save Settings" button;
// mid-typing fires zero requests (onchange, not oninput); invalid/partial values
// never hit the network. Self-contained noadd instance on dedicated ports.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADMIN_USERNAME, ADMIN_PASSWORD } from '../screenshots/seed.mjs';

const E2E_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.NOADD_BIN || resolve(E2E_DIR, '../target/debug/noadd');
const DB = resolve(E2E_DIR, '.tmp/settings-autosave.db');
const HTTP = 14104, DNS = 15104;
const BASE = `http://127.0.0.1:${HTTP}`;

function startNoadd() {
  const child = spawn(BIN, [
    '--db-path', DB,
    '--http-addr', `127.0.0.1:${HTTP}`,
    '--dns-addr', `127.0.0.1:${DNS}`,
    '--log-format', 'json',
  ], { stdio: ['ignore', 'ignore', 'inherit'] });
  child.exited = new Promise((res) => child.once('exit', res));
  return child;
}
async function waitHealthy(timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { if ((await fetch(`${BASE}/api/health`)).ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('noadd did not become healthy in time');
}
async function stopNoadd(child) {
  if (!child) return;
  child.kill('SIGTERM');
  const killer = setTimeout(() => child.kill('SIGKILL'), 10_000);
  await child.exited;
  clearTimeout(killer);
}

let server;

test.beforeAll(async () => {
  mkdirSync(resolve(E2E_DIR, '.tmp'), { recursive: true });
  for (const suffix of ['', '-wal', '-shm']) rmSync(`${DB}${suffix}`, { force: true });
  server = startNoadd();
  await waitHealthy();
  const res = await fetch(`${BASE}/api/auth/setup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD }),
  });
  if (!res.ok) throw new Error(`setup failed: ${res.status}`);
});

test.afterAll(async () => { await stopNoadd(server); });

test.use({ baseURL: BASE });

async function gotoSettings(page) {
  await page.goto('/');
  await page.getByTestId('login-username').fill(ADMIN_USERNAME);
  await page.getByTestId('login-password').fill(ADMIN_PASSWORD);
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('app-shell')).toBeVisible();
  await page.evaluate(() => { location.hash = '#settings'; });
  await page.locator('#s-block-mode').waitFor();
}

test.describe('Settings page uses one consistent save model', () => {
  test('there is no Save Settings button', async ({ page }) => {
    await gotoSettings(page);
    await expect(page.locator('#save-settings')).toHaveCount(0);
  });

  test('changing block mode persists across reload (no button click)', async ({ page }) => {
    await gotoSettings(page);
    const put = page.waitForResponse((r) =>
      r.url().includes('/api/settings') && r.request().method() === 'PUT' && r.ok());
    await page.locator('#s-block-mode').selectOption('nxdomain');
    await put;
    await page.reload();
    await page.locator('#s-block-mode').waitFor();
    await expect(page.locator('#s-block-mode')).toHaveValue('nxdomain');
  });

  test('custom IP persists across reload', async ({ page }) => {
    await gotoSettings(page);
    await page.locator('#s-block-mode').selectOption('custom_ip');
    await expect(page.locator('#s-block-custom')).toBeVisible();
    const put = page.waitForResponse((r) =>
      r.url().includes('/api/settings') && r.request().method() === 'PUT' && r.ok());
    await page.locator('#s-block-ipv4').fill('192.0.2.1');
    await page.locator('#s-block-ipv4').blur();
    await put;
    await page.reload();
    await page.locator('#s-block-mode').waitFor();
    await expect(page.locator('#s-block-mode')).toHaveValue('custom_ip');
    await expect(page.locator('#s-block-ipv4')).toHaveValue('192.0.2.1');
  });

  test('typing a partial IP fires no request until blur, and invalid IP never PUTs', async ({ page }) => {
    await gotoSettings(page);
    await page.locator('#s-block-mode').selectOption('custom_ip');
    const puts = [];
    page.on('request', (req) => {
      if (req.url().includes('/api/settings') && req.method() === 'PUT') puts.push(req.postData());
    });
    // Type an incomplete IPv4 character-by-character (fires input events per char).
    await page.locator('#s-block-ipv4').click();
    await page.keyboard.type('192.168.1');       // still incomplete/invalid
    await expect.poll(() => puts.length).toBe(0); // nothing sent mid-typing
    await page.locator('#s-block-ipv4').blur();    // blur with an invalid value
    // Give any (incorrect) handler a chance to fire, then assert none did.
    await page.waitForTimeout(300);
    expect(puts.length).toBe(0);                   // invalid value never hits the network
    // The field shows an inline error hint.
    await expect(page.locator('#settings-status')).toContainText(/IPv4/i);
  });

  test('log retention auto-saves on blur and rejects non-numeric without a request', async ({ page }) => {
    await gotoSettings(page);
    // Valid: persists.
    const put = page.waitForResponse((r) =>
      r.url().includes('/api/settings') && r.request().method() === 'PUT' && r.ok());
    await page.locator('#s-retention').fill('14');
    await page.locator('#s-retention').blur();
    await put;
    await page.reload();
    await page.locator('#s-retention').waitFor();
    await expect(page.locator('#s-retention')).toHaveValue('14');
    // Invalid: no request.
    const puts = [];
    page.on('request', (req) => {
      if (req.url().includes('/api/settings') && req.method() === 'PUT') puts.push(1);
    });
    await page.locator('#s-retention').fill('abc');
    await page.locator('#s-retention').blur();
    await page.waitForTimeout(300);
    expect(puts.length).toBe(0);
  });
});
```

- [ ] **Step 2: Register the `settings` project in `playwright.config.js`**

The `projects` array's only `specs/` entry is `touch`, whose `testMatch` is `/chart-touch\.spec\.js$/` — it will not collect the new spec. Add a sibling project immediately after the `touch` project block (before the closing `]` of `projects`):

```javascript
    {
      // Settings-page auto-save model regression. Plain Playwright spec that
      // seeds and drives its own noadd instance (dedicated ports 14104/15104),
      // like `touch`; needs no shared server, storageState, or webServer entry.
      name: 'settings',
      testDir: 'specs',
      testMatch: /settings-autosave\.spec\.js$/,
      use: { ...devices['Desktop Chrome'] },
    },
```

(`devices` is already imported at the top of the config.)

- [ ] **Step 3: Run the spec against current code — watch it FAIL**

```bash
cd /Users/henry/Develop/claude/noadd && cargo build 2>&1 | tail -2
cd e2e && npx playwright test --project=settings 2>&1 | tail -30
```
Expected FAIL: "no Save Settings button" fails (button still present); the retention and partial/invalid-IP tests fail (no auto-save on those fields / no `#settings-status` element). This proves the spec exercises the target behavior. (The block-mode-persists test may already pass because of the in-progress block-mode auto-save edit — that's fine; the other failures still gate the task.)

- [ ] **Step 4: Commit the failing spec + project registration**

```bash
git add e2e/specs/settings-autosave.spec.js e2e/playwright.config.js
git commit -m "test(e2e): settings page uses one consistent auto-save model"
```

---

### Task 2: Implement the unified save model in `index.html`

**Files:**
- Modify: `admin-ui/dist/index.html` — settings markup (`#save-settings` button ~line 3844), the `connectedCallback` handler wiring (~lines 3870-3940).

**Interfaces:**
- Consumes: existing `api.put`, control IDs listed in Current-state reference.
- Produces: `#settings-status` element; `flash`, `putSetting`, `isIpv4`, `isIpv6`, `saveBlockMode` helpers; auto-save handlers on every control; no `#save-settings` button/handler.

- [ ] **Step 1: Replace the Save Settings button with a status line**

Replace the button markup (currently `<button ... id="save-settings">Save Settings</button>` at ~line 3844) with:

```html
      <div class="fade-in" style="animation-delay:0.15s;display:flex;align-items:center;gap:10px;min-height:22px;margin-top:4px">
        <span style="color:var(--text-dim);font-size:0.8rem">Changes are saved automatically.</span>
        <span id="settings-status" style="font-size:0.8rem"></span>
      </div>
```

- [ ] **Step 2: Remove the `#save-settings` onclick handler**

Delete the entire `this.querySelector('#save-settings').onclick = async () => { ... };` block (currently ~lines 3870-3883).

- [ ] **Step 3: Add the shared save/validate helpers and rewrite every control handler**

Replace the block of onchange handlers (currently the `#s-doh-policy` / `#s-strategy` / `#s-dnssec` handlers plus the in-progress `syncBlockCustom` / `saveBlockMode` block, ~lines 3914-3940) with this single cohesive block:

```javascript
    // --- Unified auto-save: every control saves on change/blur through one
    // helper that flashes inline feedback. Invalid values never hit the network.
    const settingsStatus = this.querySelector('#settings-status');
    let statusTimer = null;
    const flash = (ok, msg) => {
      settingsStatus.style.color = ok ? 'var(--accent)' : 'var(--red)';
      settingsStatus.textContent = (ok ? '✔ ' : '✗ ') + msg;
      if (statusTimer) clearTimeout(statusTimer);
      if (ok) statusTimer = setTimeout(() => { settingsStatus.textContent = ''; }, 2000);
    };
    const putSetting = async (payload, okMsg) => {
      try {
        await api.put('/api/settings', payload);
        flash(true, okMsg);
      } catch (e) {
        flash(false, 'Save failed');
      }
    };
    const isIpv4 = (s) =>
      /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s);
    const isIpv6 = (s) => { try { new URL('http://[' + s + ']/'); return true; } catch (e) { return false; } };

    this.querySelector('#s-doh-policy').onchange = (e) =>
      putSetting({ doh_access_policy: e.target.value }, 'DoH policy saved');

    this.querySelector('#s-strategy').onchange = (e) => {
      putSetting({ upstream_strategy: e.target.value }, 'Strategy saved');
      this.loadEma();
    };

    this.querySelector('#s-dnssec').onchange = (e) =>
      putSetting({ dnssec_disabled: e.target.value === 'off' ? 'true' : 'false' }, 'DNSSEC saved');

    this.querySelector('#s-retention').onchange = (e) => {
      const v = e.target.value.trim();
      if (!/^\d+$/.test(v) || parseInt(v, 10) < 1) { flash(false, 'Retention must be a positive integer'); return; }
      putSetting({ log_retention_days: v }, 'Retention saved');
    };

    this.querySelector('#s-public-url').onchange = (e) => {
      const v = e.target.value.trim();
      if (v !== '') {
        let ok = /^https:\/\//i.test(v);
        if (ok) { try { new URL(v); } catch (err) { ok = false; } }
        if (!ok) { flash(false, 'Public URL must be a valid https:// URL'); return; }
      }
      putSetting({ public_url: v }, 'Public URL saved');
    };

    const syncBlockCustom = () => {
      this.querySelector('#s-block-custom').style.display =
        this.querySelector('#s-block-mode').value === 'custom_ip' ? 'flex' : 'none';
    };
    const saveBlockMode = () => {
      const mode = this.querySelector('#s-block-mode').value;
      // Non-custom modes ignore the IP fields; send mode only so a stale/partial
      // value in a hidden field can never trigger a backend 400.
      if (mode !== 'custom_ip') { putSetting({ block_mode: mode }, 'Block mode saved'); return; }
      const v4 = this.querySelector('#s-block-ipv4').value.trim();
      const v6 = this.querySelector('#s-block-ipv6').value.trim();
      if (v4 !== '' && !isIpv4(v4)) { flash(false, 'Invalid custom IPv4'); return; }
      if (v6 !== '' && !isIpv6(v6)) { flash(false, 'Invalid custom IPv6'); return; }
      putSetting({ block_mode: mode, block_custom_ipv4: v4, block_custom_ipv6: v6 }, 'Block mode saved');
    };
    this.querySelector('#s-block-mode').onchange = () => { syncBlockCustom(); saveBlockMode(); };
    this.querySelector('#s-block-ipv4').onchange = saveBlockMode;
    this.querySelector('#s-block-ipv6').onchange = saveBlockMode;
```

Notes:
- `✔` = ✔, `✗` = ✗ (avoid embedding raw glyphs in the plan/source-diff ambiguity; either the escape or the literal char is fine in the actual file).
- `log_retention_days` and `public_url` were previously saved only by the deleted button; they now auto-save on blur. This is the behavior change that removes the ambiguity.
- Selecting `custom_ip` fires `saveBlockMode` immediately with empty IPs → persists `block_mode=custom_ip` with empty custom IPs (documented: empty → NoError empty answer), then the IP fields save on blur.

- [ ] **Step 4: Rebuild to re-embed the UI**

```bash
cd /Users/henry/Develop/claude/noadd && cargo build 2>&1 | tail -2
```
Expected: builds clean (re-embeds index.html).

- [ ] **Step 5: Run the regression spec — watch it PASS**

```bash
cd /Users/henry/Develop/claude/noadd/e2e && npx playwright test --project=settings 2>&1 | tail -30
```
Expected: all 5 tests PASS.

- [ ] **Step 6: Manual sanity check (optional but recommended)**

Start the server, open Settings, confirm: no "Save Settings" button; changing any select flashes "✔ … saved"; editing Retention/Public URL and clicking away flashes saved; typing a partial IP in custom_ip mode sends nothing until blur; an invalid IP flashes "✗ Invalid custom IPv4/6" and sends nothing.

- [ ] **Step 7: Commit**

```bash
git add admin-ui/dist/index.html
git commit -m "feat: unify settings page on a single auto-save model, drop Save Settings button"
```

---

### Task 3: Gate + PR update

- [ ] **Step 1: No-regression gate (Rust untouched, confirm still green)**

```bash
cd /Users/henry/Develop/claude/noadd
cargo fmt --check && cargo clippy --all-targets -- -D warnings 2>&1 | tail -3 && cargo nextest run 2>&1 | tail -5
```
Expected: fmt clean, clippy clean, 297 passed / 3 skipped (unchanged — no Rust edits).

- [ ] **Step 2: Push (updates PR #138)**

```bash
git push
```
The branch already has an open PR (#138); pushing updates it. Do not open a new PR. Do not merge (awaits user confirmation + CI per CLAUDE.md).

- [ ] **Step 3: Note the UX change in the PR**

Add a short PR comment (English) summarizing the settings-model unification, since it extends the PR's scope beyond the original block-mode feature.

---

## Self-Review Notes

- **Spec coverage:** unified model (Task 2), no button (T1 test 1 + T2 S1/S2), block-mode persists on change (T1 test 2), custom IP persists (T1 test 3), no-request-mid-typing + invalid-IP-no-PUT (T1 test 4 — the user's explicit concern), retention auto-save + reject-non-numeric (T1 test 5), inline feedback via `#settings-status` (T2 S3), upstream keeps its own button (untouched). Covered.
- **Event correctness:** all text inputs use `onchange` (blur/Enter), never `oninput` — verified in every handler in T2 S3.
- **Backend-400 avoidance:** `saveBlockMode` sends IP keys only in `custom_ip` mode; client validation blocks invalid IPs/retention/URL before any PUT.
- **Type/name consistency:** `#settings-status`, `flash`, `putSetting`, `isIpv4`, `isIpv6`, `saveBlockMode`, `syncBlockCustom` used identically across markup and handlers.
- **Known limitation (acceptable):** client-side IPv6 validation uses the URL-bracket trick, a light filter; the backend `Ipv6Addr` parse remains the authority and any mismatch surfaces as "Save failed" via the `putSetting` catch.
