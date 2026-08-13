// e2e/specs/pages-no-js.spec.js
// The three pages the no-JS suites had not reached: the dashboard, settings and
// account. Filters, the query log and statistics each have their own file
// because each seeds heavily or empties something; these three do not, so they
// share one instance rather than booting three more binaries for it.
//
// What each is here to prove:
//   dashboard — a page of pure readings arrives with the readings in it, and
//               says so where the chart would be.
//   settings  — the no-JS save row is real: it posts, it persists, and a
//               rejected value comes back in the field with a reason.
//   account   — the actions that need a password proof carry the password in
//               their own form, so the path is identical with scripting off.
//
// Account spends password confirmations against the five-per-minute budget, so
// there is exactly one here plus the sign-in — the same reason
// account-sensitive-actions.spec.js is self-contained.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADMIN_USERNAME, ADMIN_PASSWORD } from '../screenshots/seed.mjs';

const E2E_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.NOADD_BIN || resolve(E2E_DIR, '../target/debug/noadd');
const DB = resolve(E2E_DIR, '.tmp/pages-no-js.db');
const HTTP = 14110, DNS = 15110;
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
let sessionToken;

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

  const login = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD }),
  });
  if (!login.ok) throw new Error(`login failed: ${login.status}`);
  sessionToken = /session=([^;]+)/.exec(login.headers.get('set-cookie') || '')?.[1];
  if (!sessionToken) throw new Error('no session cookie in the login response');
});

test.afterAll(async () => { await stopNoadd(server); });

test.use({ baseURL: BASE, javaScriptEnabled: false, reducedMotion: 'reduce' });

async function open(page, context, path) {
  await context.addCookies([{
    name: 'session', value: sessionToken, domain: '127.0.0.1', path: '/',
  }]);
  await page.goto(`${BASE}${path}`);
  await expect(page.getByTestId('app-shell')).toBeVisible();
}

// Pressing Enter in a field submits the form it belongs to, which is both how a
// browser does it and independent of where the button ended up — the status bar
// is fixed to the bottom of the viewport and can swallow a click near the fold.
async function submitFrom(locator) {
  await locator.press('Enter');
}

// Settings is the one form here that does not submit on Enter: implicit
// submission is skipped when a form holds more than one field and the browser
// cannot pick a default button for it, so this clicks the real one. `force`
// skips the hit-target check the fixed status bar can fail on a short viewport
// — the assertions after it only pass if the POST actually landed.
async function saveSettings(page) {
  await page.getByTestId('save-settings').click({ force: true });
}

test.describe('The remaining pages work with no JavaScript', () => {
  test('the dashboard arrives with its readings, and says what needs a browser', async ({ page, context }) => {
    await open(page, context, '/');

    // Six stat cards, filled in. This appliance has answered nothing, so the
    // rates are a real zero rather than a blank.
    await expect(page.getByTestId('stat-blocked-today')).toBeVisible();
    await expect(page.getByTestId('stat-block-rate')).toContainText('0.0%');
    await expect(page.getByTestId('stat-throughput-value')).toBeVisible();
    // The top-N tables are rendered, not fetched.
    await expect(page.getByTestId('top-domains-card')).toBeVisible();

    // The control that only works with a client ships hidden rather than
    // sitting there doing nothing.
    await expect(page.getByTestId('live-toggle')).toBeHidden();

    // Nothing has been queried, so the page explains what to do about it —
    // and hides the chart card rather than drawing an empty axis, which is why
    // the "drawn in the browser" note is in the markup but not on screen yet.
    await expect(page.getByTestId('dashboard-empty-state')).toBeVisible();
    await expect(page.getByTestId('dashboard-empty-state'))
      .toContainText('Point a device at noadd');
    await expect(page.locator('#chart-card')).toBeHidden();
    await expect(page.getByTestId('chart-needs-js')).toHaveCount(1);
  });

  test('settings saves through its form and persists', async ({ page, context }) => {
    await open(page, context, '/settings');

    // The no-JS save row is real markup, not a hidden fallback: `app.js`
    // removes it when it takes the form over.
    await expect(page.getByTestId('save-settings')).toBeVisible();

    // A browser posts the whole form, so every field has to be valid — an
    // appliance that has never been configured has no upstream yet, and saving
    // without one is a rejection rather than a partial write.
    await page.locator('#s-upstream').fill('1.1.1.1:53');
    await page.locator('#s-retention').fill('21');
    await saveSettings(page);

    // PRG: a flash on the redirected page, not a re-render.
    await expect(page.getByTestId('settings-saved')).toBeVisible();
    await expect(page).toHaveURL(/\/settings$/);

    // And it is really stored — a fresh load shows it.
    await page.goto(`${BASE}/settings`);
    await expect(page.locator('#s-retention')).toHaveValue('21');
    await expect(page.locator('#s-upstream')).toHaveValue('1.1.1.1:53');
  });

  test('a rejected setting comes back in the field with a reason', async ({ page, context }) => {
    await open(page, context, '/settings');

    // Store a known-good state first, so this test does not depend on another
    // one having run.
    await page.locator('#s-upstream').fill('9.9.9.9:53');
    await page.locator('#s-retention').fill('14');
    await saveSettings(page);
    await expect(page.getByTestId('settings-saved')).toBeVisible();

    await page.locator('#s-upstream').fill('not a server');
    await saveSettings(page);

    // Re-rendered with what was submitted rather than redirected, which would
    // have discarded it, and the reason sits next to the field that caused it.
    await expect(page.locator('#s-upstream')).toHaveValue('not a server');
    await expect(page.getByText('Not a valid upstream')).toBeVisible();
    await expect(page.getByTestId('settings-saved')).toHaveCount(0);

    // Nothing was written: the whole save is rejected rather than half applied.
    await page.goto(`${BASE}/settings`);
    await expect(page.locator('#s-upstream')).toHaveValue('9.9.9.9:53');
    await expect(page.locator('#s-retention')).toHaveValue('14');
  });

  test('the account page renders its tables and its delete confirmation', async ({ page, context }) => {
    await open(page, context, '/account');

    // All three tables are in the first response.
    await expect(page.getByTestId('operator-row')).toHaveCount(1);
    await expect(page.getByTestId('session-row')).not.toHaveCount(0);
    // The password field rides in the form that needs it — no dialog to open.
    await expect(page.getByTestId('operator-your-password')).toBeVisible();
    await expect(page.getByTestId('api-key-your-password')).toBeVisible();

    // A destructive row action expands into a named confirmation, which exists
    // without scripting because it is a link to a URL.
    await page.goto(`${BASE}/account?confirm_delete=1`);
    await expect(page.getByTestId('operator-confirm-row')).toBeVisible();
    await expect(page.getByTestId('operator-delete-password')).toBeVisible();
  });

  test('minting an API key shows the token in the response that created it', async ({ page, context }) => {
    await open(page, context, '/account');

    await page.getByTestId('api-key-name').fill('nojs-key');
    await page.getByTestId('api-key-your-password').fill(ADMIN_PASSWORD);
    await submitFrom(page.getByTestId('api-key-your-password'));

    // The one deliberate exception to PRG on these pages: the token exists in
    // this response and nowhere else, so it renders rather than redirecting.
    await expect(page.getByTestId('api-key-token')).toBeVisible();
    await expect(page.getByTestId('api-key-token')).not.toBeEmpty();
    await expect(page.getByTestId('api-key-row')).toContainText('nojs-key');

    // And the password is never echoed back into the markup.
    await expect(page.getByTestId('api-key-your-password')).toHaveValue('');
  });
});
