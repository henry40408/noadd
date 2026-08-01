// e2e/specs/reauth-prompt.spec.js
// The client half of re-authentication: a sensitive action that comes back
// with `code: reauth_required` must raise the password dialog, confirm it
// against /api/auth/reauth, and then retry the original request.
//
// The server's own contract is covered in tests/admin_api_test.rs. What cannot
// be reached from a browser is the *stale* state: the window is five minutes
// and lives in memory, so a session created seconds ago is always fresh. The
// first response is therefore stubbed with `page.route`, which is the only
// part that is faked — the retry, the /api/auth/reauth call, and the resulting
// key are all real, served by a real noadd.
//
// Self-contained instance on dedicated ports: it mints API keys and spends
// login attempts, and the shared @auth instance has neither to spare.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADMIN_USERNAME, ADMIN_PASSWORD } from '../screenshots/seed.mjs';

const E2E_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.NOADD_BIN || resolve(E2E_DIR, '../target/debug/noadd');
const DB = resolve(E2E_DIR, '.tmp/reauth-prompt.db');
const HTTP = 14106, DNS = 15106;
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

/// Fail the *first* POST /api/api-keys with the server's stale-proof
/// response, and let every later one through to the real server.
async function stubFirstKeyCreateAsStale(page) {
  let stubbed = false;
  await page.route(`${BASE}/api/api-keys`, async (route) => {
    if (route.request().method() !== 'POST' || stubbed) return route.continue();
    stubbed = true;
    await route.fulfill({
      status: 403,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'confirm your password to continue', code: 'reauth_required' }),
    });
  });
}

// One login for the whole file, replayed as a cookie. `/api/auth/reauth`
// shares the five-per-minute login budget, and these three tests spend three
// of it between them — a UI sign-in per test would push the total past the
// limit and fail on a 429 that has nothing to do with what is under test.
async function openAccount(page, context) {
  await context.addCookies([{
    name: 'session', value: sessionToken, domain: '127.0.0.1', path: '/',
  }]);
  await page.goto(`${BASE}/`);
  await expect(page.getByTestId('app-shell')).toBeVisible();
  await page.getByTestId('nav-account').click();
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

test('confirming the password retries the action that was refused', async ({ page, context }) => {
  await openAccount(page, context);
  await stubFirstKeyCreateAsStale(page);

  await page.getByTestId('api-key-name').fill('ci');
  await page.getByTestId('api-key-create').click();

  await expect(page.getByTestId('reauth-password')).toBeVisible();
  await page.getByTestId('reauth-password').fill(ADMIN_PASSWORD);
  await page.getByTestId('reauth-submit').click();

  // The retry went to the real server, so a real token comes back.
  await expect(page.getByTestId('api-key-reveal')).toBeVisible();
  await expect(page.getByTestId('api-key-token')).toHaveValue(/^noadd_/);
});

test('a wrong password is reported without dismissing the dialog', async ({ page, context }) => {
  await openAccount(page, context);
  await stubFirstKeyCreateAsStale(page);

  await page.getByTestId('api-key-name').fill('ci');
  await page.getByTestId('api-key-create').click();

  await page.getByTestId('reauth-password').fill('not the password');
  await page.getByTestId('reauth-submit').click();
  await expect(page.getByTestId('reauth-error')).toContainText(/incorrect/i);
  // Still open, so the operator can simply try again.
  await expect(page.getByTestId('reauth-password')).toBeVisible();

  await page.getByTestId('reauth-password').fill(ADMIN_PASSWORD);
  await page.getByTestId('reauth-submit').click();
  await expect(page.getByTestId('api-key-reveal')).toBeVisible();
});

test('cancelling creates nothing and leaves the form alone', async ({ page, context }) => {
  await openAccount(page, context);
  await stubFirstKeyCreateAsStale(page);

  await page.getByTestId('api-key-name').fill('abandoned');
  await page.getByTestId('api-key-create').click();

  await page.getByTestId('reauth-cancel').click();
  await expect(page.getByTestId('reauth-password')).toHaveCount(0);
  await expect(page.getByTestId('api-key-reveal')).not.toBeVisible();
  // The typed name survives, so cancelling costs nothing but the click.
  await expect(page.getByTestId('api-key-name')).toHaveValue('abandoned');
});
