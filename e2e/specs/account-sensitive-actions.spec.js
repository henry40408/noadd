// e2e/specs/account-sensitive-actions.spec.js
// The three account actions that need a password proof — mint an API key, add
// an operator, delete one — now carry a "your password" field in their own
// form. There is no dialog: the password posts with the action, so the path is
// the same whether or not there is JavaScript, and there is no stale-proof
// state to fake.
//
// (This replaces reauth-prompt.spec.js, which tested the dialog and the
// retry-after-403 dance that went with it. `POST /api/auth/reauth` still exists
// for API callers and is covered in tests/admin_api_test.rs.)
//
// Self-contained instance on dedicated ports: it mints API keys, provisions and
// deletes operators, and spends password attempts against the five-per-minute
// budget the shared @auth instance has already used up. Every password
// confirmation here draws on that same budget, which is why there are exactly
// three of them plus the one sign-in.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADMIN_USERNAME, ADMIN_PASSWORD } from '../screenshots/seed.mjs';

const E2E_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.NOADD_BIN || resolve(E2E_DIR, '../target/debug/noadd');
const DB = resolve(E2E_DIR, '.tmp/account-sensitive-actions.db');
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

// One login for the whole file, replayed as a cookie: a UI sign-in per test
// would spend the budget these tests are actually here to exercise.
async function openAccount(page, context, query = '') {
  await context.addCookies([{
    name: 'session', value: sessionToken, domain: '127.0.0.1', path: '/',
  }]);
  await page.goto(`${BASE}/account${query}`);
  await expect(page.getByTestId('app-shell')).toBeVisible();
}

// Submitting from the password field, which is how HTML submits a form that has
// a submit button in it. It is also independent of where the button ended up:
// the status bar is fixed to the bottom of the viewport and the account page is
// long, so a click on a button near the fold can land on the status bar instead.
async function submitFrom(locator) {
  await locator.press('Enter');
}

test('an API key is minted when the form carries the right password', async ({ page, context }) => {
  await openAccount(page, context);

  await page.getByTestId('api-key-name').fill('ci');
  await page.getByTestId('api-key-your-password').fill(ADMIN_PASSWORD);
  await submitFrom(page.getByTestId('api-key-your-password'));

  // The token is shown once, on this response — creating a key is the one
  // action here that renders rather than redirecting, because a redirect would
  // throw away the only copy there will ever be.
  await expect(page.getByTestId('api-key-reveal')).toBeVisible();
  await expect(page.getByTestId('api-key-token')).toHaveValue(/^noadd_/);
  await expect(page.locator('[data-testid="api-key-row"][data-name="ci"]')).toBeVisible();
  // No dialog was involved, and there is none to involve.
  await expect(page.getByTestId('reauth-password')).toHaveCount(0);
});

test('a wrong password creates nothing and keeps what was typed', async ({ page, context }) => {
  await openAccount(page, context);

  await page.getByTestId('api-key-name').fill('rejected');
  await page.getByTestId('api-key-your-password').fill('not the password');
  await submitFrom(page.getByTestId('api-key-your-password'));

  await expect(page.getByTestId('api-key-error')).toContainText(/password is incorrect/i);
  // The name survives so only the password has to be retyped.
  await expect(page.getByTestId('api-key-name')).toHaveValue('rejected');
  await expect(page.getByTestId('api-key-reveal')).not.toBeVisible();
  await expect(page.locator('[data-testid="api-key-row"][data-name="rejected"]')).toHaveCount(0);
});

test('adding an operator needs the password, and deleting one asks by name', async ({ page, context }) => {
  await openAccount(page, context);

  await page.getByTestId('operator-username').fill('second-operator');
  await page.getByTestId('operator-password').fill('correct-horse-battery-staple-2');
  await page.getByTestId('operator-password-confirm').fill('correct-horse-battery-staple-2');
  await page.getByTestId('operator-your-password').fill(ADMIN_PASSWORD);
  await submitFrom(page.getByTestId('operator-your-password'));

  const row = page.locator('[data-testid="operator-row"][data-name="second-operator"]');
  await expect(row).toBeVisible();
  // A successful add redirects, so a refresh cannot provision a second one.
  await expect(page).toHaveURL(/\/account$/);

  // Deleting expands that row into a confirmation naming the operator, with its
  // own password field — a better prompt than a `confirm()`, and one that is
  // there without any JavaScript. No password is spent: this is a GET.
  await row.locator('.del-op').click({ force: true });
  await expect(page.getByTestId('operator-confirm-row')).toBeVisible();
  await expect(page.getByTestId('operator-confirm-row')).toContainText('second-operator');
  await expect(page.getByTestId('operator-delete-password')).toBeVisible();

  // Cancelling leaves the operator alone.
  await page.getByTestId('operator-confirm-row').getByText('Cancel').click({ force: true });
  await expect(page.getByTestId('operator-confirm-row')).toHaveCount(0);
  await expect(row).toBeVisible();
});
