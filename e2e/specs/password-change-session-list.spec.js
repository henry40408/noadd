// e2e/specs/password-change-session-list.spec.js
// Regression: changing your own password rewrites this operator's sessions
// server-side — every other device is revoked and this one's token is rotated
// — so the session table on the same Account page is stale the moment the
// request returns. It must refresh in place, without a manual reload.
//
// Self-contained noadd instance on dedicated ports, for two reasons: the
// scenario is destructive (it changes the admin password), and it needs its own
// login rate-limit budget — the shared @auth instance already spends its five
// attempts per minute on the sign-in scenarios.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADMIN_USERNAME, ADMIN_PASSWORD } from '../screenshots/seed.mjs';

const E2E_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.NOADD_BIN || resolve(E2E_DIR, '../target/debug/noadd');
const DB = resolve(E2E_DIR, '.tmp/password-change-session-list.db');
const HTTP = 14105, DNS = 15105;
const BASE = `http://127.0.0.1:${HTTP}`;
const NEW_PASSWORD = 'an entirely different passphrase';

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

test('changing my password revokes the others and rotates this one', async ({ page }) => {
  // A second session for the same operator, minted straight against the API.
  // Its cookie is discarded — all this needs is for the session to exist
  // server-side, so the account page has something to list besides this browser.
  const second = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD }),
  });
  expect(second.status).toBe(200);

  await page.goto(`${BASE}/`);
  await page.getByTestId('login-username').fill(ADMIN_USERNAME);
  await page.getByTestId('login-password').fill(ADMIN_PASSWORD);
  await page.getByTestId('login-submit').click();
  await expect(page.getByTestId('app-shell')).toBeVisible();

  await page.getByTestId('nav-account').click();
  const rows = page.getByTestId('session-row');
  await expect(rows).toHaveCount(2);
  const idsBefore = await rows.evaluateAll((els) => els.map((e) => e.dataset.id));
  expect(idsBefore.filter(Boolean)).toHaveLength(2);

  await page.getByTestId('password-current').fill(ADMIN_PASSWORD);
  await page.getByTestId('password-new').fill(NEW_PASSWORD);
  await page.getByTestId('password-confirm').fill(NEW_PASSWORD);
  await page.getByTestId('password-save').click();
  // The form posts and the server redirects back, so the confirmation it
  // renders is the barrier: seeing it means the navigation finished and the
  // table below was built from the post-change state.
  await expect(page.getByTestId('password-changed')).toBeVisible();

  // The other device is gone and this device's row is a *different* session —
  // its token was rotated, so it carries a new id.
  await expect(rows).toHaveCount(1);
  const idAfter = await rows.getAttribute('data-id');
  expect(idAfter).toMatch(/^\d+$/);
  expect(idsBefore).not.toContain(idAfter);

  // And the rotation kept us signed in rather than bouncing us to the login
  // screen, which is what a stale cookie would have produced.
  await expect(page.getByTestId('logout-other-sessions')).toBeVisible();
  await expect(page.getByTestId('login-submit')).toHaveCount(0);
});
