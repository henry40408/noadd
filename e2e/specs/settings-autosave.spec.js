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
    // The error appears inline, right next to the IPv4 field (not a shared line).
    await expect(page.locator('#msg-block-ipv4')).toContainText(/IPv4/i);
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
