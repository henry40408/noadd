// e2e/specs/chart-touch.spec.js
// Mobile touch interaction for the Statistics charts. CSS :hover and the
// `pointermove`-driven tooltips never fire on a tap, so on mobile the charts
// looked dead. These tests run in a touch-enabled (Pixel 5) context and assert
// that a tap reveals the tooltip, it persists after the finger lifts, and a tap
// elsewhere dismisses it — while mouse hover keeps working unchanged.
//
// Self-contained server: this spec seeds a backdated 90d traffic DB (so every
// chart renders a real multi-point series) and drives its own noadd instance,
// mirroring screenshots/capture.mjs. It does NOT use the shared @app webServer.
import { test, expect, devices } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADMIN_PASSWORD, generateSeedSql } from '../screenshots/seed.mjs';

const E2E_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.NOADD_BIN || resolve(E2E_DIR, '../target/debug/noadd');
const DB = resolve(E2E_DIR, '.tmp/chart-touch.db');
// Dedicated ports, disjoint from the app/auth/onboarding instances in the config.
const HTTP = 14103, DNS = 15103;
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

function runSqlite(sql) {
  return new Promise((res, rej) => {
    const p = spawn('sqlite3', [DB], { stdio: ['pipe', 'ignore', 'inherit'] });
    p.once('exit', (code) => (code === 0 ? res() : rej(new Error(`sqlite3 exited ${code}`))));
    p.stdin.end(sql);
  });
}

let server;

test.beforeAll(async () => {
  mkdirSync(resolve(E2E_DIR, '.tmp'), { recursive: true });
  for (const suffix of ['', '-wal', '-shm']) rmSync(`${DB}${suffix}`, { force: true });

  // Boot #1: create schema + defaults, set the admin password, stop.
  server = startNoadd();
  try {
    await waitHealthy();
    const res = await fetch(`${BASE}/api/auth/setup`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: ADMIN_PASSWORD }),
    });
    if (!res.ok) throw new Error(`setup failed: ${res.status}`);
  } finally {
    await stopNoadd(server);
  }

  // Seed backdated traffic, then boot #2 with data the charts can render.
  await runSqlite(generateSeedSql(Date.now()));
  server = startNoadd();
  await waitHealthy();
});

test.afterAll(async () => {
  await stopNoadd(server);
});

// Pixel 5 = chromium with hasTouch + isMobile, so locator.tap() and
// page.touchscreen are available and dispatch real touch pointer events.
test.use({ ...devices['Pixel 5'], baseURL: BASE });

test.describe('Statistics charts respond to touch', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('login-password').fill(ADMIN_PASSWORD);
    await page.getByTestId('login-submit').click();
    await expect(page.getByTestId('app-shell')).toBeVisible();
    // Navigate by hash: the desktop sidebar nav is hidden at mobile widths
    // (replaced by an F-key bar), so click the route via the router instead.
    await page.evaluate(() => { location.hash = '#stats'; });
    // Wait for all three interactive charts to render real data.
    await page.locator('#timeline-chart .tl-svg').waitFor();
    await page.locator('#rate-trend-chart .rate-svg').waitFor();
    await page.locator('#heatmap-container .heatmap-cell').first().waitFor();
  });

  test('tapping the timeline chart shows a tooltip that persists, then dismisses', async ({ page }) => {
    const tooltip = page.locator('#timeline-chart .rate-tooltip');
    await expect(tooltip).toBeHidden();

    await page.locator('#timeline-chart .tl-svg').tap();
    await expect(tooltip).toBeVisible();

    // Persists after the finger lifts (unlike desktop hover, which dismisses).
    await page.waitForTimeout(400);
    await expect(tooltip).toBeVisible();

    // A tap outside the chart dismisses it.
    await page.touchscreen.tap(10, 10);
    await expect(tooltip).toBeHidden();
  });

  test('tapping the rate-trend chart shows a tooltip', async ({ page }) => {
    const tooltip = page.locator('#rate-trend-chart .rate-tooltip');
    await expect(tooltip).toBeHidden();

    await page.locator('#rate-trend-chart .rate-svg').tap();
    await expect(tooltip).toBeVisible();

    await page.touchscreen.tap(10, 10);
    await expect(tooltip).toBeHidden();
  });

  test('tapping a heatmap cell shows its tooltip and switches between cells', async ({ page }) => {
    const cells = page.locator('#heatmap-container .heatmap-cell');
    const first = cells.nth(30);  // a mid-grid cell, comfortably tappable
    const second = cells.nth(60);

    await first.tap();
    await expect(first).toHaveClass(/touch-active/);
    await expect(first.locator('.heatmap-tooltip')).toBeVisible();

    // Tapping another cell moves the active tooltip rather than stacking.
    await second.tap();
    await expect(second).toHaveClass(/touch-active/);
    await expect(first).not.toHaveClass(/touch-active/);

    // Tapping outside the heatmap dismisses it.
    await page.touchscreen.tap(10, 10);
    await expect(second).not.toHaveClass(/touch-active/);
  });

  test('mouse hover still shows and hides the timeline tooltip', async ({ page }) => {
    const tooltip = page.locator('#timeline-chart .rate-tooltip');
    const box = await page.locator('#timeline-chart .tl-svg').boundingBox();

    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await expect(tooltip).toBeVisible();

    // Moving the mouse off the chart dismisses immediately (no outside tap needed).
    await page.mouse.move(box.x + box.width / 2, box.y - 40);
    await expect(tooltip).toBeHidden();
  });
});
