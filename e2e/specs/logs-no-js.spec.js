// e2e/specs/logs-no-js.spec.js
// The query log with JavaScript switched off entirely. Filtering and paging are
// the claim this page makes — both live in the URL, so the filters are a GET
// form and the pager is two links, and neither needs a client.
//
// The live tail is the documented exception (it is an EventSource), so its
// button must not even be visible here.
//
// Its own noadd instance on dedicated ports, seeded through sqlite3 against the
// stopped database: several pages of history is what makes paging testable, and
// sending that many real DNS queries would be slow and dependent on an upstream.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADMIN_USERNAME, ADMIN_PASSWORD } from '../screenshots/seed.mjs';

const E2E_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.NOADD_BIN || resolve(E2E_DIR, '../target/debug/noadd');
const DB = resolve(E2E_DIR, '.tmp/logs-no-js.db');
const HTTP = 14108, DNS = 15108;
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

// Two full pages and a bit: enough that page 2 exists and page 3 does not, so
// both edges of the pager are exercised. Every row's domain, type and outcome
// is predictable, which is what makes the filter assertions exact.
const SEEDED = 120;
function seedSql(nowMs) {
  const rows = [];
  for (let i = 0; i < SEEDED; i++) {
    const blocked = i % 3 === 0 ? 1 : 0;
    const type = i % 4 === 0 ? 'AAAA' : 'A';
    const domain = blocked ? `ads${i}.tracker.example` : `site${i}.example.com`;
    rows.push(`(${nowMs - i * 1000}, '${domain}', '${type}', '10.0.0.${i % 5}', ${blocked}, 0, ${10 + (i % 30)}, '1.1.1.1:53', NULL, NULL, 0)`);
  }
  return 'INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result, authenticated_data) VALUES\n'
    + rows.join(',\n') + ';\n';
}

let server;
let sessionToken;

test.beforeAll(async () => {
  mkdirSync(resolve(E2E_DIR, '.tmp'), { recursive: true });
  for (const suffix of ['', '-wal', '-shm']) rmSync(`${DB}${suffix}`, { force: true });

  // Boot once to create the schema, set the operator up, then stop and seed.
  server = startNoadd();
  await waitHealthy();
  const res = await fetch(`${BASE}/api/auth/setup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: ADMIN_USERNAME, password: ADMIN_PASSWORD }),
  });
  if (!res.ok) throw new Error(`setup failed: ${res.status}`);
  await stopNoadd(server);

  await runSqlite(seedSql(Date.now()));

  server = startNoadd();
  await waitHealthy();
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

async function gotoLogs(page, context, query = '') {
  await context.addCookies([{
    name: 'session', value: sessionToken, domain: '127.0.0.1', path: '/',
  }]);
  await page.goto(`${BASE}/logs${query}`);
  await expect(page.getByTestId('app-shell')).toBeVisible();
}

test.describe('The query log works with no JavaScript', () => {
  test('a page of rows arrives rendered, with the live tail marked client-only', async ({ page, context }) => {
    await gotoLogs(page, context);
    // A full page, not the whole log.
    await expect(page.locator('[data-testid="log-row"]')).toHaveCount(50);
    await expect(page.locator('#log-pagination')).toContainText(`Page 1 / 3`);
    await expect(page.locator('#log-pagination')).toContainText('120 queries');
    // The one thing that genuinely needs a client is not offered.
    await expect(page.getByTestId('logs-live-toggle')).toBeHidden();
  });

  test('the pager walks pages and keeps the filters', async ({ page, context }) => {
    await gotoLogs(page, context, '?action=blocked');
    // 40 of the 120 rows are blocked, so a filtered log is one page.
    await expect(page.locator('[data-testid="log-row"]')).toHaveCount(40);
    await expect(page.locator('#log-pagination')).toContainText('Page 1 / 1');

    await gotoLogs(page, context);
    // `force`, as in filters-no-js and for the same reason: the pager sits at
    // the foot of a long page and the status bar is fixed to the bottom of the
    // viewport, so a plain click is a function of the window height. The URL
    // assertions below only pass if the navigation actually happened.
    await page.getByTestId('logs-next').click({ force: true });
    await expect(page).toHaveURL(/page=2/);
    await expect(page.locator('#log-pagination')).toContainText('Page 2 / 3');
    // And back again.
    await page.getByTestId('logs-prev').click({ force: true });
    await expect(page.locator('#log-pagination')).toContainText('Page 1 / 3');
  });

  test('filters submit as a GET and land in the URL', async ({ page, context }) => {
    await gotoLogs(page, context);
    await page.getByTestId('logs-search').fill('ads');
    await page.getByTestId('logs-type').selectOption('AAAA');
    await page.getByTestId('logs-filter-apply').click({ force: true });

    await expect(page).toHaveURL(/q=ads/);
    await expect(page).toHaveURL(/type=AAAA/);
    // Every visible row matches both filters.
    const rows = page.locator('[data-testid="log-row"]');
    await expect(rows.first()).toContainText('ads');
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
    for (let i = 0; i < count; i++) {
      await expect(rows.nth(i)).toContainText('AAAA');
      await expect(rows.nth(i)).toContainText('ads');
    }
    // The form comes back showing what is applied, so it can be adjusted
    // rather than retyped.
    await expect(page.getByTestId('logs-search')).toHaveValue('ads');
    await expect(page.getByTestId('logs-type')).toHaveValue('AAAA');
  });

  test('a filter that matches nothing says so, and is not the empty-log guide', async ({ page, context }) => {
    await gotoLogs(page, context, '?q=nothing-matches-this');
    await expect(page.locator('[data-testid="log-row"]')).toHaveCount(0);
    await expect(page.locator('#log-body')).toContainText('No logs found');
    await expect(page.getByTestId('logs-empty-state')).toHaveCount(0);
  });

  test("a row's one-click rule posts and comes back to the same view", async ({ page, context }) => {
    await gotoLogs(page, context, '?action=blocked&page=1');
    const row = page.locator('[data-testid="log-row"]').first();
    const domain = (await row.locator('td').nth(2).textContent())?.trim().split('\n')[0].trim();
    await row.locator('.log-action').click({ force: true });

    // Straight back to the filtered view it was invoked from.
    await expect(page).toHaveURL(/action=blocked/);
    // And the rule is on the filters page.
    await page.goto(`${BASE}/filters`);
    await expect(page.locator('[data-testid="rule-row"]').first()).toContainText(domain);
  });

  test('clearing the log empties it and lands on an unfiltered first page', async ({ page, context }) => {
    await gotoLogs(page, context, '?action=blocked&page=1');
    await page.getByTestId('logs-clear').click({ force: true });

    await expect(page).toHaveURL(/\/logs$/);
    await expect(page.getByTestId('logs-cleared')).toBeVisible();
    // The empty-log guide, not "No logs found" — nothing is filtered.
    await expect(page.getByTestId('logs-empty-state')).toBeVisible();
  });
});
