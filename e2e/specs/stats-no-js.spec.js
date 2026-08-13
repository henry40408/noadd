// e2e/specs/stats-no-js.spec.js
// The statistics page with JavaScript switched off entirely.
//
// The claim this page makes is that the readings are readings: five of the
// seven arrive in the first response and stay put. The three that do not are
// the timeline, the rate trend drawn from it and the heatmap — the only three
// that bucket a query against a calendar, which needs a UTC offset that arrives
// with the browser rather than with the request. Those say so here instead of
// sitting empty.
//
// The range switcher is the other half: it selects the server's window, so it
// is three links and it works with nothing running.
//
// Its own noadd instance on dedicated ports, seeded through sqlite3 against the
// stopped database — the rows have to span more than seven days for switching
// the range to change any number, and sending that much real DNS traffic would
// be slow and dependent on an upstream.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADMIN_USERNAME, ADMIN_PASSWORD } from '../screenshots/seed.mjs';

const E2E_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.NOADD_BIN || resolve(E2E_DIR, '../target/debug/noadd');
const DB = resolve(E2E_DIR, '.tmp/stats-no-js.db');
const HTTP = 14109, DNS = 15109;
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

// Two domains inside the 7-day window and a third only reachable from a wider
// one, which is what makes switching the range visibly change the page rather
// than just re-render it.
const RECENT_BLOCKED = 30;   // ads.recent.example, blocked, within 7d
const RECENT_ALLOWED = 10;   // site.recent.example, allowed, within 7d
const OLD = 20;              // old.example, allowed, ten days back
const DAY_MS = 86_400_000;

function seedSql(nowMs) {
  const rows = [];
  const row = (ts, domain, type, blocked) =>
    `(${ts}, '${domain}', '${type}', '10.0.0.7', ${blocked}, 0, 12, '1.1.1.1:53', NULL, '1.2.3.4', 0)`;
  // Spread across the last six days so every bucket is not the same one.
  for (let i = 0; i < RECENT_BLOCKED; i++) {
    rows.push(row(nowMs - (i % 6) * DAY_MS - i * 1000, 'ads.recent.example', 'A', 1));
  }
  for (let i = 0; i < RECENT_ALLOWED; i++) {
    rows.push(row(nowMs - (i % 6) * DAY_MS - i * 1000, 'site.recent.example', 'AAAA', 0));
  }
  for (let i = 0; i < OLD; i++) {
    rows.push(row(nowMs - 10 * DAY_MS - i * 1000, 'old.example', 'A', 0));
  }
  // Retention defaults to seven days and the hourly prune fires its first tick
  // immediately, so ten-day-old rows would delete themselves before the first
  // request. Widen it here: without traffic outside the default window there is
  // nothing for a wider range to find, and the switcher would only be redrawing
  // the same numbers under a different title.
  return "INSERT OR REPLACE INTO settings (key, value) VALUES ('log_retention_days', '60');\n"
    + 'INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result, authenticated_data) VALUES\n'
    + rows.join(',\n') + ';\n';
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

async function gotoStats(page, context, query = '') {
  await context.addCookies([{
    name: 'session', value: sessionToken, domain: '127.0.0.1', path: '/',
  }]);
  await page.goto(`${BASE}/stats${query}`);
  await expect(page.getByTestId('app-shell')).toBeVisible();
}

test.describe('The statistics page works with no JavaScript', () => {
  test('every reading that does not need a calendar arrives rendered', async ({ page, context }) => {
    await gotoStats(page, context);

    // Highlights: two domains were queried inside the 7-day window.
    await expect(page.locator('#highlights-grid')).toContainText('Unique Domains');
    await expect(page.locator('#highlights-grid')).toContainText('2');
    // Latency percentiles, from a seeded 12ms on every row.
    await expect(page.locator('#highlights-grid')).toContainText('Latency p50');

    // Both breakdowns, as bars rather than as a chart.
    await expect(page.locator('#qtypes-chart .bar-row')).toHaveCount(2);
    await expect(page.locator('#qtypes-chart')).toContainText('A');
    await expect(page.locator('#qtypes-chart')).toContainText('AAAA');
    await expect(page.locator('#outcomes-chart')).toContainText('Blocked');

    // Both ranged lists. 30 of 40 queries were blocked ads.
    await expect(page.getByTestId('ranged-domains')).toContainText('ads.recent.example');
    await expect(page.getByTestId('ranged-domains')).toContainText('75.0%');
    await expect(page.getByTestId('ranged-clients')).toContainText('10.0.0.7');
    // Nothing from outside the window leaked into the default range.
    await expect(page.getByTestId('ranged-domains')).not.toContainText('old.example');

    // And the health grid, which reports on the file rather than on traffic.
    await expect(page.getByTestId('db-health-card')).toContainText('Database Size');
    await expect(page.getByTestId('db-health-card')).toContainText('Total Logs');
    // The date the server could only write in UTC is still a readable date.
    await expect(page.getByTestId('db-health-card')).toContainText(/\d{4}-\d{2}-\d{2}/);
  });

  test('the three charts say they are drawn in the browser', async ({ page, context }) => {
    await gotoStats(page, context);

    await expect(page.getByTestId('timeline-needs-js')).toBeVisible();
    await expect(page.getByTestId('rate-trend-needs-js')).toBeVisible();
    await expect(page.getByTestId('heatmap-needs-js')).toBeVisible();
    // Nothing was drawn — these are the elements the client would have made.
    await expect(page.locator('#timeline-chart .tl-svg')).toHaveCount(0);
    await expect(page.locator('#heatmap-container .heatmap-cell')).toHaveCount(0);
  });

  test('the range switcher is links, and switching one widens the window', async ({ page, context }) => {
    await gotoStats(page, context);

    const switcher = page.getByTestId('range-switcher');
    await expect(switcher.locator('a')).toHaveCount(3);
    await expect(switcher.locator('a.active')).toHaveText('7d');
    await expect(page.locator('#ranged-domains-title')).toHaveText('Top Domains (last 7d)');

    // Follow the link. No client: this is an ordinary navigation.
    //
    // `force` skips the stability check, which the page header's fade-in fails
    // for its first frames — with scripting off the page is interactive the
    // moment it parses, so the card is still sliding when the click lands. The
    // assertions below only pass if the navigation actually happened, so a link
    // that did nothing still fails this test.
    await switcher.getByRole('link', { name: '30d' }).click({ force: true });
    await expect(page).toHaveURL(/\/stats\?range=30d$/);

    await expect(switcher.locator('a.active')).toHaveText('30d');
    await expect(page.locator('#ranged-domains-title')).toHaveText('Top Domains (last 30d)');
    await expect(page.locator('#timeline-title')).toHaveText('Queries (last 30d)');
    // The wider window reaches the older traffic the 7-day one could not.
    await expect(page.getByTestId('ranged-domains')).toContainText('old.example');
    await expect(page.locator('#highlights-grid')).toContainText('3');
  });

  test('a range nobody offers renders the default window rather than an error', async ({ page, context }) => {
    await gotoStats(page, context, '?range=nonsense');
    await expect(page.locator('#ranged-domains-title')).toHaveText('Top Domains (last 7d)');
    await expect(page.getByTestId('range-switcher').locator('a.active')).toHaveText('7d');
  });
});
