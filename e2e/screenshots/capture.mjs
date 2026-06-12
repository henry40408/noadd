// e2e/screenshots/capture.mjs
// Re-runnable README screenshot pipeline:
//   wipe DB -> boot #1 (schema+defaults) -> POST /api/auth/setup -> stop
//   -> sqlite3 seed (backdated 90d traffic) -> boot #2 -> login -> capture -> stop
// Run from e2e/:  npm run screenshots
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, request } from '@playwright/test';
import { ADMIN_PASSWORD, generateSeedSql } from './seed.mjs';

const E2E_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.NOADD_BIN || resolve(E2E_DIR, '../target/debug/noadd');
const DB = resolve(E2E_DIR, '.tmp/screenshots.db');
const OUT = resolve(E2E_DIR, '../docs/screenshots');
const HTTP = 14150, DNS = 15150;
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
  child.kill('SIGTERM'); // graceful: WAL checkpoint + sidecar removal
  const killer = setTimeout(() => child.kill('SIGKILL'), 10_000);
  await child.exited;
  clearTimeout(killer);
}

function runSqlite(sql) {
  return new Promise((res, rej) => {
    // stdout ignored so PRAGMA return values (e.g. busy_timeout's "5000") don't
    // leak onto our console; real errors still surface on stderr.
    const p = spawn('sqlite3', [DB], { stdio: ['pipe', 'ignore', 'inherit'] });
    p.once('exit', (code) => (code === 0 ? res() : rej(new Error(`sqlite3 exited ${code}`))));
    p.stdin.end(sql);
  });
}

// Per-page readiness: data rendered, not spinners/empty states.
const WAITS = {
  dashboard: async (page) => {
    await page.locator('[data-testid="stat-blocked-today"]').waitFor();
    await page.locator('#chart .tl-svg').waitFor();
    await page.locator('#top-domains table tbody tr').first().waitFor();
    await page.locator('#top-upstreams table tbody tr').first().waitFor();
  },
  stats: async (page) => {
    await page.locator('#timeline-chart .tl-svg').waitFor();
    await page.locator('#rate-trend-chart svg').waitFor();
    await page.locator('#heatmap-container .heatmap-cell').first().waitFor();
    await page.locator('#qtypes-chart .bar-row').first().waitFor();
    await page.locator('#outcomes-chart .bar-row').first().waitFor();
    await page.locator('#highlights-grid .stat-card').first().waitFor();
    await page.locator('#health-grid .stat-card').first().waitFor();
  },
  logs: async (page) => {
    await page.locator('#log-body tr').nth(9).waitFor();           // ≥10 rows on page 1
  },
  logsMobile: async (page) => {
    await page.locator('#log-cards .log-card').nth(5).waitFor();   // mobile card layout
  },
  filters: async (page) => {
    await page.locator('[data-testid="filter-list-row"]').nth(2).waitFor(); // 3 lists
    await page.locator('[data-testid="rule-row"]').nth(2).waitFor();        // 3 custom rules
    // Populate the domain-test card so the screenshot shows a live Blocked verdict.
    await page.getByTestId('domain-test-input').fill('doubleclick.net');
    await page.getByTestId('domain-test-submit').click();
    await page.locator('[data-testid="domain-test-result"] .badge-blocked').waitFor();
  },
};

const DESKTOP = { viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2 };
const MOBILE = { viewport: { width: 375, height: 812 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true };

const SHOTS = [
  { file: 'dashboard-dark.png',    route: '#dashboard', wait: WAITS.dashboard, scheme: 'dark',  ...DESKTOP, fullPage: true },
  { file: 'statistics-dark.png',   route: '#stats',     wait: WAITS.stats,     scheme: 'dark',  ...DESKTOP, fullPage: true },
  { file: 'query-log-dark.png',    route: '#logs',      wait: WAITS.logs,      scheme: 'dark',  ...DESKTOP, fullPage: true },
  { file: 'filters-dark.png',      route: '#filters',   wait: WAITS.filters,   scheme: 'dark',  ...DESKTOP, fullPage: true },
  { file: 'statistics-light.png',  route: '#stats',     wait: WAITS.stats,     scheme: 'light', ...DESKTOP, fullPage: true },
  { file: 'dashboard-mobile.png',  route: '#dashboard', wait: WAITS.dashboard, scheme: 'dark',  ...MOBILE,  fullPage: false },
  { file: 'query-log-mobile.png',  route: '#logs',      wait: WAITS.logsMobile, scheme: 'dark', ...MOBILE,  fullPage: false },
];

async function main() {
  mkdirSync(resolve(E2E_DIR, '.tmp'), { recursive: true });
  mkdirSync(OUT, { recursive: true });
  for (const suffix of ['', '-wal', '-shm']) rmSync(`${DB}${suffix}`, { force: true });

  // Phase 1: boot fresh -> set admin password via the product setup flow -> stop.
  let server = startNoadd();
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

  // Phase 2: backdated seed via sqlite3 against the stopped DB.
  await runSqlite(generateSeedSql(Date.now()));

  // Phase 3: boot with seeded data (retention=180d protects the backdate;
  // rebuild_filter loads the seeded list content — no network).
  server = startNoadd();
  let browser;
  try {
    await waitHealthy();

    // Login once via API; reuse the session cookie in every context.
    const api = await request.newContext({ baseURL: BASE });
    const login = await api.post('/api/auth/login', { data: { password: ADMIN_PASSWORD } });
    if (!login.ok()) throw new Error(`login failed: ${login.status()}`);
    const storageState = await api.storageState();
    await api.dispose();

    browser = await chromium.launch();
    for (const shot of SHOTS) {
      const ctx = await browser.newContext({
        baseURL: BASE,
        storageState,
        colorScheme: shot.scheme,
        viewport: shot.viewport,
        deviceScaleFactor: shot.deviceScaleFactor,
        isMobile: shot.isMobile ?? false,
        hasTouch: shot.hasTouch ?? false,
        timezoneId: 'UTC',     // matches the UTC heatmap + seed's diurnal curve
        locale: 'en-US',
        reducedMotion: 'reduce',
      });
      const page = await ctx.newPage();
      await page.goto(`/${shot.route}`);
      await page.locator('[data-testid="app-shell"]').waitFor();
      // Freeze fade-in animations / carets so re-runs are pixel-stable.
      // Collapse BOTH animation-duration AND animation-delay to 0s so staggered
      // `.fade-in` cards (animation: fadeIn 0.3s both; animation-delay 0.1–0.25s)
      // finish instantly at their opacity:1 end-state instead of being caught
      // mid-delay at the opacity:0 `from` state when the screenshot fires.
      let freeze = '*{animation-duration:0s !important;animation-delay:0s !important;'
        + 'transition:none !important;caret-color:transparent !important}';
      // The desktop status bar is `position: fixed; bottom: 0`, so in fullPage
      // captures it paints over real content at the viewport-bottom band. Hide it
      // for fullPage shots only. (Mobile uses `nav.fnbar` — a different element —
      // and mobile shots are fullPage:false, so the F1–F5 bar is untouched.)
      if (shot.fullPage) freeze += '\n.statusbar{display:none !important}';
      await page.addStyleTag({ content: freeze });
      await shot.wait(page);
      await page.evaluate(() => document.fonts.ready);
      await page.screenshot({ path: resolve(OUT, shot.file), fullPage: shot.fullPage });
      console.log(`captured ${shot.file}`);
      await ctx.close();
    }
  } finally {
    if (browser) await browser.close();
    await stopNoadd(server);
  }
  console.log(`done — PNGs in ${OUT}`);
}

main().catch((err) => { console.error(err); process.exitCode = 1; });
