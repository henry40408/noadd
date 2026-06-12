# README Screenshot Pipeline

**Goal:** A re-runnable `npm run screenshots` (in `e2e/`) that seeds ~90 days of realistic fake data into a throwaway DB, boots noadd, captures admin-UI screenshots with Playwright, writes PNGs to `docs/screenshots/`, and a `## Screenshots` section in `README.md` that showcases them.

**Branch:** `feat/redesign-admin-ui` (the redesigned UI lives here — do not target `main`).

**Decisions (fixed, do not revisit):**
- Pages: Dashboard, Statistics, Query Log, Filters. NOT Settings, NOT Login.
- Dark theme is primary for all four pages. One light-theme accent shot: **Statistics** (most visually rich: two line charts + heatmap + breakdown bars).
- Desktop 1280px primary. Two mobile (375px) shots: **Dashboard** (bottom tab bar) and **Query Log** (card layout).
- No CI staleness check. Manual re-run, documented in README.

---

## Investigated facts (all verified in source — do not re-derive)

### 1. DB schema — everything the UI shows is computed on-the-fly from `query_logs`

There are **no rollup/stats tables**. Every Dashboard and Statistics endpoint
(`/api/stats/*`, `/api/stats/v2/*`) aggregates `query_logs` per request
(`src/admin/stats.rs` → `src/db.rs`). Seeding `query_logs` + `settings` +
filter tables is sufficient.

Schema created by `Database::init_schema` (`src/db.rs:242-290`, `PRAGMA user_version = 5`):

```sql
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE query_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,      -- epoch MILLISECONDS (every reader does since_secs*1000)
    domain TEXT NOT NULL,            -- stored lowercase
    query_type TEXT NOT NULL,        -- 'A','AAAA','HTTPS','PTR','TXT','MX','SRV',...
    client_ip TEXT NOT NULL,
    blocked INTEGER NOT NULL DEFAULT 0,
    cached INTEGER NOT NULL DEFAULT 0,
    response_ms INTEGER NOT NULL DEFAULT 0,
    upstream TEXT,                   -- label string, e.g. '1.1.1.1:53', '9.9.9.9:53'; NULL when blocked/cached
    doh_token TEXT,                  -- NULL unless query arrived via tokenized DoH
    result TEXT                      -- resolved IP string; '0.0.0.0' for blocked is realistic
);

CREATE TABLE filter_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, url TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_updated INTEGER NOT NULL DEFAULT 0,  -- epoch SECONDS is fine (UI normalizeTs handles s or ms)
    rule_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE custom_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, rule_type TEXT NOT NULL); -- 'block' | 'allow'
CREATE TABLE filter_list_content (list_id INTEGER PRIMARY KEY, content TEXT NOT NULL);
CREATE TABLE doh_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE);
```

What each UI element reads (so the seed shape matters):

| UI element | Query (src/db.rs) | Notes |
|---|---|---|
| Dashboard stat cards | `count_queries_multi_since` (today/7d/30d totals+blocked), `cache_stats_multi_since` (cached/allowed/avg ms, `blocked = 0` only) | block rate = blocked/total; cache rate = SUM(cached)/COUNT over allowed rows |
| Dashboard "Queries (24h)" | `timeline_since` from `max(earliest, now-24h)` | dynamic bucket |
| Dashboard top domains/clients/upstreams | `top_*_since(now-86400)` | **24h window** — recent rows needed |
| Stats timeline 7d/30d/90d | `timeline_multi_since` — buckets 1h / 6h / 1d | total/blocked/cached per bucket |
| Block & cache rate trend | same timeline payload, rendered as % | |
| Heatmap (last 30d) | `hourly_heatmap_since`: `strftime('%w'/'%H', timestamp/1000, 'unixepoch')` | **UTC** weekday×hour |
| Query Types / Outcomes | `query_type_breakdown_since`, `outcome_breakdown_since` | Outcome CASE: `blocked=1`→Blocked, else `cached=1`→Cached, else `result` non-empty→Resolved, else Empty |
| Highlights (unique domains, p50/p95/p99) | `unique_domains_since`, `latency_summary_since` (histogram over `response_ms`) | latency includes blocked/cached 0ms rows — keep some spread |
| DB Health | file size, `COUNT(*)`, `MIN(timestamp)`, `settings.log_retention_days` | |
| Query Log page | `query_logs(...) ORDER BY timestamp DESC LIMIT 50` → `{logs, total}` | newest rows are what's visible |
| Filters page | `filter_lists` (toggle/name/`rule_count`/`last_updated`), `custom_rules` | domain test hits the live `FilterEngine` |

### 2. Auth + boot behavior → confirmed seed order

- Password: `POST /api/auth/setup {"password": ...}` (min 8 chars), only allowed while `settings.admin_password_hash` is absent; stores an argon2 hash there (`src/admin/api.rs:281-317`).
- Login: `POST /api/auth/login {"password": ...}` sets a `session` cookie (64-char token, 7d, SameSite=Strict). Sessions live in an **in-memory** store (persisted to `settings.sessions` only on save points) — so **log in AFTER the final restart**, not before.
- Boot (`src/main.rs`): `Database::open` creates schema → `seed_default_lists()` (only when `filter_lists` is empty; seeds "AdGuard DNS filter" enabled + "AdAway Default Blocklist" disabled) → `rebuild_filter()` which reads **`filter_list_content` from the DB, no network**.
- List-update scheduler (24h interval) **skips its first tick** (`src/main.rs:186`) → no download at boot. Offline-safe.
- **CRITICAL:** the hourly prune task does **NOT** skip its first tick — `tokio::time::interval` fires immediately at boot (`src/main.rs:206-218`). Default retention is 7 days, so 90 days of backdated logs would be deleted on the final restart. The seed **MUST** set `settings.log_retention_days = '180'` before that restart.
- Shutdown on SIGTERM is graceful: `wal_checkpoint(TRUNCATE)` + close removes `-wal`/`-shm` sidecars (`Database::close`), so the stopped DB file is safe for `sqlite3` CLI writes.
- The "Point a device's DNS at noadd" banner hides itself when any queries exist; seed also sets `onboarding_banner_dismissed='true'` as belt-and-braces.
- Nothing stats-related is cached in memory at boot — every stats request re-queries SQLite, so inserting rows while stopped and restarting is fully visible.

**Confirmed order:** wipe DB → boot #1 (schema + default lists) → `POST /api/auth/setup` → SIGTERM → `sqlite3` seed → boot #2 → `POST /api/auth/login` → Playwright captures → SIGTERM.

### 3. Theme switching

The UI has **no theme toggle, no localStorage key, no html attribute**. Dark is the `:root` default; light is purely `@media (prefers-color-scheme: light)` (`admin-ui/dist/index.html:45`, 550, 860). Playwright's context option `colorScheme: 'dark' | 'light'` forces it deterministically.

### 4. Selectors / waits (real markup, verified)

- Hash routes: `/#dashboard`, `/#stats`, `/#logs`, `/#filters`. Shell: `[data-testid="app-shell"]`.
- Dashboard: stat cards render into `#stats` (`.stat-card`, incl. `[data-testid="stat-blocked-today"]`); 24h chart renders `svg.tl-svg` into `#chart`; tables into `#top-domains`, `#top-clients`, `#top-upstreams`. Auto-refresh poll is every 10 s (won't interfere with an immediate screenshot).
- Statistics: `#timeline-chart .tl-svg`, `#rate-trend-chart svg`, `#heatmap-container .heatmap-cell` (exactly 168 when data present), `#qtypes-chart .bar-row`, `#outcomes-chart .bar-row`, `#highlights-grid .stat-card`, `#health-grid .stat-card`, `#ranged-domains .bar-row`. All cards show `Loading…` placeholders until async render.
- Query Log: desktop rows `#log-body tr` (50/page); mobile cards `#log-cards .log-card`; empty state is `[data-testid="logs-empty-state"]` (must NOT be present).
- Filters: `[data-testid="filter-list-row"]` (desktop table), `[data-testid="rule-row"]`, domain test `[data-testid="domain-test-input"]` / `domain-test-submit` / `domain-test-result` (renders `.badge-blocked` + matched list name).
- Mobile (≤768px): desktop nav hides, fixed bottom F-key bar `nav.fnbar` shows; log table swaps to `.show-mobile` cards.
- Timestamp display uses `normalizeTs` (`ts > 1e12 ? ms : s*1000`) — query_logs ms timestamps render correctly.

### 5. Tooling

Reuse `@playwright/test`'s `chromium` (already in `e2e/package.json`; browsers installed at `~/.cache/ms-playwright/chromium-1223`). `sqlite3` CLI assumed installed. **Standalone Node script**, not a Playwright test project — it drives its own noadd instance on dedicated ports (HTTP `14150`, DNS `15150` — clear of e2e's 14100-14102/15100-15102) and its own DB `e2e/.tmp/screenshots.db` (`.tmp/` already gitignored). Binary path: `NOADD_BIN` env or `../target/debug/noadd`, same convention as `e2e/playwright.config.js`.

---

## Task 1 — Seed generator: `e2e/screenshots/seed.mjs`

New file. Pure data module: exports `generateSeedSql(nowMs)` returning one SQL string. Deterministic PRNG (mulberry32, fixed seed) so re-runs produce the same *distribution*; timestamps anchor to run time (inherent — "today" must have data).

```js
// e2e/screenshots/seed.mjs
// Generates deterministic fake-traffic SQL for the screenshot pipeline.
// All query_logs timestamps are epoch MILLISECONDS (matches src/db.rs readers).

export const ADMIN_PASSWORD = 'correct horse battery staple';

function mulberry32(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// [domain, weight, blocked, resultIp]
const DOMAINS = [
  ['doubleclick.net',            55, true,  null],
  ['googlesyndication.com',      40, true,  null],
  ['app-measurement.com',        35, true,  null],
  ['graph.facebook.com',         30, true,  null],
  ['adservice.google.com',       25, true,  null],
  ['ads.tiktok.com',             18, true,  null],
  ['track.adform.net',           12, true,  null],
  ['telemetry.vendor.io',         9, true,  null],   // matches a seeded custom block rule
  ['www.youtube.com',            70, false, '142.250.196.110'],
  ['i.ytimg.com',                55, false, '142.250.196.118'],
  ['api.github.com',             45, false, '140.82.113.6'],
  ['github.com',                 35, false, '140.82.113.4'],
  ['fonts.gstatic.com',          50, false, '142.250.74.35'],
  ['cdn.jsdelivr.net',           30, false, '104.16.85.20'],
  ['www.netflix.com',            28, false, '54.155.178.5'],
  ['api.spotify.com',            32, false, '35.186.224.25'],
  ['www.wikipedia.org',          22, false, '208.80.154.224'],
  ['registry.npmjs.org',         20, false, '104.16.92.83'],
  ['crates.io',                  14, false, '108.138.64.68'],
  ['slack.com',                  18, false, '54.192.18.78'],
  ['mail.google.com',            26, false, '142.250.74.37'],
  ['time.apple.com',             16, false, '17.253.34.125'],
  ['ocsp.digicert.com',          12, false, '93.184.220.29'],
  ['static.xx.fbcdn.net',        15, false, '157.240.201.23'],
  ['www.cloudflare.com',         10, false, '104.16.124.96'],
];

const CLIENTS = [ // [ip, weight, dohToken]
  ['192.168.1.10', 28, null], ['192.168.1.21', 24, null],
  ['192.168.1.34', 18, null], ['192.168.1.52', 10, null],
  ['10.0.0.5',      8, null], ['100.64.0.7',   12, 'iphone'],
];
const QTYPES = [['A', 60], ['AAAA', 28], ['HTTPS', 8], ['PTR', 2], ['TXT', 1], ['MX', 1]];
// UTC diurnal curve, hour 0..23 — quiet 01-05, evening peak 19-22.
const HOUR_W = [0.30, 0.18, 0.12, 0.10, 0.10, 0.15, 0.30, 0.50, 0.70, 0.85, 0.90, 0.95,
                1.00, 0.95, 0.90, 0.85, 0.90, 1.00, 1.10, 1.25, 1.30, 1.20, 0.85, 0.50];
const SUM_HOUR_W = HOUR_W.reduce((a, b) => a + b, 0);

function pick(rand, table) {
  const total = table.reduce((a, r) => a + r[1], 0);
  let roll = rand() * total;
  for (const row of table) { roll -= row[1]; if (roll <= 0) return row; }
  return table[table.length - 1];
}
const q = (s) => (s == null ? 'NULL' : `'${String(s).replace(/'/g, "''")}'`);

export function generateSeedSql(nowMs) {
  const rand = mulberry32(42);
  const HOURS = 90 * 24;
  const rows = [];
  // Iterate absolute one-hour slots back from "now". Weight each slot by its
  // REAL UTC hour-of-day and weekday — the Statistics heatmap groups by
  // strftime('%w'/'%H', ..., 'unixepoch') (UTC), so the diurnal/weekly pattern
  // must be anchored to UTC clock hours, not to hours-since-run.
  for (let s = HOURS - 1; s >= 0; s--) {
    const slotStart = nowMs - (s + 1) * 3600_000;        // every slot fully in the past
    const dt = new Date(slotStart);
    const h = dt.getUTCHours();
    const wd = dt.getUTCDay();
    const weekend = wd === 0 || wd === 6 ? 1.18 : 1.0;
    const trend = 0.75 + 0.4 * ((HOURS - 1 - s) / (HOURS - 1)); // traffic grows over the 90d
    const perDay = 540 * weekend * trend * (0.9 + 0.2 * rand());
    const n = Math.round((perDay * HOUR_W[h]) / SUM_HOUR_W);
    for (let i = 0; i < n; i++) {
      const ts = slotStart + Math.floor(rand() * 3600_000); // ms, uniform within the hour
      const [domain, , blocked, ip] = pick(rand, DOMAINS);
      const [client, , token] = pick(rand, CLIENTS);
      const qtype = pick(rand, QTYPES)[0];
      let cached = 0, responseMs = 0, upstream = null, result = null;
      if (blocked) {
        result = '0.0.0.0';
      } else if (rand() < 0.35) {
        cached = 1; result = ip;
      } else {
        upstream = rand() < 0.7 ? '1.1.1.1:53' : '9.9.9.9:53';
        responseMs = 6 + Math.floor(Math.pow(rand(), 2.2) * 140) + (rand() < 0.02 ? 250 : 0);
        result = ip;
      }
      rows.push(`(${ts},${q(domain)},${q(qtype)},${q(client)},${blocked ? 1 : 0},${cached},${responseMs},${q(upstream)},${q(token)},${q(result)})`);
    }
  }

  const lu = Math.floor(nowMs / 1000); // last_updated in epoch seconds (UI normalizes)
  const parts = [
    'PRAGMA busy_timeout = 5000;',
    'BEGIN;',
    // Retention MUST cover the 90-day backdate — the prune task fires immediately at boot.
    `INSERT INTO settings (key, value) VALUES ('log_retention_days','180')
       ON CONFLICT(key) DO UPDATE SET value = excluded.value;`,
    `INSERT INTO settings (key, value) VALUES ('onboarding_banner_dismissed','true')
       ON CONFLICT(key) DO UPDATE SET value = excluded.value;`,
    // Filters page: defaults were seeded at boot #1 — enable both, give realistic counts,
    // and add a third list so the table looks lived-in.
    `UPDATE filter_lists SET enabled = 1, rule_count = 59842, last_updated = ${lu - 7200} WHERE name = 'AdGuard DNS filter';`,
    `UPDATE filter_lists SET enabled = 1, rule_count = 6540,  last_updated = ${lu - 7200} WHERE name = 'AdAway Default Blocklist';`,
    `INSERT INTO filter_lists (name, url, enabled, last_updated, rule_count) VALUES
       ('Peter Lowe''s Ad and tracking server list','https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt',0,${lu - 90000},3284);`,
    // Content for enabled lists so boot #2's rebuild_filter() yields a live engine
    // (offline; rule_count column is what the UI displays, mismatch is invisible).
    `INSERT INTO filter_list_content (list_id, content)
       SELECT id, '||doubleclick.net^' || char(10) || '||googlesyndication.com^' || char(10) ||
                  '||app-measurement.com^' || char(10) || '||graph.facebook.com^' || char(10) ||
                  '||adservice.google.com^' || char(10) || '||ads.tiktok.com^' || char(10) ||
                  '||track.adform.net^'
       FROM filter_lists WHERE name = 'AdGuard DNS filter'
       ON CONFLICT(list_id) DO UPDATE SET content = excluded.content;`,
    `INSERT INTO filter_list_content (list_id, content)
       SELECT id, '||ad.example.net^' FROM filter_lists WHERE name = 'AdAway Default Blocklist'
       ON CONFLICT(list_id) DO UPDATE SET content = excluded.content;`,
    `INSERT INTO custom_rules (rule, rule_type) VALUES
       ('||telemetry.vendor.io^','block'),
       ('@@||analytics.mycompany.dev^','allow'),
       ('||ads.smart-tv.lan^','block');`,
    `INSERT OR IGNORE INTO doh_tokens (token) VALUES ('iphone');`,
  ];
  for (let i = 0; i < rows.length; i += 500) {
    parts.push(
      'INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result) VALUES\n'
      + rows.slice(i, i + 500).join(',\n') + ';'
    );
  }
  parts.push('COMMIT;', 'ANALYZE;');
  return parts.join('\n');
}
```

**Implementation note for the coder:** verify the window edges once after a run with `sqlite3 e2e/.tmp/screenshots.db "SELECT MIN(timestamp), MAX(timestamp), COUNT(*) FROM query_logs"` — expect ≈ now−90d … ≈ now (both in ms) and ≈ 45–55k rows (~5 MB of SQL, sub-second insert inside one transaction).

Why these numbers: blocked weight ≈ 22% of total (realistic ad-block ratio shown on the Block Rate card), cached ≈ 35% of allowed (Cache Hit card + orange timeline band), latency power curve gives p50 ≈ 10–20 ms / p95 ≈ 80–120 ms on the Statistics highlights, and the `iphone` DoH token row makes Top Sources show a token-labeled client.

## Task 2 — Capture script: `e2e/screenshots/capture.mjs`

New file. Orchestrates the whole pipeline; uses only `node:` built-ins + `@playwright/test`'s `chromium` + `sqlite3` CLI.

```js
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
    const p = spawn('sqlite3', [DB], { stdio: ['pipe', 'inherit', 'inherit'] });
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
      await page.addStyleTag({ content: '*{animation-duration:0s !important;transition:none !important;caret-color:transparent !important}' });
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
```

Notes for the coder:
- `fullPage: false` for mobile is deliberate — the bottom `nav.fnbar` is `position: fixed` and full-page capture would detach it from the bottom edge.
- The Dashboard 10 s LIVE poll can't race a sub-second screenshot; do not pause it (pausing changes the toggle's visual state).
- `page.goto('/#stats')` with `baseURL` set resolves correctly; the SPA routes off `location.hash`.
- Keep ports 14150/15150 — e2e uses 14100–14102/15100–15102 and `reuseExistingServer` matching; do not overlap.
- Do not touch any `data-testid` or existing e2e file.

## Task 3 — npm wiring: `e2e/package.json`

Add one script (no new dependencies):

```json
"scripts": {
  "test": "bddgen && playwright test",
  "test:ui": "bddgen && playwright test --ui",
  "report": "playwright show-report",
  "screenshots": "node screenshots/capture.mjs"
}
```

## Task 4 — README: `## Screenshots` section + re-run doc

### 4a. Showcase section — insert between `## Features` and `## Quick Start` (after line 28):

```markdown
## Screenshots

The admin UI is embedded in the binary — dark/light follows your OS preference, and the layout adapts to phones with a bottom tab bar.

![Dashboard — live stat cards, 24h query timeline, top domains, sources and upstreams (dark theme)](docs/screenshots/dashboard-dark.png)

![Statistics — 7d/30d/90d query trends, block & cache rate, weekday-by-hour activity heatmap, query type and outcome breakdowns, database health (dark theme)](docs/screenshots/statistics-dark.png)

![Query log — searchable DNS history with per-query outcome, latency and one-click Allow/Block (dark theme)](docs/screenshots/query-log-dark.png)

![Filters — filter list management with rule counts, custom allow/block rules and a live domain test (dark theme)](docs/screenshots/filters-dark.png)

<table>
  <tr>
    <td width="56%"><img src="docs/screenshots/statistics-light.png" alt="Statistics page in the light theme"></td>
    <td width="22%"><img src="docs/screenshots/dashboard-mobile.png" alt="Dashboard on a 375px phone viewport with bottom tab navigation"></td>
    <td width="22%"><img src="docs/screenshots/query-log-mobile.png" alt="Query log on mobile, rows rendered as cards"></td>
  </tr>
  <tr>
    <td align="center">Light theme</td>
    <td align="center" colspan="2">Mobile layout with bottom tab bar</td>
  </tr>
</table>
```

### 4b. Re-run doc — append under `## Development` → after the "End-to-end tests" subsection (README line ~141):

```markdown
### Regenerating README screenshots

The images in `docs/screenshots/` are produced by a repeatable pipeline that
seeds a throwaway database with ~90 days of fake traffic, boots `noadd` on
throwaway ports, and re-captures every page with Playwright. Re-run it after
any admin-UI change and commit the updated PNGs:

```bash
cargo build                       # embeds the current admin UI into the binary
cd e2e
npm ci && npx playwright install chromium   # first time only
npm run screenshots
```
```

(Use the README's existing voice; keep the fenced-block nesting valid — outer fence must use more backticks or `~~~`.)

## Task 5 — Run + verify + commit

1. `pwd`-check, then `cd /home/nixos/Develop/claude/noadd && cargo build` (binary embeds current UI via `build.rs`).
2. `cd /home/nixos/Develop/claude/noadd/e2e && npm run screenshots`.
3. Verification checklist (all must pass before committing):
   - All 7 PNGs exist in `docs/screenshots/` and each is > 50 KB (an empty-state page renders far smaller).
   - `dashboard-dark.png`: stat cards show non-zero Queries/Blocked Today; 24h chart has visible area fills; Top Sources includes the `iphone` token client; Upstreams table lists `1.1.1.1:53` and `9.9.9.9:53`.
   - `statistics-dark.png`: timeline spans ~7 days with three bands (total/cached/blocked); heatmap shows 168 cells with a visible diurnal gradient (dark 01–05 columns, bright 19–22); Query Types shows A/AAAA/HTTPS…; Outcomes shows Blocked/Cached/Resolved; DB Health shows Retention `180d`, Total Logs ≈ 45–55k, Oldest Log ≈ 90 days ago (if Oldest Log shows "today", the boot prune ate the backdate → the `log_retention_days` seed didn't apply).
   - `query-log-dark.png`: 50 rows, mixed blocked/allowed badges, cached badges, upstream labels, no `logs-empty-state`.
   - `filters-dark.png`: 3 filter-list rows with rule counts (59,842 / 6,540 / 3,284), 3 custom rules, domain test shows a red **Blocked** badge for `doubleclick.net` with the matched list.
   - `statistics-light.png`: cream/paper background (`#f3efe2`), not the dark background — confirms `colorScheme: 'light'` worked.
   - Mobile shots: bottom `F1…F5` tab bar visible at the bottom edge; query-log rows are cards, not a table.
   - No lingering processes: `pgrep -f screenshots.db` → empty; `ls e2e/.tmp/screenshots.db-wal` → absent.
   - Re-run `npm run screenshots` once more — it must succeed from scratch (idempotence).
   - Existing suite untouched: `cd e2e && npm test` still green; `cargo nextest run` green; `cargo fmt --check` clean (no Rust files change in this task, but verify).
4. Stage explicitly (never `git add -A`): the 7 PNGs, `e2e/screenshots/seed.mjs`, `e2e/screenshots/capture.mjs`, `e2e/package.json`, `README.md`.

## Constraints recap (for the implementer)

- No new dependencies; reuse `@playwright/test` chromium + `sqlite3` CLI.
- `query_logs.timestamp` is **milliseconds** — seconds would put every row "before 1971" and all pages empty.
- `settings.log_retention_days='180'` must be in the seed **before boot #2** (prune fires immediately at startup).
- Login only **after** the final restart (sessions are in-memory).
- Deterministic: fixed PRNG seed, fixed viewports, `timezoneId: 'UTC'`, `locale: 'en-US'`, wait-for-render (never `waitForTimeout`), animation-freeze style tag.
- Idempotent: wipes `e2e/.tmp/screenshots.db*` at start of every run.
- Preserve all `data-testid`s; do not modify e2e tests or `playwright.config.js`.
