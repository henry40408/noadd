// e2e/screenshots/seed.mjs
// Generates deterministic fake-traffic SQL for the screenshot pipeline.
// All query_logs timestamps are epoch MILLISECONDS (matches src/db.rs readers).

export const ADMIN_USERNAME = 'testuser';
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
        // Cache hits aren't free: a small realistic latency (1–3 ms) keeps the
        // Statistics p50 off 0ms. Blocked rows stay at 0ms (blocking is instant).
        cached = 1; responseMs = 1 + Math.floor(rand() * 3); result = ip;
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
