//! Fixture SQL, written against a stopped database.
//!
//! Three suites need history noadd cannot be made to produce quickly: the
//! screenshot pipeline wants ninety days of plausible traffic, the query log
//! wants several pages of it, and the statistics page wants rows on both sides
//! of the default retention window. Sending that as real DNS traffic would be
//! slow and would depend on an upstream answering, so it is inserted directly —
//! exactly as `screenshots/seed.mjs` and the two spec files did.
//!
//! Every `query_logs.timestamp` is epoch **milliseconds**, matching the readers
//! in `src/db.rs`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds in a day.
const DAY_MS: i64 = 86_400_000;

/// Now, in epoch milliseconds — the anchor every backdated fixture counts from.
pub fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(0)
}

/// The `mulberry32` PRNG `seed.mjs` used, bit for bit.
///
/// Ported rather than replaced so a re-run of the screenshot pipeline produces
/// the same traffic it always did: the committed PNGs are a diff every time the
/// shape of the data moves, and "the seed changed" is a poor reason for one.
struct Mulberry32(u32);

impl Mulberry32 {
    fn new(seed: u32) -> Self {
        Self(seed)
    }

    /// The next float in `[0, 1)`.
    fn next(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x6d2b_79f5);
        let s = self.0;
        let mut t = (s ^ (s >> 15)).wrapping_mul(0x1 | s);
        t = t.wrapping_add((t ^ (t >> 7)).wrapping_mul(0x3d | t)) ^ t;
        f64::from(t ^ (t >> 14)) / 4_294_967_296.0
    }
}

/// A weighted table row: the value, its weight, and whatever rides along.
type Domain = (&'static str, f64, bool, Option<&'static str>);
type Client = (&'static str, f64, Option<&'static str>);

/// `[domain, weight, blocked, resultIp]`.
const DOMAINS: &[Domain] = &[
    ("doubleclick.net", 55.0, true, None),
    ("googlesyndication.com", 40.0, true, None),
    ("app-measurement.com", 35.0, true, None),
    ("graph.facebook.com", 30.0, true, None),
    ("adservice.google.com", 25.0, true, None),
    ("ads.tiktok.com", 18.0, true, None),
    ("track.adform.net", 12.0, true, None),
    // Matches a seeded custom block rule.
    ("telemetry.vendor.io", 9.0, true, None),
    ("www.youtube.com", 70.0, false, Some("142.250.196.110")),
    ("i.ytimg.com", 55.0, false, Some("142.250.196.118")),
    ("api.github.com", 45.0, false, Some("140.82.113.6")),
    ("github.com", 35.0, false, Some("140.82.113.4")),
    ("fonts.gstatic.com", 50.0, false, Some("142.250.74.35")),
    ("cdn.jsdelivr.net", 30.0, false, Some("104.16.85.20")),
    ("www.netflix.com", 28.0, false, Some("54.155.178.5")),
    ("api.spotify.com", 32.0, false, Some("35.186.224.25")),
    ("www.wikipedia.org", 22.0, false, Some("208.80.154.224")),
    ("registry.npmjs.org", 20.0, false, Some("104.16.92.83")),
    ("crates.io", 14.0, false, Some("108.138.64.68")),
    ("slack.com", 18.0, false, Some("54.192.18.78")),
    ("mail.google.com", 26.0, false, Some("142.250.74.37")),
    ("time.apple.com", 16.0, false, Some("17.253.34.125")),
    ("ocsp.digicert.com", 12.0, false, Some("93.184.220.29")),
    ("static.xx.fbcdn.net", 15.0, false, Some("157.240.201.23")),
    ("www.cloudflare.com", 10.0, false, Some("104.16.124.96")),
];

/// `[ip, weight, dohToken]`.
const CLIENTS: &[Client] = &[
    ("192.168.1.10", 28.0, None),
    ("192.168.1.21", 24.0, None),
    ("192.168.1.34", 18.0, None),
    ("192.168.1.52", 10.0, None),
    ("10.0.0.5", 8.0, None),
    ("100.64.0.7", 12.0, Some("iphone")),
];

const QTYPES: &[(&str, f64)] = &[
    ("A", 60.0),
    ("AAAA", 28.0),
    ("HTTPS", 8.0),
    ("PTR", 2.0),
    ("TXT", 1.0),
    ("MX", 1.0),
];

/// UTC diurnal curve, hour 0..23 — quiet 01-05, evening peak 19-22.
const HOUR_W: [f64; 24] = [
    0.30, 0.18, 0.12, 0.10, 0.10, 0.15, 0.30, 0.50, 0.70, 0.85, 0.90, 0.95, 1.00, 0.95, 0.90, 0.85,
    0.90, 1.00, 1.10, 1.25, 1.30, 1.20, 0.85, 0.50,
];

fn pick<T: Copy>(rand: &mut Mulberry32, table: &[T], weight: impl Fn(&T) -> f64) -> T {
    let total: f64 = table.iter().map(&weight).sum();
    let mut roll = rand.next() * total;
    for row in table {
        roll -= weight(row);
        if roll <= 0.0 {
            return *row;
        }
    }
    table[table.len() - 1]
}

/// A SQL string literal, or `NULL`.
fn q(value: Option<&str>) -> String {
    match value {
        None => "NULL".to_string(),
        Some(text) => format!("'{}'", text.replace('\'', "''")),
    }
}

/// UTC hour-of-day for an epoch-millisecond instant.
fn utc_hour(ms: i64) -> usize {
    usize::try_from(ms.rem_euclid(DAY_MS) / 3_600_000).unwrap_or(0)
}

/// UTC weekday, 0 = Sunday. 1970-01-01 was a Thursday.
fn utc_weekday(ms: i64) -> i64 {
    (ms.div_euclid(DAY_MS) + 4).rem_euclid(7)
}

/// Ninety days of plausible traffic, plus the filter lists, custom rules and
/// settings that make every screen in the screenshots look lived-in.
///
/// The diurnal and weekly shape is anchored to **UTC** hours, not to
/// hours-since-run: the statistics heatmap buckets against the viewer's clock,
/// and the capture pins the browser to UTC, so anchoring it anywhere else would
/// smear the pattern the screenshot is there to show.
pub fn screenshots(now: i64) -> String {
    let mut rand = Mulberry32::new(42);
    const HOURS: i64 = 90 * 24;
    let sum_hour_w: f64 = HOUR_W.iter().sum();
    let mut rows: Vec<String> = Vec::new();

    for slot in (0..HOURS).rev() {
        // Every slot is fully in the past.
        let slot_start = now - (slot + 1) * 3_600_000;
        let hour = utc_hour(slot_start);
        let weekday = utc_weekday(slot_start);
        let weekend = if weekday == 0 || weekday == 6 {
            1.18
        } else {
            1.0
        };
        // Traffic grows over the ninety days.
        let trend = 0.75 + 0.4 * ((HOURS - 1 - slot) as f64 / (HOURS - 1) as f64);
        let per_day = 540.0 * weekend * trend * (0.9 + 0.2 * rand.next());
        let n = ((per_day * HOUR_W[hour]) / sum_hour_w).round() as i64;

        for _ in 0..n {
            let ts = slot_start + (rand.next() * 3_600_000.0) as i64;
            let (domain, _, blocked, ip) = pick(&mut rand, DOMAINS, |d| d.1);
            let (client, _, token) = pick(&mut rand, CLIENTS, |c| c.1);
            let qtype = pick(&mut rand, QTYPES, |t| t.1).0;

            let (cached, response_ms, upstream, result) = if blocked {
                (0, 0, None, Some("0.0.0.0"))
            } else if rand.next() < 0.35 {
                // Cache hits are not free: a small realistic latency keeps the
                // statistics p50 off 0 ms. Blocked rows stay at 0 (instant).
                (1, 1 + (rand.next() * 3.0) as i64, None, ip)
            } else {
                let upstream = if rand.next() < 0.7 {
                    "1.1.1.1:53"
                } else {
                    "9.9.9.9:53"
                };
                let jitter = if rand.next() < 0.02 { 250 } else { 0 };
                let latency = 6 + (rand.next().powf(2.2) * 140.0) as i64 + jitter;
                (0, latency, Some(upstream), ip)
            };

            rows.push(format!(
                "({ts},{},{},{},{},{cached},{response_ms},{},{},{})",
                q(Some(domain)),
                q(Some(qtype)),
                q(Some(client)),
                i32::from(blocked),
                q(upstream),
                q(token),
                q(result),
            ));
        }
    }

    // `last_updated` is epoch seconds; the UI normalises it.
    let lu = now / 1000;
    let mut parts = vec![
        "PRAGMA busy_timeout = 5000;".to_string(),
        "BEGIN;".to_string(),
        // Retention MUST cover the 90-day backdate — the prune task fires
        // immediately at boot.
        "INSERT INTO settings (key, value) VALUES ('log_retention_days','180')
           ON CONFLICT(key) DO UPDATE SET value = excluded.value;"
            .to_string(),
        "INSERT INTO settings (key, value) VALUES ('onboarding_banner_dismissed','true')
           ON CONFLICT(key) DO UPDATE SET value = excluded.value;"
            .to_string(),
        format!(
            "UPDATE filter_lists SET enabled = 1, rule_count = 7, last_updated = {}
               WHERE name = 'AdGuard DNS filter';",
            lu - 7200
        ),
        format!(
            "UPDATE filter_lists SET enabled = 1, rule_count = 1, last_updated = {}
               WHERE name = 'AdAway Default Blocklist';",
            lu - 7200
        ),
        format!(
            "INSERT INTO filter_lists (name, url, enabled, last_updated, rule_count) VALUES
               ('Peter Lowe''s Ad and tracking server list',
                'https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt',
                0,{},3284);",
            lu - 90000
        ),
        // Content for the enabled lists so the second boot's rebuild yields a
        // live engine without touching the network. `rule_count` above has to
        // match what is seeded here: the filters page's Impact column is
        // computed from the loaded rules, so a list claiming 59,842 rules and
        // contributing seven would read as a bug in the screenshots.
        "INSERT INTO filter_list_content (list_id, content)
           SELECT id, '||doubleclick.net^' || char(10) || '||googlesyndication.com^' || char(10) ||
                      '||app-measurement.com^' || char(10) || '||graph.facebook.com^' || char(10) ||
                      '||adservice.google.com^' || char(10) || '||ads.tiktok.com^' || char(10) ||
                      '||track.adform.net^'
           FROM filter_lists WHERE name = 'AdGuard DNS filter'
           ON CONFLICT(list_id) DO UPDATE SET content = excluded.content;"
            .to_string(),
        "INSERT INTO filter_list_content (list_id, content)
           SELECT id, '||ad.example.net^' FROM filter_lists WHERE name = 'AdAway Default Blocklist'
           ON CONFLICT(list_id) DO UPDATE SET content = excluded.content;"
            .to_string(),
        "INSERT INTO custom_rules (rule, rule_type) VALUES
           ('||telemetry.vendor.io^','block'),
           ('@@||analytics.mycompany.dev^','allow'),
           ('||ads.smart-tv.lan^','block');"
            .to_string(),
        "INSERT OR IGNORE INTO doh_tokens (token) VALUES ('iphone');".to_string(),
    ];

    for chunk in rows.chunks(500) {
        parts.push(format!(
            "INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, \
             response_ms, upstream, doh_token, result) VALUES\n{};",
            chunk.join(",\n")
        ));
    }
    parts.push("COMMIT;".to_string());
    parts.push("ANALYZE;".to_string());
    parts.join("\n")
}

/// How many rows the query-log fixture inserts.
///
/// Two full pages and a bit: enough that page 2 exists and page 3 does not, so
/// both edges of the pager are exercised. Every row's domain, type and outcome
/// is predictable, which is what makes the filter assertions exact.
pub const LOG_ROWS: usize = 120;

/// The query-log fixture.
pub fn query_log(now: i64) -> String {
    let mut rows = Vec::with_capacity(LOG_ROWS);
    for i in 0..LOG_ROWS as i64 {
        let blocked = i32::from(i % 3 == 0);
        let qtype = if i % 4 == 0 { "AAAA" } else { "A" };
        let domain = if blocked == 1 {
            format!("ads{i}.tracker.example")
        } else {
            format!("site{i}.example.com")
        };
        rows.push(format!(
            "({}, '{domain}', '{qtype}', '10.0.0.{}', {blocked}, 0, {}, '1.1.1.1:53', NULL, NULL, 0)",
            now - i * 1000,
            i % 5,
            10 + (i % 30)
        ));
    }
    format!(
        "INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, \
         response_ms, upstream, doh_token, result, authenticated_data) VALUES\n{};\n",
        rows.join(",\n")
    )
}

/// Blocked queries inside the statistics fixture's 7-day window.
pub const STATS_RECENT_BLOCKED: i64 = 30;
/// Allowed queries inside that window.
pub const STATS_RECENT_ALLOWED: i64 = 10;
/// Queries ten days back, reachable only from a wider range.
pub const STATS_OLD: i64 = 20;

/// The statistics fixture: two domains inside the 7-day window and a third only
/// reachable from a wider one, which is what makes switching the range visibly
/// change the page rather than just re-render it.
pub fn stats(now: i64) -> String {
    let row = |ts: i64, domain: &str, qtype: &str, blocked: i32| {
        format!(
            "({ts}, '{domain}', '{qtype}', '10.0.0.7', {blocked}, 0, 12, '1.1.1.1:53', NULL, '1.2.3.4', 0)"
        )
    };
    let mut rows = Vec::new();
    // Spread across the last six days so every bucket is not the same one.
    for i in 0..STATS_RECENT_BLOCKED {
        rows.push(row(
            now - (i % 6) * DAY_MS - i * 1000,
            "ads.recent.example",
            "A",
            1,
        ));
    }
    for i in 0..STATS_RECENT_ALLOWED {
        rows.push(row(
            now - (i % 6) * DAY_MS - i * 1000,
            "site.recent.example",
            "AAAA",
            0,
        ));
    }
    for i in 0..STATS_OLD {
        rows.push(row(now - 10 * DAY_MS - i * 1000, "old.example", "A", 0));
    }
    // Retention defaults to seven days and the hourly prune fires its first
    // tick immediately, so ten-day-old rows would delete themselves before the
    // first request. Widen it here: without traffic outside the default window
    // there is nothing for a wider range to find, and the switcher would only
    // be redrawing the same numbers under a different title.
    format!(
        "INSERT OR REPLACE INTO settings (key, value) VALUES ('log_retention_days', '60');\n\
         INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, \
         response_ms, upstream, doh_token, result, authenticated_data) VALUES\n{};\n",
        rows.join(",\n")
    )
}
