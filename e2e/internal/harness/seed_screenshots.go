package harness

import (
	"fmt"
	"math"
	"strings"
)

// mulberry32 is the PRNG the screenshot traffic was generated with, bit for
// bit, so the fixture keeps its shape.
type mulberry32 uint32

// next is the next float in [0, 1).
func (m *mulberry32) next() float64 {
	*m += 0x6d2b79f5
	s := uint32(*m)
	t := (s ^ (s >> 15)) * (1 | s)
	t = (t + (t^(t>>7))*(0x3d|t)) ^ t
	return float64(t^(t>>14)) / 4294967296.0
}

type weightedDomain struct {
	name    string
	weight  float64
	blocked bool
	// resultIP is empty for a blocked domain.
	resultIP string
}

type weightedClient struct {
	ip       string
	weight   float64
	dohToken string
}

type weightedType struct {
	name   string
	weight float64
}

var screenshotDomains = []weightedDomain{
	{"doubleclick.net", 55, true, ""},
	{"googlesyndication.com", 40, true, ""},
	{"app-measurement.com", 35, true, ""},
	{"graph.facebook.com", 30, true, ""},
	{"adservice.google.com", 25, true, ""},
	{"ads.tiktok.com", 18, true, ""},
	{"track.adform.net", 12, true, ""},
	// Matches a seeded custom block rule.
	{"telemetry.vendor.io", 9, true, ""},
	{"www.youtube.com", 70, false, "142.250.196.110"},
	{"i.ytimg.com", 55, false, "142.250.196.118"},
	{"api.github.com", 45, false, "140.82.113.6"},
	{"github.com", 35, false, "140.82.113.4"},
	{"fonts.gstatic.com", 50, false, "142.250.74.35"},
	{"cdn.jsdelivr.net", 30, false, "104.16.85.20"},
	{"www.netflix.com", 28, false, "54.155.178.5"},
	{"api.spotify.com", 32, false, "35.186.224.25"},
	{"www.wikipedia.org", 22, false, "208.80.154.224"},
	{"registry.npmjs.org", 20, false, "104.16.92.83"},
	{"crates.io", 14, false, "108.138.64.68"},
	{"slack.com", 18, false, "54.192.18.78"},
	{"mail.google.com", 26, false, "142.250.74.37"},
	{"time.apple.com", 16, false, "17.253.34.125"},
	{"ocsp.digicert.com", 12, false, "93.184.220.29"},
	{"static.xx.fbcdn.net", 15, false, "157.240.201.23"},
	{"www.cloudflare.com", 10, false, "104.16.124.96"},
}

var screenshotClients = []weightedClient{
	{"192.168.1.10", 28, ""},
	{"192.168.1.21", 24, ""},
	{"192.168.1.34", 18, ""},
	{"192.168.1.52", 10, ""},
	{"10.0.0.5", 8, ""},
	{"100.64.0.7", 12, "iphone"},
}

var screenshotTypes = []weightedType{
	{"A", 60}, {"AAAA", 28}, {"HTTPS", 8}, {"PTR", 2}, {"TXT", 1}, {"MX", 1},
}

// diurnalWeights is the UTC diurnal curve by hour: quiet 01-05, evening peak 19-22.
var diurnalWeights = [24]float64{
	0.30, 0.18, 0.12, 0.10, 0.10, 0.15, 0.30, 0.50, 0.70, 0.85, 0.90, 0.95, 1.00, 0.95, 0.90, 0.85,
	0.90, 1.00, 1.10, 1.25, 1.30, 1.20, 0.85, 0.50,
}

func pick[T any](rand *mulberry32, table []T, weight func(T) float64) T {
	total := 0.0
	for _, row := range table {
		total += weight(row)
	}
	roll := rand.next() * total
	for _, row := range table {
		roll -= weight(row)
		if roll <= 0 {
			return row
		}
	}
	return table[len(table)-1]
}

// sqlText is a SQL string literal, or NULL for the empty string.
func sqlText(value string) string {
	if value == "" {
		return "NULL"
	}
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// ScreenshotsSeed is ninety days of plausible traffic, plus the filter lists,
// custom rules and settings that make every screen look lived-in. The diurnal
// and weekly shape is anchored to UTC hours.
func ScreenshotsSeed(now int64) string {
	rand := mulberry32(42)
	const hours = 90 * 24
	sumWeights := 0.0
	for _, weight := range diurnalWeights {
		sumWeights += weight
	}
	var rows []string
	for slot := int64(hours - 1); slot >= 0; slot-- {
		// Every slot is fully in the past.
		slotStart := now - (slot+1)*hourMillis
		hour := floorMod(slotStart, dayMillis) / hourMillis
		weekday := floorMod(floorDiv(slotStart, dayMillis)+4, 7)
		weekend := 1.0
		if weekday == 0 || weekday == 6 {
			weekend = 1.18
		}
		// Traffic grows over the ninety days.
		trend := 0.75 + 0.4*(float64(hours-1-slot)/float64(hours-1))
		perDay := 540.0 * weekend * trend * (0.9 + 0.2*rand.next())
		count := int64(math.Round(perDay * diurnalWeights[hour] / sumWeights))
		for range count {
			rows = append(rows, screenshotRow(&rand, slotStart))
		}
	}
	return screenshotSetup(now) + chunkedInserts(rows) + "COMMIT;\nANALYZE;\n"
}

func floorDiv(a, b int64) int64 {
	quotient := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		quotient--
	}
	return quotient
}

func floorMod(a, b int64) int64 { return a - floorDiv(a, b)*b }

func screenshotRow(rand *mulberry32, slotStart int64) string {
	timestamp := slotStart + int64(rand.next()*3_600_000.0)
	domain := pick(rand, screenshotDomains, func(d weightedDomain) float64 { return d.weight })
	client := pick(rand, screenshotClients, func(c weightedClient) float64 { return c.weight })
	queryType := pick(rand, screenshotTypes, func(t weightedType) float64 { return t.weight }).name

	var cached, responseMillis int64
	var upstream, result string
	switch {
	case domain.blocked:
		result = "0.0.0.0"
	case rand.next() < 0.35:
		// A small cache-hit latency keeps the statistics p50 off 0 ms.
		cached, responseMillis, result = 1, 1+int64(rand.next()*3.0), domain.resultIP
	default:
		upstream = "9.9.9.9:53"
		if rand.next() < 0.7 {
			upstream = "1.1.1.1:53"
		}
		jitter := int64(0)
		if rand.next() < 0.02 {
			jitter = 250
		}
		responseMillis = 6 + int64(math.Pow(rand.next(), 2.2)*140.0) + jitter
		result = domain.resultIP
	}
	return fmt.Sprintf("(%d,%s,%s,%s,%d,%d,%d,%s,%s,%s)", timestamp, sqlText(domain.name), sqlText(queryType),
		sqlText(client.ip), b2i(domain.blocked), cached, responseMillis, sqlText(upstream),
		sqlText(client.dohToken), sqlText(result))
}

func chunkedInserts(rows []string) string {
	var out strings.Builder
	for start := 0; start < len(rows); start += 500 {
		end := min(start+500, len(rows))
		out.WriteString("INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, " +
			"response_ms, upstream, doh_token, result) VALUES\n" + strings.Join(rows[start:end], ",\n") + ";\n")
	}
	return out.String()
}

func screenshotSetup(now int64) string {
	// last_updated is epoch seconds; the UI normalises it.
	updated := now / 1000
	return fmt.Sprintf(`PRAGMA busy_timeout = 5000;
BEGIN;
INSERT INTO settings (key, value) VALUES ('log_retention_days','180')
  ON CONFLICT(key) DO UPDATE SET value = excluded.value;
INSERT INTO settings (key, value) VALUES ('onboarding_banner_dismissed','true')
  ON CONFLICT(key) DO UPDATE SET value = excluded.value;
UPDATE filter_lists SET enabled = 1, rule_count = 7, last_updated = %d WHERE name = 'AdGuard DNS filter';
UPDATE filter_lists SET enabled = 1, rule_count = 1, last_updated = %d WHERE name = 'AdAway Default Blocklist';
INSERT INTO filter_lists (name, url, enabled, last_updated, rule_count) VALUES
  ('Peter Lowe''s Ad and tracking server list',
   'https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt', 0, %d, 3284);
INSERT INTO filter_list_content (list_id, content)
  SELECT id, '||doubleclick.net^' || char(10) || '||googlesyndication.com^' || char(10) ||
             '||app-measurement.com^' || char(10) || '||graph.facebook.com^' || char(10) ||
             '||adservice.google.com^' || char(10) || '||ads.tiktok.com^' || char(10) ||
             '||track.adform.net^'
  FROM filter_lists WHERE name = 'AdGuard DNS filter'
  ON CONFLICT(list_id) DO UPDATE SET content = excluded.content;
INSERT INTO filter_list_content (list_id, content)
  SELECT id, '||ad.example.net^' FROM filter_lists WHERE name = 'AdAway Default Blocklist'
  ON CONFLICT(list_id) DO UPDATE SET content = excluded.content;
INSERT INTO custom_rules (rule, rule_type) VALUES
  ('||telemetry.vendor.io^','block'),
  ('@@||analytics.mycompany.dev^','allow'),
  ('||ads.smart-tv.lan^','block');
INSERT OR IGNORE INTO doh_tokens (token) VALUES ('iphone');
`, updated-7200, updated-7200, updated-90000)
}
