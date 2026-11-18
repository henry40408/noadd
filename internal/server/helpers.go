package server

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// safeNext accepts only a same-origin destination expressed as an absolute
// path.
//
// next is attacker-controlled: /login?next=https://evil.example would be an
// open redirect behind noadd's own URL. Protocol-relative "//evil.example" and
// "/\evil.example" (which browsers normalise into it) are refused too, as are
// control characters, since the value lands in a Location header.
func safeNext(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, `/\`) {
		return "", false
	}
	for _, r := range raw {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return raw, true
}

// nextOr returns the validated destination in raw, or fallback.
func nextOr(raw, fallback string) string {
	if next, ok := safeNext(raw); ok {
		return next
	}
	return fallback
}

// loginURL is /login, carrying next when there is a destination worth
// returning to. "/" is omitted: sign-in lands there anyway.
func loginURL(next string) string {
	target, ok := safeNext(next)
	if !ok || target == "/" {
		return "/login"
	}
	return "/login?next=" + encodeQueryValue(target)
}

// encodeQueryValue percent-encodes a path so it survives as a single
// query-string value. Only unreserved characters and "/" pass, so no ?, # or &
// can silently truncate the value.
func encodeQueryValue(value string) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		b := value[i]
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9',
			b == '-', b == '.', b == '_', b == '~', b == '/':
			out.WriteByte(b)
		default:
			out.WriteByte('%')
			out.WriteByte(hex[b>>4])
			out.WriteByte(hex[b&0x0f])
		}
	}
	return out.String()
}

// safeURL keeps a javascript: homepage out of an href: escaping does not stop
// navigation. Only absolute http(s) survives; anything else yields "".
func safeURL(raw string) string {
	candidate := strings.TrimSpace(raw)
	lowered := strings.ToLower(candidate)
	if strings.HasPrefix(lowered, "http://") || strings.HasPrefix(lowered, "https://") {
		return candidate
	}
	return ""
}

// requestHost is the Host this request arrived on. Client-supplied: fine for
// the status bar label (the view escapes it), never for identity.
func requestHost(r *http.Request) string {
	return r.Host
}

// dnsTarget is where to point a device's DNS, for the onboarding notice: the
// host from the request (a name that resolves) and the port of the DNS
// listener, whose bind address is often 0.0.0.0, useless to type in.
func dnsTarget(host, dnsAddr string) string {
	// Strip the HTTP port; the DNS one is what belongs here.
	name, _, _ := strings.Cut(host, ":")
	cut := strings.LastIndex(dnsAddr, ":")
	if cut < 0 || cut == len(dnsAddr)-1 {
		return name
	}
	return name + ":" + dnsAddr[cut+1:]
}

// thousands separates an integer's digits, matching Intl.NumberFormat as
// app.js uses it in the same column.
func thousands(n int64) string {
	digits := strconv.FormatUint(absUint(n), 10)
	var out strings.Builder
	if n < 0 {
		out.WriteByte('-')
	}
	for i := 0; i < len(digits); i++ {
		if i > 0 && (len(digits)-i)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteByte(digits[i])
	}
	return out.String()
}

func absUint(n int64) uint64 {
	if n < 0 {
		return uint64(-(n + 1)) + 1
	}
	return uint64(n)
}

// compact abbreviates a count to at most one decimal (12.3K, 1.2M).
func compact(n int64) string {
	switch {
	case n >= 1_000_000:
		return scaledCount(float64(n)/1_000_000, "M")
	case n >= 1_000:
		return scaledCount(float64(n)/1_000, "K")
	default:
		return thousands(n)
	}
}

func scaledCount(value float64, suffix string) string {
	rounded := math.Round(value*10) / 10
	if math.Abs(rounded-math.Trunc(rounded)) < 2.220446049250313e-16 {
		return strconv.FormatInt(int64(rounded), 10) + suffix
	}
	return strconv.FormatFloat(rounded, 'f', 1, 64) + suffix
}

// formatNumAdaptive shows full digits below a million and abbreviates above.
// It mirrors formatNumAdaptive in app.js, which redraws the same cards from
// pushed snapshots; a count that switched notation would look like it changed.
func formatNumAdaptive(n int64) string {
	return formatNumAdaptiveAt(n, 1_000_000)
}

// formatNumAdaptiveAt takes a custom threshold: the statistics tiles for
// totals that run to eight digits hold off until ten million.
func formatNumAdaptiveAt(n, threshold int64) string {
	if n < threshold {
		return thousands(n)
	}
	return compact(n)
}

// percent1 turns a fraction into a one-decimal percentage.
func percent1(value float64) string {
	return strconv.FormatFloat(value*100, 'f', 1, 64)
}

// sharePercent is one row's share of the visible total; empty when there is
// none.
func sharePercent(count, sum int64) string {
	if sum <= 0 || count <= 0 {
		return ""
	}
	return strconv.FormatFloat(float64(count)/float64(sum)*100, 'f', 1, 64) + "%"
}

// formatQPS prints queries per second: two decimals on a trickle, none on a
// flood. Matches fmtQps in app.js.
func formatQPS(value float64) string {
	switch {
	case value >= 100:
		return strconv.FormatFloat(math.Round(value), 'f', 0, 64)
	case value >= 10:
		return strconv.FormatFloat(value, 'f', 1, 64)
	default:
		return strconv.FormatFloat(value, 'f', 2, 64)
	}
}

// formatBytes prints bytes at the precision the size deserves.
func formatBytes(bytes int64) string {
	const kb = 1024.0
	const mb = kb * 1024
	const gb = mb * 1024
	value := float64(bytes)
	switch {
	case value >= gb:
		return fmt.Sprintf("%.2f GB", value/gb)
	case value >= mb:
		return fmt.Sprintf("%.2f MB", value/mb)
	case value >= kb:
		return fmt.Sprintf("%.1f KB", value/kb)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// formatBytesOrDash uses a dash where zero means "no data".
func formatBytesOrDash(value float64) string {
	if value > 0 {
		return formatBytes(int64(math.Round(value)))
	}
	return "—"
}

// isoDate is a date the way the server can write one: an ISO day, in UTC. The
// cell also carries its timestamp for app.js to restate in the browser's
// locale.
func isoDate(ts int64) string {
	return time.Unix(ts, 0).UTC().Format("2006-01-02")
}

// pluralUnit words a count of a unit, with "s" unless it is one.
func pluralUnit(count int64, name string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, name)
	}
	return fmt.Sprintf("%d %ss", count, name)
}

// timeAgo words how long ago a timestamp was as app.js words it, so a redrawn
// row keeps its phrasing.
func timeAgo(ts, now int64) string {
	if ts == 0 {
		return "never"
	}
	diff := max(now-ts, 0)
	switch {
	case diff < 60:
		return pluralUnit(diff, "second") + " ago"
	case diff < 3_600:
		return pluralUnit(diff/60, "minute") + " ago"
	case diff < 86_400:
		return pluralUnit(diff/3_600, "hour") + " ago"
	default:
		return pluralUnit(diff/86_400, "day") + " ago"
	}
}

// maybeTimeAgo renders an unset timestamp (0 or nil) as a dash.
func maybeTimeAgo(ts *int64, now int64) string {
	if ts == nil || *ts == 0 {
		return "—"
	}
	return timeAgo(*ts, now)
}

// expiryText says when an API key stops working: never, "in 30 days" or
// expired.
func expiryText(ts *int64, now int64) string {
	if ts == nil || *ts == 0 {
		return "never"
	}
	remaining := *ts - now
	switch {
	case remaining <= 0:
		return "expired"
	case remaining < 3_600:
		return "in " + pluralUnit(max(remaining/60, 1), "minute")
	case remaining < 86_400:
		return "in " + pluralUnit(remaining/3_600, "hour")
	default:
		return "in " + pluralUnit(remaining/86_400, "day")
	}
}

// logsFilters are the filters a /logs view applies, trimmed, with empty
// strings meaning "not applied".
type logsFilters struct {
	q, action, queryType, token string
}

// logsQueryString rebuilds the page's query string with page replaced. The
// pager must carry every filter, or paging silently drops them.
func logsQueryString(filters logsFilters, page int64) string {
	var parts []string
	add := func(key, value string) {
		if value != "" {
			parts = append(parts, key+"="+encodeQueryValue(value))
		}
	}
	add("q", filters.q)
	add("action", filters.action)
	add("type", filters.queryType)
	add("token", filters.token)
	if page > 1 {
		parts = append(parts, "page="+strconv.FormatInt(page, 10))
	}
	return strings.Join(parts, "&")
}

// logsHref is /logs, with a query string when there is one.
func logsHref(query string) string {
	if query == "" {
		return "/logs"
	}
	return "/logs?" + query
}
