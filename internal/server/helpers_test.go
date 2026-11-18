package server

import (
	"reflect"
	"testing"

	"github.com/henry40408/noadd/internal/db"
)

func TestSafeNextAcceptsOnlySameOriginPaths(t *testing.T) {
	for _, accepted := range []string{"/settings", "/logs?page=2"} {
		if got, ok := safeNext(accepted); !ok || got != accepted {
			t.Errorf("safeNext(%q) = %q, %v", accepted, got, ok)
		}
	}
	for _, refused := range []string{
		"https://evil.example", "//evil.example", `/\evil.example`,
		"settings", "/settings\r\nX-Injected: 1", "", "/a\x00b", "/a\x7fb",
	} {
		if got, ok := safeNext(refused); ok {
			t.Errorf("safeNext(%q) accepted as %q", refused, got)
		}
	}
}

func TestLoginURLCarriesOnlyADestinationWorthReturningTo(t *testing.T) {
	cases := map[string]string{
		"":                     "/login",
		"/":                    "/login",
		"https://evil.example": "/login",
		"/settings":            "/login?next=/settings",
	}
	for next, want := range cases {
		if got := loginURL(next); got != want {
			t.Errorf("loginURL(%q) = %q, want %q", next, got, want)
		}
	}
}

func TestQueryValueEncodingKeepsTheDestinationWhole(t *testing.T) {
	if got := encodeQueryValue("/logs?page=2&type=blocked"); got != "/logs%3Fpage%3D2%26type%3Dblocked" {
		t.Errorf("got %q", got)
	}
	if got := encodeQueryValue("/settings"); got != "/settings" {
		t.Errorf("got %q", got)
	}
	if got := encodeQueryValue("é"); got != "%C3%A9" {
		t.Errorf("multi-byte: got %q", got)
	}
}

func TestCountsAreGroupedTheWayTheClientGroupsThem(t *testing.T) {
	cases := map[int64]string{
		0: "0", 999: "999", 1_000: "1,000", 87_654: "87,654", 1_234_567: "1,234,567", -1_234: "-1,234",
	}
	for n, want := range cases {
		if got := thousands(n); got != want {
			t.Errorf("thousands(%d) = %q, want %q", n, got, want)
		}
	}
	if got := thousands(-9223372036854775808); got != "-9,223,372,036,854,775,808" {
		t.Errorf("min int64: %q", got)
	}
}

func TestCompactCountsLoseNothingAReaderNeeds(t *testing.T) {
	cases := map[int64]string{999: "999", 1_000: "1K", 12_345: "12.3K", 1_250_000: "1.3M"}
	for n, want := range cases {
		if got := compact(n); got != want {
			t.Errorf("compact(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestCountsSwitchNotationOnlyAboveAMillion(t *testing.T) {
	cases := map[int64]string{999_999: "999,999", 1_000_000: "1M", 1_250_000: "1.3M"}
	for n, want := range cases {
		if got := formatNumAdaptive(n); got != want {
			t.Errorf("formatNumAdaptive(%d) = %q, want %q", n, got, want)
		}
	}
	if got := formatNumAdaptiveAt(9_999_999, 10_000_000); got != "9,999,999" {
		t.Errorf("got %q", got)
	}
	if got := formatNumAdaptiveAt(10_000_000, 10_000_000); got != "10M" {
		t.Errorf("got %q", got)
	}
}

func TestOnlyAbsoluteHTTPURLsSurviveIntoAnHref(t *testing.T) {
	for _, kept := range []string{"https://example.com/list", "http://example.com", "HTTPS://example.com"} {
		if got := safeURL(kept); got != kept {
			t.Errorf("safeURL(%q) = %q", kept, got)
		}
	}
	for _, dropped := range []string{
		"javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,<script>",
		"//evil.example", "/relative", "",
	} {
		if got := safeURL(dropped); got != "" {
			t.Errorf("safeURL(%q) = %q, want empty", dropped, got)
		}
	}
}

func TestSizesAreWrittenTheWayTheClientWritesThem(t *testing.T) {
	cases := map[int64]string{512: "512 B", 1_536: "1.5 KB", 5 << 20: "5.00 MB", 3 << 30: "3.00 GB"}
	for n, want := range cases {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
	if got := formatBytesOrDash(0); got != "—" {
		t.Errorf("zero: %q", got)
	}
	if got := formatBytesOrDash(2_048.4); got != "2.0 KB" {
		t.Errorf("got %q", got)
	}
}

func TestADateTheServerWritesIsAnUnambiguousOne(t *testing.T) {
	if got := isoDate(1_786_579_200); got != "2026-08-13" {
		t.Errorf("got %q", got)
	}
}

func TestBarsAreSizedAgainstTheLargestRowAndSharesAgainstTheTotal(t *testing.T) {
	rows := barRows([]db.NameCount{{Name: "b.example", Count: 25}, {Name: "a.example", Count: 75}})
	if rows[0].Label != "a.example" || rows[0].Width != "100.0" || rows[0].Share != "75.0%" || rows[0].CountTitle != "75 (75.0%)" {
		t.Errorf("first row %+v", rows[0])
	}
	if rows[1].Width != "33.3" || rows[1].Share != "25.0%" {
		t.Errorf("second row %+v", rows[1])
	}
}

func TestABarListOfNothingDividesByNothing(t *testing.T) {
	if got := barRows(nil); len(got) != 0 {
		t.Errorf("got %v", got)
	}
	rows := barRows([]db.NameCount{{Name: "none", Count: 0}})
	if rows[0].Width != "0.0" || rows[0].Share != "" || rows[0].CountTitle != "0" {
		t.Errorf("row %+v", rows[0])
	}
}

func TestARateIsOneDecimalOfAPercent(t *testing.T) {
	for value, want := range map[float64]string{0: "0.0", 0.755: "75.5", 1: "100.0"} {
		if got := percent1(value); got != want {
			t.Errorf("percent1(%v) = %q, want %q", value, got, want)
		}
	}
}

func TestAShareOfNothingIsNotAShare(t *testing.T) {
	cases := []struct {
		count, sum int64
		want       string
	}{{0, 0, ""}, {5, 0, ""}, {0, 10, ""}, {3, 4, "75.0%"}}
	for _, c := range cases {
		if got := sharePercent(c.count, c.sum); got != c.want {
			t.Errorf("sharePercent(%d, %d) = %q, want %q", c.count, c.sum, got, c.want)
		}
	}
}

func TestThroughputKeepsThePrecisionTheNumberDeserves(t *testing.T) {
	for value, want := range map[float64]string{0.0333: "0.03", 9.99: "9.99", 12.34: "12.3", 1234.56: "1235"} {
		if got := formatQPS(value); got != want {
			t.Errorf("formatQPS(%v) = %q, want %q", value, got, want)
		}
	}
}

func TestTheDNSTargetPairsTheBrowsersHostWithTheDNSPort(t *testing.T) {
	cases := []struct{ dnsAddr, want string }{
		{"0.0.0.0:53", "noadd.lan:53"}, {"127.0.0.1:5353", "noadd.lan:5353"}, {"53", "noadd.lan"},
	}
	for _, c := range cases {
		if got := dnsTarget("noadd.lan:8080", c.dnsAddr); got != c.want {
			t.Errorf("dnsTarget(%q) = %q, want %q", c.dnsAddr, got, c.want)
		}
	}
}

func TestAnExpirySaysWhichSideOfNowItIsOn(t *testing.T) {
	const now = 1_800_000_000
	at := func(ts int64) *int64 { return &ts }
	cases := []struct {
		ts   *int64
		want string
	}{
		{nil, "never"}, {at(0), "never"}, {at(now - 60), "expired"},
		{at(now + 86_400*30 + 10), "in 30 days"}, {at(now + 7_200 + 10), "in 2 hours"},
		{at(now + 5), "in 1 minute"}, {at(now + 86_400 + 10), "in 1 day"},
	}
	for _, c := range cases {
		if got := expiryText(c.ts, now); got != c.want {
			t.Errorf("expiryText(%v) = %q, want %q", c.ts, got, c.want)
		}
	}
}

func TestAColumnWithNothingInItSaysSo(t *testing.T) {
	const now = 1_800_000_000
	zero, current := int64(0), int64(now)
	if got := maybeTimeAgo(nil, now); got != "—" {
		t.Errorf("nil: %q", got)
	}
	if got := maybeTimeAgo(&zero, now); got != "—" {
		t.Errorf("zero: %q", got)
	}
	if got := maybeTimeAgo(&current, now); got != "0 seconds ago" {
		t.Errorf("now: %q", got)
	}
}

func TestRelativeTimesAreSingularWhereTheyShouldBe(t *testing.T) {
	const now = 1_800_000_000
	cases := map[int64]string{
		0: "never", now: "0 seconds ago", now - 1: "1 second ago", now - 90: "1 minute ago",
		now - 7_200: "2 hours ago", now - 172_800: "2 days ago",
		// A clock that moved backwards must not render a negative age.
		now + 60: "0 seconds ago",
	}
	for ts, want := range cases {
		if got := timeAgo(ts, now); got != want {
			t.Errorf("timeAgo(%d) = %q, want %q", ts, got, want)
		}
	}
}

func TestLogsQueryStringCarriesEveryFilterAndOnlyPageChanges(t *testing.T) {
	filters := logsFilters{q: "ads & x", action: "blocked", queryType: "AAAA", token: "tok"}
	if got := logsQueryString(filters, 1); got != "q=ads%20%26%20x&action=blocked&type=AAAA&token=tok" {
		t.Errorf("page 1: %q", got)
	}
	if got := logsQueryString(filters, 3); got != "q=ads%20%26%20x&action=blocked&type=AAAA&token=tok&page=3" {
		t.Errorf("page 3: %q", got)
	}
	if got := logsHref(logsQueryString(logsFilters{}, 1)); got != "/logs" {
		t.Errorf("unfiltered: %q", got)
	}
	if !reflect.DeepEqual(filters, logsFilters{q: "ads & x", action: "blocked", queryType: "AAAA", token: "tok"}) {
		t.Error("filters mutated")
	}
}
