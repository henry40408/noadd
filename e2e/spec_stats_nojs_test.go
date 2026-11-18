package e2e

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

var isoDay = regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)

// The statistics page with JavaScript off. Every reading arrives rendered
// except the three charts (timeline, rate trend, heatmap), which need the
// viewer's UTC offset and say so instead of sitting empty. The range switcher
// picks the server's window, so it is three plain links.
//
// Seeded with rows older than seven days, so switching the range changes numbers.
func TestSpecStatsNoJS(t *testing.T) {
	server := specInstance(t, "stats-no-js", statsNoJSPort)
	session := seeded(t, server, harness.StatsSeed(harness.NowMillis()))

	openStats := func(p page, query string) error { return p.open(session, "/stats"+query) }

	runCases(t, server, noJS, []specCase{
		{"every reading that does not need a calendar arrives rendered", func(p page) error {
			highlights := p.Loc("#highlights-grid")
			domains := p.LocTestID("ranged-domains")
			health := p.LocTestID("db-health-card")
			return sequence(
				func() error { return openStats(p, "") },
				// Highlights: two domains were queried inside the 7-day window.
				func() error { return highlights.ExpectTextContains("Unique Domains") },
				func() error { return highlights.ExpectTextContains("2") },
				// Latency percentiles, from a seeded 12 ms on every row.
				func() error { return highlights.ExpectTextContains("Latency p50") },
				// Both breakdowns, as bars rather than as a chart.
				func() error { return p.Loc("#qtypes-chart .bar-row").ExpectCount(2) },
				func() error { return p.Loc("#qtypes-chart").ExpectTextContains("A") },
				func() error { return p.Loc("#qtypes-chart").ExpectTextContains("AAAA") },
				func() error { return p.Loc("#outcomes-chart").ExpectTextContains("Blocked") },
				// Both ranged lists. 30 of 40 queries were blocked ads.
				func() error { return domains.ExpectTextContains("ads.recent.example") },
				func() error { return domains.ExpectTextContains("75.0%") },
				func() error { return p.LocTestID("ranged-clients").ExpectTextContains("10.0.0.7") },
				// Nothing from outside the window leaked into the default range.
				func() error { return domains.ExpectTextExcludes("old.example") },
				// And the health grid, which reports on the file, not traffic.
				func() error { return health.ExpectTextContains("Database Size") },
				func() error { return health.ExpectTextContains("Total Logs") },
				// The UTC date the server writes is still a readable date.
				func() error {
					text, err := health.Text()
					if err != nil {
						return err
					}
					if !isoDay.MatchString(text) {
						return fmt.Errorf("no YYYY-MM-DD date in the health card: %q", text)
					}
					return nil
				},
			)
		}},
		{"the three charts say they are drawn in the browser", func(p page) error {
			return sequence(
				func() error { return openStats(p, "") },
				p.LocTestID("timeline-needs-js").ExpectVisible,
				p.LocTestID("rate-trend-needs-js").ExpectVisible,
				p.LocTestID("heatmap-needs-js").ExpectVisible,
				// Nothing the client would draw is there.
				func() error { return p.Loc("#timeline-chart .tl-svg").ExpectCount(0) },
				func() error { return p.Loc("#heatmap-container .heatmap-cell").ExpectCount(0) },
			)
		}},
		{"the range switcher is links, and switching one widens the window", func(p page) error {
			switcher := p.LocTestID("range-switcher")
			domains := p.LocTestID("ranged-domains")
			return sequence(
				func() error { return openStats(p, "") },
				func() error { return switcher.Loc("a").ExpectCount(3) },
				func() error { return switcher.Loc("a.active").ExpectTextEq("7d") },
				func() error { return p.Loc("#ranged-domains-title").ExpectTextEq("Top Domains (last 7d)") },
				// A script click: with scripting off the page is interactive
				// while the header is still fading in, so a pointer click can
				// miss. The assertions below only pass if the navigation happened.
				switcher.Loc("a").HavingText("30d").ClickJS,
				func() error { return p.ExpectURLEndsWith("/stats?range=30d") },
				func() error { return switcher.Loc("a.active").ExpectTextEq("30d") },
				func() error { return p.Loc("#ranged-domains-title").ExpectTextEq("Top Domains (last 30d)") },
				func() error { return p.Loc("#timeline-title").ExpectTextEq("Queries (last 30d)") },
				// The wider window reaches the older traffic.
				func() error { return domains.ExpectTextContains("old.example") },
				func() error { return p.Loc("#highlights-grid").ExpectTextContains("3") },
			)
		}},
		{"a range nobody offers renders the default window rather than an error", func(p page) error {
			return sequence(
				func() error { return openStats(p, "?range=nonsense") },
				func() error { return p.Loc("#ranged-domains-title").ExpectTextEq("Top Domains (last 7d)") },
				func() error { return p.LocTestID("range-switcher").Loc("a.active").ExpectTextEq("7d") },
			)
		}},
	})
}
