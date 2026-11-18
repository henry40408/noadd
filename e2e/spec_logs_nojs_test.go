package e2e

import (
	"fmt"
	"strings"
	"testing"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// The query log with JavaScript off: filters are a GET form and the pager is
// two links, so both work from the URL alone. The live tail needs a client, so
// its button must not be visible. Seeded with three pages of history.
func TestSpecLogsNoJS(t *testing.T) {
	server := specInstance(t, "logs-no-js", logsNoJSPort)
	session := seeded(t, server, harness.QueryLogSeed(harness.NowMillis()))

	openLogs := func(p page, query string) error { return p.open(session, "/logs"+query) }

	runCases(t, server, noJS, []specCase{
		{"a page of rows arrives rendered, with the live tail marked client-only", func(p page) error {
			return sequence(
				func() error { return openLogs(p, "") },
				// A full page, not the whole log.
				func() error { return p.LocTestID("log-row").ExpectCount(50) },
				func() error { return p.Loc("#log-pagination").ExpectTextContains("Page 1 / 3") },
				func() error {
					return p.Loc("#log-pagination").ExpectTextContains(fmt.Sprintf("%d queries", harness.QueryLogRows))
				},
				// The live tail needs a client, so it is not offered.
				p.LocTestID("logs-live-toggle").ExpectHidden,
			)
		}},
		{"the pager walks pages and keeps the filters", func(p page) error {
			return sequence(
				func() error { return openLogs(p, "?action=blocked") },
				// 40 of the 120 rows are blocked, so a filtered log is one page.
				func() error { return p.LocTestID("log-row").ExpectCount(40) },
				func() error { return p.Loc("#log-pagination").ExpectTextContains("Page 1 / 1") },
				func() error { return openLogs(p, "") },
				// A script click: the pager sits under the fixed status bar on a
				// short window. The URL assertions prove the navigation happened.
				p.LocTestID("logs-next").ClickJS,
				func() error { return p.ExpectURLContains("page=2") },
				func() error { return p.Loc("#log-pagination").ExpectTextContains("Page 2 / 3") },
				// And back again.
				p.LocTestID("logs-prev").ClickJS,
				func() error { return p.Loc("#log-pagination").ExpectTextContains("Page 1 / 3") },
			)
		}},
		{"filters submit as a GET and land in the URL", func(p page) error {
			rows := p.LocTestID("log-row")
			return sequence(
				func() error { return openLogs(p, "") },
				func() error { return p.LocTestID("logs-search").Fill("ads") },
				func() error { return p.LocTestID("logs-type").SelectValue("AAAA") },
				p.LocTestID("logs-filter-apply").ClickJS,
				func() error { return p.ExpectURLContains("q=ads") },
				func() error { return p.ExpectURLContains("type=AAAA") },
				// Every visible row matches both filters.
				func() error { return rows.ExpectCountAtLeast(1) },
				func() error { return everyRowContains(rows, "AAAA", "ads") },
				// The form comes back showing what is applied.
				func() error { return p.LocTestID("logs-search").ExpectValue("ads") },
				func() error { return p.LocTestID("logs-type").ExpectValue("AAAA") },
			)
		}},
		{"a filter that matches nothing says so, and is not the empty-log guide", func(p page) error {
			return sequence(
				func() error { return openLogs(p, "?q=nothing-matches-this") },
				func() error { return p.LocTestID("log-row").ExpectCount(0) },
				func() error { return p.Loc("#log-body").ExpectTextContains("No logs found") },
				func() error { return p.LocTestID("logs-empty-state").ExpectCount(0) },
			)
		}},
		{"a row's one-click rule posts and comes back to the same view", func(p page) error {
			if err := openLogs(p, "?action=blocked&page=1"); err != nil {
				return err
			}
			row := p.LocTestID("log-row").First()
			// Domain on the first line, metadata under it; trimmed first because
			// textContent starts with the newline after <td>.
			cell, err := row.Loc("td").Nth(2).TextRaw()
			if err != nil {
				return err
			}
			domain, _, _ := strings.Cut(strings.TrimSpace(cell), "\n")
			domain = strings.TrimSpace(domain)
			if domain == "" {
				return fmt.Errorf("the first row carried no domain")
			}
			return sequence(
				row.Loc(".log-action").ClickJS,
				// Straight back to the filtered view it was invoked from.
				func() error { return p.ExpectURLContains("action=blocked") },
				// And the rule is on the filters page.
				func() error { return p.goToAfterSubmit("/filters") },
				func() error { return p.LocTestID("rule-row").First().ExpectTextContains(domain) },
			)
		}},
		{"clearing the log empties it and lands on an unfiltered first page", func(p page) error {
			return sequence(
				func() error { return openLogs(p, "?action=blocked&page=1") },
				p.LocTestID("logs-clear").ClickJS,
				func() error { return p.ExpectURLEndsWith("/logs") },
				p.LocTestID("logs-cleared").ExpectVisible,
				// The empty-log guide, not "No logs found": nothing is filtered.
				p.LocTestID("logs-empty-state").ExpectVisible,
			)
		}},
	})
}

// everyRowContains checks each matched row against every needle.
func everyRowContains(rows harness.Locator, needles ...string) error {
	count, err := rows.Count()
	if err != nil {
		return err
	}
	for i := range count {
		for _, needle := range needles {
			if err := rows.Nth(i).ExpectTextContains(needle); err != nil {
				return err
			}
		}
	}
	return nil
}
