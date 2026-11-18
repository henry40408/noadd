package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// pushGrace is how long a pushed row gets to reach the page once the server
// has sent it.
const pushGrace = 500 * time.Millisecond

// The query log's live tail: a real query must arrive after the page is open,
// which seeding a stopped database cannot show.
//
// The tail rides the shell's event stream (/api/events?logs=1), and turning it
// on re-opens that one connection, so both are asserted: a row arrives, and
// the status indicator on the same connection does not blink OFFLINE.
func TestSpecLogsLiveTail(t *testing.T) {
	server := specInstance(t, "logs-live-tail", logsLiveTailPort)
	session := provision(t, server)
	api := harness.NewAPI(server)

	runCases(t, server, desktop, []specCase{
		{"a query answered while the page is open arrives as a row", func(p page) error {
			toggle := p.LocTestID("logs-live-toggle")
			status := p.LocTestID("server-status")
			return sequence(
				func() error { return p.open(session, "/logs") },
				// The indicator must be up before the toggle to mean anything after.
				func() error { return status.ExpectAttr("data-state", "online") },
				toggle.ExpectVisible,
				// Unlike the dashboard's, this toggle keeps its label; state is a class.
				func() error { return toggle.ExpectClass("paused") },
				toggle.Click,
				func() error { return toggle.ExpectNotClass("paused") },
				// Sent after the tail is on, so the row cannot come from the
				// initial render. noadd logs it whether or not an upstream answers.
				func() error { return harness.SendDNSQuery(server.DNSPort, "tailed-query.example") },
				func() error { return p.ExpectPageText("tailed-query.example") },
				// Re-opening the connection must not read as the server going away.
				func() error { return status.ExpectAttr("data-state", "online") },
			)
		}},
		{"switching the tail off stops new rows without dropping the stream", func(p page) error {
			toggle := p.LocTestID("logs-live-toggle")
			return sequence(
				func() error { return p.open(session, "/logs") },
				toggle.Click,
				func() error { return toggle.ExpectNotClass("paused") },
				// Off again: the subscription goes, the connection stays.
				toggle.Click,
				func() error { return toggle.ExpectClass("paused") },
				func() error { return harness.SendDNSQuery(server.DNSPort, "not-tailed.example") },
				// An absence proves nothing until the row could have arrived. The
				// logger broadcasts an entry before it flushes it, so once
				// /api/logs has the row a live subscription has already been sent
				// it; the grace covers the push reaching the page.
				func() error { return waitForLoggedQuery(api, session, "not-tailed.example") },
				func() error { time.Sleep(pushGrace); return nil },
				func() error { return p.LocTestID("server-status").ExpectAttr("data-state", "online") },
				func() error {
					seen, err := p.HasText("not-tailed.example")
					if err != nil {
						return err
					}
					if seen {
						return fmt.Errorf("a paused tail still received rows, so the subscription outlived the toggle")
					}
					return nil
				},
			)
		}},
	})
}

func waitForLoggedQuery(api *harness.API, session, domain string) error {
	return harness.Eventually("the query reaching the log", func() (bool, error) {
		body, err := api.GetJSON(session, "/api/logs?search="+domain)
		if err != nil {
			return false, err
		}
		total, _ := body["total"].(float64)
		return total > 0, nil
	})
}
