package e2e

import (
	"testing"
	"time"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// tickWait outlasts events.TickInterval (10 s, a constant the binary does not
// let a test shorten), so at least one tick has pushed a snapshot by then.
const tickWait = 13 * time.Second

// The dashboard's first snapshot comes with the connection; the next one comes
// from the hub's tick. Both must carry the same numbers: a tick snapshot built
// with the wrong time unit read an empty window, zeroed the stat cards and
// swapped in the onboarding guidance, so only a test that outlives a tick sees
// it.
func TestSpecDashboardSurvivesTick(t *testing.T) {
	server := specInstance(t, "dashboard-tick", dashboardTickPort)
	session := seeded(t, server, harness.QueryLogSeed(harness.NowMillis()))

	queries := "#stats .stat-card:nth-child(1) .stat-value"
	blocked := "#stats .stat-card:nth-child(2) .stat-value"
	runCases(t, server, desktop, []specCase{
		{"the stat cards keep their numbers after the stream's next tick", func(p page) error {
			return sequence(
				func() error { return p.open(session, "/") },
				func() error { return p.Loc(queries).ExpectTextEq("120") },
				func() error { return p.Loc(blocked).ExpectTextEq("40") },
				func() error { return p.LocTestID("server-status").ExpectAttr("data-state", "online") },
				func() error { time.Sleep(tickWait); return nil },
				func() error { return p.LocTestID("server-status").ExpectAttr("data-state", "online") },
				func() error { return p.Loc(queries).ExpectTextEq("120") },
				func() error { return p.Loc(blocked).ExpectTextEq("40") },
				p.LocTestID("dashboard-empty-state").ExpectHidden,
			)
		}},
	})
}
