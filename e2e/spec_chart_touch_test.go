package e2e

import (
	"testing"
	"time"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

const (
	// outsideX and outsideY are a point outside every chart, for the "tap
	// outside dismisses" half.
	outsideX, outsideY = 10.0, 10.0
	// afterLift is long enough for the synthetic mouse events a tap triggers.
	afterLift = 400 * time.Millisecond
)

// Touch on the statistics charts: :hover and pointermove tooltips never fire
// on a tap. On a touch-enabled Pixel 5, a tap reveals the tooltip, it persists
// after the finger lifts, and a tap elsewhere dismisses it, while mouse hover
// keeps working.
//
// Own instance, seeded with the 90-day screenshot traffic so every chart has a
// real multi-point series.
func TestSpecChartTouch(t *testing.T) {
	server := specInstance(t, "chart-touch", chartTouchPort)
	seeded(t, server, harness.ScreenshotsSeed(harness.NowMillis()))

	// gotoStats signs in and lands on the statistics page with all three
	// charts drawn. It navigates by URL: the desktop nav strip is hidden at
	// mobile widths.
	gotoStats := func(p page) error {
		return sequence(
			p.signIn,
			func() error { return p.goTo("/stats") },
			// Wait for all three interactive charts to render real data.
			p.Loc("#timeline-chart .tl-svg").ExpectVisible,
			p.Loc("#rate-trend-chart .rate-svg").ExpectVisible,
			p.Loc("#heatmap-container .heatmap-cell").First().ExpectVisible,
		)
	}
	tapCentre := func(p page, target harness.Locator) error {
		x, y, err := target.ViewportCentre()
		if err != nil {
			return err
		}
		return p.Tap(x, y)
	}

	runCases(t, server, phone, []specCase{
		{"tapping the timeline chart shows a tooltip that persists, then dismisses", func(p page) error {
			tooltip := p.Loc("#timeline-chart .rate-tooltip")
			return sequence(
				func() error { return gotoStats(p) },
				tooltip.ExpectHidden,
				func() error { return tapCentre(p, p.Loc("#timeline-chart .tl-svg")) },
				tooltip.ExpectVisible,
				// Persists after the finger lifts.
				func() error { time.Sleep(afterLift); return nil },
				tooltip.ExpectVisible,
				// A tap outside the chart dismisses it.
				func() error { return p.Tap(outsideX, outsideY) },
				tooltip.ExpectHidden,
			)
		}},
		{"tapping the rate-trend chart shows a tooltip", func(p page) error {
			tooltip := p.Loc("#rate-trend-chart .rate-tooltip")
			return sequence(
				func() error { return gotoStats(p) },
				tooltip.ExpectHidden,
				func() error { return tapCentre(p, p.Loc("#rate-trend-chart .rate-svg")) },
				tooltip.ExpectVisible,
				func() error { return p.Tap(outsideX, outsideY) },
				tooltip.ExpectHidden,
			)
		}},
		{"tapping a heatmap cell shows its tooltip and switches between cells", func(p page) error {
			cells := p.Loc("#heatmap-container .heatmap-cell")
			// Mid-grid cells, comfortably tappable.
			first, second := cells.Nth(30), cells.Nth(60)
			return sequence(
				func() error { return gotoStats(p) },
				func() error { return tapCentre(p, first) },
				func() error { return first.ExpectClass("touch-active") },
				first.Loc(".heatmap-tooltip").ExpectVisible,
				// Another tap moves the active tooltip rather than stacking.
				func() error { return tapCentre(p, second) },
				func() error { return second.ExpectClass("touch-active") },
				func() error { return first.ExpectNotClass("touch-active") },
				// Tapping outside the heatmap dismisses it.
				func() error { return p.Tap(outsideX, outsideY) },
				func() error { return second.ExpectNotClass("touch-active") },
			)
		}},
		{"mouse hover still shows and hides the timeline tooltip", func(p page) error {
			tooltip := p.Loc("#timeline-chart .rate-tooltip")
			if err := gotoStats(p); err != nil {
				return err
			}
			box, err := p.Loc("#timeline-chart .tl-svg").ViewportRect()
			if err != nil {
				return err
			}
			return sequence(
				func() error { return p.MovePointerTo(box.X+box.Width/2, box.Y+box.Height/2) },
				tooltip.ExpectVisible,
				// Moving off the chart dismisses; no outside tap needed.
				func() error { return p.MovePointerTo(box.X+box.Width/2, box.Y-40) },
				tooltip.ExpectHidden,
			)
		}},
	})
}
