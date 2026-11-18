package e2e

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// chartOffsets are east-positive offsets in minutes: UTC, Taipei, New York,
// India, Nepal, the Marquesas, Kiritimati and Baker Island.
var chartOffsets = []int{0, 480, -300, 330, 345, -570, 840, -720}

// The browser's chart folds (timelineFromQuarters and heatmapFromQuarters in
// app.js, over the page's UTC quarter-hour series) must equal what
// /api/stats/v2/timeline and /heatmap answer for the same tz_offset, for every
// range and for offsets either side of UTC, including half- and
// three-quarter-hour zones. The folds take the offset as an argument, so the
// machine's own zone does not matter.
//
// The seed keeps every row at least an hour clear of every window's edge, so
// the page and the API, asked seconds apart, see the same rows.
func TestSpecStatsCharts(t *testing.T) {
	server := specInstance(t, "stats-charts", statsChartsPort)
	session := seeded(t, server, harness.ChartFoldSeed(harness.NowMillis()))
	api := harness.NewAPI(server)

	cases := make([]specCase, 0, 3)
	for _, chartRange := range []string{"7d", "30d", "90d"} {
		cases = append(cases, specCase{
			fmt.Sprintf("the %s timeline and the heatmap fold to what the API answers", chartRange),
			func(p page) error {
				if err := p.open(session, "/stats?range="+chartRange); err != nil {
					return err
				}
				// Drawn from the embedded series, with no request of its own.
				if err := p.Loc("#timeline-chart .tl-svg").ExpectVisible(); err != nil {
					return err
				}
				if err := p.Loc("#heatmap-container .heatmap-cell").First().ExpectVisible(); err != nil {
					return err
				}
				folds, err := pageFolds(p)
				if err != nil {
					return err
				}
				return compareFoldsWithAPI(api, session, chartRange, folds)
			},
		})
	}
	runCases(t, server, desktop, cases)
}

// pageFolds is what the page's folds produce for each of chartOffsets.
func pageFolds(p page) ([]map[string]any, error) {
	return harness.Eval[[]map[string]any](p.Browser, fmt.Sprintf(`(() => {
		const el = document.querySelector('stats-page');
		const series = JSON.parse(el.dataset.series);
		const bucket = Number(el.dataset.bucketSecs);
		return %s.map(offset => ({
			timeline: timelineFromQuarters(series, bucket, offset),
			heatmap: heatmapFromQuarters(series, offset),
		}));
	})()`, harness.JSLiteral(chartOffsets)))
}

func compareFoldsWithAPI(api *harness.API, session, chartRange string, folds []map[string]any) error {
	if len(folds) != len(chartOffsets) {
		return fmt.Errorf("expected a fold per offset, got %d", len(folds))
	}
	for i, offset := range chartOffsets {
		timeline, err := api.GetJSONValue(session, fmt.Sprintf("/api/stats/v2/timeline?range=%s&tz_offset=%d", chartRange, offset))
		if err != nil {
			return err
		}
		heatmap, err := api.GetJSONValue(session, fmt.Sprintf("/api/stats/v2/heatmap?tz_offset=%d", offset))
		if err != nil {
			return err
		}
		if points, ok := timeline.([]any); !ok || len(points) <= 1 {
			return fmt.Errorf("the API timeline for %s is too short to compare: %v", chartRange, timeline)
		}
		if !reflect.DeepEqual(folds[i]["timeline"], timeline) {
			return fmt.Errorf("timeline %s, offset %d min:\n  page %v\n  api  %v", chartRange, offset, folds[i]["timeline"], timeline)
		}
		if !reflect.DeepEqual(folds[i]["heatmap"], sortedCells(heatmap)) {
			return fmt.Errorf("heatmap, offset %d min:\n  page %v\n  api  %v", offset, folds[i]["heatmap"], heatmap)
		}
	}
	return nil
}

// sortedCells is the API's cells in weekday-then-hour order, the fold's order,
// so the comparison does not depend on the server's ordering.
func sortedCells(cells any) any {
	list, _ := cells.([]any)
	sorted := slices.Clone(list)
	key := func(cell any) (float64, float64) {
		fields, _ := cell.(map[string]any)
		weekday, _ := fields["weekday"].(float64)
		hour, _ := fields["hour"].(float64)
		return weekday, hour
	}
	slices.SortStableFunc(sorted, func(a, b any) int {
		aDay, aHour := key(a)
		bDay, bHour := key(b)
		if aDay != bDay {
			return compareFloats(aDay, bDay)
		}
		return compareFloats(aHour, bHour)
	})
	return sorted
}

func compareFloats(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
