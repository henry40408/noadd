package server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/db"
)

// pagesSeedNumbered logs count queries for d00.example, d01.example, ...,
// newest first, one millisecond apart.
func pagesSeedNumbered(h *apiHarness, count int) {
	nowMs := time.Now().UnixMilli()
	entries := make([]db.QueryLogEntry, count)
	for i := range entries {
		entries[i] = db.QueryLogEntry{
			Timestamp: nowMs - int64(i), Domain: fmt.Sprintf("d%02d.example", i),
			QueryType: "A", ClientIP: "10.0.0.5", ResponseMs: 1,
		}
	}
	h.seedLogs(entries...)
}

func TestLogsPageCountsPagesOfFiftyRows(t *testing.T) {
	cases := map[int]string{1: "Page 1 / 1", 50: "Page 1 / 1", 51: "Page 1 / 2", 100: "Page 1 / 2", 101: "Page 1 / 3"}
	for rows, want := range cases {
		t.Run(fmt.Sprint(rows), func(t *testing.T) {
			h := newAPIHarness(t, harnessOptions{})
			pagesSeedNumbered(h, rows)
			wantContains(t, h.pageBody("/logs"), want)
		})
	}
}

func TestLogsPageSecondPageHoldsTheOlderRowsOnly(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	pagesSeedNumbered(h, 60)

	first := logRows(t, h.pageBody("/logs"))
	wantContains(t, first, "d00.example")
	wantContains(t, first, "d49.example")
	wantAbsent(t, first, "d50.example")

	second := logRows(t, h.pageBody("/logs?page=2"))
	wantContains(t, second, "d50.example")
	wantContains(t, second, "d59.example")
	wantAbsent(t, second, "d49.example")
	wantAbsent(t, second, "d00.example")
}

func TestLogsPageOffersPrevAndNextOnlyWhereThereIsSomewhereToGo(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	pagesSeedNumbered(h, 120)
	const prev, next = `data-testid="logs-prev"`, `data-testid="logs-next"`

	first := h.pageBody("/logs")
	wantAbsent(t, first, prev)
	wantContains(t, first, next)
	wantContains(t, first, `href="/logs?page=2"`)

	middle := h.pageBody("/logs?page=2")
	wantContains(t, middle, prev)
	wantContains(t, middle, next)
	wantContains(t, middle, `href="/logs"`)
	wantContains(t, middle, `href="/logs?page=3"`)

	last := h.pageBody("/logs?page=3")
	wantContains(t, last, prev)
	wantAbsent(t, last, next)
}

func TestLogsPageWordsTheAgeOfARowFromItsMillisecondTimestamp(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute).UnixMilli()
	h.seedLogs(db.QueryLogEntry{Timestamp: fiveMinutesAgo, Domain: "old.example", QueryType: "A", ClientIP: "10.0.0.5", ResponseMs: 1})
	wantContains(t, logRows(t, h.pageBody("/logs")), "5 minutes ago")
}

func TestLogsPageSelectsOnlyTheQueryTypeAndTokenFilteredOn(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, token := range []string{"laptop", "phone"} {
		if _, err := h.db.AddDohToken(ctxBackground(), token); err != nil {
			t.Fatal(err)
		}
	}
	body := h.pageBody("/logs?type=MX&token=phone")
	wantContains(t, body, `<option value="MX" selected>`)
	wantAbsent(t, body, `<option value="A" selected>`)
	wantContains(t, body, `<option value="phone" selected>`)
	wantAbsent(t, body, `<option value="laptop" selected>`)

	plain := h.pageBody("/logs")
	wantAbsent(t, plain, `<option value="A" selected>`)
	wantAbsent(t, plain, `<option value="laptop" selected>`)
	wantContains(t, plain, `<option value="laptop"`)
}

func TestLogsPageFiltersToAllowedQueries(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedQueries("ads.example.com", "10.0.0.5", 2, true)
	h.seedQueries("good.example.com", "10.0.0.6", 1, false)
	rows := logRows(t, h.pageBody("/logs?action=allowed"))
	wantContains(t, rows, "good.example.com")
	wantAbsent(t, rows, "ads.example.com")
	unknown := logRows(t, h.pageBody("/logs?action=whatever"))
	wantContains(t, unknown, "ads.example.com")
	wantContains(t, unknown, "good.example.com")
}

func TestLogsRowActionIsTheOppositeOfTheVerdict(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.seedQueries("ads.example.com", "10.0.0.5", 1, true)
	h.seedQueries("good.example.com", "10.0.0.6", 1, false)
	rows := logRows(t, h.pageBody("/logs"))
	if !strings.Contains(rows, "@@||ads.example.com^") || !strings.Contains(rows, "||good.example.com^") {
		t.Errorf("rows lack the opposite-verdict rules")
	}
}
