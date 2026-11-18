package stats

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"slices"
	"testing"

	"github.com/henry40408/noadd/internal/db"
)

func openDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "stats.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	return database
}

func logFor(domain string, ms int64) db.QueryLogEntry {
	return db.QueryLogEntry{
		Timestamp: ms, Domain: domain, QueryType: "A", ClientIP: "127.0.0.1", ResponseMs: 1,
	}
}

func retentionOf(t *testing.T, database *db.DB) *int64 {
	t.Helper()
	health, err := ComputeDBHealth(context.Background(), database, 0)
	if err != nil {
		t.Fatal(err)
	}
	return health.LogRetentionDays
}

func TestDBHealthRetentionDefaultsWhenSettingAbsent(t *testing.T) {
	got := retentionOf(t, openDB(t))
	if got == nil || *got != DefaultLogRetentionDays {
		t.Fatalf("retention = %v", got)
	}
}

func TestDBHealthRetentionReflectsConfiguredSetting(t *testing.T) {
	database := openDB(t)
	if err := database.SetSetting(context.Background(), "log_retention_days", "30"); err != nil {
		t.Fatal(err)
	}
	if got := retentionOf(t, database); got == nil || *got != 30 {
		t.Fatalf("retention = %v", got)
	}
}

func TestDBHealthRetentionDefaultsWhenSettingUnparseable(t *testing.T) {
	database := openDB(t)
	if err := database.SetSetting(context.Background(), "log_retention_days", "not-a-number"); err != nil {
		t.Fatal(err)
	}
	if got := retentionOf(t, database); got == nil || *got != DefaultLogRetentionDays {
		t.Fatalf("retention = %v", got)
	}
}

// The save accepts anything, so each suggestion must read back as itself
// rather than collapsing to the default.
func TestLogRetentionSuggestionsAreUsable(t *testing.T) {
	if !slices.Contains(LogRetentionDaysSuggestions, DefaultLogRetentionDays) {
		t.Fatal("default retention is not among the suggestions")
	}
	if !slices.IsSorted(LogRetentionDaysSuggestions) {
		t.Fatal("a datalist renders in document order, so the suggestions must ascend")
	}
	database := openDB(t)
	for _, days := range LogRetentionDaysSuggestions {
		if days <= 0 {
			t.Fatalf("retention of %d days would keep nothing", days)
		}
		if err := database.SetSetting(context.Background(), "log_retention_days", fmt.Sprint(days)); err != nil {
			t.Fatal(err)
		}
		if got := retentionOf(t, database); got == nil || *got != days {
			t.Fatalf("suggestion %d read back as %v", days, got)
		}
	}
}

func TestDBHealthDerivedFieldsZeroOnEmptyDB(t *testing.T) {
	health, err := ComputeDBHealth(context.Background(), openDB(t), 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if health.BytesPerLog != 0 || health.LogCoverageDays != 0 || health.ProjectedFullBytes != 0 {
		t.Fatalf("health = %+v", health)
	}
}

func TestDBHealthDerivedFieldsReflectLoggedSpan(t *testing.T) {
	database := openDB(t)
	const dayMs = 86_400_000
	err := database.InsertQueryLogs(context.Background(),
		[]db.QueryLogEntry{logFor("example.com", dayMs), logFor("example.com", 4*dayMs)})
	if err != nil {
		t.Fatal(err)
	}
	health, err := ComputeDBHealth(context.Background(), database, 5*86_400)
	if err != nil {
		t.Fatal(err)
	}
	if health.BytesPerLog <= 0 {
		t.Fatal("bytes per log not positive")
	}
	if math.Abs(health.LogCoverageDays-3) > 1e-6 {
		t.Fatalf("coverage = %v, want 3", health.LogCoverageDays)
	}
	if health.ProjectedFullBytes <= 0 {
		t.Fatal("projection not positive")
	}
}

func TestDomainSuggestionsOrderedByFrequency(t *testing.T) {
	database := openDB(t)
	const now = 10 * 86_400
	recentMs := int64(now-3600) * 1000
	logs := []db.QueryLogEntry{logFor("rare.example", recentMs)}
	for range 5 {
		logs = append(logs, logFor("common.example", recentMs))
	}
	for range 3 {
		logs = append(logs, logFor("middling.example", recentMs))
	}
	if err := database.InsertQueryLogs(context.Background(), logs); err != nil {
		t.Fatal(err)
	}
	got := DomainSuggestions(context.Background(), database, now)
	want := []string{"common.example", "middling.example", "rare.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDomainSuggestionsSpanAWeekButNoFurther(t *testing.T) {
	database := openDB(t)
	const now = 30 * 86_400
	err := database.InsertQueryLogs(context.Background(), []db.QueryLogEntry{
		logFor("within.example", int64(now-6*86_400)*1000),
		logFor("expired.example", int64(now-8*86_400)*1000),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := DomainSuggestions(context.Background(), database, now)
	if !slices.Equal(got, []string{"within.example"}) {
		t.Fatalf("got %v", got)
	}
}

func TestDomainSuggestionsEmptyWhenNothingQueried(t *testing.T) {
	if got := DomainSuggestions(context.Background(), openDB(t), 10*86_400); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestDomainSuggestionsStayAShortlist(t *testing.T) {
	database := openDB(t)
	const now = 10 * 86_400
	var logs []db.QueryLogEntry
	for i := range domainSuggestionLimit + 10 {
		logs = append(logs, logFor(fmt.Sprintf("d%d.example", i), int64(now-3600)*1000))
	}
	if err := database.InsertQueryLogs(context.Background(), logs); err != nil {
		t.Fatal(err)
	}
	if got := DomainSuggestions(context.Background(), database, now); len(got) != domainSuggestionLimit {
		t.Fatalf("len = %d", len(got))
	}
}

func TestTimelineBucketSecsRoundsToCleanIntervals(t *testing.T) {
	cases := map[int64]int64{1: 60, 48 * 60: 60, 48*60 + 48: 300, 48 * 300: 300, 48 * 600: 600, 48 * 1800: 1800, 48*1800 + 48: 3600}
	for rangeSecs, want := range cases {
		if got := timelineBucketSecs(rangeSecs); got != want {
			t.Errorf("range %d: bucket %d, want %d", rangeSecs, got, want)
		}
	}
}
