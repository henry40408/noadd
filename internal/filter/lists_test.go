package filter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/henry40408/noadd/internal/db"
)

func newManager(t *testing.T) (*db.DB, *Manager) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(ctx) })
	return database, &Manager{
		DB:         database,
		Holder:     NewHolder(New(EngineInput{})),
		Downloader: NewDownloader("noadd-test"),
	}
}

// Rust: test_seed_default_lists
func TestSeedDefaultLists(t *testing.T) {
	ctx := context.Background()
	database, manager := newManager(t)
	if err := manager.SeedDefaultLists(ctx); err != nil {
		t.Fatal(err)
	}
	lists, err := database.GetFilterLists(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != len(DefaultLists) {
		t.Fatalf("got %d lists, want %d", len(lists), len(DefaultLists))
	}
	for i, list := range lists {
		want := DefaultLists[i]
		if list.Name != want.Name || list.URL != want.URL || list.Enabled != want.Enabled {
			t.Errorf("list %d = %+v, want %+v", i, list, want)
		}
	}
}

// Rust: test_seed_default_lists_idempotent
func TestSeedDefaultListsIdempotent(t *testing.T) {
	ctx := context.Background()
	database, manager := newManager(t)
	for range 2 {
		if err := manager.SeedDefaultLists(ctx); err != nil {
			t.Fatal(err)
		}
	}
	lists, err := database.GetFilterLists(ctx)
	if err != nil || len(lists) != len(DefaultLists) {
		t.Fatalf("lists = %d, err = %v", len(lists), err)
	}
}

// Rust: test_rebuild_filter_from_custom_rules
func TestRebuildFilterFromCustomRules(t *testing.T) {
	ctx := context.Background()
	database, manager := newManager(t)
	if _, err := database.AddCustomRule(ctx, "||ads.example.com^", "block"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddCustomRule(ctx, "@@||safe.ads.example.com^", "allow"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	engine := manager.Holder.Load()
	wantBlocked(t, engine, "ads.example.com")
	wantBlocked(t, engine, "sub.ads.example.com")
	wantAllowed(t, engine, "safe.ads.example.com")
	wantAllowed(t, engine, "example.org")
	if got := engine.UniqueRulesByList(); got[CustomListID] != 1 {
		t.Errorf("custom list unique rules = %v", got)
	}
}

// Rust: test_update_all_lists_no_rebuild_does_not_rebuild
func TestUpdateAllListsNoRebuildDoesNotRebuild(t *testing.T) {
	ctx := context.Background()
	database, manager := newManager(t)
	if _, err := database.AddCustomRule(ctx, "||ads.example.com^", "block"); err != nil {
		t.Fatal(err)
	}
	wantAllowed(t, manager.Holder.Load(), "ads.example.com")

	if _, err := manager.UpdateAllListsNoRebuild(ctx); err != nil {
		t.Fatal(err)
	}
	wantAllowed(t, manager.Holder.Load(), "ads.example.com")

	if err := manager.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	wantBlocked(t, manager.Holder.Load(), "ads.example.com")
}

// Rust: test_store_list_content_reports_whether_content_changed
func TestStoreListContentReportsWhetherContentChanged(t *testing.T) {
	ctx := context.Background()
	database, manager := newManager(t)
	id, err := database.AddFilterList(ctx, "test", "https://example.invalid/list.txt", true)
	if err != nil {
		t.Fatal(err)
	}
	currentRow := func() db.FilterListRow {
		lists, err := database.GetFilterLists(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, list := range lists {
			if list.ID == id {
				return list
			}
		}
		t.Fatal("list vanished")
		return db.FilterListRow{}
	}
	store := func(content string, wantChanged bool, wantCount int64) {
		t.Helper()
		update, err := manager.StoreListContent(ctx, currentRow(), content)
		if err != nil {
			t.Fatal(err)
		}
		if update.Changed != wantChanged || update.RuleCount != wantCount {
			t.Fatalf("update = %+v, want changed=%v count=%d", update, wantChanged, wantCount)
		}
	}
	oneRule := "||ads.example.com^\n"
	store(oneRule, true, 1)
	store(oneRule, false, 1)
	store("||ads.example.com^\n||b.example.com^\n", true, 2)
}

// Not in Rust: the whole download -> store -> rebuild path, with the status
// code ignored like the Rust client does and first-list-wins priority across
// lists.
func TestUpdateAllListsDownloadsAndRebuilds(t *testing.T) {
	ctx := context.Background()
	var userAgent atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent.Store(r.Header.Get("User-Agent"))
		switch r.URL.Path {
		case "/a.txt":
			_, _ = w.Write([]byte("||ads.example^\n@@||ok.ads.example^\n"))
		case "/b.txt":
			_, _ = w.Write([]byte("||ads.example^\n||b.example^\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("||nothing.example^\n"))
		}
	}))
	t.Cleanup(server.Close)

	database, manager := newManager(t)
	for _, name := range []string{"a", "b", "gone"} {
		if _, err := database.AddFilterList(ctx, name, server.URL+"/"+name+".txt", true); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.UpdateAllLists(ctx); err != nil {
		t.Fatal(err)
	}
	if got := userAgent.Load(); got != "noadd-test" {
		t.Errorf("User-Agent = %v", got)
	}
	engine := manager.Holder.Load()
	wantVerdict(t, engine, "x.ads.example", Verdict{Blocked: true, Rule: "ads.example", List: "b"})
	wantVerdict(t, engine, "ok.ads.example", Verdict{Rule: "ok.ads.example"})
	wantBlocked(t, engine, "b.example")
	wantBlocked(t, engine, "nothing.example")
}

func TestUpdateAllListsNoRebuildSurvivesPanickingDownload(t *testing.T) {
	ctx := context.Background()
	database, manager := newManager(t)
	manager.Downloader = nil // a nil downloader panics on first use
	if _, err := database.AddFilterList(ctx, "doomed", "http://x.test/a", true); err != nil {
		t.Fatal(err)
	}
	changed, err := manager.UpdateAllListsNoRebuild(ctx)
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v, want the panic reported as a failed list only", changed, err)
	}
}

func TestDownloadRespectsSizeLimit(t *testing.T) {
	ctx := context.Background()
	const limit = 16
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size, _ := strconv.Atoi(r.URL.Query().Get("size"))
		_, _ = w.Write([]byte(strings.Repeat("a", size)))
	}))
	t.Cleanup(server.Close)
	downloader := NewDownloader("noadd-test")
	downloader.maxBytes = limit

	body, err := downloader.Fetch(ctx, server.URL+"?size=16")
	if err != nil || len(body) != limit {
		t.Fatalf("body at the limit: len %d, err %v", len(body), err)
	}
	if _, err := downloader.Fetch(ctx, server.URL+"?size=17"); err == nil {
		t.Fatal("body over the limit was accepted")
	}
}

func TestOversizedDownloadKeepsStoredList(t *testing.T) {
	ctx := context.Background()
	var oversized atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if oversized.Load() {
			_, _ = w.Write([]byte("||new.example^\n||more.example^\n"))
			return
		}
		_, _ = w.Write([]byte("||old.example^\n"))
	}))
	t.Cleanup(server.Close)
	database, manager := newManager(t)
	id, err := database.AddFilterList(ctx, "a", server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.DownloadAndUpdateList(ctx, id); err != nil {
		t.Fatal(err)
	}

	oversized.Store(true)
	manager.Downloader.maxBytes = int64(len("||old.example^\n"))
	if _, err := manager.DownloadAndUpdateList(ctx, id); err == nil {
		t.Fatal("oversized download succeeded")
	}
	stored, found, err := database.GetFilterListContent(ctx, id)
	if err != nil || !found || stored != "||old.example^\n" {
		t.Errorf("stored list = %q, found %v, err %v", stored, found, err)
	}
}
