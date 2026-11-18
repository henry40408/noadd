package filter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func errorPageServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "noadd-test" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found page"))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestFetchKeepsAnErrorPageButFetchCheckedRefusesIt(t *testing.T) {
	server := errorPageServer(t)
	downloader := NewDownloader("noadd-test")

	body, err := downloader.Fetch(context.Background(), server.URL)
	if err != nil || body != "not found page" {
		t.Fatalf("Fetch = %q, %v", body, err)
	}
	_, err = downloader.FetchChecked(context.Background(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("FetchChecked error = %v, want an HTTP 404 failure", err)
	}
}

func TestFetchReportsABadURLAndAnUnreachableHost(t *testing.T) {
	downloader := NewDownloader("noadd-test")
	if _, err := downloader.Fetch(context.Background(), "http://[::1"); err == nil {
		t.Error("a malformed URL was accepted")
	}
	server := errorPageServer(t)
	url := server.URL
	server.Close()
	if _, err := downloader.Fetch(context.Background(), url); err == nil {
		t.Error("an unreachable host was accepted")
	}
}

func TestDownloadAndUpdateListIgnoresAnUnknownID(t *testing.T) {
	_, manager := newManager(t)
	update, err := manager.DownloadAndUpdateList(context.Background(), 12345)
	if err != nil || update.Changed || update.RuleCount != 0 {
		t.Fatalf("update = %+v, err = %v", update, err)
	}
}

func TestDownloadAndUpdateListReportsAFailedDownload(t *testing.T) {
	ctx := context.Background()
	database, manager := newManager(t)
	server := errorPageServer(t)
	url := server.URL
	id, err := database.AddFilterList(ctx, "gone", url, true)
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	if _, err := manager.DownloadAndUpdateList(ctx, id); err == nil {
		t.Fatal("no error for an unreachable list")
	}
}

func TestStoreListContentReportsDatabaseFailure(t *testing.T) {
	ctx := context.Background()
	database, manager := newManager(t)
	id, err := database.AddFilterList(ctx, "closed", "https://example.invalid/list.txt", true)
	if err != nil {
		t.Fatal(err)
	}
	lists, err := database.GetFilterLists(ctx)
	if err != nil || len(lists) == 0 {
		t.Fatalf("lists = %v, err = %v", lists, err)
	}
	if err := database.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.StoreListContent(ctx, lists[0], "||a.example^\n"); err == nil {
		t.Fatalf("list %d: no error from a closed database", id)
	}
	if _, err := manager.DownloadAndUpdateList(ctx, id); err == nil {
		t.Fatal("DownloadAndUpdateList: no error from a closed database")
	}
	if _, err := manager.UpdateAllListsNoRebuild(ctx); err == nil {
		t.Fatal("UpdateAllListsNoRebuild: no error from a closed database")
	}
	if err := manager.Rebuild(ctx); err == nil {
		t.Fatal("Rebuild: no error from a closed database")
	}
}
