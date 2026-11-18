package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const sampleJSON = `{
  "filters": [
    {
      "filterKey": "adguard_dns", "filterId": 1, "groupId": 1,
      "name": "AdGuard DNS filter", "description": "Desc 1",
      "homepage": "https://example.com/1", "deprecated": false, "tags": [1],
      "languages": [], "version": "1", "expires": 345600, "displayNumber": 1,
      "downloadUrl": "https://example.com/filter_1.txt",
      "subscriptionUrl": "https://example.com/sub_1",
      "timeAdded": "2021-01-01T00:00:00+0000", "timeUpdated": "2026-04-19T00:00:00+0000"
    }
  ],
  "groups": [ { "groupId": 1, "groupName": "General" } ],
  "tags": []
}`

func fakeRegistry(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleJSON))
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

// Rust: fetch_populates_cache
func TestFetchPopulatesCache(t *testing.T) {
	server, hits := fakeRegistry(t, http.StatusOK)
	client := NewClient(server.URL+"/filters.json", time.Hour, "ua")
	data, err := client.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Filters) != 1 || data.Filters[0].Name != "AdGuard DNS filter" ||
		data.Filters[0].DownloadURL != "https://example.com/filter_1.txt" ||
		len(data.Groups) != 1 || data.Groups[0].GroupName != "General" {
		t.Fatalf("data = %+v", data)
	}
	again, err := client.List(context.Background())
	if err != nil || again.Filters[0].Name != "AdGuard DNS filter" {
		t.Fatalf("second call = %+v, %v", again, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hit %d times, want 1", hits.Load())
	}
}

// Rust: cache_expires_after_ttl
func TestCacheExpiresAfterTTL(t *testing.T) {
	server, hits := fakeRegistry(t, http.StatusOK)
	client := NewClient(server.URL+"/filters.json", time.Millisecond, "ua")
	if _, err := client.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	data, err := client.List(context.Background())
	if err != nil || len(data.Filters) != 1 {
		t.Fatalf("second call = %+v, %v", data, err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hit %d times, want 2", hits.Load())
	}
}

// Rust: upstream_error_surfaces
func TestUpstreamErrorSurfaces(t *testing.T) {
	server, _ := fakeRegistry(t, http.StatusInternalServerError)
	client := NewClient(server.URL+"/filters.json", time.Hour, "ua")
	_, err := client.List(context.Background())
	if err == nil {
		t.Fatal("want an error")
	}
	message := strings.ToLower(err.Error())
	if !strings.Contains(message, "http") || !strings.Contains(message, "500") {
		t.Fatalf("error = %v", err)
	}
}

func TestHomepageMayBeMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"filters":[{"filterId":2,"name":"n","description":"d","downloadUrl":"u","groupId":1,"deprecated":true,"timeUpdated":"t"}],"groups":[]}`))
	}))
	t.Cleanup(server.Close)
	data, err := NewClient(server.URL, time.Hour, "ua").List(context.Background())
	if err != nil || data.Filters[0].Homepage != nil || !data.Filters[0].Deprecated {
		t.Fatalf("data = %+v, %v", data, err)
	}
}

func TestMalformedURLIsAnHTTPError(t *testing.T) {
	client := NewClient("http://[::1", time.Hour, "ua")
	_, err := client.List(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "http error:") {
		t.Fatalf("error = %v", err)
	}
}

func TestUnreachableRegistryIsAnHTTPError(t *testing.T) {
	server, _ := fakeRegistry(t, http.StatusOK)
	url := server.URL + "/filters.json"
	server.Close()
	_, err := NewClient(url, time.Hour, "ua").List(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "http error:") {
		t.Fatalf("error = %v", err)
	}
}

func TestTruncatedBodyIsAnHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte(`{"filters"`))
	}))
	t.Cleanup(server.Close)
	_, err := NewClient(server.URL, time.Hour, "ua").List(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "http error:") {
		t.Fatalf("error = %v", err)
	}
}

func TestInvalidJSONIsAParseErrorAndIsNotCached(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("not json"))
	}))
	t.Cleanup(server.Close)
	client := NewClient(server.URL, time.Hour, "ua")
	for attempt := 1; attempt <= 2; attempt++ {
		_, err := client.List(context.Background())
		if err == nil || !strings.HasPrefix(err.Error(), "parse error:") {
			t.Fatalf("attempt %d: error = %v", attempt, err)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d, want a refetch after each failure", hits.Load())
	}
}
