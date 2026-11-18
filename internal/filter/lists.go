package filter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/henry40408/noadd/internal/db"
)

// DefaultList is a list that is added on first run.
type DefaultList struct {
	Name    string
	URL     string
	Enabled bool
}

// DefaultLists are seeded into an empty database.
var DefaultLists = []DefaultList{
	{"AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", true},
	{"AdAway Default Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt", false},
}

const (
	downloadTimeout     = 60 * time.Second
	concurrentDownloads = 4
)

// Downloader fetches list bodies.
type Downloader struct {
	Client    *http.Client
	UserAgent string
}

// NewDownloader returns a downloader with the 60 s timeout lists get.
func NewDownloader(userAgent string) *Downloader {
	return &Downloader{Client: &http.Client{Timeout: downloadTimeout}, UserAgent: userAgent}
}

// Fetch returns the body at url. Like the Rust client it does not look at the
// status code: an error page becomes a list with no rules.
func (d *Downloader) Fetch(ctx context.Context, url string) (string, error) {
	return d.get(ctx, url, false)
}

// FetchChecked is Fetch that treats an HTTP error status as a failure, for a
// caller that must not store an error page as a list.
func (d *Downloader) FetchChecked(ctx context.Context, url string) (string, error) {
	return d.get(ctx, url, true)
}

func (d *Downloader) get(ctx context.Context, url string, failOnStatus bool) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", d.UserAgent)
	response, err := d.Client.Do(request)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	if failOnStatus && response.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP status %s for url (%s)", response.Status, url)
	}
	body, err := io.ReadAll(response.Body)
	return string(body), err
}

// ListUpdate is the result of refreshing one list.
type ListUpdate struct {
	RuleCount int64
	// Changed is false when the download matched what was stored.
	Changed bool
}

// Manager keeps the stored lists fresh and rebuilds the engine from them.
type Manager struct {
	DB         *db.DB
	Holder     *Holder
	Downloader *Downloader
}

// SeedDefaultLists adds the default lists to an empty database.
func (m *Manager) SeedDefaultLists(ctx context.Context) error {
	existing, err := m.DB.GetFilterLists(ctx)
	if err != nil || len(existing) > 0 {
		return err
	}
	for _, list := range DefaultLists {
		if _, err := m.DB.AddFilterList(ctx, list.Name, list.URL, list.Enabled); err != nil {
			return err
		}
	}
	return nil
}

// DownloadAndUpdateList downloads one list by id and stores it. An unknown id
// is not an error.
func (m *Manager) DownloadAndUpdateList(ctx context.Context, listID int64) (ListUpdate, error) {
	lists, err := m.DB.GetFilterLists(ctx)
	if err != nil {
		return ListUpdate{}, err
	}
	for _, list := range lists {
		if list.ID != listID {
			continue
		}
		content, err := m.Downloader.Fetch(ctx, list.URL)
		if err != nil {
			return ListUpdate{}, err
		}
		return m.StoreListContent(ctx, list, content)
	}
	return ListUpdate{}, nil
}

// StoreListContent stores freshly downloaded content. Identical content is
// not rewritten and not parsed again; only the download time moves.
func (m *Manager) StoreListContent(ctx context.Context, list db.FilterListRow, content string) (ListUpdate, error) {
	now := time.Now().Unix()
	stored, found, err := m.DB.GetFilterListContent(ctx, list.ID)
	if err != nil {
		return ListUpdate{}, err
	}
	if found && stored == content {
		if err := m.DB.UpdateFilterListStats(ctx, list.ID, now, list.RuleCount); err != nil {
			return ListUpdate{}, err
		}
		return ListUpdate{RuleCount: max(list.RuleCount, 0)}, nil
	}
	if err := m.DB.SetFilterListContent(ctx, list.ID, content); err != nil {
		return ListUpdate{}, err
	}
	ruleCount := int64(len(ParseList(content)))
	if err := m.DB.UpdateFilterListStats(ctx, list.ID, now, ruleCount); err != nil {
		return ListUpdate{}, err
	}
	return ListUpdate{RuleCount: ruleCount, Changed: true}, nil
}

// UpdateAllListsNoRebuild downloads every enabled list, at most four at a
// time, and does not rebuild the engine. It reports whether any list changed,
// that is, whether a rebuild would produce anything new.
func (m *Manager) UpdateAllListsNoRebuild(ctx context.Context) (bool, error) {
	lists, err := m.DB.GetFilterLists(ctx)
	if err != nil {
		return false, err
	}

	var (
		mu         sync.Mutex
		wg         sync.WaitGroup
		anyChanged bool
		failures   []string
	)
	slots := make(chan struct{}, concurrentDownloads)
	for _, list := range lists {
		if !list.Enabled {
			continue
		}
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			var update ListUpdate
			err := CatchPanic(func() (err error) {
				update, err = m.DownloadAndUpdateList(ctx, list.ID)
				return err
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s (%v)", list.Name, err))
				return
			}
			anyChanged = anyChanged || update.Changed
			slog.Info("updated filter list", "event", "filter.list_updated",
				"list_id", list.ID, "name", list.Name, "rule_count", update.RuleCount, "changed", update.Changed)
		}()
	}
	wg.Wait()

	if len(failures) > 0 {
		slog.Warn("some filter lists failed to update; keeping previous data for those",
			"event", "filter.list_update_failed", "failed", len(failures), "lists", strings.Join(failures, ", "))
	}
	return anyChanged, nil
}

// UpdateAllLists downloads every enabled list and rebuilds the engine.
func (m *Manager) UpdateAllLists(ctx context.Context) error {
	if _, err := m.UpdateAllListsNoRebuild(ctx); err != nil {
		return err
	}
	return m.Rebuild(ctx)
}
