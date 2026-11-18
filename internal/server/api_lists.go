package server

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/henry40408/noadd/internal/filter"
	"github.com/henry40408/noadd/internal/version"
)

const (
	// batchAddLimit is the most lists one batch may add.
	batchAddLimit       = 50
	batchAddConcurrency = 4
	// checkListTimeout bounds the reachability probe of POST /api/lists/{id}/check.
	checkListTimeout = 10 * time.Second
)

// triggerRebuild queues a filter rebuild and returns at once, so a handler
// that changes rules or lists can answer without waiting for it.
func (a *api) triggerRebuild(r *http.Request) {
	ctx := writeCtx(r)
	a.Rebuild.SpawnCoalesced(func() error { return a.ListManager.Rebuild(ctx) })
}

// filterListResponse is a list plus what removing it would unblock.
type filterListResponse struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Enabled     bool   `json:"enabled"`
	LastUpdated int64  `json:"last_updated"`
	RuleCount   int64  `json:"rule_count"`
	// UniqueRules is null when the list contributes no rules to the engine.
	UniqueRules *int64 `json:"unique_rules"`
}

// getLists handles GET /api/lists.
func (a *api) getLists(w http.ResponseWriter, r *http.Request, _ authedUser) {
	lists, err := a.DB.GetFilterLists(r.Context())
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	// From the live engine, not storage: uniqueness is a property of the
	// loaded rule set.
	unique := a.Filter.Load().UniqueRulesByList()
	response := make([]filterListResponse, 0, len(lists))
	for _, list := range lists {
		item := filterListResponse{
			ID: list.ID, Name: list.Name, URL: list.URL, Enabled: list.Enabled,
			LastUpdated: list.LastUpdated, RuleCount: list.RuleCount,
		}
		if count, found := unique[list.ID]; found {
			value := int64(count)
			item.UniqueRules = &value
		}
		response = append(response, item)
	}
	writeJSON(w, http.StatusOK, response)
}

type addListRequest struct {
	Name *string `json:"name"`
	URL  *string `json:"url"`
}

type addListResponse struct {
	ID int64 `json:"id"`
}

// listFailure is why a filter list could not be created or edited. field
// places the form's message; the JSON endpoint answers a bare status.
type listFailure struct {
	field    string
	message  string
	internal bool
}

// validateList checks a list's name and URL, for both the form and the JSON
// endpoint. The URL check is only the scheme; whether it serves a list is the
// job of the check endpoint.
func validateList(name, url string) *listFailure {
	if strings.TrimSpace(name) == "" {
		return &listFailure{field: "name", message: "Name is required"}
	}
	url = strings.TrimSpace(url)
	if url == "" {
		return &listFailure{field: "url", message: "URL is required"}
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return &listFailure{field: "url", message: "URL must start with http:// or https://"}
	}
	return nil
}

// createFilterList adds an enabled list without fetching it, so a slow remote
// does not hold the request open.
func (a *api) createFilterList(r *http.Request, name, url string) (int64, *listFailure) {
	if failure := validateList(name, url); failure != nil {
		return 0, failure
	}
	id, err := a.DB.AddFilterList(writeCtx(r), strings.TrimSpace(name), strings.TrimSpace(url), true)
	if err != nil {
		return 0, &listFailure{internal: true}
	}
	return id, nil
}

// modifyFilterList changes a list's name and URL together, validated as a pair.
func (a *api) modifyFilterList(r *http.Request, id int64, name, url string) *listFailure {
	if failure := validateList(name, url); failure != nil {
		return failure
	}
	if err := a.DB.UpdateFilterList(writeCtx(r), id, strings.TrimSpace(name), strings.TrimSpace(url)); err != nil {
		return &listFailure{internal: true}
	}
	return nil
}

// listFailureStatus is the bare status the JSON endpoints answer.
func listFailureStatus(failure *listFailure) int {
	if failure.internal {
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}

// addList handles POST /api/lists. The list is created enabled but not
// fetched, so a slow remote does not hold the request open.
func (a *api) addList(w http.ResponseWriter, r *http.Request, _ authedUser) {
	var body addListRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Name == nil {
		missingField(w, "name")
		return
	}
	if body.URL == nil {
		missingField(w, "url")
		return
	}
	id, failure := a.createFilterList(r, *body.Name, *body.URL)
	if failure != nil {
		writeStatus(w, listFailureStatus(failure))
		return
	}
	writeJSON(w, http.StatusCreated, addListResponse{ID: id})
}

type updateListRequest struct {
	Enabled *bool   `json:"enabled"`
	Name    *string `json:"name"`
	URL     *string `json:"url"`
}

// updateList handles PUT /api/lists/{id}. enabled applies on its own; name
// and URL only when both are given.
func (a *api) updateList(w http.ResponseWriter, r *http.Request, _ authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body updateListRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	ctx := writeCtx(r)
	if body.Enabled != nil {
		if err := a.DB.UpdateFilterListEnabled(ctx, id, *body.Enabled); err != nil {
			writeStatus(w, http.StatusInternalServerError)
			return
		}
	}
	if body.Name != nil && body.URL != nil {
		if failure := a.modifyFilterList(r, id, *body.Name, *body.URL); failure != nil {
			writeStatus(w, listFailureStatus(failure))
			return
		}
	}
	a.triggerRebuild(r)
	writeStatus(w, http.StatusOK)
}

// deleteList handles DELETE /api/lists/{id}.
func (a *api) deleteList(w http.ResponseWriter, r *http.Request, _ authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.DB.DeleteFilterList(writeCtx(r), id); err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	a.triggerRebuild(r)
	writeStatus(w, http.StatusOK)
}

type checkListURLRequest struct {
	URL *string `json:"url"`
}

// checkListURL handles POST /api/lists/{id}/check: fetch the list's URL (or
// the one in the body) and report what came back. It makes an outbound request
// to an operator-chosen address, like the list download itself; LAN-hosted
// lists are legitimate, so private addresses are not refused.
func (a *api) checkListURL(w http.ResponseWriter, r *http.Request, _ authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	url, ok := a.checkTargetURL(w, r, id)
	if !ok {
		return
	}
	client := &http.Client{Timeout: checkListTimeout}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "url": url})
		return
	}
	request.Header.Set("User-Agent", version.UserAgent())
	response, err := client.Do(request)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "url": url})
		return
	}
	defer func() { _ = response.Body.Close() }()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             response.StatusCode >= 200 && response.StatusCode < 300,
		"status":         response.StatusCode,
		"content_length": max(response.ContentLength, 0),
		"url":            url,
	})
}

// checkTargetURL is the URL in the body when there is one, else the stored URL
// of list id. A request without a JSON content type has no body to read.
func (a *api) checkTargetURL(w http.ResponseWriter, r *http.Request, id int64) (string, bool) {
	if r.Header.Get("Content-Type") != "" {
		var body checkListURLRequest
		if !decodeJSON(w, r, &body) {
			return "", false
		}
		if body.URL != nil {
			return *body.URL, true
		}
	}
	url, found, err := a.DB.FilterListURL(r.Context(), id)
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return "", false
	}
	if !found {
		writeStatus(w, http.StatusNotFound)
		return "", false
	}
	return url, true
}

type listUpdateResponse struct {
	Message string `json:"message"`
}

// triggerListUpdate handles POST /api/lists/update. It always rebuilds, unlike
// the daily refresh, because it is how an operator recovers from a failed
// rebuild.
func (a *api) triggerListUpdate(w http.ResponseWriter, r *http.Request, _ authedUser) {
	if _, err := a.ListManager.UpdateAllListsNoRebuild(writeCtx(r)); err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	a.triggerRebuild(r)
	writeJSON(w, http.StatusOK, listUpdateResponse{Message: "All lists downloaded; rebuild in progress"})
}

type batchAddRequest struct {
	Items *[]batchAddItem `json:"items"`
}

type batchAddItem struct {
	Name *string `json:"name"`
	URL  *string `json:"url"`
}

type batchAddedEntry struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	RuleCount int64  `json:"rule_count"`
}

type batchFailedEntry struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Error string `json:"error"`
}

type batchAddResponse struct {
	Added  []batchAddedEntry  `json:"added"`
	Failed []batchFailedEntry `json:"failed"`
}

// batchAddLists handles POST /api/lists/batch.
func (a *api) batchAddLists(w http.ResponseWriter, r *http.Request, _ authedUser) {
	var body batchAddRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Items == nil {
		missingField(w, "items")
		return
	}
	items := make([]batchAddItem, 0, len(*body.Items))
	for _, item := range *body.Items {
		if item.Name == nil || item.URL == nil {
			missingField(w, missingItemField(item))
			return
		}
		items = append(items, item)
	}
	if len(items) == 0 || len(items) > batchAddLimit {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, a.addListsBatch(writeCtx(r), items))
	a.triggerRebuild(r)
}

// addListsBatch downloads each list, four at a time, and rolls back the ones
// that fail. Results keep the order of the request.
func (a *api) addListsBatch(ctx context.Context, items []batchAddItem) batchAddResponse {
	outcomes := make([]batchOutcome, len(items))
	slots := make(chan struct{}, batchAddConcurrency)
	var wg sync.WaitGroup
	for i, item := range items {
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			outcomes[i] = a.addOneList(ctx, strings.TrimSpace(*item.Name), strings.TrimSpace(*item.URL))
		}()
	}
	wg.Wait()

	response := batchAddResponse{Added: []batchAddedEntry{}, Failed: []batchFailedEntry{}}
	for _, outcome := range outcomes {
		if outcome.failed != nil {
			response.Failed = append(response.Failed, *outcome.failed)
			continue
		}
		response.Added = append(response.Added, *outcome.added)
	}
	return response
}

type batchOutcome struct {
	added  *batchAddedEntry
	failed *batchFailedEntry
}

// addOneList inserts, downloads and stores one list; any failure after the
// insert deletes the row again.
func (a *api) addOneList(ctx context.Context, name, url string) batchOutcome {
	fail := func(err error) batchOutcome {
		return batchOutcome{failed: &batchFailedEntry{Name: name, URL: url, Error: err.Error()}}
	}
	id, err := a.DB.AddFilterList(ctx, name, url, true)
	if err != nil {
		return fail(err)
	}
	rollback := func(cause error) batchOutcome {
		_ = a.DB.DeleteFilterList(ctx, id)
		return fail(cause)
	}
	content, err := a.ListManager.Downloader.FetchChecked(ctx, url)
	if err != nil {
		return rollback(err)
	}
	ruleCount := int64(len(filter.ParseList(content)))
	if err := a.DB.SetFilterListContent(ctx, id, content); err != nil {
		return rollback(err)
	}
	_ = a.DB.UpdateFilterListStats(ctx, id, time.Now().Unix(), ruleCount)
	return batchOutcome{added: &batchAddedEntry{ID: id, Name: name, URL: url, RuleCount: ruleCount}}
}

// getRegistryFilters handles GET /api/registry/filters.
func (a *api) getRegistryFilters(w http.ResponseWriter, r *http.Request, _ authedUser) {
	data, err := a.Registry.List(r.Context())
	if err != nil {
		a.log.Warn("registry fetch failed", "event", "registry.fetch_failed", "error", err)
		writeStatus(w, http.StatusBadGateway)
		return
	}
	data.Filters = nonNil(data.Filters)
	data.Groups = nonNil(data.Groups)
	writeJSON(w, http.StatusOK, data)
}

func missingItemField(item batchAddItem) string {
	if item.Name == nil {
		return "name"
	}
	return "url"
}
