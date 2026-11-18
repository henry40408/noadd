package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/henry40408/noadd/internal/registry"
	"github.com/henry40408/noadd/internal/views"
)

// registryQuery is the registry page's three filters, all in the URL.
type registryQuery struct {
	search         string
	groupID        int64
	hasGroup       bool
	showDeprecated bool
}

// registryQueryFrom reads the filters leniently: a bad group means no group.
func registryQueryFrom(query url.Values) registryQuery {
	filters := registryQuery{search: strings.TrimSpace(query.Get("q")), showDeprecated: query.Has("deprecated")}
	if id, err := strconv.ParseInt(query.Get("group"), 10, 64); err == nil {
		filters.groupID, filters.hasGroup = id, true
	}
	return filters
}

// queryString returns to this exact view, for the form the page posts to and
// for the link back from a failure.
func (q registryQuery) queryString() string {
	var parts []string
	if q.search != "" {
		parts = append(parts, "q="+encodeQueryValue(q.search))
	}
	if q.hasGroup {
		parts = append(parts, "group="+strconv.FormatInt(q.groupID, 10))
	}
	if q.showDeprecated {
		parts = append(parts, "deprecated=1")
	}
	if len(parts) == 0 {
		return ""
	}
	return "?" + strings.Join(parts, "&")
}

// registryGroupClass picks a group pill's colour class from its name.
func registryGroupClass(groupName string) string {
	lowered := strings.ToLower(groupName)
	for _, class := range []string{"security", "regional", "general"} {
		if strings.Contains(lowered, class) {
			return class
		}
	}
	return ""
}

// registryBatchOutcome is what a batch add left to report; the zero value is a
// plain GET.
type registryBatchOutcome struct {
	addedCount int
	failures   []views.RegistryFailure
}

func registryGroupOptions(groups []registry.Group, selected registryQuery) []views.RegistryGroup {
	options := make([]views.RegistryGroup, 0, len(groups))
	for _, group := range groups {
		options = append(options, views.RegistryGroup{
			Value: strconv.FormatInt(group.GroupID, 10), Label: group.GroupName,
			Selected: selected.hasGroup && selected.groupID == group.GroupID,
		})
	}
	return options
}

func (q registryQuery) admits(filter registry.Filter) bool {
	if filter.Deprecated && !q.showDeprecated {
		return false
	}
	if q.hasGroup && filter.GroupID != q.groupID {
		return false
	}
	needle := strings.ToLower(q.search)
	return needle == "" || strings.Contains(strings.ToLower(filter.Name+" "+filter.Description), needle)
}

func (a *api) registryRows(r *http.Request, data registry.Data, q registryQuery) []views.RegistryRow {
	// What the operator already has, so a row is not offered twice.
	existing := map[string]bool{}
	lists, _ := a.DB.GetFilterLists(r.Context())
	for _, list := range lists {
		existing[list.URL] = true
	}
	groupNames := map[int64]string{}
	for _, group := range data.Groups {
		groupNames[group.GroupID] = group.GroupName
	}
	rows := make([]views.RegistryRow, 0, len(data.Filters))
	for _, filter := range data.Filters {
		if !q.admits(filter) {
			continue
		}
		groupName := groupNames[filter.GroupID]
		homepage := ""
		if filter.Homepage != nil {
			homepage = safeURL(*filter.Homepage)
		}
		rows = append(rows, views.RegistryRow{
			FilterID: filter.FilterID, GroupID: filter.GroupID, Name: filter.Name, Description: filter.Description,
			Homepage: homepage, GroupName: groupName, GroupClass: registryGroupClass(groupName),
			AlreadyAdded: existing[filter.DownloadURL], Deprecated: filter.Deprecated,
		})
	}
	return rows
}

// registryPageFor builds the page for this view, whatever brought the operator
// to it. The registry is a third party, so a failed fetch is a rendered state.
func (a *api) registryPageFor(r *http.Request, shell views.ShellData, q registryQuery, outcome registryBatchOutcome) views.RegistryPage {
	page := views.RegistryPage{
		Shell: shell, Q: q.search, ShowDeprecated: q.showDeprecated, CurrentQuery: q.queryString(),
		AddedCount: outcome.addedCount, Failures: outcome.failures, Limit: batchAddLimit,
	}
	data, err := a.Registry.List(r.Context())
	if err != nil {
		page.LoadFailed = true
		return page
	}
	page.Groups = registryGroupOptions(data.Groups, q)
	page.Total = len(data.Filters)
	page.Rows = a.registryRows(r, data, q)
	page.Shown = len(page.Rows)
	return page
}

// registryPage handles GET /filters/registry. It is reached from the filters
// page, so the navigation keeps marking Filters.
func (a *api) registryPage(w http.ResponseWriter, r *http.Request, _ authedUser) {
	shell := a.shellFor(w, r, "/filters")
	writeHTML(w, http.StatusOK, views.Registry(a.registryPageFor(r, shell, registryQueryFrom(r.URL.Query()), registryBatchOutcome{})))
}

func oneFailure(name, message string) registryBatchOutcome {
	return registryBatchOutcome{failures: []views.RegistryFailure{{Name: name, Error: message}}}
}

// pickedFilterIDs reads one filter_id per ticked box, ignoring non-numbers.
func pickedFilterIDs(form url.Values) map[int64]bool {
	picked := map[int64]bool{}
	for _, raw := range form["filter_id"] {
		if id, err := strconv.ParseInt(raw, 10, 64); err == nil {
			picked[id] = true
		}
	}
	return picked
}

// addPickedLists adds the ticked registry lists. ok is true only when every
// one was added; otherwise outcome says what to render. Names and URLs come
// from the registry, not the form: the server decides what an id means.
func (a *api) addPickedLists(r *http.Request, picked map[int64]bool) (outcome registryBatchOutcome, ok bool) {
	if len(picked) == 0 {
		return oneFailure("No lists selected", "tick at least one list before adding"), false
	}
	data, err := a.Registry.List(r.Context())
	if err != nil {
		return oneFailure("Registry unavailable", "could not re-read the registry to resolve the selection"), false
	}
	var items []batchAddItem
	for _, filter := range data.Filters {
		if picked[filter.FilterID] {
			items = append(items, batchAddItem{Name: &filter.Name, URL: &filter.DownloadURL})
		}
	}
	if len(items) == 0 || len(items) > batchAddLimit {
		return oneFailure("Nothing was added",
			fmt.Sprintf("a batch must have between 1 and %d lists in it", batchAddLimit)), false
	}
	result := a.addListsBatch(writeCtx(r), items)
	a.triggerRebuild(r)
	if len(result.Failed) == 0 {
		return registryBatchOutcome{}, true
	}
	// Partial failure renders: a redirect would lose the reasons.
	outcome.addedCount = len(result.Added)
	for _, failed := range result.Failed {
		outcome.failures = append(outcome.failures, views.RegistryFailure{Name: failed.Name, Error: failed.Error})
	}
	return outcome, false
}

// registryAddSubmit handles POST /filters/registry/add: add every ticked list.
// A failure answers 200 with the page, not an error status, as the Rust
// handler does.
func (a *api) registryAddSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	form, ok := parseForm(w, r)
	if !ok {
		return
	}
	outcome, added := a.addPickedLists(r, pickedFilterIDs(form))
	if added {
		// All added: redirect, so a refresh cannot add them twice.
		filtersSaved(w, r, flashFiltersSaved)
		return
	}
	shell := a.shellFor(w, r, "/filters")
	writeHTML(w, http.StatusOK, views.Registry(a.registryPageFor(r, shell, registryQueryFrom(r.URL.Query()), outcome)))
}
