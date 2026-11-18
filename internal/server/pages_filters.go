package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/stats"
	"github.com/henry40408/noadd/internal/views"
)

// recommendedListName is the list the "enable recommended" escape hatch picks,
// as app.js does.
const recommendedListName = "AdGuard DNS filter"

// listImpact phrases what removing one list would cost, from the engine's
// per-list counts. Distinct phrases rather than one number: only a list in the
// engine gets a count, and a zero anywhere else would falsely read as
// "redundant". Must phrase it the same as listImpact in app.js.
func listImpact(unique map[int64]uint32, list db.FilterListRow) (text string, none bool) {
	count, inEngine := unique[list.ID]
	switch {
	case inEngine && count == 0:
		return "No impact", true
	case inEngine && count == 1:
		return "1 rule", false
	case inEngine:
		return thousands(int64(count)) + " rules", false
	case !list.Enabled:
		return "Disabled", false
	// Enabled but not in the engine: its rules are all allow rules, or it has
	// none (failed download or empty parse); say which.
	case list.RuleCount > 0:
		return "No block rules", false
	default:
		return "No rules", false
	}
}

// filtersView is the page's mutable bits: what was typed, what was rejected,
// what is expanded.
type filtersView struct {
	testDomain     string
	editID         int64
	editName       string
	editURL        string
	editError      string
	listName       string
	listURL        string
	listErrorField string
	listError      string
	ruleText       string
	ruleError      string
}

func (a *api) filterListRows(r *http.Request, now int64) (rows []views.FilterList, allDisabled bool) {
	lists, _ := a.DB.GetFilterLists(r.Context())
	allDisabled = len(lists) > 0
	// From the live engine, not storage: it describes the loaded rule set, and
	// every list change already triggers the rebuild that recomputes it.
	unique := a.Filter.Load().UniqueRulesByList()
	for _, list := range lists {
		allDisabled = allDisabled && !list.Enabled
		impact, none := listImpact(unique, list)
		rows = append(rows, views.FilterList{
			ID: list.ID, Name: list.Name, URL: list.URL, Enabled: list.Enabled,
			RuleCount: thousands(list.RuleCount), RuleCountCompact: compact(list.RuleCount),
			LastUpdatedText: timeAgo(list.LastUpdated, now), LastUpdated: list.LastUpdated,
			ImpactText: impact, ImpactNone: none,
		})
	}
	return rows, allDisabled
}

func (a *api) customRuleRows(r *http.Request) []views.CustomRule {
	rules, _ := a.DB.GetAllCustomRules(r.Context())
	rows := make([]views.CustomRule, 0, len(rules))
	for _, rule := range rules {
		rows = append(rows, views.CustomRule{ID: rule.ID, Rule: rule.Rule, Type: rule.RuleType, Allow: rule.RuleType == "allow"})
	}
	return rows
}

// filtersPageFor builds the page from live storage plus whatever the caller
// carries. The navigation is forced to /filters: a rejected POST arrives on a
// sub-path and must still mark the page.
func (a *api) filtersPageFor(r *http.Request, shell views.ShellData, view filtersView) views.FiltersPage {
	shell.CurrentPath = "/filters"
	now := a.Now().Unix()
	lists, allDisabled := a.filterListRows(r, now)

	// Checked against the live engine, as POST /api/filter/check does.
	domain := strings.TrimRight(strings.TrimSpace(view.testDomain), ".")
	page := views.FiltersPage{
		Shell: shell, Lists: lists, Rules: a.customRuleRows(r), AllDisabled: allDisabled,
		TestDomain:        view.testDomain,
		DomainSuggestions: stats.DomainSuggestions(r.Context(), a.DB, now),
		Tested:            domain != "",
		EditID:            view.editID, EditName: view.editName, EditURL: view.editURL, EditError: view.editError,
		ListName: view.listName, ListURL: view.listURL,
		ListErrorField: view.listErrorField, ListError: view.listError,
		RuleText: view.ruleText, RuleError: view.ruleError,
	}
	if page.Tested {
		verdict := a.Filter.Load().Check(domain)
		page.VerdictBlocked, page.VerdictRule = verdict.Blocked, verdict.Rule
		if verdict.Blocked {
			page.VerdictList = verdict.List
		}
	}
	return page
}

func (a *api) renderFilters(w http.ResponseWriter, r *http.Request, status int, view filtersView) {
	writeHTML(w, status, views.Filters(a.filtersPageFor(r, a.shell(w, r), view)))
}

// filtersPage handles GET /filters.
func (a *api) filtersPage(w http.ResponseWriter, r *http.Request, _ authedUser) {
	query := r.URL.Query()
	// A bad edit value expands nothing rather than answering 400.
	editID, _ := strconv.ParseInt(query.Get("edit"), 10, 64)
	view := filtersView{testDomain: query.Get("test"), editID: editID}
	// Filled from storage, never the URL, so a link cannot pre-fill the form.
	if editID != 0 {
		lists, _ := a.DB.GetFilterLists(r.Context())
		for _, list := range lists {
			if list.ID == editID {
				view.editName, view.editURL = list.Name, list.URL
			}
		}
	}
	a.renderFilters(w, r, http.StatusOK, view)
}

// filtersSaved redirects back with a notice, so a refresh cannot resubmit.
func filtersSaved(w http.ResponseWriter, r *http.Request, value flash) {
	setFlash(w, value)
	redirectSeeOther(w, r, "/filters")
}

// listFailureText is the status and message a rejected list form shows.
func listFailureText(failure *listFailure) (int, string) {
	if failure.internal {
		return http.StatusInternalServerError, "Could not save — check the server log"
	}
	return http.StatusBadRequest, failure.message
}

// filtersListAddSubmit handles POST /filters/lists.
func (a *api) filtersListAddSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, "name", "url") {
		return
	}
	_, failure := a.createFilterList(r, form.Get("name"), form.Get("url"))
	if failure == nil {
		// Adding does not fetch the list, so there is nothing to rebuild yet.
		filtersSaved(w, r, flashFiltersSaved)
		return
	}
	status, message := listFailureText(failure)
	a.renderFilters(w, r, status, filtersView{
		listName: form.Get("name"), listURL: form.Get("url"),
		listErrorField: failure.field, listError: message,
	})
}

// filtersListEditSubmit handles POST /filters/lists/{id}/edit. A rejected edit
// re-renders the row expanded with the submitted values.
func (a *api) filtersListEditSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, "name", "url") {
		return
	}
	failure := a.modifyFilterList(r, id, form.Get("name"), form.Get("url"))
	if failure == nil {
		a.triggerRebuild(r)
		filtersSaved(w, r, flashFiltersSaved)
		return
	}
	status, message := listFailureText(failure)
	a.renderFilters(w, r, status, filtersView{
		editID: id, editName: form.Get("name"), editURL: form.Get("url"), editError: message,
	})
}

// filtersListToggleSubmit handles POST /filters/lists/{id}/toggle. enabled is
// absent when unticked: a browser does not post an unchecked box.
func (a *api) filtersListToggleSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	form, ok := parseForm(w, r)
	if !ok {
		return
	}
	_, enabled := form["enabled"]
	if err := a.DB.UpdateFilterListEnabled(writeCtx(r), id, enabled); err == nil {
		a.triggerRebuild(r)
	}
	filtersSaved(w, r, flashFiltersSaved)
}

// filtersListDeleteSubmit handles POST /filters/lists/{id}/delete.
func (a *api) filtersListDeleteSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.DB.DeleteFilterList(writeCtx(r), id); err == nil {
		a.triggerRebuild(r)
	}
	filtersSaved(w, r, flashFiltersSaved)
}

// filtersListsUpdateSubmit handles POST /filters/lists/update. It downloads
// every list before answering, as POST /api/lists/update does; the pending
// request is the progress indicator.
func (a *api) filtersListsUpdateSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	// Always rebuilds on success, like the API: the way out of a failed rebuild.
	if _, err := a.ListManager.UpdateAllListsNoRebuild(writeCtx(r)); err == nil {
		a.triggerRebuild(r)
	}
	filtersSaved(w, r, flashListsUpdating)
}

// filtersEnableRecommendedSubmit handles POST /filters/lists/enable-recommended:
// the escape hatch when every list is off, re-enabling one with the pick
// app.js makes.
func (a *api) filtersEnableRecommendedSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	lists, _ := a.DB.GetFilterLists(r.Context())
	if len(lists) > 0 {
		pick := lists[0]
		for _, list := range lists {
			if list.Name == recommendedListName {
				pick = list
				break
			}
		}
		if err := a.DB.UpdateFilterListEnabled(writeCtx(r), pick.ID, true); err == nil {
			a.triggerRebuild(r)
		}
	}
	filtersSaved(w, r, flashFiltersSaved)
}

// filtersRuleAddSubmit handles POST /filters/rules.
func (a *api) filtersRuleAddSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, "rule") {
		return
	}
	_, failure := a.createCustomRule(r, form.Get("rule"))
	// A duplicate is not an error: the wanted rule is there.
	if failure == 0 {
		filtersSaved(w, r, flashFiltersSaved)
		return
	}
	status, message := http.StatusBadRequest, "Not a rule noadd understands — see the syntax reference below"
	if failure != ruleUnparseable {
		status, message = http.StatusInternalServerError, "Could not save — check the server log"
	}
	a.renderFilters(w, r, status, filtersView{ruleText: form.Get("rule"), ruleError: message})
}

// filtersRuleDeleteSubmit handles POST /filters/rules/{id}/delete.
func (a *api) filtersRuleDeleteSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.DB.DeleteCustomRule(writeCtx(r), id); err == nil {
		a.triggerRebuild(r)
	}
	filtersSaved(w, r, flashFiltersSaved)
}
