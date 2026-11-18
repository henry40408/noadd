package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/db"
)

// expectPageRebuild runs action and fails unless it starts a filter rebuild:
// a page POST that changed filtering must republish the engine.
func expectPageRebuild(t *testing.T, h *apiHarness, action func()) {
	t.Helper()
	updates, stop := h.deps.Rebuild.Subscribe()
	defer stop()
	action()
	select {
	case status := <-updates:
		if !status.Rebuilding {
			t.Fatalf("first rebuild message was not the start: %+v", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the change did not trigger a rebuild")
	}
}

func TestListImpactSaysNoImpactOnlyForAnEngineListWithoutUniqueRules(t *testing.T) {
	cases := []struct {
		name   string
		unique map[int64]uint32
		list   db.FilterListRow
		text   string
		none   bool
	}{
		{"zero", map[int64]uint32{7: 0}, db.FilterListRow{ID: 7, Enabled: true, RuleCount: 50}, "No impact", true},
		{"one", map[int64]uint32{7: 1}, db.FilterListRow{ID: 7, Enabled: true}, "1 rule", false},
		{"two", map[int64]uint32{7: 2}, db.FilterListRow{ID: 7, Enabled: true}, "2 rules", false},
		{"disabled outside the engine", nil, db.FilterListRow{ID: 7, Enabled: false, RuleCount: 50}, "Disabled", false},
		{"one rule outside the engine", nil, db.FilterListRow{ID: 7, Enabled: true, RuleCount: 1}, "No block rules", false},
		{"no rules outside the engine", nil, db.FilterListRow{ID: 7, Enabled: true, RuleCount: 0}, "No rules", false},
	}
	for _, c := range cases {
		text, none := listImpact(c.unique, c.list)
		if text != c.text || none != c.none {
			t.Errorf("%s: got %q/%v, want %q/%v", c.name, text, none, c.text, c.none)
		}
	}
}

const allDisabledWarningShown = `data-testid="filters-all-disabled-warning" class="all-disabled-warning"`

func TestFiltersPageWarnsOnlyWhenListsExistAndEveryOneIsOff(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantAbsent(t, h.pageBody("/filters"), allDisabledWarningShown)

	first, second := h.seedList("first"), h.seedList("second")
	wantAbsent(t, h.pageBody("/filters"), allDisabledWarningShown)

	if err := h.db.UpdateFilterListEnabled(ctxBackground(), first, false); err != nil {
		t.Fatal(err)
	}
	wantAbsent(t, h.pageBody("/filters"), allDisabledWarningShown)

	if err := h.db.UpdateFilterListEnabled(ctxBackground(), second, false); err != nil {
		t.Fatal(err)
	}
	wantContains(t, h.pageBody("/filters"), allDisabledWarningShown)
}

func TestFiltersPageBadgesAnAllowRuleAndABlockRuleApart(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	if _, err := h.db.AddCustomRule(ctxBackground(), "@@||fine.example^", "allow"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.AddCustomRule(ctxBackground(), "||bad.example^", "block"); err != nil {
		t.Fatal(err)
	}
	body := h.pageBody("/filters")
	wantContains(t, body, `data-type="allow"><td style="width:70px"><span class="badge badge-allowed">allow</span>`)
	wantContains(t, body, `data-type="block"><td style="width:70px"><span class="badge badge-blocked">block</span>`)
}

func TestFiltersEditFormOpensOnlyForTheListAskedFor(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	first, second := h.seedList("alpha"), h.seedList("beta")

	opened := h.pageBody("/filters?edit=" + itoa(second))
	wantContains(t, opened, `action="/filters/lists/`+itoa(second)+`/edit"`)
	wantContains(t, opened, `name="name" value="beta"`)
	wantContains(t, opened, `name="url" value="https://lists.example/beta"`)
	wantAbsent(t, opened, `action="/filters/lists/`+itoa(first)+`/edit"`)
	wantAbsent(t, opened, `value="alpha"`)

	closed := h.pageBody("/filters")
	wantAbsent(t, closed, `data-testid="list-edit-name"`)
	// Id 0 is the "nothing expanded" value, not a list to look up.
	wantAbsent(t, h.pageBody("/filters?edit=0"), `data-testid="list-edit-name"`)
}

func TestFiltersListChangesTriggerARebuild(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	id := h.seedList("mine")
	path := "/filters/lists/" + itoa(id)

	expectPageRebuild(t, h, func() {
		wantRedirect(t, h.signedIn(http.MethodPost, path+"/toggle", ""), "/filters")
	})
	h.settleRebuilds()
	expectPageRebuild(t, h, func() {
		wantRedirect(t, h.signedIn(http.MethodPost, path+"/edit", formBody("name", "renamed", "url", "https://y.example/l")), "/filters")
	})
	h.settleRebuilds()
	expectPageRebuild(t, h, func() {
		wantRedirect(t, h.signedIn(http.MethodPost, "/filters/lists/enable-recommended", ""), "/filters")
	})
	h.settleRebuilds()
	expectPageRebuild(t, h, func() {
		wantRedirect(t, h.signedIn(http.MethodPost, "/filters/lists/update", ""), "/filters")
	})
	h.settleRebuilds()
	expectPageRebuild(t, h, func() {
		wantRedirect(t, h.signedIn(http.MethodPost, path+"/delete", ""), "/filters")
	})
}

func TestFiltersRuleDeleteTriggersARebuild(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	id, err := h.db.AddCustomRule(ctxBackground(), "||ads.example^", "block")
	if err != nil {
		t.Fatal(err)
	}
	expectPageRebuild(t, h, func() {
		wantRedirect(t, h.signedIn(http.MethodPost, "/filters/rules/"+itoa(id)+"/delete", ""), "/filters")
	})
}

func TestFiltersEnableRecommendedWithNoListsJustRedirects(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantRedirect(t, h.signedIn(http.MethodPost, "/filters/lists/enable-recommended", ""), "/filters")
}

func TestFiltersEnableRecommendedFallsBackToTheFirstListWhenTheNamedOneIsAbsent(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	first, second := h.seedList("first"), h.seedList("second")
	for _, id := range []int64{first, second} {
		if err := h.db.UpdateFilterListEnabled(ctxBackground(), id, false); err != nil {
			t.Fatal(err)
		}
	}
	wantRedirect(t, h.signedIn(http.MethodPost, "/filters/lists/enable-recommended", ""), "/filters")
	for _, list := range mustLists(t, h) {
		if list.Enabled != (list.ID == first) {
			t.Fatalf("list %q enabled = %v", list.Name, list.Enabled)
		}
	}
}
