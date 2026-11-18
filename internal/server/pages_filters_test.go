package server

import (
	"net/http"
	"testing"

	"github.com/henry40408/noadd/internal/db"
)

func TestListImpactPhrasesEachStateDistinctly(t *testing.T) {
	unique := map[int64]uint32{1: 0, 2: 1, 3: 1234}
	cases := []struct {
		list db.FilterListRow
		text string
		none bool
	}{
		{db.FilterListRow{ID: 1, Enabled: true}, "No impact", true},
		{db.FilterListRow{ID: 2, Enabled: true}, "1 rule", false},
		{db.FilterListRow{ID: 3, Enabled: true}, "1,234 rules", false},
		{db.FilterListRow{ID: 4, Enabled: false, RuleCount: 9}, "Disabled", false},
		{db.FilterListRow{ID: 5, Enabled: true, RuleCount: 9}, "No block rules", false},
		{db.FilterListRow{ID: 6, Enabled: true}, "No rules", false},
	}
	for _, c := range cases {
		text, none := listImpact(unique, c.list)
		if text != c.text || none != c.none {
			t.Errorf("list %d: got %q/%v, want %q/%v", c.list.ID, text, none, c.text, c.none)
		}
	}
}

func (h *apiHarness) seedList(name string) int64 {
	h.t.Helper()
	id, err := h.db.AddFilterList(ctxBackground(), name, "https://lists.example/"+name, true)
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

func TestFiltersPageTestsADomainFromTheURL(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	if _, err := h.db.AddCustomRule(ctxBackground(), "||ads.example^", "block"); err != nil {
		t.Fatal(err)
	}
	if err := h.deps.ListManager.Rebuild(ctxBackground()); err != nil {
		t.Fatal(err)
	}
	blocked := h.pageBody("/filters?test=ads.example.")
	wantContains(t, blocked, `badge badge-blocked">Blocked`)
	wantContains(t, blocked, "Rule: <code")
	wantAbsent(t, h.pageBody("/filters"), `badge badge-blocked">Blocked`)
	wantContains(t, h.pageBody("/filters?test=fine.example"), `badge badge-allowed">Allowed`)
}

func TestFiltersPageExpandsAnEditFormFromStorageNotTheURL(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	id := h.seedList("mine")
	wantContains(t, h.pageBody("/filters?edit="+itoa(id)), "https://lists.example/mine")
	// A junk or unknown id is a plain page.
	h.pageBody("/filters?edit=abc")
	h.pageBody("/filters?edit=424242")
}

func TestFiltersListAddRedirectsOrReRendersWithTheFieldError(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantRedirect(t, h.signedIn(http.MethodPost, "/filters/lists", formBody("name", "n", "url", "https://x.example/l")), "/filters")
	if lists, _ := h.db.GetFilterLists(ctxBackground()); len(lists) != 1 {
		t.Fatalf("lists = %d", len(lists))
	}

	bad := h.signedIn(http.MethodPost, "/filters/lists", formBody("name", "n", "url", "ftp://x"))
	wantStatus(t, bad, http.StatusBadRequest)
	wantContains(t, bad.Body.String(), "URL must start with http:// or https://")
	wantContains(t, bad.Body.String(), "ftp://x")
	wantContains(t, bad.Body.String(), `class="nav-item active" href="/filters"`)

	blank := h.signedIn(http.MethodPost, "/filters/lists", formBody("name", " ", "url", "https://x"))
	wantStatus(t, blank, http.StatusBadRequest)
	wantContains(t, blank.Body.String(), "Name is required")
}

func TestFiltersListEditRejectionKeepsTheRowExpanded(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	id := h.seedList("mine")
	bad := h.signedIn(http.MethodPost, "/filters/lists/"+itoa(id)+"/edit", formBody("name", "renamed", "url", "nope"))
	wantStatus(t, bad, http.StatusBadRequest)
	wantContains(t, bad.Body.String(), "renamed")
	ok := h.signedIn(http.MethodPost, "/filters/lists/"+itoa(id)+"/edit", formBody("name", "renamed", "url", "https://y.example/l"))
	wantRedirect(t, ok, "/filters")
	lists, _ := h.db.GetFilterLists(ctxBackground())
	if lists[0].Name != "renamed" {
		t.Fatalf("name = %q", lists[0].Name)
	}
}

func TestFiltersToggleReadsAnAbsentBoxAsOff(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	id := h.seedList("mine")
	wantRedirect(t, h.signedIn(http.MethodPost, "/filters/lists/"+itoa(id)+"/toggle", ""), "/filters")
	if lists, _ := h.db.GetFilterLists(ctxBackground()); lists[0].Enabled {
		t.Fatal("list still enabled")
	}
	wantRedirect(t, h.signedIn(http.MethodPost, "/filters/lists/"+itoa(id)+"/toggle", "enabled=on"), "/filters")
	if lists, _ := h.db.GetFilterLists(ctxBackground()); !lists[0].Enabled {
		t.Fatal("list not re-enabled")
	}
}

func TestFiltersEnableRecommendedPrefersTheNamedListElseTheFirst(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	first := h.seedList("first")
	named := h.seedList(recommendedListName)
	for _, id := range []int64{first, named} {
		if err := h.db.UpdateFilterListEnabled(ctxBackground(), id, false); err != nil {
			t.Fatal(err)
		}
	}
	wantRedirect(t, h.signedIn(http.MethodPost, "/filters/lists/enable-recommended", ""), "/filters")
	for _, list := range mustLists(t, h) {
		if list.Enabled != (list.ID == named) {
			t.Fatalf("list %q enabled = %v", list.Name, list.Enabled)
		}
	}
}

func mustLists(t *testing.T, h *apiHarness) []db.FilterListRow {
	t.Helper()
	lists, err := h.db.GetFilterLists(ctxBackground())
	if err != nil {
		t.Fatal(err)
	}
	return lists
}

func TestFiltersListDeleteRemovesTheList(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	id := h.seedList("mine")
	wantRedirect(t, h.signedIn(http.MethodPost, "/filters/lists/"+itoa(id)+"/delete", ""), "/filters")
	if len(mustLists(t, h)) != 0 {
		t.Fatal("list not deleted")
	}
}

func TestFiltersRuleAddAcceptsADuplicateAndRejectsGibberish(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for range 2 {
		wantRedirect(t, h.signedIn(http.MethodPost, "/filters/rules", formBody("rule", "||ads.example^")), "/filters")
	}
	if rules, _ := h.db.GetAllCustomRules(ctxBackground()); len(rules) != 1 {
		t.Fatalf("rules = %d", len(rules))
	}
	bad := h.signedIn(http.MethodPost, "/filters/rules", formBody("rule", "<script>"))
	wantStatus(t, bad, http.StatusBadRequest)
	wantContains(t, bad.Body.String(), "Not a rule noadd understands")
	// The echoed value is escaped.
	wantAbsent(t, bad.Body.String(), "<script>")
}

func TestFiltersRuleDeleteRemovesTheRule(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	id, err := h.db.AddCustomRule(ctxBackground(), "||ads.example^", "block")
	if err != nil {
		t.Fatal(err)
	}
	wantRedirect(t, h.signedIn(http.MethodPost, "/filters/rules/"+itoa(id)+"/delete", ""), "/filters")
	if rules, _ := h.db.GetAllCustomRules(ctxBackground()); len(rules) != 0 {
		t.Fatal("rule not deleted")
	}
}

func TestFiltersUpdateRedirectsWithTheUpdatingNotice(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.signedIn(http.MethodPost, "/filters/lists/update", "")
	wantRedirect(t, recorder, "/filters")
	page := h.page(pageRequest{path: "/filters", cookies: append(cookiePairs(recorder), "session="+h.token)})
	wantStatus(t, page, http.StatusOK)
}

func TestFiltersPostsRefuseAnAnonymousBrowser(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, path := range []string{
		"/filters/lists", "/filters/lists/update", "/filters/lists/enable-recommended",
		"/filters/lists/1/edit", "/filters/lists/1/toggle", "/filters/lists/1/delete",
		"/filters/rules", "/filters/rules/1/delete",
	} {
		wantRedirect(t, h.page(pageRequest{method: http.MethodPost, path: path, body: "x=y"}), "/login?next="+encodeQueryValue(path))
	}
}
