package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// registryFixture serves a small registry and the lists it points at.
func registryFixture(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/registry.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"groups":[{"groupId":1,"groupName":"General"},{"groupId":2,"groupName":"Security lists"}],
"filters":[
{"filterId":10,"name":"Alpha","description":"ads","homepage":"https://alpha.example","downloadUrl":"%[1]s/alpha.txt","groupId":1,"deprecated":false,"timeUpdated":"x"},
{"filterId":11,"name":"Beta","description":"malware","homepage":"javascript:alert(1)","downloadUrl":"%[1]s/beta.txt","groupId":2,"deprecated":false,"timeUpdated":"x"},
{"filterId":12,"name":"Old","description":"gone","downloadUrl":"%[1]s/old.txt","groupId":1,"deprecated":true,"timeUpdated":"x"},
{"filterId":13,"name":"Broken","description":"404","downloadUrl":"%[1]s/missing.txt","groupId":1,"deprecated":false,"timeUpdated":"x"}]}`, base)
	})
	for _, name := range []string{"alpha", "beta", "old"} {
		mux.HandleFunc("/"+name+".txt", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, "||"+name+".example^\n") })
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	base = server.URL
	return server.URL + "/registry.json"
}

func TestRegistryPageFiltersByGroupSearchAndDeprecation(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{registryURL: registryFixture(t)})
	all := h.pageBody("/filters/registry")
	wantContains(t, all, "Alpha")
	wantContains(t, all, "Beta")
	wantAbsent(t, all, ">Old<")
	wantContains(t, h.pageBody("/filters/registry?deprecated=1"), ">Old<")
	byGroup := h.pageBody("/filters/registry?group=2")
	wantContains(t, byGroup, "Beta")
	wantAbsent(t, byGroup, "Alpha")
	bySearch := h.pageBody("/filters/registry?q=%20MALWARE%20")
	wantContains(t, bySearch, "Beta")
	wantAbsent(t, bySearch, "Alpha")
	// The filters survive into the form's action.
	wantContains(t, bySearch, "q=MALWARE")
	// A bad group is no group, not a 400.
	wantContains(t, h.pageBody("/filters/registry?group=x"), "Alpha")
	wantAbsent(t, all, `href="javascript:`)
}

func TestRegistryPageRendersAnOutageInsteadOfAnError(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	body := h.pageBody("/filters/registry")
	wantContains(t, body, `class="nav-item active" href="/filters"`)
}

func TestRegistryAddRedirectsWhenEverythingWasAdded(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{registryURL: registryFixture(t)})
	recorder := h.signedIn(http.MethodPost, "/filters/registry/add", "filter_id=10&filter_id=11")
	wantRedirect(t, recorder, "/filters")
	if lists := mustLists(t, h); len(lists) != 2 {
		t.Fatalf("lists = %d", len(lists))
	}
	// Added rows are shown as already added, not hidden.
	wantContains(t, h.pageBody("/filters/registry"), "Alpha")
}

func TestRegistryAddFailuresAnswer200WithTheReasons(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{registryURL: registryFixture(t)})

	none := h.signedIn(http.MethodPost, "/filters/registry/add", "")
	wantStatus(t, none, http.StatusOK)
	wantContains(t, none.Body.String(), "No lists selected")
	wantContains(t, none.Body.String(), "tick at least one list before adding")

	unknown := h.signedIn(http.MethodPost, "/filters/registry/add", "filter_id=999&filter_id=abc")
	wantStatus(t, unknown, http.StatusOK)
	wantContains(t, unknown.Body.String(), "Nothing was added")

	partial := h.signedIn(http.MethodPost, "/filters/registry/add?q=a", "filter_id=10&filter_id=13")
	wantStatus(t, partial, http.StatusOK)
	body := partial.Body.String()
	wantContains(t, body, "Broken")
	wantContains(t, body, `data-testid="registry-added"`)
	if lists := mustLists(t, h); len(lists) != 1 || lists[0].Name != "Alpha" {
		t.Fatalf("a failed list must be rolled back: %+v", lists)
	}
}

func TestRegistryAddWhenTheRegistryIsDownAnswers200(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	recorder := h.signedIn(http.MethodPost, "/filters/registry/add", "filter_id=10")
	wantStatus(t, recorder, http.StatusOK)
	wantContains(t, recorder.Body.String(), "Registry unavailable")
}

func TestRegistryHelpers(t *testing.T) {
	for name, want := range map[string]string{
		"Security lists": "security", "REGIONAL": "regional", "General": "general", "Other": "",
	} {
		if got := registryGroupClass(name); got != want {
			t.Errorf("registryGroupClass(%q) = %q, want %q", name, got, want)
		}
	}
	query := registryQueryFrom(map[string][]string{"q": {" a b&c "}, "group": {"7"}, "deprecated": {""}})
	if got := query.queryString(); got != "?q=a%20b%26c&group=7&deprecated=1" {
		t.Errorf("queryString = %q", got)
	}
	if got := registryQueryFrom(map[string][]string{"group": {"x"}}).queryString(); got != "" {
		t.Errorf("a bare view = %q", got)
	}
	if !strings.HasPrefix(registryQueryFrom(map[string][]string{"group": {"0"}}).queryString(), "?group=0") {
		t.Error("group 0 is a group, not no group")
	}
}

func TestRegistryPostsRefuseAnAnonymousBrowser(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantRedirect(t, h.page(pageRequest{method: http.MethodPost, path: "/filters/registry/add", body: "filter_id=1"}),
		"/login?next="+encodeQueryValue("/filters/registry/add"))
}
