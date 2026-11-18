package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pagesRegistryOf serves a registry of count lists whose downloads are
// refused, so a batch add finishes at once with one failure per list.
func pagesRegistryOf(t *testing.T, count int) string {
	t.Helper()
	var filters []string
	for id := 1; id <= count; id++ {
		filters = append(filters, fmt.Sprintf(
			`{"filterId":%d,"name":"List %d","description":"d","downloadUrl":"http://127.0.0.1:1/%d.txt","groupId":1,"deprecated":false,"timeUpdated":"x"}`,
			id, id, id))
	}
	body := `{"groups":[{"groupId":1,"groupName":"General"},{"groupId":2,"groupName":"Security"}],"filters":[` + strings.Join(filters, ",") + `]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }))
	t.Cleanup(server.Close)
	return server.URL
}

func pagesPickedIDs(count int) string {
	var pairs []string
	for id := 1; id <= count; id++ {
		pairs = append(pairs, fmt.Sprintf("filter_id=%d", id))
	}
	return strings.Join(pairs, "&")
}

func TestRegistryBatchAcceptsExactlyTheLimitAndRefusesOneMore(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{registryURL: pagesRegistryOf(t, batchAddLimit+1)})

	atLimit := h.signedIn(http.MethodPost, "/filters/registry/add", pagesPickedIDs(batchAddLimit))
	wantStatus(t, atLimit, http.StatusOK)
	wantAbsent(t, atLimit.Body.String(), "Nothing was added")
	wantContains(t, atLimit.Body.String(), "List 1")
	h.settleRebuilds()

	overLimit := h.signedIn(http.MethodPost, "/filters/registry/add", pagesPickedIDs(batchAddLimit+1))
	wantStatus(t, overLimit, http.StatusOK)
	wantContains(t, overLimit.Body.String(), "Nothing was added")
	wantContains(t, overLimit.Body.String(), "between 1 and 50 lists")
}

func TestRegistryPageSelectsOnlyTheGroupAskedFor(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{registryURL: pagesRegistryOf(t, 1)})

	picked := h.pageBody("/filters/registry?group=2")
	wantContains(t, picked, `<option value="2" selected>`)
	wantAbsent(t, picked, `<option value="1" selected>`)

	none := h.pageBody("/filters/registry")
	wantAbsent(t, none, " selected>")
	wantContains(t, none, `<option value="1"`)
}

func TestRegistryBatchRebuildsTheEngineOnceListsWereAdded(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{registryURL: pagesRegistryOf(t, 1)})
	expectPageRebuild(t, h, func() {
		wantStatus(t, h.signedIn(http.MethodPost, "/filters/registry/add", "filter_id=1"), http.StatusOK)
	})
}
