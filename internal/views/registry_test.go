package views

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

type registryFixture struct {
	Groups []struct {
		GroupID   int64  `json:"groupId"`
		GroupName string `json:"groupName"`
	} `json:"groups"`
	Filters []struct {
		FilterID    int64  `json:"filterId"`
		GroupID     int64  `json:"groupId"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Homepage    string `json:"homepage"`
		Deprecated  bool   `json:"deprecated"`
		DownloadURL string `json:"downloadUrl"`
	} `json:"filters"`
}

func loadRegistryFixture(t *testing.T) registryFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/registry-filters.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture registryFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

type registryView struct {
	query          string
	group          int64
	showDeprecated bool
	currentQuery   string
}

func groupClass(name string) string {
	lowered := strings.ToLower(name)
	for _, class := range []string{"security", "regional", "general"} {
		if strings.Contains(lowered, class) {
			return class
		}
	}
	return ""
}

// registryPageFor does what the handler will do with the fixture: filter, mark
// what is already added and resolve each group.
func registryPageFor(t *testing.T, view registryView) RegistryPage {
	fixture := loadRegistryFixture(t)
	page := RegistryPage{
		Shell: ShellData{Version: goldenVersion, Host: "127.0.0.1:19080", CurrentPath: "/filters"},
		Q:     view.query, ShowDeprecated: view.showDeprecated, CurrentQuery: view.currentQuery,
		Total: len(fixture.Filters), Limit: 50,
	}
	names := map[int64]string{}
	for _, group := range fixture.Groups {
		names[group.GroupID] = group.GroupName
		page.Groups = append(page.Groups, RegistryGroup{
			Value: strconv.FormatInt(group.GroupID, 10), Label: group.GroupName, Selected: group.GroupID == view.group,
		})
	}
	needle := strings.ToLower(view.query)
	for _, filter := range fixture.Filters {
		haystack := strings.ToLower(filter.Name + " " + filter.Description)
		if (filter.Deprecated && !view.showDeprecated) || (view.group != 0 && filter.GroupID != view.group) ||
			!strings.Contains(haystack, needle) {
			continue
		}
		page.Rows = append(page.Rows, RegistryRow{
			FilterID: filter.FilterID, GroupID: filter.GroupID, Name: filter.Name, Description: filter.Description,
			Homepage: filter.Homepage, GroupName: names[filter.GroupID], GroupClass: groupClass(names[filter.GroupID]),
			// The two default lists are the ones every database starts with.
			AlreadyAdded: filter.FilterID == 1 || filter.FilterID == 2, Deprecated: filter.Deprecated,
		})
	}
	page.Shown = len(page.Rows)
	return page
}

func TestRegistryMatchesGoldens(t *testing.T) {
	data := registryPageFor(t, registryView{})
	assertGolden(t, "registry_data", Registry(data))

	empty := registryPageFor(t, registryView{})
	empty.Shell.ShowNextStep, empty.Shell.NextStepAddr = true, "127.0.0.1:53"
	assertGolden(t, "registry_empty", Registry(empty))

	search := registryPageFor(t, registryView{query: "ad", group: 1, showDeprecated: true, currentQuery: "?q=ad&group=1&deprecated=1"})
	assertGolden(t, "registry_search", Registry(search))
}

func TestRegistryOutcomesMatchGoldens(t *testing.T) {
	none := registryPageFor(t, registryView{})
	none.Failures = []RegistryFailure{{Name: "No lists selected", Error: "tick at least one list before adding"}}
	assertGolden(t, "registry_add_none", Registry(none))

	down := RegistryPage{
		Shell:      ShellData{Version: goldenVersion, Host: "127.0.0.1:19080", CurrentPath: "/filters"},
		LoadFailed: true, Limit: 50,
	}
	down.Shell.ShowNextStep, down.Shell.NextStepAddr = true, "127.0.0.1:53"
	assertGolden(t, "registry_load_failed", Registry(down))
	down.Failures = []RegistryFailure{{Name: "Registry unavailable", Error: "could not re-read the registry to resolve the selection"}}
	assertGolden(t, "registry_add_load_failed", Registry(down))
}

// 待 Opus 審查: XSS. Registry names and descriptions come from a third party.
func TestRegistryEscapesEveryString(t *testing.T) {
	const payload = `"><script>alert(1)</script>`
	page := RegistryPage{
		Q: payload, CurrentQuery: "?q=" + payload, Limit: 50, AddedCount: 1,
		Groups:   []RegistryGroup{{Value: payload, Label: payload}},
		Rows:     []RegistryRow{{Name: payload, Description: payload, GroupName: payload, Homepage: payload}},
		Failures: []RegistryFailure{{Name: payload, Error: payload}},
	}
	if strings.Contains(Registry(page), "<script>alert") {
		t.Fatal("unescaped payload in registry output")
	}
}
