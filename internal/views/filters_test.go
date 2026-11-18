package views

import (
	"strings"
	"testing"
)

func filtersShell() ShellData {
	return ShellData{Version: goldenVersion, Host: "127.0.0.1:19080", CurrentPath: "/filters"}
}

const recommendedURL = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_"

func emptyFilters() FiltersPage {
	shell := filtersShell()
	shell.ShowNextStep, shell.NextStepAddr = true, "127.0.0.1:53"
	return FiltersPage{
		Shell: shell,
		Lists: []FilterList{
			{ID: 1, Name: "AdGuard DNS filter", URL: recommendedURL + "1.txt", Enabled: true, RuleCount: "0", RuleCountCompact: "0", LastUpdatedText: "never", ImpactText: "No rules"},
			{ID: 2, Name: "AdAway Default Blocklist", URL: recommendedURL + "2.txt", RuleCount: "0", RuleCountCompact: "0", LastUpdatedText: "never", ImpactText: "Disabled"},
		},
	}
}

func dataFilters() FiltersPage {
	disabled := func(id int64, name, url string) FilterList {
		return FilterList{ID: id, Name: name, URL: url, RuleCount: "0", RuleCountCompact: "0", LastUpdatedText: "never", ImpactText: "Disabled"}
	}
	const host = "http://host.docker.internal:18091/"
	page := FiltersPage{
		Shell: filtersShell(),
		Lists: []FilterList{
			disabled(1, "AdGuard DNS filter", recommendedURL+"1.txt"),
			disabled(2, "AdAway Default Blocklist", recommendedURL+"2.txt"),
			{ID: 3, Name: "list one", URL: host + "one.txt", Enabled: true, RuleCount: "3", RuleCountCompact: "3", LastUpdatedText: "2 minutes ago", LastUpdated: 1, ImpactText: "3 rules"},
			{ID: 4, Name: "list two", URL: host + "two.txt", Enabled: true, RuleCount: "3", RuleCountCompact: "3", LastUpdatedText: "2 minutes ago", LastUpdated: 1, ImpactText: "2 rules"},
			disabled(5, "list three", host+"three.txt"),
		},
		Rules: []CustomRule{
			{ID: 1, Rule: "ads.example.com", Type: "block"},
			{ID: 2, Rule: "@@||ok.ads.example.com^", Type: "allow", Allow: true},
			{ID: 3, Rule: "||tracker.example.net^", Type: "block"},
		},
		DomainSuggestions: []string{
			"allowed.example.com", "ads.example.com", "ads.list-one.test", "adserver.list-two.test",
			"cname.example.com", "dnssec.example.com", "nodata.example.com", "nxd.example.com",
			"ok.ads.example.com", "ok.list-two.test", "telemetry.list-one.test", "tracker.example.net",
		},
	}
	return page
}

func TestFiltersMatchGoldens(t *testing.T) {
	assertGolden(t, "filters_empty", Filters(emptyFilters()))
	assertGolden(t, "filters_data", Filters(dataFilters()))

	edit := dataFilters()
	edit.EditID, edit.EditName, edit.EditURL = 3, "list one", "http://host.docker.internal:18091/one.txt"
	assertGolden(t, "filters_edit", Filters(edit))

	editError := dataFilters()
	editError.EditID, editError.EditURL, editError.EditError = 3, "ftp://bad", "Name is required"
	assertGolden(t, "filters_edit_error", Filters(editError))
}

func TestFiltersFormErrorsMatchGoldens(t *testing.T) {
	list := dataFilters()
	list.ListName, list.ListURL = "x", "ftp://bad"
	list.ListError, list.ListErrorField = "URL must start with http:// or https://", "url"
	assertGolden(t, "filters_add_list_error", Filters(list))

	rule := dataFilters()
	rule.RuleError = "Not a rule noadd understands — see the syntax reference below"
	assertGolden(t, "filters_add_rule_error", Filters(rule))
}

func TestFiltersVerdictsMatchGoldens(t *testing.T) {
	blocked := dataFilters()
	blocked.TestDomain, blocked.Tested, blocked.VerdictBlocked = "ads.example.com", true, true
	blocked.VerdictRule, blocked.VerdictList = "ads.example.com", "Custom"
	assertGolden(t, "filters_test_blocked", Filters(blocked))

	allowed := dataFilters()
	allowed.TestDomain, allowed.Tested, allowed.VerdictRule = "ok.ads.example.com", true, "ok.ads.example.com"
	assertGolden(t, "filters_test_allowed", Filters(allowed))

	none := dataFilters()
	none.TestDomain, none.Tested = "example.org", true
	assertGolden(t, "filters_test_none", Filters(none))
}

// 待 Opus 審查: XSS. List names, URLs, rules and the tested domain all come
// from operator input or from a downloaded list.
func TestFiltersEscapeEveryString(t *testing.T) {
	const payload = `"><img src=x onerror=alert(1)>`
	page := dataFilters()
	page.Lists = []FilterList{{ID: 1, Name: payload, URL: payload, RuleCount: payload, RuleCountCompact: payload, LastUpdatedText: payload, ImpactText: payload}}
	page.Rules = []CustomRule{{ID: 1, Rule: payload, Type: payload}}
	page.TestDomain, page.Tested, page.VerdictBlocked = payload, true, true
	page.VerdictRule, page.VerdictList = payload, payload
	page.DomainSuggestions = []string{payload}
	page.EditID, page.EditName, page.EditURL, page.EditError = 1, payload, payload, payload
	page.ListName, page.ListURL, page.ListError, page.ListErrorField = payload, payload, payload, payload
	page.RuleText, page.RuleError = payload, payload
	if strings.Contains(Filters(page), "<img") {
		t.Fatal("unescaped payload in filters output")
	}
}
