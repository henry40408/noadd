package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/cache"
	"github.com/henry40408/noadd/internal/dns"
	"github.com/henry40408/noadd/internal/upstream"
)

// listServer serves three fixed paths: two lists and a 404.
func listServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/one.txt":
			_, _ = w.Write([]byte("0.0.0.0 ads.list-one.test\n0.0.0.0 shared.test\n||track.one.test^\n"))
		case "/two.txt":
			_, _ = w.Write([]byte("0.0.0.0 shared.test\n0.0.0.0 only-two.test\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestListsRequireAnOperator(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, route := range [][2]string{
		{"GET", "/api/lists"}, {"POST", "/api/lists"}, {"POST", "/api/lists/batch"},
		{"POST", "/api/lists/update"}, {"PUT", "/api/lists/1"}, {"DELETE", "/api/lists/1"},
		{"POST", "/api/lists/1/check"}, {"GET", "/api/registry/filters"},
		{"GET", "/api/rules"}, {"POST", "/api/rules"}, {"DELETE", "/api/rules/1"},
		{"GET", "/api/settings"}, {"PUT", "/api/settings"}, {"POST", "/api/filter/check"},
		{"GET", "/api/upstream/health"}, {"GET", "/api/upstream/latency"},
	} {
		recorder := h.do(request{method: route[0], path: route[1], body: `{}`})
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", route[0], route[1], recorder.Code)
		}
	}
}

func TestAddListValidatesNameAndScheme(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, body := range []string{
		`{"name":"","url":"http://x.test/a"}`,
		`{"name":"  ","url":"http://x.test/a"}`,
		`{"name":"a","url":"ftp://x.test/a"}`,
		`{"name":"a","url":"HTTP://x.test/a"}`,
		`{"name":"a","url":""}`,
	} {
		wantStatus(t, h.authed("POST", "/api/lists", body), http.StatusBadRequest)
	}
	wantStatus(t, h.authed("POST", "/api/lists", `{"name":"a"}`), http.StatusUnprocessableEntity)
	recorder := h.authed("POST", "/api/lists", `{"name":" one ","url":" http://x.test/a "}`)
	wantStatus(t, recorder, http.StatusCreated)
	var created addListResponse
	decodeBody(t, recorder, &created)
	lists := h.listsJSON()
	last := lists[len(lists)-1]
	if last.ID != created.ID || last.Name != "one" || last.URL != "http://x.test/a" || !last.Enabled {
		t.Fatalf("stored list = %+v", last)
	}
}

func (h *apiHarness) listsJSON() []filterListResponse {
	h.t.Helper()
	recorder := h.authed("GET", "/api/lists", "")
	wantStatus(h.t, recorder, http.StatusOK)
	var lists []filterListResponse
	decodeBody(h.t, recorder, &lists)
	return lists
}

func TestUpdateListEnabledNameAndURL(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	id := h.addList("one", "http://x.test/one")
	wantStatus(t, h.authed("PUT", fmt.Sprintf("/api/lists/%d", id), `{"enabled":false}`), http.StatusOK)
	// name alone is ignored: it only applies together with url.
	wantStatus(t, h.authed("PUT", fmt.Sprintf("/api/lists/%d", id), `{"name":"renamed"}`), http.StatusOK)
	if list := h.listByID(id); list.Enabled || list.Name != "one" {
		t.Fatalf("list = %+v", list)
	}
	wantStatus(t, h.authed("PUT", fmt.Sprintf("/api/lists/%d", id), `{"name":"renamed","url":"ftp://bad"}`), http.StatusBadRequest)
	wantStatus(t, h.authed("PUT", fmt.Sprintf("/api/lists/%d", id), `{"name":"renamed","url":"https://x.test/two"}`), http.StatusOK)
	if list := h.listByID(id); list.Name != "renamed" || list.URL != "https://x.test/two" {
		t.Fatalf("list = %+v", list)
	}
	wantStatus(t, h.authed("PUT", "/api/lists/abc", `{}`), http.StatusBadRequest)
}

func (h *apiHarness) addList(name, url string) int64 {
	h.t.Helper()
	recorder := h.authed("POST", "/api/lists", fmt.Sprintf(`{"name":%q,"url":%q}`, name, url))
	wantStatus(h.t, recorder, http.StatusCreated)
	var created addListResponse
	decodeBody(h.t, recorder, &created)
	return created.ID
}

func (h *apiHarness) listByID(id int64) filterListResponse {
	h.t.Helper()
	for _, list := range h.listsJSON() {
		if list.ID == id {
			return list
		}
	}
	h.t.Fatalf("no list %d", id)
	return filterListResponse{}
}

func TestDeleteListIsIdempotent(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	id := h.addList("one", "http://x.test/one")
	wantStatus(t, h.authed("DELETE", fmt.Sprintf("/api/lists/%d", id), ""), http.StatusOK)
	wantStatus(t, h.authed("DELETE", fmt.Sprintf("/api/lists/%d", id), ""), http.StatusOK)
	if len(h.listsJSON()) != 0 {
		t.Fatal("list not deleted")
	}
}

func TestTriggerListUpdateDownloadsRebuildsAndReportsUniqueRules(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	server := listServer(t)
	one := h.addList("list one", server.URL+"/one.txt")
	two := h.addList("list two", server.URL+"/two.txt")

	recorder := h.authed("POST", "/api/lists/update", "")
	wantStatus(t, recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), "All lists downloaded; rebuild in progress") {
		t.Fatalf("body %q", recorder.Body.String())
	}
	h.eventually(func() bool { return h.listByID(one).UniqueRules != nil })

	first, second := h.listByID(one), h.listByID(two)
	if first.RuleCount != 3 || second.RuleCount != 2 || first.LastUpdated == 0 {
		t.Fatalf("lists = %+v %+v", first, second)
	}
	if first.UniqueRules == nil || *first.UniqueRules != 2 || second.UniqueRules == nil || *second.UniqueRules != 1 {
		t.Fatalf("unique rules = %v %v", first.UniqueRules, second.UniqueRules)
	}
}

func TestDisabledListHasNullUniqueRules(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	h.addList("never fetched", "http://x.test/a")
	if !strings.Contains(h.authed("GET", "/api/lists", "").Body.String(), `"unique_rules":null`) {
		t.Fatal("unique_rules should be null")
	}
}

func TestBatchAddKeepsGoodListsAndRollsBackBadOnes(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	server := listServer(t)
	body := fmt.Sprintf(`{"items":[
		{"name":" one ","url":%q},
		{"name":"missing","url":%q},
		{"name":"two","url":%q}]}`, server.URL+"/one.txt", server.URL+"/missing.txt", server.URL+"/two.txt")
	recorder := h.authed("POST", "/api/lists/batch", body)
	wantStatus(t, recorder, http.StatusOK)
	var response batchAddResponse
	decodeBody(t, recorder, &response)
	if len(response.Added) != 2 || len(response.Failed) != 1 {
		t.Fatalf("response = %+v", response)
	}
	if response.Added[0].Name != "one" || response.Added[0].RuleCount != 3 || response.Added[1].RuleCount != 2 {
		t.Fatalf("added = %+v", response.Added)
	}
	if response.Failed[0].Name != "missing" || !strings.Contains(response.Failed[0].Error, "404") {
		t.Fatalf("failed = %+v", response.Failed)
	}
	if lists := h.listsJSON(); len(lists) != 2 {
		t.Fatalf("%d lists stored, want the 2 good ones", len(lists))
	}
}

func TestBatchAddBounds(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.authed("POST", "/api/lists/batch", `{"items":[]}`), http.StatusBadRequest)
	wantStatus(t, h.authed("POST", "/api/lists/batch", `{}`), http.StatusUnprocessableEntity)
	item := `{"name":"a","url":"http://127.0.0.1:1/x"}`
	tooMany := `{"items":[` + strings.Repeat(item+",", batchAddLimit) + item + `]}`
	wantStatus(t, h.authed("POST", "/api/lists/batch", tooMany), http.StatusBadRequest)
}

func TestCheckListURL(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	server := listServer(t)
	id := h.addList("one", server.URL+"/one.txt")

	var result map[string]any
	recorder := h.authed("POST", fmt.Sprintf("/api/lists/%d/check", id), "")
	wantStatus(t, recorder, http.StatusOK)
	decodeBody(t, recorder, &result)
	if result["ok"] != true || result["status"] != float64(200) || result["url"] != server.URL+"/one.txt" || result["content_length"] == float64(0) {
		t.Fatalf("result = %v", result)
	}

	recorder = h.authed("POST", fmt.Sprintf("/api/lists/%d/check", id), fmt.Sprintf(`{"url":%q}`, server.URL+"/missing.txt"))
	decodeBody(t, recorder, &result)
	if result["ok"] != false || result["status"] != float64(404) {
		t.Fatalf("404 result = %v", result)
	}

	recorder = h.authed("POST", "/api/lists/999/check", `{"url":"http://127.0.0.1:1/x"}`)
	wantStatus(t, recorder, http.StatusOK)
	decodeBody(t, recorder, &result)
	if result["ok"] != false || result["error"] == nil {
		t.Fatalf("unreachable result = %v", result)
	}
	wantStatus(t, h.authed("POST", "/api/lists/999/check", ""), http.StatusNotFound)
}

func TestRegistryFailureIs502(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.authed("GET", "/api/registry/filters", ""), http.StatusBadGateway)
}

func TestRulesLifecycleAndFilterCheck(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	if body := h.authed("GET", "/api/rules", "").Body.String(); body != "[]" {
		t.Fatalf("empty rules = %q", body)
	}
	wantStatus(t, h.authed("POST", "/api/rules", `{"rule":"#comment"}`), http.StatusBadRequest)
	wantStatus(t, h.authed("POST", "/api/rules", `{"rule":""}`), http.StatusBadRequest)
	wantStatus(t, h.authed("POST", "/api/rules", `{}`), http.StatusUnprocessableEntity)

	recorder := h.authed("POST", "/api/rules", `{"rule":" ||ads.example.com^ "}`)
	wantStatus(t, recorder, http.StatusCreated)
	var created addRuleResponse
	decodeBody(t, recorder, &created)
	if created.ID == 0 {
		t.Fatal("no id")
	}
	duplicate := h.authed("POST", "/api/rules", `{"rule":"||ads.example.com^"}`)
	wantStatus(t, duplicate, http.StatusOK)
	if duplicate.Body.String() != `{"id":0}` {
		t.Fatalf("duplicate body %q", duplicate.Body.String())
	}
	wantStatus(t, h.authed("POST", "/api/rules", `{"rule":"@@||ok.ads.example.com^"}`), http.StatusCreated)
	h.eventually(func() bool {
		return strings.Contains(h.authed("POST", "/api/filter/check", `{"domain":"ads.example.com"}`).Body.String(), "blocked")
	})
	h.eventually(func() bool {
		return strings.Contains(h.authed("POST", "/api/filter/check", `{"domain":"ok.ads.example.com"}`).Body.String(), `"rule"`)
	})

	rules := h.authed("GET", "/api/rules", "").Body.String()
	if !strings.Contains(rules, `"rule_type":"block"`) || !strings.Contains(rules, `"rule_type":"allow"`) {
		t.Fatalf("rules = %s", rules)
	}
	for body, want := range map[string]string{
		`{"domain":"ADS.example.com."}`:      `"action":"blocked"`,
		`{"domain":" sub.ads.example.com "}`: `"action":"blocked"`,
		`{"domain":"ok.ads.example.com"}`:    `"rule":"ok.ads.example.com"`,
		`{"domain":"other.test"}`:            `{"action":"allowed"}`,
		`{"domain":""}`:                      `{"action":"allowed"}`,
	} {
		recorder := h.authed("POST", "/api/filter/check", body)
		wantStatus(t, recorder, http.StatusOK)
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("check %s = %s, want %s", body, recorder.Body.String(), want)
		}
	}

	wantStatus(t, h.authed("DELETE", fmt.Sprintf("/api/rules/%d", created.ID), ""), http.StatusOK)
	wantStatus(t, h.authed("DELETE", "/api/rules/9999", ""), http.StatusOK)
	h.eventually(func() bool {
		return strings.Contains(h.authed("POST", "/api/filter/check", `{"domain":"ads.example.com"}`).Body.String(), `"allowed"`)
	})
}

func TestSettingsRoundTripAndRuntimeEffects(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.authed("PUT", "/api/settings",
		`{"upstream_servers":"127.0.0.1:5301, 127.0.0.2:5302","upstream_strategy":"lowest-latency","log_retention_days":"30","block_mode":" nxdomain "}`), http.StatusOK)

	if got := h.deps.Forwarder.Servers(); len(got) != 2 || got[0] != "127.0.0.1:5301" {
		t.Fatalf("servers = %v", got)
	}
	if h.deps.Forwarder.Strategy() != upstream.LowestLatency {
		t.Fatalf("strategy = %v", h.deps.Forwarder.Strategy())
	}
	if h.deps.Handler.BlockConfig().Mode != dns.BlockNXDomain {
		t.Fatalf("block mode = %v", h.deps.Handler.BlockConfig().Mode)
	}
	var settings map[string]string
	decodeBody(t, h.authed("GET", "/api/settings", ""), &settings)
	if settings["upstream_strategy"] != "lowest-latency" || settings["block_mode"] != " nxdomain " || settings["log_retention_days"] != "30" {
		t.Fatalf("settings = %v", settings)
	}
	if _, present := settings["onboarding_banner_dismissed"]; present {
		t.Fatal("unset keys must be omitted")
	}
}

func TestSettingsMergeStoredBlockValues(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.authed("PUT", "/api/settings", `{"block_mode":"custom_ip","block_custom_ipv4":"192.0.2.1"}`), http.StatusOK)
	wantStatus(t, h.authed("PUT", "/api/settings", `{"block_custom_ipv6":"100::"}`), http.StatusOK)
	config := h.deps.Handler.BlockConfig()
	if config.Mode != dns.BlockCustomIP || config.CustomV4.String() != "192.0.2.1" || config.CustomV6.String() != "100::" {
		t.Fatalf("config = %+v", config)
	}
}

func TestSettingsRejectBadValuesWithoutWritingAnything(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	for _, body := range []string{
		`{"log_retention_days":"7","upstream_servers":"not an upstream"}`,
		`{"log_retention_days":"7","upstream_servers":""}`,
		`{"log_retention_days":"7","block_mode":"drop"}`,
		`{"log_retention_days":"7","block_custom_ipv4":"::1"}`,
		`{"log_retention_days":"7","block_custom_ipv4":"1.2.3"}`,
		`{"log_retention_days":"7","block_custom_ipv6":"1.2.3.4"}`,
		`{"log_retention_days":"7","block_custom_ipv6":"fe80::1%eth0"}`,
	} {
		wantStatus(t, h.authed("PUT", "/api/settings", body), http.StatusBadRequest)
	}
	var settings map[string]string
	decodeBody(t, h.authed("GET", "/api/settings", ""), &settings)
	if len(settings) != 0 {
		t.Fatalf("a rejected save wrote %v", settings)
	}
	wantStatus(t, h.authed("PUT", "/api/settings", `{"block_mode":null}`), http.StatusUnprocessableEntity)
	wantStatus(t, h.authed("PUT", "/api/settings", `{"block_mode":5}`), http.StatusUnprocessableEntity)
	wantStatus(t, h.authed("PUT", "/api/settings", `{"block_custom_ipv4":" ","block_custom_ipv6":""}`), http.StatusOK)
}

func TestDNSSECSettingFlushesCacheOnlyOnAFlip(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	key := cache.Key{Domain: "example.test", QueryType: 1}
	h.deps.Cache.Put(key, []byte{0, 1}, time.Minute, false)
	wantStatus(t, h.authed("PUT", "/api/settings", `{"dnssec_disabled":"false"}`), http.StatusOK)
	if _, state := h.deps.Cache.Get(key); state == cache.Miss {
		t.Fatal("an unchanged value flushed the cache")
	}
	wantStatus(t, h.authed("PUT", "/api/settings", `{"dnssec_disabled":" true "}`), http.StatusOK)
	if h.deps.Forwarder.DNSSECEnabled() {
		t.Fatal("dnssec still on")
	}
	if _, state := h.deps.Cache.Get(key); state != cache.Miss {
		t.Fatal("a flip did not flush the cache")
	}
}

func TestUpstreamLatencyAndHealth(t *testing.T) {
	h := newAPIHarness(t, harnessOptions{})
	wantStatus(t, h.authed("PUT", "/api/settings", `{"upstream_servers":"127.0.0.1:1,127.0.0.1:2","upstream_strategy":"lowest-latency"}`), http.StatusOK)
	if body := h.authed("GET", "/api/upstream/latency", "").Body.String(); body != "[]" {
		t.Fatalf("unobserved latency = %q", body)
	}
	h.deps.Forwarder.UpdateLatency(0, 12.34)
	h.deps.Forwarder.UpdateLatency(1, 5.06)
	var entries []upstreamLatencyEntry
	decodeBody(t, h.authed("GET", "/api/upstream/latency", ""), &entries)
	if len(entries) != 2 || entries[0].EMAMS != 12.3 || entries[0].Preferred || entries[1].EMAMS != 5.1 || !entries[1].Preferred {
		t.Fatalf("entries = %+v", entries)
	}

	wantStatus(t, h.authed("PUT", "/api/settings", `{"upstream_strategy":"sequential"}`), http.StatusOK)
	decodeBody(t, h.authed("GET", "/api/upstream/latency", ""), &entries)
	if entries[0].Preferred || entries[1].Preferred {
		t.Fatalf("only lowest-latency has a preferred server: %+v", entries)
	}

	var health []upstreamHealthEntry
	decodeBody(t, h.authed("GET", "/api/upstream/health", ""), &health)
	if len(health) != 2 || health[0].Server != "127.0.0.1:1" || health[0].OK {
		t.Fatalf("health = %+v", health)
	}
}
