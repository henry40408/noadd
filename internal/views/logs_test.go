package views

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	logRowPattern     = regexp.MustCompile(`(?s)<tr data-testid="log-row">(.*?)</tr>`)
	logCellPattern    = regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`)
	optionPattern     = regexp.MustCompile(`<option value="([^"]*)"[^>]*>`)
	tagPattern        = regexp.MustCompile(`</?[a-z][^>]*>`)
	attrValuePattern  = func(name string) *regexp.Regexp { return regexp.MustCompile(name + `="([^"]*)"`) }
	datalistPattern   = regexp.MustCompile(`(?s)<datalist id="log-domain-list">(.*?)</datalist>`)
	nextFieldPattern  = regexp.MustCompile(`name="next" value="([^"]*)"`)
	ruleFieldPattern  = regexp.MustCompile(`name="rule" value="([^"]*)"`)
	actionLabelRegexp = regexp.MustCompile(`data-blocked="(?:true|false)">([^<]*)</button>`)
)

func firstGroup(t *testing.T, pattern *regexp.Regexp, source string) string {
	t.Helper()
	match := pattern.FindStringSubmatch(source)
	if match == nil {
		return ""
	}
	return html.UnescapeString(match[1])
}

func visibleText(markup string) string {
	return html.UnescapeString(tagPattern.ReplaceAllString(markup, ""))
}

// logRowFromGolden reads one table row of a Rust golden back into the values
// the view takes, so the data goldens can be checked without the database
// they were captured from.
func logRowFromGolden(t *testing.T, row string) LogRow {
	t.Helper()
	cells := logCellPattern.FindAllStringSubmatch(row, -1)
	if len(cells) != 8 {
		t.Fatalf("log row has %d cells: %.200s", len(cells), row)
	}
	domainCell, clientCell, sourceCell := cells[2][1], cells[4][1], cells[6][1]
	result := ""
	if strings.Contains(domainCell, "→ ") {
		result = firstGroup(t, attrValuePattern("title"), domainCell[strings.Index(domainCell, `<div class="mono"`):])
	}
	token := ""
	if strings.Contains(clientCell, "<br>") {
		token = visibleText(clientCell[strings.Index(clientCell, "<br>"):])
	}
	ms, _ := strconv.ParseInt(visibleText(cells[7][1]), 10, 64)
	upstream := ""
	if strings.Contains(sourceCell, `class="mono"`) {
		upstream = visibleText(sourceCell)
	}
	return LogRow{
		TimestampMS: 1,
		TimeText:    visibleText(cells[0][1]),
		Blocked:     strings.Contains(cells[1][1], "st-block"),
		Domain:      firstGroup(t, attrValuePattern("title"), domainCell),
		Result:      strings.TrimPrefix(result, ""),
		DNSSEC:      strings.Contains(domainCell, "badge-dnssec"),
		QueryType:   visibleText(cells[3][1]),
		ClientIP:    strings.TrimSuffix(html.UnescapeString(tagPattern.ReplaceAllString(strings.SplitN(clientCell, "<br>", 2)[0], "")), token),
		DoHToken:    token,
		Cached:      strings.Contains(sourceCell, "badge-cached"),
		Upstream:    upstream,
		ResponseMS:  ms,
		ActionRule:  firstGroup(t, ruleFieldPattern, cells[5][1]),
		ActionLabel: firstGroup(t, actionLabelRegexp, cells[5][1]),
	}
}

func goldenOptions(t *testing.T, golden, selectID string) []LogOption {
	t.Helper()
	block := regexp.MustCompile(`(?s)<select id="log-` + selectID + `".*?</select>`).FindString(golden)
	var options []LogOption
	for i, match := range optionPattern.FindAllStringSubmatch(block, -1) {
		if i == 0 {
			continue // the "All …" entry is the view's own
		}
		options = append(options, LogOption{Value: html.UnescapeString(match[1]), Selected: strings.Contains(match[0], "selected")})
	}
	return options
}

// logsPageFromGolden builds the page a golden shows from the golden itself,
// except for what the caller states: the filters, paging and totals.
func logsPageFromGolden(t *testing.T, name string, page LogsPage) LogsPage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name+".golden.html"))
	if err != nil {
		t.Fatal(err)
	}
	// The goldens carry normalisation markers where the values were volatile;
	// any stand-in works, since the Go output is normalised the same way.
	golden := strings.NewReplacer("<TS>", "1", "<AGO>", "3 minutes ago").Replace(string(raw))
	for _, match := range logRowPattern.FindAllStringSubmatch(golden, -1) {
		page.Rows = append(page.Rows, logRowFromGolden(t, match[1]))
	}
	page.QueryTypes = goldenOptions(t, golden, "type")
	page.Tokens = goldenOptions(t, golden, "token")
	page.CurrentHref = firstGroup(t, nextFieldPattern, golden)
	for _, option := range optionPattern.FindAllStringSubmatch(datalistPattern.FindString(golden), -1) {
		page.DomainSuggestions = append(page.DomainSuggestions, html.UnescapeString(option[1]))
	}
	page.Shell = ShellData{Version: goldenVersion, Host: "127.0.0.1:19080", CurrentPath: "/logs"}
	return page
}

func TestLogsEmptyMatchesGolden(t *testing.T) {
	page := LogsPage{
		Shell: ShellData{
			Version: goldenVersion, Host: "127.0.0.1:19080", CurrentPath: "/logs",
			ShowNextStep: true, NextStepAddr: "127.0.0.1:53",
		},
		Page: 1, TotalPages: 1, Total: "0", CurrentHref: "/logs",
	}
	page = logsPageFromGolden(t, "logs_empty", page)
	page.Shell.ShowNextStep, page.Shell.NextStepAddr = true, "127.0.0.1:53"
	assertGolden(t, "logs_empty", Logs(page))
}

func TestLogsDataMatchesGoldens(t *testing.T) {
	cases := map[string]LogsPage{
		"logs_data":     {Page: 1, TotalPages: 4, Total: "200", HasNext: true, NextHref: "/logs?page=2", CurrentHref: "/logs"},
		"logs_bad_page": {Page: 1, TotalPages: 4, Total: "200", HasNext: true, NextHref: "/logs?page=2", CurrentHref: "/logs"},
		"logs_filtered": {
			Q: "ads", Action: "blocked", QueryType: "A", Token: "alpha-token", Page: 1, TotalPages: 1, Total: "9", Filtered: true,
		},
		"logs_wildcard": {
			Q: "*example*", Page: 2, TotalPages: 3, Total: "148", Filtered: true, HasPrev: true, HasNext: true,
			PrevHref: "/logs?q=%2Aexample%2A", NextHref: "/logs?q=%2Aexample%2A&page=3",
		},
	}
	for name, page := range cases {
		assertGolden(t, name, Logs(logsPageFromGolden(t, name, page)))
	}
}

func TestLogsClearedBanner(t *testing.T) {
	page := LogsPage{Shell: ShellData{LogsCleared: true}, Page: 1, TotalPages: 1, Total: "0"}
	if !strings.Contains(Logs(page), `data-testid="logs-cleared"`) {
		t.Error("cleared banner missing")
	}
}

// 待 Opus 審查: XSS. Domains, answers, client addresses, tokens and upstreams
// are whatever a network peer sent.
func TestLogsEscapeEveryString(t *testing.T) {
	const payload = `"><script>alert(1)</script>`
	row := LogRow{
		TimeText: payload, Domain: payload, Result: payload, QueryType: payload, ClientIP: payload, DoHToken: payload,
		Upstream: payload, ActionRule: payload, ActionLabel: payload, DNSSEC: true,
	}
	page := LogsPage{
		Rows: []LogRow{row, {Domain: payload, Cached: true, Blocked: true}},
		Q:    payload, Action: payload, QueryType: payload, Token: payload,
		Tokens: []LogOption{{Value: payload}}, QueryTypes: []LogOption{{Value: payload}},
		DomainSuggestions: []string{payload}, CurrentHref: payload, PrevHref: payload, NextHref: payload,
		HasPrev: true, HasNext: true, Total: payload,
	}
	if strings.Contains(Logs(page), "<script>alert") {
		t.Fatal("unescaped payload in logs output")
	}
}
