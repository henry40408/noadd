package views

import (
	"strconv"
	"strings"
	"testing"
)

var (
	logQueryTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA", "HTTPS"}
	logTokens     = []string{"alpha-token", "beta-token"}
	logDomains    = []string{
		"allowed.example.com", "ads.example.com", "ads.list-one.test", "adserver.list-two.test", "cname.example.com",
		"dnssec.example.com", "nodata.example.com", "nxd.example.com", "ok.ads.example.com", "ok.list-two.test",
		"telemetry.list-one.test", "tracker.example.net",
	}
)

func logsShell() ShellData {
	return ShellData{Version: goldenVersion, Host: "127.0.0.1:19080", CurrentPath: "/logs"}
}

func logOptions(selected string, values []string) []LogOption {
	options := make([]LogOption, 0, len(values))
	for _, value := range values {
		options = append(options, LogOption{Value: value, Selected: value == selected})
	}
	return options
}

// parseLogRows reads a table like logRowsFirstPage. The Rust server offered to
// allow a blocked row's domain and to block any other.
func parseLogRows(t *testing.T, table string) []LogRow {
	t.Helper()
	var rows []LogRow
	for _, line := range strings.Split(strings.TrimSpace(table), "\n") {
		fields := strings.Split(line, "|")
		if len(fields) != 7 {
			t.Fatalf("log row has %d fields: %q", len(fields), line)
		}
		flags, domain := fields[0], fields[1]
		ms, err := strconv.ParseInt(fields[6], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		blocked := strings.Contains(flags, "b")
		rule, label := "||"+domain+"^", "Block"
		if blocked {
			rule, label = "@@||"+domain+"^", "Allow"
		}
		rows = append(rows, LogRow{
			TimestampMS: 1, TimeText: "3 minutes ago", Blocked: blocked, Domain: domain, Result: fields[3],
			DNSSEC: strings.Contains(flags, "d"), QueryType: fields[2], ClientIP: "192.168.215.1", DoHToken: fields[4],
			Cached: strings.Contains(flags, "c"), Upstream: fields[5], ResponseMS: ms, ActionRule: rule, ActionLabel: label,
		})
	}
	return rows
}

// logsPageWith completes the page a data golden shows: its rows, the filter
// menus (the one the page filters on is selected) and the shell. The caller
// states the filters, paging and totals.
func logsPageWith(t *testing.T, page LogsPage, rows string) LogsPage {
	t.Helper()
	page.Rows = parseLogRows(t, rows)
	page.QueryTypes = logOptions(page.QueryType, logQueryTypes)
	page.Tokens = logOptions(page.Token, logTokens)
	page.DomainSuggestions = logDomains
	page.Shell = logsShell()
	return page
}

func TestLogsEmptyMatchesGolden(t *testing.T) {
	page := LogsPage{
		Shell:      logsShell(),
		QueryTypes: logOptions("", logQueryTypes),
		Page:       1, TotalPages: 1, Total: "0", CurrentHref: "/logs",
	}
	page.Shell.ShowNextStep, page.Shell.NextStepAddr = true, "127.0.0.1:53"
	assertGolden(t, "logs_empty", Logs(page))
}

func TestLogsDataMatchesGoldens(t *testing.T) {
	cases := []struct {
		name string
		rows string
		page LogsPage
	}{
		{"logs_data", logRowsFirstPage, LogsPage{Page: 1, TotalPages: 4, Total: "200", HasNext: true, NextHref: "/logs?page=2", CurrentHref: "/logs"}},
		{"logs_bad_page", logRowsFirstPage, LogsPage{Page: 1, TotalPages: 4, Total: "200", HasNext: true, NextHref: "/logs?page=2", CurrentHref: "/logs"}},
		{"logs_filtered", logRowsFiltered, LogsPage{
			Q: "ads", Action: "blocked", QueryType: "A", Token: "alpha-token", Page: 1, TotalPages: 1, Total: "9", Filtered: true,
			CurrentHref: "/logs?q=ads&action=blocked&type=A&token=alpha-token",
		}},
		{"logs_wildcard", logRowsWildcardPage, LogsPage{
			Q: "*example*", Page: 2, TotalPages: 3, Total: "148", Filtered: true, HasPrev: true, HasNext: true,
			PrevHref: "/logs?q=%2Aexample%2A", NextHref: "/logs?q=%2Aexample%2A&page=3",
			CurrentHref: "/logs?q=%2Aexample%2A&page=2",
		}},
	}
	for _, c := range cases {
		assertGolden(t, c.name, Logs(logsPageWith(t, c.page, c.rows)))
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
