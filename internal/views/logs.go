package views

import "strconv"

// LogOption is one <option>; its value is also its label.
type LogOption struct {
	Value    string
	Selected bool
}

// LogRow is one logged query, formatted the way the table shows it.
type LogRow struct {
	// TimestampMS is what the client's per-second ticker reads from data-ts.
	TimestampMS int64
	TimeText    string
	Blocked     bool
	Domain      string
	// Result is the answer worth showing; empty otherwise.
	Result     string
	DNSSEC     bool
	QueryType  string
	ClientIP   string
	DoHToken   string
	Cached     bool
	Upstream   string
	ResponseMS int64
	// ActionRule is the rule the row's one-click action adds, ActionLabel its
	// button text.
	ActionRule  string
	ActionLabel string
}

// LogsPage is the query log.
type LogsPage struct {
	Shell ShellData
	Rows  []LogRow
	// Tokens and QueryTypes fill the filter dropdowns.
	Tokens, QueryTypes []LogOption
	// DomainSuggestions back the search box's datalist; empty renders none.
	DomainSuggestions []string

	// Q, Action, QueryType and Token are the filters as submitted.
	Q, Action, QueryType, Token string

	Page, TotalPages int64
	Total            string
	HasPrev, HasNext bool
	PrevHref         string
	NextHref         string
	// CurrentHref is the current view as a path, carried by row actions to
	// return here.
	CurrentHref string
	// Filtered tells "nothing matched" from "nothing has happened yet".
	Filtered bool
}

func statusMark(blocked bool, extra ...attr) node {
	class, title, mark := "st st-ok", "allowed", "✔"
	if blocked {
		class, title, mark = "st st-block", "blocked", "✖"
	}
	attrs := append([]attr{a("class", class), a("title", title)}, extra...)
	return el("span", attrs, text(mark))
}

func dnssecBadge() node {
	return el("span", []attr{a("class", "badge badge-dnssec"), a("style", "flex:0 0 auto")}, text("dnssec"))
}

func actionForm(row LogRow, currentHref string, extra ...attr) node {
	buttonClass := "btn btn-sm log-action btn-danger"
	if row.Blocked {
		buttonClass = "btn btn-sm log-action btn-allow"
	}
	attrs := append([]attr{a("method", "post"), a("action", "/logs/rules"), a("class", "inline-form")}, extra...)
	return el("form", attrs,
		void("input", a("type", "hidden"), a("name", "rule"), a("value", row.ActionRule)), sp(),
		void("input", a("type", "hidden"), a("name", "next"), a("value", currentHref)), sp(),
		submit(buttonClass, []attr{a("data-domain", row.Domain), a("data-blocked", strconv.FormatBool(row.Blocked))}, text(row.ActionLabel)))
}

func optionList(options []LogOption) []node {
	var items []node
	for _, option := range options {
		items = append(items, selectOption(option.Value, option.Value, option.Selected))
	}
	return items
}

func selectOption(value, label string, selected bool) node {
	attrs := []attr{a("value", value)}
	if selected {
		attrs = append(attrs, flag("selected"))
	}
	return el("option", attrs, text(label))
}

func emptyStateBox(testID string) node {
	attrs := []attr{}
	if testID != "" {
		attrs = append(attrs, a("data-testid", testID))
	}
	attrs = append(attrs, a("style", "text-align:center;color:var(--text-secondary);padding:24px 12px"))
	return el("div", attrs,
		styled("div", "color:var(--text-primary);font-weight:600;margin-bottom:6px", text("No DNS queries logged yet")),
		styled("div", "font-size:0.9rem", text("Once a device uses noadd as its DNS resolver, its queries will appear here.")))
}

const resultStyle = "font-size:0.85rem;color:var(--text-dim);"

func resultLine(result, style string) node {
	return when(result != "", func() node {
		return el("div", []attr{a("class", "mono"), a("style", style), a("title", result)}, text("→ "+result))
	})
}

func timeAgo(row LogRow) node {
	return el("span", []attr{a("class", "timeago"), a("data-ts", id64(row.TimestampMS))}, text(row.TimeText))
}

func sourceCell(row LogRow) node {
	switch {
	case row.Cached:
		return span("badge badge-cached", "cached")
	case row.Upstream != "":
		return el("span", []attr{a("class", "mono"), a("style", "font-size:0.9rem")}, text(row.Upstream))
	default:
		return span("text-dim", "-")
	}
}

func tableRow(row LogRow, currentHref string) node {
	domain := el("div", []attr{a("style", "display:flex;align-items:center;gap:6px;max-width:300px")},
		el("span", []attr{
			a("style", "overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;color:var(--text-primary)"),
			a("title", row.Domain),
		}, text(row.Domain)),
		when(row.DNSSEC, dnssecBadge))
	client := group(text(row.ClientIP), when(row.DoHToken != "", func() node {
		return group(br(), styled("span", "color:var(--accent);font-size:0.85rem", text(row.DoHToken)))
	}))
	return el("tr", []attr{a("data-testid", "log-row")},
		el("td", nil, timeAgo(row)),
		styled("td", "text-align:center", statusMark(row.Blocked)),
		el("td", nil, domain, resultLine(row.Result, resultStyle+"max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap")),
		el("td", class("mono"), text(row.QueryType)),
		el("td", class("mono"), client),
		el("td", nil, actionForm(row, currentHref)),
		el("td", nil, sourceCell(row)),
		el("td", class("mono"), text(strconv.FormatInt(row.ResponseMS, 10))))
}

func tableBody(page LogsPage) node {
	if len(page.Rows) > 0 {
		var rows []node
		for _, row := range page.Rows {
			rows = append(rows, tableRow(row, page.CurrentHref))
		}
		return group(rows...)
	}
	if page.Filtered {
		return el("tr", nil, el("td", []attr{a("colspan", "8"), a("style", "text-align:center;color:var(--text-dim)")}, text("No logs found")))
	}
	return el("tr", nil, el("td", []attr{a("colspan", "8"), a("style", "padding:0")}, emptyStateBox("logs-empty-state")))
}

func logCard(row LogRow, currentHref string) node {
	row1 := divClass("log-card-row1",
		statusMark(row.Blocked, a("style", "flex:0 0 auto")), sp(),
		el("span", []attr{a("class", "log-card-domain"), a("title", row.Domain)}, text(row.Domain)),
		when(row.DNSSEC, dnssecBadge), sp(),
		actionForm(row, currentHref, a("style", "flex-shrink:0")))
	var source node
	switch {
	case row.Cached:
		source = span("lc-cached", "cached")
	case row.Upstream != "":
		source = span("lc-up", row.Upstream)
	}
	row2 := divClass("log-card-row2",
		el("span", class("lc-time"), timeAgo(row)), sp(),
		span("lc-type", row.QueryType), sp(),
		span("lc-client text-secondary", row.ClientIP),
		source,
		when(row.DoHToken != "", func() node { return span("lc-token", row.DoHToken) }), sp(),
		span("lc-ms", strconv.FormatInt(row.ResponseMS, 10)+"ms"))
	return divClass("log-card", row1,
		resultLine(row.Result, resultStyle+"margin-bottom:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"), row2)
}

func cardList(page LogsPage) node {
	if len(page.Rows) > 0 {
		var cards []node
		for _, row := range page.Rows {
			cards = append(cards, logCard(row, page.CurrentHref))
		}
		return group(cards...)
	}
	if page.Filtered {
		return styled("p", "color:var(--text-dim);text-align:center;padding:16px", text("No logs found"))
	}
	return emptyStateBox("")
}

func searchBox(page LogsPage) node {
	attrs := []attr{
		a("type", "text"), a("id", "log-search"), a("name", "q"), a("value", page.Q), a("data-testid", "logs-search"),
		a("placeholder", "Domain prefix, or *pattern*"),
		a("title", "Plain text matches the domain prefix (fast). Use * or % anywhere for a substring/wildcard match (slower)."),
	}
	if len(page.DomainSuggestions) > 0 {
		attrs = append(attrs, a("list", "log-domain-list"))
	}
	return void("input", append(attrs, a("autocomplete", "off"))...)
}

func logDatalist(values []string) node {
	if len(values) == 0 {
		return ""
	}
	var options []node
	for _, value := range values {
		options = append(options, el("option", []attr{a("value", value)}))
	}
	return group(el("datalist", []attr{a("id", "log-domain-list")}, options...), sp())
}

func filterSelect(id, name, testID string, options ...node) node {
	return el("select", []attr{a("id", id), a("name", name), a("data-testid", testID)}, options...)
}

func logFilters(page LogsPage) node {
	action := filterSelect("log-action", "action", "logs-action",
		selectOption("", "All", page.Action == ""),
		selectOption("allowed", "Allowed", page.Action == "allowed"),
		selectOption("blocked", "Blocked", page.Action == "blocked"))
	types := filterSelect("log-type", "type", "logs-type",
		append([]node{selectOption("", "All Types", page.QueryType == "")}, optionList(page.QueryTypes)...)...)
	tokens := filterSelect("log-token", "token", "logs-token",
		append([]node{selectOption("", "All Tokens", page.Token == "")}, optionList(page.Tokens)...)...)
	clear := button([]attr{
		a("type", "submit"), a("form", "clear-logs-form"), a("class", "btn btn-danger btn-sm"),
		a("id", "clear-logs"), a("data-testid", "logs-clear"),
	},
		icon(el("polyline", []attr{a("points", "3 6 5 6 21 6")}),
			el("path", []attr{a("d", "M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2")})),
		text(" Clear All"))
	return el("form", []attr{a("method", "get"), a("action", "/logs"), a("class", "filters-row fade-in"), a("id", "log-filters")},
		searchBox(page), sp(), logDatalist(page.DomainSuggestions), action, sp(), types, sp(), tokens, sp(),
		submit("btn btn-sm nojs-only", []attr{a("data-testid", "logs-filter-apply")}, text("Filter")), sp(), clear)
}

func pagerLink(id, testID, label, href string) node {
	return el("a", []attr{a("class", "btn btn-sm"), a("id", id), a("data-testid", testID), a("href", href)}, text(label))
}

func disabledPager(id, label string) node {
	return el("span", []attr{a("class", "btn btn-sm"), a("id", id), a("aria-disabled", "true"), a("style", "opacity:.45")}, text(label))
}

func pagination(page LogsPage) node {
	prev, next := disabledPager("pg-prev", "Prev"), disabledPager("pg-next", "Next")
	if page.HasPrev {
		prev = pagerLink("pg-prev", "logs-prev", "Prev", page.PrevHref)
	}
	if page.HasNext {
		next = pagerLink("pg-next", "logs-next", "Next", page.NextHref)
	}
	position := el("span", nil,
		text("Page "+id64(page.Page)+" / "+id64(page.TotalPages)),
		when(page.Total != "0", func() node { return text(" · " + page.Total + " queries") }))
	return divClassID("pagination", "log-pagination", prev, sp(), position, sp(), next)
}

func logsHeader() node {
	live := el("button", []attr{
		a("class", "live-toggle paused js-only"), a("id", "log-live-btn"), a("data-testid", "logs-live-toggle"),
		a("title", "Stream new queries live as they arrive. Click to toggle."), flag("hidden"),
	}, el("span", class("live-dot")), text(" LIVE"))
	return el("div", []attr{a("class", "page-header fade-in"), a("style", "display:flex;align-items:center;justify-content:space-between")},
		el("div", nil, el("h2", nil, text("Query Log")), el("p", nil, text("DNS query history"))), live)
}

func logsTable(page LogsPage) node {
	head := el("tr", nil, el("th", nil, text("Time")), el("th", nil, text("Status")), el("th", nil, text("Query")),
		el("th", nil, text("Type")), el("th", nil, text("Client")), el("th", nil), el("th", nil, text("Source")), el("th", nil, text("ms")))
	table := el("table", nil, el("thead", nil, head), el("tbody", []attr{a("id", "log-body")}, tableBody(page)))
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.05s")},
		divClass("table-wrap hide-mobile-block", table),
		el("div", []attr{a("id", "log-cards"), a("class", "show-mobile")}, cardList(page)),
		pagination(page))
}

// Logs renders the query log inside the signed-in shell.
func Logs(page LogsPage) string {
	body := el("logs-page", nil,
		logsHeader(),
		when(page.Shell.LogsCleared, func() node {
			return el("div", []attr{a("class", "rebuild-banner show done"), a("data-testid", "logs-cleared")},
				divClass("text", span("label", "Query log cleared")))
		}),
		logFilters(page),
		el("form", []attr{a("method", "post"), a("action", "/logs/clear"), a("id", "clear-logs-form"), flag("hidden")}),
		logsTable(page))
	return Shell(page.Shell, body)
}
