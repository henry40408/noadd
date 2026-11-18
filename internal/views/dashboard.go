package views

// TopRow is one row of a "top N" table, every value already formatted.
type TopRow struct {
	Label string
	// SubLabel is a second line under the label (the DoH token a client came
	// in on); empty when there is none.
	SubLabel string
	Count    string
	// Share is "12.3%", or empty when a share would be a lie.
	Share string
	// AvgMS is only shown by the upstreams table.
	AvgMS string
}

// DashboardPage is the dashboard: readings only, all formatted by the caller.
type DashboardPage struct {
	Shell ShellData

	QueriesToday, QueriesTodayFull, Queries7d, Queries30d string
	BlockedToday, BlockedTodayFull, Blocked7d, Blocked30d string
	BlockRate, BlockRate7d, BlockRate30d                  string
	CacheRate, CacheRate7d, CacheRate30d                  string
	AvgMS, AvgMS7d, AvgMS30d                              string
	QPSNow, QPSToday, QPS7d                               string

	// HasQueries is false only on an appliance that has never answered a query.
	HasQueries bool
	// DNSAddr is where to point a device, for the empty-state guide.
	DNSAddr string

	TopDomains, TopClients, TopUpstreams []TopRow
}

func class(name string) []attr { return []attr{a("class", name)} }

func divClass(name string, children ...node) node { return el("div", class(name), children...) }

func styled(tag, style string, children ...node) node {
	return el(tag, []attr{a("style", style)}, children...)
}

// countCell is the count, followed by its share when there is one.
func countCell(row TopRow) node {
	return group(
		text(row.Count),
		when(row.Share != "", func() node {
			return group(text(" "), styled("span", "color:var(--text-dim);font-size:0.75em", text("("+row.Share+")")))
		}))
}

func noData() node { return el("p", class("text-dim"), text("No data")) }

const rightAligned = "text-align:right"
const countCellStyle = "text-align:right;white-space:nowrap"

func truncateCell(classes, title string) node {
	return el("div", []attr{a("class", classes), a("title", title)}, text(title))
}

func domainsTable(rows []TopRow) node {
	var body []node
	for _, row := range rows {
		body = append(body, el("tr", nil,
			el("td", nil, truncateCell("truncate-cell", row.Label)),
			el("td", []attr{a("class", "mono"), a("style", countCellStyle)}, countCell(row))))
	}
	return el("table", class("top-table"),
		el("colgroup", nil, void("col"), void("col", a("style", "width:140px"))),
		el("thead", nil, el("tr", nil, el("th", nil, text("Domain")), styled("th", rightAligned, text("Count")))),
		el("tbody", nil, body...))
}

func clientsTable(rows []TopRow) node {
	var body []node
	for _, row := range rows {
		label := truncateCell("truncate-cell mono", row.Label)
		sub := when(row.SubLabel != "", func() node {
			return el("div", []attr{
				a("class", "truncate-cell"), a("title", row.SubLabel), a("style", "color:var(--accent);font-size:0.7rem"),
			}, text(row.SubLabel))
		})
		body = append(body, el("tr", nil,
			el("td", nil, label, sub),
			el("td", []attr{a("class", "mono"), a("style", countCellStyle)}, countCell(row))))
	}
	return el("table", class("top-table"),
		el("colgroup", nil, void("col"), void("col", a("style", "width:140px"))),
		el("thead", nil, el("tr", nil, el("th", nil, text("Client")), styled("th", rightAligned, text("Count")))),
		el("tbody", nil, body...))
}

func upstreamsTable(rows []TopRow) node {
	var body []node
	for _, row := range rows {
		body = append(body, el("tr", nil,
			el("td", nil, truncateCell("truncate-cell mono", row.Label)),
			el("td", []attr{a("class", "mono"), a("style", countCellStyle)}, countCell(row)),
			el("td", []attr{a("class", "mono hide-mobile"), a("style", countCellStyle)}, text(row.AvgMS))))
	}
	head := el("tr", nil,
		el("th", nil, text("Upstream")),
		styled("th", "text-align:right;width:140px", text("Queries")),
		el("th", []attr{a("class", "hide-mobile"), a("style", "text-align:right;width:120px")}, text("Avg Latency")))
	return el("table", class("top-table"), el("thead", nil, head), el("tbody", nil, body...))
}

func topCard(delay, id, testID, title, bodyID string, body node) node {
	attrs := []attr{a("class", "card fade-in"), a("style", "animation-delay:"+delay), a("id", id)}
	if testID != "" {
		attrs = append(attrs, a("data-testid", testID))
	}
	return el("div", attrs, divClass("card-title", text(title)), el("div", []attr{a("id", bodyID)}, body))
}

func tableOrEmpty(rows []TopRow, table func([]TopRow) node) node {
	if len(rows) == 0 {
		return noData()
	}
	return table(rows)
}

func unit(value, unitText string) node {
	return group(text(value), styled("span", "font-size:0.9rem;color:var(--text-dim)", text(unitText)))
}

func statCard(index, testID string, label node, value node, sub string) node {
	attrs := []attr{a("class", "stat-card"), a("data-i", index)}
	if testID != "" {
		attrs = append(attrs, a("data-testid", testID))
	}
	return el("div", attrs, label, value, divClass("stat-sub", text(sub)))
}

func statLabel(label string) node { return divClass("stat-label", text(label)) }

func statValue(classes, title, value string) node {
	return el("div", []attr{a("class", classes), a("title", title)}, text(value))
}

func onboardEmpty(page DashboardPage) node {
	attrs := []attr{a("class", "card fade-in"), a("id", "onboard-empty"), a("data-testid", "dashboard-empty-state")}
	if page.HasQueries {
		attrs = append(attrs, a("style", "display:none"))
	}
	const paragraph = "color:var(--text-secondary);font-size:0.9rem;margin:8px 0"
	return el("div", attrs, when(!page.HasQueries, func() node {
		return group(
			divClass("card-title", text("Point a device at noadd to get started")),
			styled("p", paragraph, text("noadd hasn't served any DNS queries yet. To start filtering, configure a device or router to use this server as its DNS resolver, then send some traffic.")),
			styled("p", paragraph, text("Set the device's DNS server to: "),
				el("code", class("mono text-primary"), text(page.DNSAddr))))
	}))
}

func statGrid(page DashboardPage) node {
	valueAttrs := func(classes string) []attr { return class(classes) }
	return divClassID("stat-grid fade-in", "stats",
		statCard("0", "", statLabel("Queries 24h"), statValue("stat-value accent", page.QueriesTodayFull, page.QueriesToday),
			"7d: "+page.Queries7d+" / 30d: "+page.Queries30d),
		statCard("1", "stat-blocked-today", statLabel("Blocked 24h"), statValue("stat-value red", page.BlockedTodayFull, page.BlockedToday),
			"7d: "+page.Blocked7d+" / 30d: "+page.Blocked30d),
		statCard("2", "stat-block-rate", statLabel("Block Rate"), el("div", valueAttrs("stat-value red"), text(page.BlockRate+"%")),
			"7d: "+page.BlockRate7d+"% / 30d: "+page.BlockRate30d+"%"),
		statCard("3", "", statLabel("Cache Hit Rate"), el("div", valueAttrs("stat-value text-orange"), text(page.CacheRate+"%")),
			"7d: "+page.CacheRate7d+"% / 30d: "+page.CacheRate30d+"%"),
		statCard("4", "", statLabel("Avg Response"), el("div", valueAttrs("stat-value text-orange"), unit(page.AvgMS, "ms")),
			"7d: "+page.AvgMS7d+" ms / 30d: "+page.AvgMS30d+" ms"),
		statCard("5", "stat-throughput", statLabel("Throughput"),
			el("div", []attr{a("class", "stat-value accent"), a("data-testid", "stat-throughput-value")}, unit(page.QPSNow, "q/s")),
			"24h: "+page.QPSToday+" / 7d: "+page.QPS7d),
	)
}

func divClassID(classes, id string, children ...node) node {
	return el("div", []attr{a("class", classes), a("id", id)}, children...)
}

func chartCard(hasQueries bool) node {
	style := "animation-delay:0.1s"
	if !hasQueries {
		style += ";display:none"
	}
	return el("div", []attr{a("class", "card fade-in"), a("id", "chart-card"), a("style", style)},
		divClass("card-title", text("Queries (24h)")),
		divClassID("chart-container", "chart",
			el("p", []attr{a("class", "panel-empty"), a("data-testid", "chart-needs-js")},
				text("The 24-hour chart is drawn in the browser. The numbers above and below it are complete without it."))))
}

func dashboardHeader() node {
	live := el("button", []attr{
		a("class", "live-toggle js-only"), a("id", "live-btn"), a("data-testid", "live-toggle"),
		a("title", "Auto-refresh every 10s. Click to toggle."), flag("hidden"),
	}, el("span", class("live-dot")), text(" LIVE"))
	return el("div", []attr{a("class", "page-header fade-in"), a("style", "display:flex;align-items:center;justify-content:space-between")},
		el("div", nil, el("h2", nil, text("Dashboard")), el("p", nil, text("DNS query statistics overview"))), live)
}

// Dashboard renders the dashboard inside the signed-in shell.
func Dashboard(page DashboardPage) string {
	grid := el("div", []attr{
		a("class", "dashboard-grid-2col"), a("style", "display:grid;grid-template-columns:1fr 1fr;gap:16px"),
	},
		topCard("0.15s", "domains-card", "top-domains-card", "Top Queried Domains", "top-domains", tableOrEmpty(page.TopDomains, domainsTable)),
		topCard("0.2s", "clients-card", "", "Top Sources", "top-clients", tableOrEmpty(page.TopClients, clientsTable)))
	body := el("dashboard-page", nil,
		dashboardHeader(), onboardEmpty(page), statGrid(page), chartCard(page.HasQueries), grid,
		topCard("0.25s", "upstreams-card", "", "Upstream DNS Servers", "top-upstreams", tableOrEmpty(page.TopUpstreams, upstreamsTable)))
	return Shell(page.Shell, body)
}
