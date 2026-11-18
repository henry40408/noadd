package views

import "strconv"

// BarRow is one row of a horizontal bar list, every value already formatted.
type BarRow struct {
	Label string
	// Width is the fill as a percentage of the widest row, "42.1". It goes into
	// a style attribute, so the caller must only ever pass a number.
	Width      string
	Count      string
	Share      string
	CountTitle string
}

// StatCard is one tile of a stat grid.
type StatCard struct {
	Label string
	Value string
	// ValueClass colours the value, e.g. "accent". Never empty.
	ValueClass string
	// Unit is set small after the value; empty for none.
	Unit  string
	Sub   string
	Title string
	// TS is the Unix time behind a date the server could only write in UTC;
	// zero on every other card.
	TS int64
}

// RangeOption is one of the range links.
type RangeOption struct {
	Label  string
	Active bool
}

// StatsPage is the statistics page.
type StatsPage struct {
	Shell ShellData
	// Range is "7d", "30d" or "90d", for the card titles.
	Range  string
	Ranges []RangeOption
	// SeriesJSON is the quarter-hour series the charts fold in the browser.
	SeriesJSON string
	BucketSecs int64

	Highlights             []StatCard
	QueryTypes, Outcomes   []BarRow
	TopDomains, TopClients []BarRow
	Health                 []StatCard
}

// barRow is shared by the four bar lists, so they cannot drift apart.
func barRow(row BarRow, color string) node {
	fillStyle := "width:" + row.Width + "%;background:" + color
	return divClass("bar-row",
		el("div", []attr{a("class", "bar-row-label"), a("title", row.Label)}, text(row.Label)),
		divClass("bar-row-track", el("div", []attr{a("class", "bar-row-fill"), a("style", fillStyle)})),
		el("div", []attr{a("class", "bar-row-count"), a("title", row.CountTitle)},
			el("div", nil, text(row.Count)),
			when(row.Share != "", func() node { return divClass("bar-row-pct", text(row.Share)) })))
}

func barList(rows []BarRow, color string) node {
	if len(rows) == 0 {
		return el("p", class("text-dim"), text("No data yet"))
	}
	var items []node
	for _, row := range rows {
		items = append(items, barRow(row, color))
	}
	return divClass("bar-list", items...)
}

func statsCard(card StatCard, withDateTS bool) node {
	attrs := []attr{a("class", "stat-value "+card.ValueClass)}
	if card.Title != "" {
		attrs = append(attrs, a("title", card.Title))
	}
	if withDateTS && card.TS != 0 {
		attrs = append(attrs, a("data-date-ts", strconv.FormatInt(card.TS, 10)))
	}
	value := group(text(card.Value), when(card.Unit != "", func() node {
		return styled("span", "font-size:0.9rem;color:var(--text-dim)", text(card.Unit))
	}))
	return divClass("stat-card",
		statLabel(card.Label),
		el("div", attrs, value),
		when(withDateTS && card.Sub != "", func() node { return divClass("stat-sub", text(card.Sub)) }))
}

func statsCards(cards []StatCard, withDateTS bool) []node {
	var items []node
	for _, card := range cards {
		items = append(items, statsCard(card, withDateTS))
	}
	return items
}

func rangeSwitcher(options []RangeOption) node {
	var links []node
	for _, option := range options {
		attrs := []attr{a("href", "/stats?range="+option.Label)}
		if option.Active {
			attrs = append(attrs, a("class", "active"), a("aria-current", "page"))
		}
		links = append(links, text(" "), el("a", attrs, text(option.Label)))
	}
	return el("div", []attr{a("class", "range-switcher"), a("id", "range-switcher"), a("data-testid", "range-switcher")}, links...)
}

func titled(id, title string) node {
	return el("div", []attr{a("class", "card-title"), a("id", id)}, text(title))
}

func needsJS(id, message string) node {
	return el("p", []attr{a("class", "panel-empty"), a("data-testid", id)}, text(message))
}

func idCard(id string, children ...node) node {
	return el("div", []attr{a("class", "card"), a("id", id)}, children...)
}

func fadeRow(delay string, children ...node) node {
	return el("div", []attr{a("class", "stats-row-2col fade-in"), a("style", "animation-delay:"+delay)}, children...)
}

func rangedCard(page StatsPage, name, title string, rows []BarRow, color string) node {
	return idCard("ranged-"+name+"-card",
		titled("ranged-"+name+"-title", title+" (last "+page.Range+")"),
		el("div", []attr{a("id", "ranged-"+name), a("data-testid", "ranged-"+name)}, barList(rows, color)))
}

func statsHeader(page StatsPage) node {
	return el("div", []attr{
		a("class", "page-header fade-in"),
		a("style", "display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px"),
	}, el("div", nil, el("h2", nil, text("Statistics")), el("p", nil, text("Long-term traffic patterns"))),
		rangeSwitcher(page.Ranges))
}

func chartRow(page StatsPage) node {
	return fadeRow("0.05s",
		idCard("timeline-card",
			titled("timeline-title", "Queries (last "+page.Range+")"),
			divClassID("chart-container", "timeline-chart",
				needsJS("timeline-needs-js", "This chart is drawn in the browser, aligned to its calendar. The figures around it are complete without it."))),
		idCard("rate-trend-card",
			titled("rate-trend-title", "Block & Cache rate (last "+page.Range+")"),
			divClassID("rate-chart-container", "rate-trend-chart",
				needsJS("rate-trend-needs-js", "Drawn in the browser from the same series as the chart beside it."))))
}

func heatmapCard() node {
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.08s"), a("id", "heatmap-card")},
		divClass("card-title", text("Activity by hour (last 30d)")),
		el("div", []attr{a("id", "heatmap-container")},
			needsJS("heatmap-needs-js", "Drawn in the browser: hour-of-day rows need the viewer's time zone to line up.")))
}

func healthCard(page StatsPage) node {
	return el("div", []attr{
		a("class", "card fade-in"), a("style", "animation-delay:0.2s"), a("id", "health-card"), a("data-testid", "db-health-card"),
	}, divClass("card-title", text("Database Health")),
		divClassID("stat-grid", "health-grid", statsCards(page.Health, true)...))
}

// Stats renders the statistics page inside the signed-in shell.
func Stats(page StatsPage) string {
	highlights := el("div", []attr{
		a("class", "stat-grid fade-in"), a("id", "highlights-grid"), a("style", "animation-delay:0.03s"),
	}, statsCards(page.Highlights, false)...)
	body := el("stats-page", []attr{
		a("data-series", page.SeriesJSON), a("data-bucket-secs", strconv.FormatInt(page.BucketSecs, 10)),
	},
		statsHeader(page), highlights, chartRow(page), heatmapCard(),
		fadeRow("0.1s",
			idCard("qtypes-card", divClass("card-title", text("Query Types")),
				el("div", []attr{a("id", "qtypes-chart")}, barList(page.QueryTypes, "var(--accent)"))),
			idCard("outcomes-card", divClass("card-title", text("Outcomes")),
				el("div", []attr{a("id", "outcomes-chart")}, barList(page.Outcomes, "var(--orange)")))),
		fadeRow("0.15s",
			rangedCard(page, "domains", "Top Domains", page.TopDomains, "var(--accent)"),
			rangedCard(page, "clients", "Top Sources", page.TopClients, "var(--green)")),
		healthCard(page))
	return Shell(page.Shell, body)
}
