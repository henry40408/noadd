package views

import "strconv"

// RegistryRow is one registry entry as the list shows it.
type RegistryRow struct {
	FilterID int64
	// GroupID is the same id the group <select> carries.
	GroupID     int64
	Name        string
	Description string
	// Homepage must already be safe to link (absolute http or https); empty
	// renders no link. Escaping alone does not stop a javascript: URL.
	Homepage  string
	GroupName string
	// GroupClass is the pill's colour class, from a fixed set.
	GroupClass   string
	AlreadyAdded bool
	Deprecated   bool
}

// RegistryGroup is one <option> of the group filter.
type RegistryGroup struct {
	Value    string
	Label    string
	Selected bool
}

// RegistryFailure is one list the batch could not add, and why.
type RegistryFailure struct {
	Name  string
	Error string
}

// RegistryPage is the registry browser.
type RegistryPage struct {
	Shell          ShellData
	Q              string
	Groups         []RegistryGroup
	ShowDeprecated bool
	Rows           []RegistryRow
	// LoadFailed renders the outage state with a retry link.
	LoadFailed bool
	Shown      int
	Total      int
	// CurrentQuery is the query string that returns to this view.
	CurrentQuery string
	AddedCount   int
	Failures     []RegistryFailure
	// Limit is the cap a selection may not exceed.
	Limit int
}

func registryHeader() node {
	return el("div", []attr{
		a("class", "page-header fade-in"),
		a("style", "display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px"),
	},
		el("div", nil, el("h2", nil, text("Browse Filter Registry")), el("p", nil, text("Add lists from the AdGuard HostlistsRegistry"))),
		sp(),
		el("a", []attr{a("class", "btn btn-sm"), a("href", "/filters"), a("data-testid", "registry-back")}, text("Back to Filters")))
}

func addedBanner(count int) node {
	return el("div", []attr{a("class", "rebuild-banner show done"), a("data-testid", "registry-added")},
		divClass("text",
			span("label", "Added "+strconv.Itoa(count)), sp(),
			span("meta", "The filter engine is rebuilding; the change takes effect in a moment.")))
}

func failuresCard(failures []RegistryFailure) node {
	var items []node
	for _, failure := range failures {
		items = append(items, el("li", nil, span("mono", failure.Name), text(" — "+failure.Error)))
	}
	return el("div", []attr{a("class", "card fade-in registry-summary error"), a("data-testid", "registry-failures")},
		divClass("card-title", text("Not added")),
		styled("ul", "margin:8px 0 0;padding-left:18px", items...))
}

func unavailableCard(currentQuery string) node {
	return divClass("card fade-in",
		el("div", []attr{a("class", "registry-error"), a("data-testid", "registry-unavailable")},
			text("Failed to load the registry."), br(), sp(),
			el("a", []attr{a("class", "btn btn-sm"), a("style", "margin-top:14px"), a("href", "/filters/registry"+currentQuery)}, text("Retry"))))
}

func groupOptions(groups []RegistryGroup) []node {
	options := []node{el("option", []attr{a("value", "")}, text("All groups"))}
	for _, group := range groups {
		attrs := []attr{a("value", group.Value)}
		if group.Selected {
			attrs = append(attrs, flag("selected"))
		}
		options = append(options, el("option", attrs, text(group.Label)))
	}
	return options
}

func filterToolbar(page RegistryPage) node {
	deprecated := []attr{a("type", "checkbox"), a("id", "reg-deprecated"), a("name", "deprecated"), a("value", "1")}
	if page.ShowDeprecated {
		deprecated = append(deprecated, flag("checked"))
	}
	form := el("form", []attr{
		a("method", "get"), a("action", "/filters/registry"), a("class", "registry-toolbar"),
		a("id", "registry-filters"), a("data-testid", "registry-filters"),
	},
		void("input", a("type", "text"), a("id", "reg-search"), a("name", "q"), a("value", page.Q), a("placeholder", "Search name or description")), sp(),
		el("select", []attr{a("id", "reg-group"), a("name", "group")}, groupOptions(page.Groups)...), sp(),
		el("label", class("check"), void("input", deprecated...), text(" Show deprecated")), sp(),
		submit("btn btn-sm nojs-only", []attr{a("id", "reg-filter-submit")}, text("Apply")))
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.05s")}, form)
}

func homepageLink(url string) node {
	arrow := icon(
		el("path", []attr{a("d", "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6")}),
		el("polyline", []attr{a("points", "15 3 21 3 21 9")}),
		line("10", "14", "21", "3"))
	return el("a", []attr{a("class", "home"), a("href", url), a("target", "_blank"), a("rel", "noopener noreferrer")},
		arrow, el("span", nil, text("Homepage")))
}

func registryRow(row RegistryRow) node {
	rowAttrs := []attr{a("class", "registry-row"), a("data-testid", "registry-row"), a("data-name", row.Name), a("data-group-id", id64(row.GroupID))}
	if row.Deprecated {
		rowAttrs = append(rowAttrs, a("data-deprecated", "1"))
	}
	checkbox := []attr{a("type", "checkbox"), a("name", "filter_id"), a("value", id64(row.FilterID))}
	if row.AlreadyAdded {
		checkbox = append(checkbox, flag("disabled"))
	}
	nameRow := divClass("name-row",
		span("name", row.Name),
		when(row.GroupName != "", func() node { return span("group-pill "+row.GroupClass, row.GroupName) }),
		when(row.AlreadyAdded, func() node { return span("added-pill", "Added") }),
		when(row.Deprecated, func() node { return span("dep-pill", "Deprecated") }))
	info := divClass("info", nameRow, divClass("desc", text(row.Description)),
		when(row.Homepage != "", func() node { return homepageLink(row.Homepage) }))
	return el("label", rowAttrs, void("input", checkbox...), info)
}

func registryBody(page RegistryPage) node {
	empty := []attr{a("class", "registry-empty"), a("data-testid", "registry-empty")}
	if len(page.Rows) != 0 {
		empty = append(empty, flag("hidden"))
	}
	children := []node{el("div", empty, text("No filters match your search."))}
	for _, row := range page.Rows {
		children = append(children, registryRow(row))
	}
	return el("div", []attr{a("class", "registry-body"), a("id", "reg-body")}, children...)
}

func registryForm(page RegistryPage) node {
	list := el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.08s")},
		el("div", []attr{a("class", "card-title"), a("id", "registry-count"), a("data-testid", "registry-count")},
			text("Showing "+strconv.Itoa(page.Shown)+" of "+strconv.Itoa(page.Total))),
		registryBody(page))
	foot := el("div", []attr{a("class", "card fade-in registry-foot"), a("style", "animation-delay:0.1s")},
		el("div", []attr{a("class", "count"), a("data-testid", "registry-selected")}, text("Up to "+strconv.Itoa(page.Limit)+" lists at a time")), sp(),
		el("a", []attr{a("class", "btn btn-sm"), a("href", "/filters")}, text("Cancel")), sp(),
		submit("btn btn-primary btn-sm", []attr{a("id", "reg-add"), a("data-testid", "registry-add")}, text("Add Selected")))
	return el("form", []attr{a("method", "post"), a("action", "/filters/registry/add"+page.CurrentQuery), a("id", "registry-form")}, list, foot)
}

// Registry renders the registry browser inside the signed-in shell.
func Registry(page RegistryPage) string {
	content := []node{registryForm(page)}
	content = append([]node{filterToolbar(page)}, content...)
	if page.LoadFailed {
		content = []node{unavailableCard(page.CurrentQuery)}
	}
	children := append([]node{
		registryHeader(),
		when(page.AddedCount != 0, func() node { return addedBanner(page.AddedCount) }),
		when(len(page.Failures) != 0, func() node { return failuresCard(page.Failures) }),
	}, content...)
	body := el("registry-page", []attr{a("data-limit", strconv.Itoa(page.Limit))}, children...)
	return Shell(page.Shell, body)
}
