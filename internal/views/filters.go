package views

import "strconv"

// FilterList is one filter list, formatted the way the page shows it.
type FilterList struct {
	ID      int64
	Name    string
	URL     string
	Enabled bool
	// RuleCount is thousands-separated; RuleCountCompact is "12.3K".
	RuleCount        string
	RuleCountCompact string
	// LastUpdatedText is "never" or how long ago; LastUpdated is the raw time
	// app.js derives its own text from.
	LastUpdatedText string
	LastUpdated     int64
	// ImpactText is already phrased; ImpactNone draws it as a badge.
	ImpactText string
	ImpactNone bool
}

// CustomRule is one custom rule.
type CustomRule struct {
	ID    int64
	Rule  string
	Type  string
	Allow bool
}

// FiltersPage is the domain test, the filter lists and the custom rules.
type FiltersPage struct {
	Shell ShellData
	Lists []FilterList
	Rules []CustomRule
	// AllDisabled: every list is off, so nothing is blocked.
	AllDisabled       bool
	TestDomain        string
	DomainSuggestions []string

	Tested         bool
	VerdictBlocked bool
	// VerdictRule is empty when the domain was allowed by default.
	VerdictRule string
	VerdictList string

	// EditID expands one list row into an edit form; zero for none.
	EditID    int64
	EditName  string
	EditURL   string
	EditError string

	ListName string
	ListURL  string
	// ListErrorField is "name" or "url".
	ListErrorField string
	ListError      string
	RuleText       string
	RuleError      string
}

func icon(children ...node) node { return el("svg", svgAttrs(), children...) }

func refreshIcon() node {
	return icon(
		el("polyline", []attr{a("points", "23 4 23 10 17 10")}),
		el("path", []attr{a("d", "M20.49 15a9 9 0 1 1-2.12-9.36L23 10")}))
}

func searchIcon() node {
	return icon(
		el("circle", []attr{a("cx", "11"), a("cy", "11"), a("r", "8")}),
		line("21", "21", "16.65", "16.65"))
}

func plusIcon() node { return icon(line("12", "5", "12", "19"), line("5", "12", "19", "12")) }

func trashIcon() node {
	return icon(
		el("polyline", []attr{a("points", "3 6 5 6 21 6")}),
		el("path", []attr{a("d", "M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2")}))
}

func id64(id int64) string { return strconv.FormatInt(id, 10) }

func sp() node { return text(" ") }

func button(attrs []attr, children ...node) node { return el("button", attrs, children...) }

func submit(classes string, extra []attr, children ...node) node {
	attrs := append([]attr{a("type", "submit"), a("class", classes)}, extra...)
	return button(attrs, children...)
}

func savedBanner(testID, label, meta string) node {
	return el("div", []attr{a("class", "rebuild-banner show done"), a("data-testid", testID)},
		divClass("text", span("label", label), sp(), span("meta", meta)))
}

func fieldMessage(extra []attr, message node) node {
	return el("div", append([]attr{a("class", "field-msg error")}, extra...), message)
}

func secondaryStyle(size, margin string) string {
	return "color:var(--text-secondary);font-size:" + size + ";margin-bottom:" + margin
}

func domainTestForm(page FiltersPage) node {
	input := []attr{
		a("type", "text"), a("id", "test-domain"), a("name", "test"), a("data-testid", "domain-test-input"),
		a("placeholder", "ads.example.com"), a("value", page.TestDomain),
	}
	if len(page.DomainSuggestions) > 0 {
		input = append(input, a("list", "domain-list"))
	}
	input = append(input, a("autocomplete", "off"))
	return el("form", []attr{
		a("method", "get"), a("action", "/filters"), a("class", "input-row"), a("id", "domain-test-form"),
	},
		void("input", input...), sp(),
		datalist("domain-list", page.DomainSuggestions),
		submit("btn btn-primary btn-sm", []attr{a("id", "test-btn"), a("data-testid", "domain-test-submit")}, refreshIcon(), text(" Test")))
}

// datalist is omitted when there are no values; a trailing space follows it
// only when it is rendered.
func datalist(id string, values []string) node {
	if len(values) == 0 {
		return ""
	}
	var options []node
	for _, value := range values {
		options = append(options, void("option", a("value", value)))
	}
	return group(el("datalist", []attr{a("id", id)}, options...), sp())
}

func codeText(s string) node { return el("code", class("text-primary"), text(s)) }

func verdict(page FiltersPage) node {
	if !page.Tested {
		return ""
	}
	if page.VerdictBlocked {
		return group(
			span("badge badge-blocked", "Blocked"), sp(),
			styled("span", "color:var(--text-secondary);font-size:0.85rem;margin-left:8px",
				text("Rule: "), codeText(page.VerdictRule), text(" · List: "), codeText(page.VerdictList)))
	}
	return group(
		span("badge badge-allowed", "Allowed"),
		when(page.VerdictRule != "", func() node {
			return group(sp(), styled("span", "color:var(--text-secondary);font-size:0.85rem;margin-left:8px",
				text("Rule: "), codeText(page.VerdictRule)))
		}))
}

func domainTestCard(page FiltersPage) node {
	return divClass("card fade-in",
		divClass("card-title", text("Domain Test")),
		styled("p", secondaryStyle("0.85rem", "8px"), text("Check whether a domain is allowed or blocked by your current filters.")),
		domainTestForm(page),
		el("div", []attr{a("id", "test-result"), a("data-testid", "domain-test-result"), a("style", "margin-top:12px")}, verdict(page)))
}

func allDisabledWarning(show bool) node {
	attrs := []attr{a("data-testid", "filters-all-disabled-warning")}
	if !show {
		attrs = append(attrs, a("style", "display:none"))
	}
	attrs = append(attrs, a("class", "all-disabled-warning"))
	return el("div", attrs,
		styled("div", "color:var(--text-primary);font-weight:600;margin-bottom:4px", text("No filter list is enabled")),
		styled("div", secondaryStyle("0.9rem", "8px"), text("Every filter list is turned off, so noadd is not blocking anything. Enable a recommended list to start filtering.")),
		el("form", []attr{a("method", "post"), a("action", "/filters/lists/enable-recommended")},
			submit("btn btn-primary btn-sm", []attr{a("data-testid", "filters-enable-recommended"), a("id", "enable-recommended")},
				text("Enable AdGuard DNS filter"))))
}

func listActionsRow() node {
	return el("div", []attr{a("class", "filters-row"), a("style", "margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap")},
		el("form", []attr{a("method", "post"), a("action", "/filters/lists/update")},
			submit("btn btn-primary btn-sm", []attr{a("id", "update-all")}, refreshIcon(), text(" Update All"))),
		sp(),
		el("a", []attr{a("class", "btn btn-sm"), a("href", "/filters/registry"), a("id", "browse-registry")}, searchIcon(), text(" Browse Registry")))
}

// toggleForm is the same markup in the desktop table and the mobile card, bar
// the test id only the table's copy has.
func toggleForm(list FilterList, testID string) node {
	input := []attr{a("type", "checkbox"), a("name", "enabled")}
	if testID != "" {
		input = append(input, a("data-testid", testID))
	}
	input = append(input, a("data-id", id64(list.ID)))
	if list.Enabled {
		input = append(input, flag("checked"))
	}
	return el("form", []attr{
		a("method", "post"), a("action", "/filters/lists/"+id64(list.ID)+"/toggle"), a("class", "list-toggle-form"),
	},
		el("label", class("toggle"), sp(), void("input", input...),
			divClass("toggle-track"), divClass("toggle-thumb")),
		sp(), submit("btn btn-sm nojs-only", nil, text("apply")))
}

func editLink(list FilterList, extra ...attr) node {
	attrs := append([]attr{
		a("href", "/filters?edit="+id64(list.ID)), a("class", "btn btn-sm edit-list"),
		a("data-id", id64(list.ID)), a("data-name", list.Name), a("data-url", list.URL),
	}, extra...)
	return el("a", attrs, text("Edit"))
}

func deleteListForm(list FilterList, extra ...attr) node {
	attrs := append([]attr{
		a("method", "post"), a("action", "/filters/lists/"+id64(list.ID)+"/delete"), a("class", "inline-form"),
	}, extra...)
	return el("form", attrs,
		submit("btn btn-danger btn-sm del-list", []attr{a("data-id", id64(list.ID))}, trashIcon()))
}

func impactCell(list FilterList) node {
	if list.ImpactNone {
		return span("badge badge-off", list.ImpactText)
	}
	return text(list.ImpactText)
}

func listRow(list FilterList) node {
	return el("tr", []attr{a("data-testid", "filter-list-row"), a("data-name", list.Name)},
		el("td", nil, toggleForm(list, "filter-list-toggle")),
		el("td", class("text-primary"), text(list.Name)),
		el("td", nil, text(list.RuleCount)),
		el("td", []attr{a("data-testid", "filter-list-impact")}, impactCell(list)),
		el("td", nil, el("span", []attr{a("class", "timeago"), a("data-ts", id64(list.LastUpdated))}, text(list.LastUpdatedText))),
		el("td", []attr{a("style", "white-space:nowrap")}, editLink(list), sp(), deleteListForm(list)))
}

func editRow(page FiltersPage, list FilterList) node {
	inputs := el("div", class("input-row"),
		void("input", a("type", "text"), a("name", "name"), a("value", page.EditName), a("placeholder", "List name"), a("data-testid", "list-edit-name")), sp(),
		void("input", a("type", "url"), a("name", "url"), a("value", page.EditURL), a("placeholder", "https://..."), a("data-testid", "list-edit-url")), sp(),
		submit("btn btn-primary btn-sm", []attr{a("data-testid", "list-edit-save")}, text("Save")), sp(),
		el("a", []attr{a("href", "/filters"), a("class", "btn btn-sm")}, text("Cancel")))
	form := el("form", []attr{a("method", "post"), a("action", "/filters/lists/"+id64(list.ID)+"/edit")},
		inputs,
		when(page.EditError != "", func() node {
			return fieldMessage([]attr{a("data-testid", "list-edit-error")}, text(page.EditError))
		}))
	return el("tr", []attr{a("class", "edit-row"), a("data-testid", "filter-list-edit-row")},
		el("td", []attr{a("colspan", "6")}, form))
}

func listsTable(page FiltersPage) node {
	var rows []node
	for _, list := range page.Lists {
		rows = append(rows, listRow(list))
		if page.EditID == list.ID {
			rows = append(rows, editRow(page, list))
		}
	}
	head := el("tr", nil, el("th", nil, text("Enabled")), el("th", nil, text("Name")), el("th", nil, text("Rules")),
		el("th", nil, text("Impact")), el("th", nil, text("Updated")), el("th", nil))
	return divClass("table-wrap hide-mobile-block",
		el("table", nil, el("thead", nil, head), el("tbody", []attr{a("id", "lists-body")}, rows...)))
}

func listCard(list FilterList) node {
	row1 := divClass("log-card-row1",
		toggleForm(list, ""), sp(),
		styled("span", "flex:1;color:var(--text-primary);font-size:0.85rem", text(list.Name)), sp(),
		editLink(list, a("style", "flex-shrink:0")), sp(),
		deleteListForm(list, a("style", "flex-shrink:0")))
	row2 := divClass("log-card-row2",
		el("span", nil, text(list.RuleCountCompact+" rules")), sp(),
		el("span", []attr{a("data-testid", "filter-list-impact-card")}, text(list.ImpactText)), sp(),
		el("span", nil, text(list.LastUpdatedText)))
	return divClass("log-card", row1, row2)
}

func listsCards(lists []FilterList) node {
	var cards []node
	for _, list := range lists {
		cards = append(cards, listCard(list))
	}
	return el("div", []attr{a("id", "lists-cards"), a("class", "show-mobile")}, cards...)
}

func addListForm(page FiltersPage) node {
	form := el("form", []attr{a("method", "post"), a("action", "/filters/lists"), a("class", "input-row"), a("id", "add-list-form")},
		void("input", a("type", "text"), a("id", "list-name"), a("name", "name"), a("data-testid", "list-name-input"), a("placeholder", "List name"), a("value", page.ListName)), sp(),
		void("input", a("type", "url"), a("id", "list-url"), a("name", "url"), a("data-testid", "list-url-input"), a("placeholder", "https://..."), a("value", page.ListURL)), sp(),
		submit("btn btn-primary btn-sm", []attr{a("id", "add-list"), a("data-testid", "list-add-submit")}, plusIcon(), text(" Add")))
	message := when(page.ListError != "", func() node {
		return fieldMessage([]attr{a("id", "msg-add-list"), a("data-testid", "list-add-error")}, group(
			text(page.ListError),
			when(page.ListErrorField != "", func() node { return text(" (" + page.ListErrorField + ")") })))
	})
	return group(el("div", []attr{a("class", "card-title"), a("style", "margin-top:16px")}, text("Add Custom List")), form, message)
}

func listsCard(page FiltersPage) node {
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.05s")},
		divClass("card-title", text("Filter Lists")),
		allDisabledWarning(page.AllDisabled),
		listActionsRow(),
		styled("p", secondaryStyle("0.85rem", "8px"),
			text("Impact is what you would stop blocking by turning a list off. Two lists holding the same rules both read "),
			el("em", nil, text("No impact")),
			text(" — turn one off at a time, and the rest recompute.")),
		listsTable(page), listsCards(page.Lists), addListForm(page))
}

func ruleBadge(allow bool) node {
	if allow {
		return span("badge badge-allowed", "allow")
	}
	return span("badge badge-blocked", "block")
}

func ruleRow(rule CustomRule) node {
	remove := el("form", []attr{a("method", "post"), a("action", "/filters/rules/"+id64(rule.ID)+"/delete"), a("class", "inline-form")},
		submit("btn btn-danger btn-sm del-rule", []attr{a("data-testid", "rule-delete"), a("data-id", id64(rule.ID))}, trashIcon()))
	return el("tr", []attr{a("data-testid", "rule-row"), a("data-rule", rule.Rule), a("data-type", rule.Type)},
		styled("td", "width:70px", ruleBadge(rule.Allow)),
		el("td", []attr{a("class", "mono"), a("style", "color:var(--text-primary);font-size:0.85rem")}, text(rule.Rule)),
		styled("td", "width:40px", remove))
}

func rulesList(rules []CustomRule) node {
	attrs := []attr{a("id", "rules-list"), a("data-testid", "rules-list"), a("style", "margin-top:12px")}
	if len(rules) == 0 {
		return el("div", attrs, styled("p", "color:var(--text-dim);font-size:0.85rem", text("No rules")))
	}
	var rows []node
	for _, rule := range rules {
		rows = append(rows, ruleRow(rule))
	}
	return el("div", attrs, el("table", nil, el("tbody", nil, rows...)))
}

func syntaxExample(code, description string) node {
	return el("div", nil, el("code", nil, text(code)), br(), text(description))
}

func syntaxReference() node {
	return divClass("syntax-ref",
		el("strong", class("text-secondary"), text("Syntax Reference")), sp(),
		divClass("syntax-ref-list",
			syntaxExample("||ads.example.com^", "Block domain and all subdomains"),
			syntaxExample("@@||safe.example.com^", "Allow domain and all subdomains"),
			syntaxExample("example.com", "Block exact domain only"),
			syntaxExample("0.0.0.0 example.com", "Block exact domain (hosts format)")))
}

func rulesCard(page FiltersPage) node {
	form := el("form", []attr{a("method", "post"), a("action", "/filters/rules"), a("class", "input-row"), a("id", "add-rule-form")},
		void("input", a("type", "text"), a("id", "add-rule-input"), a("name", "rule"), a("data-testid", "rule-input"),
			a("placeholder", "||ads.example.com^ or @@||safe.example.com^"), a("value", page.RuleText)), sp(),
		submit("btn btn-primary btn-sm", []attr{a("id", "add-rule-btn"), a("data-testid", "rule-submit")}, plusIcon(), text(" Add")))
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.1s")},
		divClass("card-title", text("Custom Rules")), form,
		when(page.RuleError != "", func() node {
			return fieldMessage([]attr{a("id", "msg-add-rule"), a("data-testid", "rule-add-error")}, text(page.RuleError))
		}),
		rulesList(page.Rules), syntaxReference())
}

// Filters renders the filters page inside the signed-in shell.
func Filters(page FiltersPage) string {
	body := el("filters-page", nil,
		divClass("page-header fade-in", el("h2", nil, text("Filters")), el("p", nil, text("Domain test, filter lists, and custom rules"))),
		when(page.Shell.FiltersSaved, func() node {
			return savedBanner("filters-saved", "Saved", "The filter engine is rebuilding; the change takes effect in a moment.")
		}),
		when(page.Shell.ListsUpdating, func() node {
			return savedBanner("lists-updated", "All lists downloaded", "The filter engine is rebuilding with the new rules.")
		}),
		domainTestCard(page), listsCard(page), rulesCard(page))
	return Shell(page.Shell, body)
}
