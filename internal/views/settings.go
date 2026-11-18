package views

// SettingsPage is the settings form.
type SettingsPage struct {
	Shell            ShellData
	UpstreamServers  string
	UpstreamStrategy string
	DNSSECOn         bool
	BlockMode        string
	BlockCustomIPv4  string
	BlockCustomIPv6  string
	LogRetentionDays string
	PublicURL        string
	DoHAccessPolicy  string

	// The suggestions back the three free-text fields' datalists.
	BlockCustomIPv4Suggestions []string
	BlockCustomIPv6Suggestions []string
	LogRetentionSuggestions    []string

	// ErrorField names the field a rejected save objected to, so the message
	// lands next to that input. Empty when there is nothing to report.
	ErrorField   string
	ErrorMessage string
	Saved        bool
}

// fieldMsg is the line under a field; it carries the error when field failed.
func fieldMsg(page SettingsPage, id, field string) node {
	failed := page.ErrorField == field
	classes := "field-msg"
	if failed {
		classes += " error"
	}
	return el("div", []attr{a("class", classes), a("id", id)},
		when(failed, func() node { return text(page.ErrorMessage) }))
}

// plainMsg is a field-msg the server never fills.
func plainMsg(id string) node {
	return el("div", []attr{a("class", "field-msg"), a("id", id)})
}

func selectField(id, name string, options ...node) node {
	return el("select", []attr{a("id", id), a("name", name)}, options...)
}

func inputRow(style string, children ...node) node {
	attrs := []attr{a("class", "input-row")}
	if style != "" {
		attrs = append(attrs, a("style", style))
	}
	return el("div", attrs, children...)
}

func cardTitle(title string) node { return divClass("card-title", text(title)) }

func spacedTitle(title string) node {
	return el("div", []attr{a("class", "card-title"), a("style", "margin-top:16px")}, text(title))
}

func cardDesc(children ...node) node { return el("p", class("card-desc"), children...) }

func accentCode(content string) node {
	return styled("code", "color:var(--accent);font-size:0.8rem", text(content))
}

func fieldLabel(forID, label string) node {
	return el("label", []attr{a("class", "field-label"), a("for", forID)}, text(label))
}

func settingsDatalist(id string, values []string) node {
	var options []node
	for _, value := range values {
		options = append(options, el("option", []attr{a("value", value)}))
	}
	return el("datalist", []attr{a("id", id)}, options...)
}

func serverInfoCard() node {
	return divClass("card fade-in",
		cardTitle("Server Info"),
		styled("p", "color:var(--text-dim);font-size:0.8rem;margin-bottom:12px", text("These values are set via CLI arguments and cannot be changed at runtime.")),
		el("div", []attr{a("id", "server-info"), a("style", "font-family:var(--font-sans);font-size:0.85rem;color:var(--text-secondary)")}, text("Loading...")))
}

func upstreamIntro() node {
	return styled("p", "color:var(--text-secondary);font-size:0.8rem;margin-bottom:6px",
		text("One server per line — "), el("code", class("text-accent"), text("ip:port")),
		text(", "), el("code", class("text-accent"), text("tls://host")),
		text(" (DoT), or "), el("code", class("text-accent"), text("https://host/dns-query")),
		text(" (DoH)"))
}

func upstreamCard(page SettingsPage) node {
	// The placeholder keeps its "&#10;" so the browser shows a line break.
	textarea := raw(`<textarea id="s-upstream" name="upstream_servers" rows="4" placeholder="1.1.1.1:53&#10;tls://dns.quad9.net:853">` +
		escape(page.UpstreamServers) + `</textarea>`)
	strategy := selectField("s-strategy", "upstream_strategy",
		selectOption("sequential", "Sequential (try in order)", page.UpstreamStrategy == "sequential"),
		selectOption("round-robin", "Round Robin (rotate)", page.UpstreamStrategy == "round-robin"),
		selectOption("lowest-latency", "Lowest Latency (fastest first)", page.UpstreamStrategy == "lowest-latency"))
	dnssec := selectField("s-dnssec", "dnssec",
		selectOption("on", "On (surface AD)", page.DNSSECOn),
		selectOption("off", "Off", !page.DNSSECOn))
	blockMode := selectField("s-block-mode", "block_mode",
		selectOption("null_ip", "Null IP (0.0.0.0 / ::)", page.BlockMode == "null_ip"),
		selectOption("nxdomain", "NXDOMAIN", page.BlockMode == "nxdomain"),
		selectOption("refused", "REFUSED", page.BlockMode == "refused"),
		selectOption("custom_ip", "Custom IP", page.BlockMode == "custom_ip"))
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.05s")},
		cardTitle("Upstream DNS"), upstreamIntro(), textarea,
		fieldMsg(page, "msg-upstream", "upstream_servers"),
		styled("div", "margin-top:8px;display:flex;align-items:center;gap:10px",
			submit("btn btn-sm btn-primary", []attr{a("id", "apply-upstream")}, text("Save & apply")), sp(),
			el("span", []attr{a("id", "upstream-apply-msg"), a("style", "font-size:0.8rem")})),
		el("div", []attr{a("id", "upstream-health"), a("style", "margin-top:14px")}),
		spacedTitle("Strategy"),
		styled("p", secondaryStyle("0.85rem", "8px"), text("How upstream servers are selected for each DNS query.")),
		inputRow("margin-bottom:2px", strategy), plainMsg("msg-strategy"),
		el("div", []attr{a("id", "ema-latency"), a("style", "margin-top:12px")}),
		spacedTitle("DNSSEC"),
		cardDesc(text("Surfaces the upstream's DNSSEC verdict (AD flag) per query in the log. This is transparency, not local validation — for end-to-end trustworthy results: use a validating upstream (1.1.1.1 / 9.9.9.9), set the upstream to "),
			accentCode("tls://…"),
			text(" so the verdict reaches noadd untampered, and point devices at noadd's DoH endpoint.")),
		fieldLabel("s-dnssec", "DNSSEC status"), inputRow("margin-bottom:2px", dnssec), plainMsg("msg-dnssec"),
		spacedTitle("Block mode"),
		cardDesc(text("How blocked queries are answered. Default returns a null IP (0.0.0.0 / ::).")),
		fieldLabel("s-block-mode", "Response"), inputRow("margin-bottom:2px", blockMode),
		fieldMsg(page, "msg-block-mode", "block_mode"),
		customBlockFields(page))
}

func customIPInput(id, name, value, placeholder, listID string) node {
	return inputRow("margin-bottom:2px", void("input",
		a("type", "text"), a("id", id), a("name", name), a("value", value),
		a("placeholder", placeholder), a("list", listID), a("autocomplete", "off")))
}

func customBlockFields(page SettingsPage) node {
	attrs := []attr{a("id", "s-block-custom")}
	if page.BlockMode != "custom_ip" {
		attrs = append(attrs, a("style", "display:none"))
	}
	return el("div", attrs,
		customIPInput("s-block-ipv4", "block_custom_ipv4", page.BlockCustomIPv4, "Custom IPv4 for A, e.g. 192.0.2.1", "block-ipv4-list"),
		settingsDatalist("block-ipv4-list", page.BlockCustomIPv4Suggestions),
		fieldMsg(page, "msg-block-ipv4", "block_custom_ipv4"),
		customIPInput("s-block-ipv6", "block_custom_ipv6", page.BlockCustomIPv6, "Custom IPv6 for AAAA, e.g. 100::1", "block-ipv6-list"),
		settingsDatalist("block-ipv6-list", page.BlockCustomIPv6Suggestions),
		fieldMsg(page, "msg-block-ipv6", "block_custom_ipv6"))
}

func retentionCard(page SettingsPage) node {
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.1s")},
		cardTitle("Log Retention"),
		inputRow("margin-bottom:2px",
			void("input", a("type", "text"), a("id", "s-retention"), a("name", "log_retention_days"), a("value", page.LogRetentionDays),
				a("placeholder", "7"), a("style", "max-width:80px"), a("list", "retention-list"), a("autocomplete", "off")),
			styled("span", "color:var(--text-dim);font-size:0.85rem", text("days"))),
		settingsDatalist("retention-list", page.LogRetentionSuggestions),
		fieldMsg(page, "msg-retention", "log_retention_days"))
}

func publicURLCard(page SettingsPage) node {
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.12s")},
		cardTitle("Public URL"),
		styled("p", secondaryStyle("0.85rem", "8px"), text("Used for Apple mobileconfig profiles. Must be HTTPS with a valid domain.")),
		inputRow("margin-bottom:2px", void("input", a("type", "url"), a("id", "s-public-url"), a("name", "public_url"),
			a("value", page.PublicURL), a("placeholder", "https://dns.example.com"))),
		fieldMsg(page, "msg-public-url", "public_url"))
}

func dohPolicyCard(page SettingsPage) node {
	policy := selectField("s-doh-policy", "doh_access_policy",
		selectOption("allow", "Allow (open access)", page.DoHAccessPolicy == "allow"),
		selectOption("deny", "Deny (require token)", page.DoHAccessPolicy == "deny"))
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.2s;margin-top:24px")},
		cardTitle("DoH Access Control"),
		cardDesc(text("Default policy for unauthenticated DoH requests (without a token in URL).")),
		fieldLabel("s-doh-policy", "Default Policy"), inputRow("", policy), plainMsg("msg-doh-policy"))
}

func saveRow(saved bool) node {
	return el("div", []attr{
		a("class", "fade-in"), a("id", "settings-save-row"),
		a("style", "animation-delay:0.15s;margin-top:4px;display:flex;align-items:center;gap:10px"),
	},
		submit("btn btn-primary btn-sm", []attr{a("id", "save-settings"), a("data-testid", "save-settings")}, text("Save settings")),
		when(saved, func() node {
			return group(sp(), el("span", []attr{a("style", "color:var(--accent);font-size:0.8rem"), a("data-testid", "settings-saved")}, text("✔ saved")))
		}))
}

func dohTokensCard() node {
	return el("div", []attr{a("class", "card fade-in"), a("style", "animation-delay:0.22s;margin-top:24px")},
		cardTitle("DoH Tokens"),
		cardDesc(text("Each token becomes a DoH URL path: "), accentCode("/dns-query/your-token"), text(". Always works regardless of policy.")),
		inputRow("",
			void("input", a("type", "text"), a("id", "token-value"), a("placeholder", "e.g. my-phone, home-network")), sp(),
			button([]attr{a("type", "button"), a("class", "btn btn-primary btn-sm"), a("id", "add-token")}, text("Add"))),
		el("div", []attr{a("id", "doh-tokens-list")}))
}

// Settings renders the settings page inside the signed-in shell.
func Settings(page SettingsPage) string {
	form := el("form", []attr{a("method", "post"), a("action", "/settings"), a("id", "settings-form")},
		upstreamCard(page), retentionCard(page), publicURLCard(page), dohPolicyCard(page), saveRow(page.Saved))
	body := el("settings-page", nil,
		divClass("page-header fade-in", el("h2", nil, text("Settings")), el("p", nil, text("Server configuration"))),
		serverInfoCard(), form, dohTokensCard())
	return Shell(page.Shell, body)
}
