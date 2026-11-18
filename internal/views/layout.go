package views

// NavItem is one navigation entry. The single Nav table drives both the
// desktop strip and the mobile F-key bar.
type NavItem struct {
	Href   string
	TestID string
	// Key is the digit shown in the desktop strip ("1:" to "6:").
	Key string
	// FKey is the function key shown in the mobile bar ("F1" to "F6").
	FKey  string
	Label string
	// Short is the abbreviated label of the narrow mobile bar.
	Short string
}

// Nav is the navigation, in display order.
var Nav = []NavItem{
	{Href: "/", TestID: "nav-dashboard", Key: "1", FKey: "F1", Label: "dashboard", Short: "dash"},
	{Href: "/stats", TestID: "nav-stats", Key: "2", FKey: "F2", Label: "statistics", Short: "stats"},
	{Href: "/logs", TestID: "nav-logs", Key: "3", FKey: "F3", Label: "query-log", Short: "logs"},
	{Href: "/filters", TestID: "nav-filters", Key: "4", FKey: "F4", Label: "filters", Short: "filt"},
	{Href: "/settings", TestID: "nav-settings", Key: "5", FKey: "F5", Label: "settings", Short: "conf"},
	{Href: "/account", TestID: "nav-account", Key: "6", FKey: "F6", Label: "account", Short: "acct"},
}

// ShellData is everything the signed-in shell needs, independent of the page
// inside it. The flash flags are resolved where the flash is consumed, because
// consuming it twice would lose it.
type ShellData struct {
	Version string
	// Host is the request's Host, shown in the status bar. Attacker-influenced,
	// so it only ever goes through escaping.
	Host string
	// CurrentPath makes the matching navigation item render active.
	CurrentPath string

	Welcome           bool
	ProxyLogoutNotice bool
	SettingsSaved     bool
	PasswordChanged   bool
	FiltersSaved      bool
	ListsUpdating     bool
	AccountSaved      bool
	SessionsRevoked   bool
	LogsCleared       bool
	// ShowNextStep shows the onboarding notice; NextStepAddr is where to point
	// a device, empty when the notice is not shown.
	ShowNextStep bool
	NextStepAddr string
}

const fontsURL = "https://fonts.bunny.net/css?family=ibm-plex-mono:400,500,600,700&display=swap"

// document is the bare document: content goes in #app, scripts after it. Login
// and setup pass none, since they work without any.
func document(content, scripts node) string {
	head := el("head", nil,
		void("meta", a("charset", "UTF-8")),
		void("meta", a("name", "viewport"), a("content", "width=device-width, initial-scale=1.0")),
		void("link", a("rel", "icon"), a("type", "image/svg+xml"), a("href", "/favicon.svg")),
		void("link", a("rel", "apple-touch-icon"), a("href", "/apple-touch-icon.png")),
		el("title", nil, text("noadd")),
		void("link", a("rel", "preconnect"), a("href", "https://fonts.bunny.net")),
		// Unescaped on purpose: the "&" is part of the URL as served before.
		raw(`<link href="`+fontsURL+`" rel="stylesheet">`),
		void("link", a("rel", "stylesheet"), a("href", "/app.css")),
	)
	body := el("body", nil, el("div", []attr{a("id", "app")}, content), scripts)
	return "<!DOCTYPE html>" + el("html", []attr{a("lang", "en")}, head, body).String()
}

func navClass(item NavItem, currentPath string) string {
	if item.Href == currentPath {
		return "nav-item active"
	}
	return "nav-item"
}

func navStrip(shell ShellData) node {
	var items []node
	for _, item := range Nav {
		items = append(items, text(" "), el("a", []attr{
			a("class", navClass(item, shell.CurrentPath)), a("href", item.Href), a("data-testid", item.TestID),
		}, el("b", nil, text(item.Key+":")), text(item.Label)))
	}
	return el("nav", []attr{a("class", "nav-strip")}, items...)
}

func functionKeyBar(shell ShellData) node {
	var items []node
	for _, item := range Nav {
		items = append(items, text(" "), el("a", []attr{
			a("class", navClass(item, shell.CurrentPath)), a("href", item.Href),
		}, el("span", []attr{a("class", "fk")}, text(item.FKey)), el("b", nil, text(item.Short))))
	}
	return el("nav", []attr{a("class", "fnbar")}, items...)
}

func topbar(shell ShellData) node {
	return el("header", []attr{a("class", "topbar")},
		el("div", []attr{a("class", "brand")}, text("noadd "), el("span", []attr{a("class", "v")}, text(shell.Version))),
		navStrip(shell),
		el("div", []attr{a("class", "topbar-meta")}, text("dns sinkhole")),
		el("form", []attr{a("method", "post"), a("action", "/logout"), a("class", "topbar-logout")},
			el("button", []attr{
				a("type", "submit"), a("class", "nav-item"), a("id", "topbar-logout"),
				a("data-testid", "topbar-logout"), a("title", "Log out of this session"),
			}, text("[ logout ]"))),
	)
}

func welcomeBanner() node {
	check := el("svg", []attr{a("viewBox", "0 0 24 24"), a("fill", "none"), a("stroke", "currentColor"), a("stroke-width", "2")},
		el("polyline", []attr{a("points", "20 6 9 17 4 12")}))
	return el("div", []attr{a("class", "rebuild-banner show done"), a("data-testid", "setup-welcome")},
		el("div", []attr{a("class", "icon")}, check),
		el("div", []attr{a("class", "text")},
			el("span", []attr{a("class", "label")}, text("Setup complete — welcome to noadd!")),
			text(" "),
			el("span", []attr{a("class", "meta")}, text("Your admin password is set and you're signed in."))))
}

func proxyLogoutBanner() node {
	return el("div", []attr{a("class", "rebuild-banner show"), a("data-testid", "proxy-logout-notice")},
		el("div", []attr{a("class", "text")},
			el("span", []attr{a("class", "label")}, text("This session is managed by your reverse proxy")),
			text(" "),
			el("span", []attr{a("class", "meta")}, text("noadd cannot end it — log out at your proxy or SSO provider instead."))))
}

func svgAttrs() []attr {
	return []attr{a("viewBox", "0 0 24 24"), a("fill", "none"), a("stroke", "currentColor"), a("stroke-width", "2")}
}

func rect(x, y string) node {
	return el("rect", []attr{a("x", x), a("y", y), a("width", "7"), a("height", "7"), a("rx", "1")})
}

func line(x1, y1, x2, y2 string) node {
	return el("line", []attr{a("x1", x1), a("y1", y1), a("x2", x2), a("y2", y2)})
}

// nextStepBanner is decided by the server, not fetched by the client.
func nextStepBanner(shell ShellData) node {
	icon := el("span", []attr{a("class", "icon")},
		el("svg", svgAttrs(), rect("3", "3"), rect("14", "3"), rect("3", "14"), rect("14", "14")))
	label := el("span", []attr{a("class", "label")},
		text("Point a device's DNS at noadd to start blocking — set its DNS server to "),
		el("strong", []attr{a("data-testid", "next-step-banner-addr")}, text(shell.NextStepAddr)),
		text("."))
	dismiss := el("form", []attr{a("method", "post"), a("action", "/onboarding/dismiss"), a("style", "margin-left:auto")},
		void("input", a("type", "hidden"), a("name", "next"), a("value", shell.CurrentPath)),
		text(" "),
		el("button", []attr{
			a("class", "btn"), a("type", "submit"), a("data-testid", "next-step-banner-dismiss"), a("title", "Dismiss"),
		}, el("svg", svgAttrs(), line("18", "6", "6", "18"), line("6", "6", "18", "18"))))
	banner := el("div", []attr{
		a("class", "rebuild-banner show"), a("role", "status"), a("aria-live", "polite"), a("data-testid", "next-step-banner"),
	}, icon, text(" "), el("span", []attr{a("class", "text")}, text(" "), label, text(" ")), dismiss)
	return el("next-step-banner", nil, banner)
}

func statusBar(shell ShellData) node {
	// Ships hidden: without a client it cannot sense the server, so it must not
	// claim it is up.
	return el("footer", []attr{a("class", "statusbar")},
		el("server-status", []attr{a("class", "live"), a("data-testid", "server-status"), flag("hidden")}, text("ONLINE")),
		text(" "),
		el("span", nil, text("noadd "+shell.Version)),
		text(" "),
		el("span", []attr{a("class", "right")}, text(shell.Host)))
}

// Shell is the signed-in application shell, settled entirely by the server:
// the active nav item, the version, the status-bar host and any one-shot
// notice. The page body fills #page-content; its custom element upgrades in
// place.
func Shell(shell ShellData, page node) string {
	main := el("main", []attr{a("class", "main-content")},
		when(shell.Welcome, welcomeBanner),
		when(shell.ProxyLogoutNotice, proxyLogoutBanner),
		el("div", []attr{a("id", "notice-host")}),
		el("rebuild-banner", nil),
		when(shell.ShowNextStep, func() node { return nextStepBanner(shell) }),
		el("div", []attr{a("id", "page-content")}, page))
	content := el("div", []attr{a("class", "app-shell"), a("data-testid", "app-shell")},
		topbar(shell), main, statusBar(shell), functionKeyBar(shell))
	return document(content, el("script", []attr{a("src", "/app.js")}))
}
