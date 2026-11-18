package views

import "strconv"

// LoginPage is the sign-in page.
type LoginPage struct {
	Version  string
	Error    string
	Username string
	// Next is where to go after signing in; empty omits the hidden field.
	Next string
}

// SetupPage is the first-run wizard.
type SetupPage struct {
	Error             string
	Username          string
	MinPasswordLength int
}

const bootLogo = "\n" +
	"███╗   ██╗ ██████╗  █████╗ ██████╗ ██████╗\n" +
	"████╗  ██║██╔═══██╗██╔══██╗██╔══██╗██╔══██╗\n" +
	"██╔██╗ ██║██║   ██║███████║██║  ██║██║  ██║\n" +
	"██║╚██╗██║██║   ██║██╔══██║██║  ██║██║  ██║\n" +
	"██║ ╚████║╚██████╔╝██║  ██║██████╔╝██████╔╝\n" +
	"╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═════╝"

func bootLogoNode() node {
	return el("pre", []attr{a("class", "boot-logo"), a("aria-hidden", "true")}, text(bootLogo))
}

func br() node { return void("br") }

// errorBox is the message box both pages share, hidden until there is a
// message, which is what rendering without app.js needs.
func errorBox(id, testID, message string) node {
	attrs := []attr{a("class", "login-error"), a("id", id), a("data-testid", testID), a("role", "alert")}
	if message != "" {
		attrs = append(attrs, a("style", "display:block"))
	}
	return el("div", attrs, when(message != "", func() node { return text(message) }))
}

func span(class, content string) node {
	return el("span", []attr{a("class", class)}, text(content))
}

func loginLine(label, labelFor string, input node) node {
	return el("div", []attr{a("class", "login-line")},
		el("label", []attr{a("for", labelFor)}, text(label)), text(" "), input)
}

func submitButton(id, testID, label string) node {
	return el("button", []attr{
		a("type", "submit"), a("class", "btn btn-primary boot-submit"), a("id", id), a("data-testid", testID),
	}, text(label))
}

func bootBox(children ...node) string {
	box := el("div", []attr{a("class", "login-box boot fade-in")}, children...)
	return document(el("div", []attr{a("class", "login-container")}, box), "")
}

// Login renders the sign-in page.
func Login(page LoginPage) string {
	logLines := []node{text("noadd dns sinkhole")}
	if page.Version != "" {
		logLines = append(logLines, text(" · "+page.Version))
	}
	logLines = append(logLines, br(),
		text("admin console ............ "), span("ok", "ok"), br(),
		text("session .................. "), span("ok", "awaiting operator"), br())
	form := []node{}
	if page.Next != "" {
		form = append(form, void("input", a("type", "hidden"), a("name", "next"), a("value", page.Next)))
	}
	form = append(form,
		loginLine("username:", "li-user", void("input",
			a("type", "text"), a("id", "li-user"), a("name", "username"), a("autocomplete", "username"),
			a("data-testid", "login-username"), a("value", page.Username), flag("autofocus"))),
		loginLine("password:", "pw", void("input",
			a("type", "password"), a("id", "pw"), a("name", "password"), a("autocomplete", "current-password"),
			a("data-testid", "login-password"))),
		submitButton("login-btn", "login-submit", "authenticate"))
	return bootBox(
		bootLogoNode(),
		el("div", []attr{a("class", "boot-log")}, logLines...),
		errorBox("login-error", "login-error", page.Error),
		el("form", []attr{a("method", "post"), a("action", "/login")}, form...))
}

// Setup renders the first-run wizard.
func Setup(page SetupPage) string {
	logLines := []node{
		text("noadd dns sinkhole · first boot"), br(),
		text("admin account ............ "), span("warn", "none"), br(),
		text("create operator credentials to continue_"),
	}
	passwordInput := func(id, name, testID string) node {
		return void("input", a("type", "password"), a("id", id), a("name", name),
			a("autocomplete", "new-password"), a("data-testid", testID))
	}
	form := el("form", []attr{a("method", "post"), a("action", "/setup")},
		loginLine("username:", "setup-user", void("input",
			a("type", "text"), a("id", "setup-user"), a("name", "username"), a("autocomplete", "username"),
			a("data-testid", "setup-username"), a("value", page.Username), flag("autofocus"))),
		loginLine("password:", "setup-pw", passwordInput("setup-pw", "password", "setup-password")),
		loginLine("confirm:", "setup-pw2", passwordInput("setup-pw2", "confirm", "setup-password-confirm")),
		loginLine("setup token:", "setup-token", void("input",
			a("type", "text"), a("id", "setup-token"), a("name", "setup_token"), a("autocomplete", "off"),
			a("autocapitalize", "characters"), a("spellcheck", "false"), a("placeholder", "XXXXX-XXXXX"),
			a("data-testid", "setup-token"))),
		submitButton("setup-btn", "setup-submit", "create account"),
		el("div", []attr{a("class", "boot-hint")},
			text("minimum "+strconv.Itoa(page.MinPasswordLength)+" characters — a few unrelated words work best")),
		el("div", []attr{a("class", "boot-hint")},
			text("setup token: printed to the server's stderr when noadd started with no operator")))
	return bootBox(
		bootLogoNode(),
		el("div", []attr{a("class", "boot-log")}, logLines...),
		errorBox("setup-error", "setup-error", page.Error),
		form)
}
