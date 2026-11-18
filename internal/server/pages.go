package server

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/henry40408/noadd/internal/views"
)

// maxFormBody matches axum's default body limit for the Form extractor.
const maxFormBody = 2 << 20

// onboardingDismissedKey is the setting the onboarding notice's dismissal
// writes; the JSON API shares it.
const onboardingDismissedKey = "onboarding_banner_dismissed"

// writeHTML answers with a rendered page.
func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// redirectSeeOther answers like axum's Redirect::to: 303.
func redirectSeeOther(w http.ResponseWriter, r *http.Request, target string) {
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// ssr runs h for an authenticated operator; otherwise it redirects a page
// request, the way Rust's SsrUser does: to the wizard when no operator exists
// yet, else to sign-in with the destination remembered. Every page and every
// page POST goes through it, so the session is resolved before any HTML.
func (a *api) ssr(h func(http.ResponseWriter, *http.Request, authedUser)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, status := a.authenticate(r)
		if status != 0 {
			if a.needsSetup(r) {
				redirectSeeOther(w, r, "/setup")
				return
			}
			redirectSeeOther(w, r, loginURL(r.URL.RequestURI()))
			return
		}
		h(w, r, user)
	}
}

// maybeUser reports whether the request carries a valid credential.
func (a *api) maybeUser(r *http.Request) bool {
	_, status := a.authenticate(r)
	return status == 0
}

// shellFor builds the shell's data for this request, consuming the pending
// flash (the Set-Cookie that clears it goes on w). path names the page being
// served, which differs from the request path when a rejected POST re-renders
// another page.
func (a *api) shellFor(w http.ResponseWriter, r *http.Request, path string) views.ShellData {
	pending := takeFlash(w, r)
	nextStepAddr, showNextStep := a.nextStepTarget(r, path)
	return views.ShellData{
		Version:           a.Version,
		Host:              requestHost(r),
		CurrentPath:       path,
		Welcome:           pending == flashWelcome,
		ProxyLogoutNotice: pending == flashProxyLogout,
		SettingsSaved:     pending == flashSettingsSaved,
		PasswordChanged:   pending == flashPasswordChanged,
		FiltersSaved:      pending == flashFiltersSaved,
		ListsUpdating:     pending == flashListsUpdating,
		AccountSaved:      pending == flashAccountSaved,
		SessionsRevoked:   pending == flashSessionsRevoked,
		LogsCleared:       pending == flashLogsCleared,
		ShowNextStep:      showNextStep,
		NextStepAddr:      nextStepAddr,
	}
}

func (a *api) shell(w http.ResponseWriter, r *http.Request) views.ShellData {
	return a.shellFor(w, r, r.URL.Path)
}

// nextStepTarget says where to tell an operator to point a device, or false
// when the notice is not shown. Checks run cheapest first: the hub's traffic
// latch settles it without a database read on any install that has served
// traffic.
func (a *api) nextStepTarget(r *http.Request, path string) (string, bool) {
	// The dashboard has its own empty state; both would read as two notices.
	if path == "/" {
		return "", false
	}
	if a.Events != nil && a.Events.HasTraffic() {
		return "", false
	}
	any, err := a.DB.HasAnyQueryLogs(r.Context())
	// A failed read hides the notice: wrongly showing it to a working
	// appliance is worse than briefly missing it on a fresh one.
	if err != nil {
		return "", false
	}
	if any {
		if a.Events != nil {
			a.Events.NoteTraffic()
		}
		return "", false
	}
	dismissed, found, err := a.DB.GetSetting(r.Context(), onboardingDismissedKey)
	if err == nil && found && dismissed == "true" {
		return "", false
	}
	return dnsTarget(requestHost(r), a.ServerInfo.DNSAddr), true
}

// parseForm reads an application/x-www-form-urlencoded body like axum's Form
// extractor: 415 for another content type, 413 past 2 MiB, 400 for bad
// encoding. It reports whether parsing succeeded.
func parseForm(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	contentType := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
	if contentType != "application/x-www-form-urlencoded" {
		writeText(w, http.StatusUnsupportedMediaType,
			"Form requests must have `Content-Type: application/x-www-form-urlencoded`")
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeText(w, http.StatusRequestEntityTooLarge, "length limit exceeded")
			return nil, false
		}
		writeText(w, http.StatusBadRequest, "Failed to deserialize form body")
		return nil, false
	}
	return r.PostForm, true
}

// requireFields answers 422 as serde does for the first absent field.
func requireFields(w http.ResponseWriter, form url.Values, names ...string) bool {
	for _, name := range names {
		if _, present := form[name]; !present {
			writeText(w, http.StatusUnprocessableEntity,
				"Failed to deserialize form body: missing field `"+name+"`")
			return false
		}
	}
	return true
}

// registerPageRoutes adds the server-rendered pages and their form posts.
func (a *api) registerPageRoutes(t *routeTable) {
	const (
		get  = http.MethodGet
		post = http.MethodPost
	)
	t.handleFunc(get, "/{$}", a.ssr(a.dashboardPage))
	t.handleFunc(get, "/stats", a.ssr(a.statsPage))
	t.handleFunc(get, "/logs", a.ssr(a.logsPage))
	t.handleFunc(post, "/logs/rules", a.ssr(a.logsRuleSubmit))
	t.handleFunc(post, "/logs/clear", a.ssr(a.logsClearSubmit))
	t.handleFunc(post, "/onboarding/dismiss", a.ssr(a.onboardingDismissSubmit))
	t.handleFunc(get, "/login", a.loginPage)
	t.handleFunc(post, "/login", a.loginSubmit)
	t.handleFunc(get, "/setup", a.setupPage)
	t.handleFunc(post, "/setup", a.setupSubmit)
	t.handleFunc(post, "/logout", a.ssr(a.logoutSubmit))
	t.handleFunc(get, "/settings", a.ssr(a.settingsPage))
	t.handleFunc(post, "/settings", a.ssr(a.settingsSubmit))
	t.handleFunc(get, "/account", a.ssr(a.accountPage))
	t.handleFunc(post, "/account/password", a.ssr(a.accountPasswordSubmit))
	t.handleFunc(post, "/account/operators", a.ssr(a.accountOperatorAddSubmit))
	t.handleFunc(post, "/account/operators/{id}/delete", a.ssr(a.accountOperatorDeleteSubmit))
	t.handleFunc(post, "/account/sessions/{id}/revoke", a.ssr(a.accountSessionRevokeSubmit))
	t.handleFunc(post, "/account/sessions/revoke-others", a.ssr(a.accountSessionsRevokeOthersSubmit))
	t.handleFunc(post, "/account/api-keys", a.ssr(a.accountAPIKeyCreateSubmit))
	t.handleFunc(post, "/account/api-keys/{id}/delete", a.ssr(a.accountAPIKeyDeleteSubmit))
}
