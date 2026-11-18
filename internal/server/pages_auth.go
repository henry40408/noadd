package server

import (
	"net/http"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/views"
)

// loginPage handles GET /login. A signed-in browser is sent onwards; with no
// operator yet, to the wizard.
func (a *api) loginPage(w http.ResponseWriter, r *http.Request) {
	next, hasNext := safeNext(r.URL.Query().Get("next"))
	if a.maybeUser(r) {
		redirectSeeOther(w, r, nextOrRoot(next, hasNext))
		return
	}
	if a.needsSetup(r) {
		redirectSeeOther(w, r, "/setup")
		return
	}
	writeHTML(w, http.StatusOK, views.Login(views.LoginPage{Version: a.Version, Next: nextIf(next, hasNext)}))
}

func nextOrRoot(next string, ok bool) string {
	if ok {
		return next
	}
	return "/"
}

func nextIf(next string, ok bool) string {
	if ok {
		return next
	}
	return ""
}

// loginSubmit handles POST /login. A refusal re-renders the form (keeping the
// message and username) with a real status: 401 for a bad credential, 429 for
// the rate limit, never 200.
func (a *api) loginSubmit(w http.ResponseWriter, r *http.Request) {
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, "username", "password") {
		return
	}
	username := form.Get("username")
	next, hasNext := safeNext(form.Get("next"))
	token, failure := a.startPasswordSession(r, loginAttempt{username: username, password: form.Get("password")})
	if failure == 0 {
		http.SetCookie(w, a.sessionCookie(token))
		redirectSeeOther(w, r, nextOrRoot(next, hasNext))
		return
	}
	status, message := loginFailureText(failure)
	writeHTML(w, status, views.Login(views.LoginPage{
		Version: a.Version, Error: message, Username: username, Next: nextIf(next, hasNext),
	}))
}

func loginFailureText(failure loginFailure) (int, string) {
	switch failure {
	case loginRateLimited:
		return http.StatusTooManyRequests, "ERR: too many attempts — wait a minute, then retry"
	case loginInvalid:
		return http.StatusUnauthorized, "ERR: incorrect password — access denied"
	default:
		return http.StatusInternalServerError, "ERR: internal error — check the server log"
	}
}

func setupView(message, username string) string {
	return views.Setup(views.SetupPage{Error: message, Username: username, MinPasswordLength: auth.MinPasswordLength})
}

// setupPage handles GET /setup.
func (a *api) setupPage(w http.ResponseWriter, r *http.Request) {
	if !a.needsSetup(r) {
		redirectSeeOther(w, r, "/login")
		return
	}
	writeHTML(w, http.StatusOK, setupView("", ""))
}

// setupSubmit handles POST /setup. The confirm field exists only in the form,
// so it is checked here rather than in the shared createFirstOperator. A
// successful setup signs the operator straight in.
func (a *api) setupSubmit(w http.ResponseWriter, r *http.Request) {
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, "username", "password", "confirm") {
		return
	}
	username, password := form.Get("username"), form.Get("password")
	if password != form.Get("confirm") {
		writeHTML(w, http.StatusBadRequest, setupView("Passwords do not match", username))
		return
	}
	if failure := a.createFirstOperator(r, username, password, form.Get("setup_token")); failure != nil {
		status, message := setupFailureText(failure)
		writeHTML(w, status, setupView(message, username))
		return
	}
	token, loginFail := a.startPasswordSession(r, loginAttempt{username: username, password: password})
	if loginFail != 0 {
		// The account exists; only the automatic sign-in failed, so /login
		// rather than a wizard that would refuse to run again.
		redirectSeeOther(w, r, "/login")
		return
	}
	http.SetCookie(w, a.sessionCookie(token))
	setFlash(w, flashWelcome)
	redirectSeeOther(w, r, "/")
}

func setupFailureText(failure *setupError) (int, string) {
	switch failure.failure {
	case setupDisabled:
		return http.StatusForbidden, "setup is disabled when forward auth is configured"
	case setupAlreadyConfigured:
		return http.StatusConflict, "already configured"
	case setupRateLimited:
		return http.StatusTooManyRequests, "too many attempts, try again later"
	case setupBadToken:
		return http.StatusForbidden, setupTokenRefusal
	case setupInvalid:
		return http.StatusBadRequest, failure.message
	default:
		return http.StatusInternalServerError, "internal error — check the server log"
	}
}

// logoutSubmit handles POST /logout: a form, so it works without JavaScript; a
// POST, so a link prefetcher cannot sign anyone out.
func (a *api) logoutSubmit(w http.ResponseWriter, r *http.Request, user authedUser) {
	redirectTo, hasRedirect := a.endSession(w, r, user)
	if hasRedirect {
		// The proxy owns this session; hand the browser to its logout URL.
		w.Header().Set("Clear-Site-Data", clearSiteData)
		redirectSeeOther(w, r, redirectTo)
		return
	}
	if user.ViaForwardAuth {
		// Proxy-managed with nowhere to hand off to: the next request carries
		// the same header, so tell the operator where to end the session. No
		// Clear-Site-Data, which would also wipe the flash explaining this.
		setFlash(w, flashProxyLogout)
		redirectSeeOther(w, r, "/")
		return
	}
	// No next: the session just ended is not somewhere to return to.
	w.Header().Set("Clear-Site-Data", clearSiteData)
	redirectSeeOther(w, r, "/login")
}

// onboardingDismissSubmit handles POST /onboarding/dismiss: a real form, so
// dismissal works without JavaScript. It writes the same setting as the JSON
// API.
func (a *api) onboardingDismissSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, "next") {
		return
	}
	// On failure the notice just comes back later, which beats a 500.
	_ = a.DB.SetSetting(writeCtx(r), onboardingDismissedKey, "true")
	// No flash: the operator asked for one less notice, not another.
	redirectSeeOther(w, r, nextOr(form.Get("next"), "/"))
}
