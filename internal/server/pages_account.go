package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/views"
)

const (
	rateLimitedText    = "Too many attempts — wait a minute, then retry"
	passwordMismatch   = "Passwords do not match"
	invalidExpiryText  = "Expiry must be a date (YYYY-MM-DD)"
	noValueDash        = "—"
	needsSessionAction = "This action needs a browser session"
)

// accountView is what a handler carries into the page beyond live storage.
type accountView struct {
	passwordError        *string
	passwordChanged      bool
	operatorUsername     string
	operatorError        string
	confirmOperatorID    int64
	confirmOperatorError string
	apiKeyName           string
	apiKeyExpires        string
	apiKeyError          string
	newKeyName           string
	newKeyToken          string
}

func dashIfEmpty(value *string) string {
	if value == nil {
		return noValueDash
	}
	return *value
}

func (a *api) operatorRows(userID int64, r *http.Request, now int64) []views.OperatorRow {
	users, _ := a.DB.ListUsers(r.Context())
	lastOne := len(users) <= 1
	rows := make([]views.OperatorRow, 0, len(users))
	for _, user := range users {
		isYou := user.ID == userID
		created := user.CreatedAt
		rows = append(rows, views.OperatorRow{
			ID: user.ID, Username: user.Username,
			CreatedText: maybeTimeAgo(&created, now),
			IsYou:       isYou, Deletable: !isYou && !lastOne,
		})
	}
	return rows
}

func (a *api) sessionRows(r *http.Request, user authedUser, now int64) []views.SessionRow {
	snapshot, _ := a.sessionsSnapshot(r, user.SessionTokenHash, user.SessionTokenHash != "")
	rows := make([]views.SessionRow, 0, len(snapshot))
	for _, session := range snapshot {
		created, lastSeen := session.CreatedAt, session.LastSeen
		rows = append(rows, views.SessionRow{
			ID: session.ID, Username: session.Username,
			IP: dashIfEmpty(session.IP), UserAgent: dashIfEmpty(session.UserAgent),
			CreatedText: maybeTimeAgo(&created, now), LastSeenText: maybeTimeAgo(&lastSeen, now),
			IsCurrent: session.IsCurrent,
		})
	}
	return rows
}

func (a *api) apiKeyRows(r *http.Request, userID, now int64) []views.APIKeyRow {
	keys, _ := a.DB.ListAPIKeysForUser(r.Context(), userID)
	rows := make([]views.APIKeyRow, 0, len(keys))
	for _, key := range keys {
		created := key.CreatedAt
		rows = append(rows, views.APIKeyRow{
			ID: key.ID, Name: key.Name, Prefix: key.Prefix,
			CreatedText:  maybeTimeAgo(&created, now),
			LastUsedText: maybeTimeAgo(key.LastUsedAt, now),
			ExpiresText:  expiryText(key.ExpiresAt, now),
		})
	}
	return rows
}

// accountPageFor builds the page from live storage plus what the caller
// carries. shell comes in built for "/account", so the tab stays active on the
// POST paths.
func (a *api) accountPageFor(r *http.Request, user authedUser, shell views.ShellData, view accountView) views.AccountPage {
	now := a.Now().Unix()
	username, _, _ := a.DB.GetUsername(r.Context(), user.UserID)
	operators := a.operatorRows(user.UserID, r, now)

	// An id naming nobody expands nothing.
	var confirmID int64
	var confirmName string
	for _, operator := range operators {
		if operator.ID == view.confirmOperatorID {
			confirmID, confirmName = operator.ID, operator.Username
		}
	}
	return views.AccountPage{
		Shell: shell, Username: username, ViaSSO: user.ViaForwardAuth,
		MinPasswordLength: auth.MinPasswordLength,
		PasswordError:     view.passwordError, PasswordChanged: view.passwordChanged,
		Operators: operators, Sessions: a.sessionRows(r, user, now), APIKeys: a.apiKeyRows(r, user.UserID, now),
		OperatorUsername: view.operatorUsername, OperatorError: view.operatorError,
		ConfirmOperatorID: confirmID, ConfirmOperatorName: confirmName,
		ConfirmOperatorError: view.confirmOperatorError,
		APIKeyName:           view.apiKeyName, APIKeyExpires: view.apiKeyExpires, APIKeyError: view.apiKeyError,
		NewKeyName: view.newKeyName, NewKeyToken: view.newKeyToken,
		AccountSaved: shell.AccountSaved, SessionsRevoked: shell.SessionsRevoked,
	}
}

// renderAccount answers with the account page. The POST paths pass their
// rejection through view; the shell is always built for "/account".
func (a *api) renderAccount(w http.ResponseWriter, r *http.Request, user authedUser, status int, view accountView) {
	shell := a.shellFor(w, r, "/account")
	writeHTML(w, status, views.Account(a.accountPageFor(r, user, shell, view)))
}

// accountPage handles GET /account.
func (a *api) accountPage(w http.ResponseWriter, r *http.Request, user authedUser) {
	shell := a.shell(w, r)
	// A bad confirm_delete expands nothing rather than answering 400.
	confirmID, _ := strconv.ParseInt(r.URL.Query().Get("confirm_delete"), 10, 64)
	view := accountView{passwordChanged: shell.PasswordChanged, confirmOperatorID: confirmID}
	writeHTML(w, http.StatusOK, views.Account(a.accountPageFor(r, user, shell, view)))
}

func passwordRejection(message string) accountView {
	return accountView{passwordError: &message}
}

// accountPasswordSubmit handles POST /account/password. The confirmation
// field exists only in the form, so it is checked here. A success redirects:
// the session cookie was rotated, and a re-render would keep the old password
// in the form.
func (a *api) accountPasswordSubmit(w http.ResponseWriter, r *http.Request, user authedUser) {
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, "current_password", "new_password", "confirm_password") {
		return
	}
	if form.Get("new_password") != form.Get("confirm_password") {
		a.renderAccount(w, r, user, http.StatusBadRequest, passwordRejection(passwordMismatch))
		return
	}
	// Cookie-only, like the JSON endpoint: API-key and forward-auth callers
	// hold no session to rotate.
	if user.SessionTokenHash == "" {
		a.renderAccount(w, r, user, http.StatusUnauthorized,
			passwordRejection("Changing a password needs a browser session"))
		return
	}
	token, failure := a.changePasswordForSession(r, passwordChange{
		actor:           sessionActor{userID: user.UserID, tokenHash: user.SessionTokenHash, ip: a.clientIP(r)},
		currentPassword: form.Get("current_password"),
		newPassword:     form.Get("new_password"),
	})
	if failure != nil {
		status, message := passwordFailureText(failure)
		a.renderAccount(w, r, user, status, passwordRejection(message))
		return
	}
	if token != "" {
		http.SetCookie(w, a.sessionCookie(token))
	}
	setFlash(w, flashPasswordChanged)
	redirectSeeOther(w, r, "/account")
}

func passwordFailureText(failure *passwordChangeError) (int, string) {
	switch failure.failure {
	case changeRateLimited:
		return http.StatusTooManyRequests, rateLimitedText
	case changeRejected:
		return http.StatusBadRequest, failure.message
	case changeWrongPassword:
		return http.StatusUnauthorized, "Current password is incorrect"
	default:
		return http.StatusInternalServerError, "Could not change the password — check the server log"
	}
}

// accountSaved redirects back with a notice, so a refresh cannot resubmit.
func accountSaved(w http.ResponseWriter, r *http.Request, value flash) {
	setFlash(w, value)
	redirectSeeOther(w, r, "/account")
}

// confirmFormPassword checks the password a sensitive form carried. Every
// password-gated form runs its action only when this returns zero status.
func (a *api) confirmFormPassword(r *http.Request, user authedUser, password string) (int, string) {
	// The proxy already vouched for a forward-auth operator.
	if user.ViaForwardAuth {
		return 0, ""
	}
	if user.SessionTokenHash == "" {
		return http.StatusUnauthorized, needsSessionAction
	}
	actor := sessionActor{userID: user.UserID, tokenHash: user.SessionTokenHash, ip: a.clientIP(r)}
	switch a.confirmPassword(r, actor, password) {
	case 0:
		return 0, ""
	case reauthRateLimited:
		return http.StatusTooManyRequests, rateLimitedText
	case reauthInvalid:
		return http.StatusUnauthorized, "Your password is incorrect"
	default:
		return http.StatusInternalServerError, "Could not confirm your password — check the server log"
	}
}

// accountOperatorAddSubmit handles POST /account/operators.
func (a *api) accountOperatorAddSubmit(w http.ResponseWriter, r *http.Request, user authedUser) {
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, "username", "password", "confirm", "your_password") {
		return
	}
	// Keep the username across a rejection, never a password: it would land in
	// the page source and caches.
	reject := func(status int, message string) {
		a.renderAccount(w, r, user, status,
			accountView{operatorUsername: form.Get("username"), operatorError: message})
	}
	if form.Get("password") != form.Get("confirm") {
		reject(http.StatusBadRequest, passwordMismatch)
		return
	}
	if status, message := a.confirmFormPassword(r, user, form.Get("your_password")); status != 0 {
		reject(status, message)
		return
	}
	_, failure := a.createOperator(r, user.UserID, form.Get("username"), form.Get("password"))
	if failure == nil {
		accountSaved(w, r, flashAccountSaved)
		return
	}
	switch failure.failure {
	case operatorInvalid:
		reject(http.StatusBadRequest, failure.message)
	case operatorConflict:
		reject(http.StatusConflict, "That username is already taken")
	default:
		reject(http.StatusInternalServerError, "Could not add the operator — check the server log")
	}
}

// accountOperatorDeleteSubmit handles POST /account/operators/{id}/delete. The
// form appears on the row expanded by ?confirm_delete={id}, so the password
// field belongs to one named operator.
func (a *api) accountOperatorDeleteSubmit(w http.ResponseWriter, r *http.Request, user authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, "your_password") {
		return
	}
	reject := func(status int, message string) {
		a.renderAccount(w, r, user, status, accountView{confirmOperatorID: id, confirmOperatorError: message})
	}
	if status, message := a.confirmFormPassword(r, user, form.Get("your_password")); status != 0 {
		reject(status, message)
		return
	}
	switch a.removeOperator(r, user.UserID, id) {
	case 0:
		accountSaved(w, r, flashAccountSaved)
	case operatorLast:
		reject(http.StatusConflict, "This is the last operator — deleting it would lock everyone out")
	case operatorNotFound:
		reject(http.StatusNotFound, "That operator is already gone")
	default:
		reject(http.StatusInternalServerError, "Could not delete the operator — check the server log")
	}
}

// accountSessionRevokeSubmit handles POST /account/sessions/{id}/revoke. No
// password, like DELETE /api/sessions/{id}: a session killed in a hurry should
// not wait on authentication.
func (a *api) accountSessionRevokeSubmit(w http.ResponseWriter, r *http.Request, user authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	revokedOwn, failure := a.revokeSessionRow(r, user.UserID, id, user.SessionTokenHash, user.SessionTokenHash != "")
	// Revoking your own session signs you out: go to sign-in, cookies cleared.
	if failure == 0 && revokedOwn {
		clearSessionCookies(w, r)
		w.Header().Set("Clear-Site-Data", clearSiteData)
		redirectSeeOther(w, r, "/login")
		return
	}
	// Already gone is the state asked for, so it reports the same.
	accountSaved(w, r, flashSessionsRevoked)
}

// accountSessionsRevokeOthersSubmit handles POST /account/sessions/revoke-others.
func (a *api) accountSessionsRevokeOthersSubmit(w http.ResponseWriter, r *http.Request, user authedUser) {
	var keep *string
	if user.SessionTokenHash != "" {
		keep = &user.SessionTokenHash
	}
	_ = a.revokeEveryOtherSession(r, user.UserID, keep)
	accountSaved(w, r, flashSessionsRevoked)
}

// accountAPIKeyCreateSubmit handles POST /account/api-keys. It is the one
// success that does not redirect: the token is not stored, so a redirect would
// discard the only copy. A refresh re-posts and mints a second key, which the
// operator can see and delete.
func (a *api) accountAPIKeyCreateSubmit(w http.ResponseWriter, r *http.Request, user authedUser) {
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, "name", "expires", "your_password") {
		return
	}
	reject := func(status int, message string) {
		a.renderAccount(w, r, user, status, accountView{
			apiKeyName: form.Get("name"), apiKeyExpires: form.Get("expires"), apiKeyError: message,
		})
	}
	expiresAt, valid := parseExpiryDate(form.Get("expires"))
	if !valid {
		reject(http.StatusBadRequest, invalidExpiryText)
		return
	}
	if status, message := a.confirmFormPassword(r, user, form.Get("your_password")); status != 0 {
		reject(status, message)
		return
	}
	created, invalid, err := a.issueAPIKey(r, user.UserID, form.Get("name"), expiresAt)
	switch {
	case invalid:
		reject(http.StatusBadRequest, "Name is required, and at most 64 characters")
	case err != nil:
		reject(http.StatusInternalServerError, "Could not create the key — check the server log")
	default:
		a.renderAccount(w, r, user, http.StatusOK, accountView{newKeyName: created.Name, newKeyToken: created.Token})
	}
}

// parseExpiryDate turns a YYYY-MM-DD date into the instant that day ends: end
// of day, so today's date means "until today is over", in UTC since the server
// does not know the browser's zone. An empty value is a key that never expires.
func parseExpiryDate(raw string) (expiresAt *int64, valid bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}
	parts := strings.Split(raw, "-")
	if len(parts) != 3 {
		return nil, false
	}
	var numbers [3]int
	for i, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		numbers[i] = number
	}
	year, month, day := numbers[0], numbers[1], numbers[2]
	// Go normalises 2023-02-30 into March; the round trip catches it. Years
	// stay in four digits, as the Rust date type caps them.
	date := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	if year < 0 || year > 9999 || date.Year() != year || int(date.Month()) != month || date.Day() != day {
		return nil, false
	}
	end := date.Unix() + 86_399
	return &end, true
}

// accountAPIKeyDeleteSubmit handles POST /account/api-keys/{id}/delete. No
// password, matching DELETE /api/api-keys/{id}: revoking a key you own only
// ever reduces access.
func (a *api) accountAPIKeyDeleteSubmit(w http.ResponseWriter, r *http.Request, user authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	_, _ = a.revokeAPIKey(r, user.UserID, id)
	accountSaved(w, r, flashAccountSaved)
}
