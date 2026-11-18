package server

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/db"
)

const setupTokenRefusal = "setup token is missing or wrong; it is printed to the server's stderr at startup"

// clearSiteData asks the browser to drop this origin's cookies, cached
// responses and storage beyond what Set-Cookie expires. Not executionContexts,
// which reloads the page: the JSON caller must still read redirect_to.
const clearSiteData = `"cache", "cookies", "storage"`

// loginFailure is why a password sign-in was refused. loginInvalid covers
// unknown username, wrong password, forward-auth account and locked account,
// so a caller cannot tell them apart.
type loginFailure int

const (
	loginRateLimited loginFailure = iota + 1
	loginInvalid
	loginInternal
)

// loginAttempt is one sign-in request.
type loginAttempt struct {
	username string
	password string
}

// startPasswordSession verifies a username and password and mints a session,
// returning its raw token for the Set-Cookie. It is the only password sign-in
// path (rate limit, constant Argon2 cost, per-account lockout, audit events),
// shared by the JSON endpoint and the HTML form: do not add a second copy.
func (a *api) startPasswordSession(r *http.Request, attempt loginAttempt) (token string, failure loginFailure) {
	ip := a.clientIP(r)
	if !a.LoginLimiter.Check(ip) {
		a.log.Warn("login rate limited",
			"event", "auth.failed", "method", "password", "reason", "rate_limited", "ip", ip.String())
		return "", loginRateLimited
	}
	a.LoginLimiter.Record(ip)

	logFailed := func() {
		a.log.Warn("login failed",
			"event", "auth.failed", "method", "password", "ip", ip.String(),
			"user_agent", logSafe(headerLogValue(r.Header, "User-Agent")))
	}

	// Bound Argon2's input before hashing. The verdict does not depend on the
	// username, so this leaks nothing.
	if len(attempt.password) > auth.MaxLoginPasswordLength {
		logFailed()
		return "", loginInvalid
	}

	user, found, err := a.DB.GetUserAuth(r.Context(), strings.TrimSpace(attempt.username))
	if err != nil {
		return "", loginInternal
	}
	if !found {
		// Same Argon2 cost as a real account, so timing does not reveal it.
		a.spendVerifyCost(r, attempt.password)
		logFailed()
		return "", loginInvalid
	}
	// A forward-auth account stores a sentinel, not a hash. Checked before
	// verifying (which would fail on it), and padded so neither status nor
	// timing reveals a proxy-provisioned account.
	if auth.HasNoPassword(user.PasswordHash) {
		a.spendVerifyCost(r, attempt.password)
		logFailed()
		return "", loginInvalid
	}
	// Only for a resolved username: an unknown one is never counted, so the
	// lockout cannot become an enumeration oracle.
	if a.Lockout.IsLocked(user.ID) {
		a.spendVerifyCost(r, attempt.password)
		logFailed()
		return "", loginInvalid
	}

	valid, err := a.Work.Verify(r.Context(), attempt.password, user.PasswordHash)
	if err != nil {
		return "", loginInternal
	}
	locked := a.Lockout.IsLocked(user.ID)
	if !valid {
		a.noteAccountFailure(user.ID, ip, "login")
	}
	if !acceptAfterVerify(valid, locked) {
		logFailed()
		return "", loginInvalid
	}
	a.Lockout.RecordSuccess(user.ID)

	token, err = a.mintSession(r, user.ID, "login successful", "")
	if err != nil {
		return "", loginInternal
	}
	return token, 0
}

// spendVerifyCost pads a refused sign-in with the work a real verification
// costs. A failure only costs the padding.
func (a *api) spendVerifyCost(r *http.Request, password string) {
	if err := a.Work.SpendVerifyCost(r.Context(), password); err != nil {
		a.log.Error("timing-equalisation task did not complete", "error", err.Error())
	}
}

// mintSession stores a new session for userID and returns its raw token. The
// token goes only into the Set-Cookie; everything persisted, held in memory or
// logged is its hash. Signing in is a password proof, so it satisfies reauthed.
func (a *api) mintSession(r *http.Request, userID int64, message, reason string) (string, error) {
	now := a.Now().Unix()
	ip := a.clientIP(r)
	token := auth.NewSessionToken()
	tokenHash := auth.HashToken(token)
	ipText := ip.String()
	userAgent, hasUserAgent := r.Header["User-Agent"]
	var userAgentPtr *string
	if hasUserAgent && len(userAgent) > 0 {
		userAgentPtr = &userAgent[0]
	}
	sessionID, err := a.DB.InsertSession(writeCtx(r), db.NewSession{
		TokenHash: tokenHash, UserID: userID, CreatedAt: now, LastSeen: now,
		IP: &ipText, UserAgent: userAgentPtr,
	})
	if err != nil {
		return "", err
	}
	a.Sessions.Store(tokenHash, auth.SessionInfo{
		SessionID: sessionID, UserID: userID, CreatedAt: now, LastSeen: now, LastReauthAt: now,
	})
	attrs := []any{
		"event", "session.created",
		"user_id", userID,
		"session_id", sessionID,
		"sid_hash", a.sid(tokenHash),
		"ip", ipText,
		"user_agent", logSafe(headerLogValue(r.Header, "User-Agent")),
	}
	if reason != "" {
		attrs = append(attrs, "reason", reason)
	}
	a.log.Info(message, attrs...)
	return token, nil
}

// sessionCookie is the Set-Cookie for a fresh session token, shared by sign-in
// and password rotation so both agree on every attribute.
func (a *api) sessionCookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:     auth.SessionCookieName(a.CookieSecure),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.CookieSecure,
		// Lax, not Strict: Lax already withholds the cookie from cross-site
		// unsafe methods and no GET writes, so Strict would only break deep
		// links.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   auth.SessionMaxAge,
	}
}

// clearSessionCookies expires every session cookie the request carried, not
// just the first. The __Host- removal always carries Secure, because a browser
// ignores a __Host- Set-Cookie without it.
func clearSessionCookies(w http.ResponseWriter, r *http.Request) {
	for _, name := range sessionCookieNames {
		if _, err := r.Cookie(name); err != nil {
			continue
		}
		http.SetCookie(w, &http.Cookie{
			Name:    name,
			Value:   "",
			Path:    "/",
			Secure:  name == hostSessionCookie,
			MaxAge:  -1,
			Expires: time.Unix(0, 0),
		})
	}
}

type loginRequest struct {
	Username *string `json:"username"`
	Password *string `json:"password"`
}

type successBody struct {
	Success bool `json:"success"`
}

// login handles POST /api/auth/login.
func (a *api) login(w http.ResponseWriter, r *http.Request) {
	var body loginRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Username == nil || body.Password == nil {
		missingField(w, "username")
		return
	}
	token, failure := a.startPasswordSession(r, loginAttempt{username: *body.Username, password: *body.Password})
	switch failure {
	case loginRateLimited:
		writeStatus(w, http.StatusTooManyRequests)
	case loginInvalid:
		writeStatus(w, http.StatusUnauthorized)
	case loginInternal:
		writeStatus(w, http.StatusInternalServerError)
	default:
		http.SetCookie(w, a.sessionCookie(token))
		writeJSON(w, http.StatusOK, successBody{Success: true})
	}
}

// setupFailure is why first-run setup was refused.
type setupFailure int

const (
	setupDisabled setupFailure = iota + 1
	setupAlreadyConfigured
	setupRateLimited
	setupBadToken
	setupInvalid
	setupInternal
)

// setupError carries the failure and, for setupInvalid, the message the
// operator can act on.
type setupError struct {
	failure setupFailure
	message string
}

// createFirstOperator creates the first operator account. It is the only setup
// path, shared by POST /api/auth/setup and POST /setup: its guards are what
// stop a second account being claimed.
func (a *api) createFirstOperator(r *http.Request, username, password, setupToken string) *setupError {
	// Under forward auth the first proxied request provisions the operator;
	// leaving setup open would let anyone bypassing the proxy claim the first
	// account before then.
	if a.ForwardAuth != nil {
		return &setupError{failure: setupDisabled}
	}
	count, err := a.DB.CountUsers(r.Context())
	if err != nil {
		return &setupError{failure: setupInternal}
	}
	if count > 0 {
		return &setupError{failure: setupAlreadyConfigured}
	}
	// Throttle, then token, then the password work: the token is what keeps a
	// stranger from reaching Argon2 or the insert, and attempts are never
	// refunded.
	ip := a.clientIP(r)
	if !a.SetupToken.AllowAttempt(ip) {
		return &setupError{failure: setupRateLimited}
	}
	if !a.SetupToken.Matches(setupToken) {
		a.log.Warn("first-run setup token missing or wrong",
			"event", "setup.token_rejected", "ip", ip.String())
		return &setupError{failure: setupBadToken}
	}
	normalized, ok := auth.NormalizeUsername(username)
	if !ok {
		return &setupError{failure: setupInvalid, message: "invalid username"}
	}
	if err := auth.ValidatePolicy(password, normalized); err != nil {
		return &setupError{failure: setupInvalid, message: err.Error()}
	}
	hash, err := a.Work.Hash(r.Context(), password)
	if err != nil {
		return &setupError{failure: setupInternal}
	}
	// The count above is only a fast path; this insert is the arbiter when
	// setups race.
	_, created, err := a.DB.CreateFirstUser(writeCtx(r), normalized, hash, a.Now().Unix())
	if err != nil {
		return &setupError{failure: setupInternal}
	}
	if !created {
		return &setupError{failure: setupAlreadyConfigured}
	}
	a.SetupToken.Clear()
	return nil
}

type setupRequest struct {
	Username   *string `json:"username"`
	Password   *string `json:"password"`
	SetupToken string  `json:"setup_token"`
}

// setup handles POST /api/auth/setup.
func (a *api) setup(w http.ResponseWriter, r *http.Request) {
	var body setupRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Username == nil || body.Password == nil {
		missingField(w, "username")
		return
	}
	failure := a.createFirstOperator(r, *body.Username, *body.Password, body.SetupToken)
	if failure == nil {
		writeJSON(w, http.StatusOK, successBody{Success: true})
		return
	}
	switch failure.failure {
	case setupDisabled:
		writeAPIError(w, http.StatusForbidden, "setup is disabled when forward auth is configured")
	case setupAlreadyConfigured:
		writeAPIError(w, http.StatusConflict, "already configured")
	case setupRateLimited:
		writeAPIError(w, http.StatusTooManyRequests, "too many attempts")
	case setupBadToken:
		writeAPIError(w, http.StatusForbidden, setupTokenRefusal)
	case setupInvalid:
		writeAPIError(w, http.StatusBadRequest, failure.message)
	default:
		writeInternalError(w)
	}
}

// reauthFailure is why a password confirmation was refused.
type reauthFailure int

const (
	reauthRateLimited reauthFailure = iota + 1
	// reauthInvalid covers a wrong password, no password to check, or a
	// session gone meanwhile, so they cannot be told apart.
	reauthInvalid
	reauthInternal
)

// sessionActor is the signed-in session a password-gated action runs as.
type sessionActor struct {
	userID    int64
	tokenHash string
	ip        netip.Addr
}

// confirmPassword verifies an operator's own password and stamps their session
// as re-authenticated. It is the only password check for a sensitive action,
// shared by POST /api/auth/reauth and the account page's forms: one rate
// limit, one lockout, one audit event.
func (a *api) confirmPassword(r *http.Request, actor sessionActor, password string) reauthFailure {
	if !a.LoginLimiter.Check(actor.ip) {
		a.log.Warn("reauthentication rate limited",
			"event", "auth.failed", "method", "password", "reason", "rate_limited",
			"user_id", actor.userID, "ip", actor.ip.String())
		return reauthRateLimited
	}
	a.LoginLimiter.Record(actor.ip)

	if len(password) > auth.MaxLoginPasswordLength {
		return reauthInvalid
	}
	hash, found, err := a.DB.GetUserPasswordHash(r.Context(), actor.userID)
	if err != nil {
		return reauthInternal
	}
	if !found {
		return reauthInvalid
	}
	// A forward-auth operator holds the sentinel: answer 401, not the 500
	// verifying the sentinel would produce.
	if auth.HasNoPassword(hash) {
		return reauthInvalid
	}
	if a.Lockout.IsLocked(actor.userID) {
		a.spendVerifyCost(r, password)
		return reauthInvalid
	}
	valid, err := a.Work.Verify(r.Context(), password, hash)
	if err != nil {
		return reauthInternal
	}
	locked := a.Lockout.IsLocked(actor.userID)
	if !valid {
		a.noteAccountFailure(actor.userID, actor.ip, "reauth")
	}
	if !acceptAfterVerify(valid, locked) {
		a.log.Warn("reauthentication rejected",
			"event", "auth.failed", "method", "password", "reason", "reauth",
			"user_id", actor.userID, "ip", actor.ip.String())
		return reauthInvalid
	}
	a.Lockout.RecordSuccess(actor.userID)
	if !a.Sessions.MarkReauthenticated(actor.tokenHash) {
		// The session expired or was revoked since it was validated.
		return reauthInvalid
	}
	a.log.Info("password confirmed for a sensitive action",
		"event", "auth.reauthenticated",
		"user_id", actor.userID, "sid_hash", a.sid(actor.tokenHash), "ip", actor.ip.String())
	return 0
}

type reauthRequest struct {
	Password *string `json:"password"`
}

// reauth handles POST /api/auth/reauth: prove the password again, opening this
// session's reauth window. Cookie-only, since it stamps a session.
func (a *api) reauth(w http.ResponseWriter, r *http.Request) {
	var body reauthRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Password == nil {
		missingField(w, "password")
		return
	}
	userID, tokenHash, ok := a.currentSession(r)
	if !ok {
		writeStatus(w, http.StatusUnauthorized)
		return
	}
	actor := sessionActor{userID: userID, tokenHash: tokenHash, ip: a.clientIP(r)}
	switch a.confirmPassword(r, actor, *body.Password) {
	case reauthRateLimited:
		writeStatus(w, http.StatusTooManyRequests)
	case reauthInvalid:
		writeStatus(w, http.StatusUnauthorized)
	case reauthInternal:
		writeStatus(w, http.StatusInternalServerError)
	default:
		writeStatus(w, http.StatusNoContent)
	}
}

// revokeOthers handles POST /api/auth/revoke-others: log out every other
// session, keeping the caller's. A forward-auth or API-key caller has no
// session cookie, so all sessions are revoked.
func (a *api) revokeOthers(w http.ResponseWriter, r *http.Request, user authedUser) {
	var keep *string
	if hash, live := a.liveSessionTokenHash(r); live {
		keep = &hash
	}
	if err := a.revokeEveryOtherSession(r, user.UserID, keep); err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	writeStatus(w, http.StatusOK)
}

// revokeEveryOtherSession revokes every session except keep. Shared by
// POST /api/auth/revoke-others and the account page's form.
func (a *api) revokeEveryOtherSession(r *http.Request, actorUserID int64, keep *string) error {
	revokedRows, err := a.Sessions.RevokeOthers(writeCtx(r), keep)
	if err != nil {
		return err
	}
	// scope and revoked_rows are deliberate: the delete spans every operator,
	// and the count is database rows, which can exceed live sessions.
	a.log.Info("revoked other sessions across all operators",
		"event", "session.destroyed",
		"reason", "revoked_others",
		"scope", "all_operators",
		"user_id", actorUserID,
		"ip", a.clientIP(r).String(),
		"revoked_rows", revokedRows,
	)
	return nil
}

// endSession revokes every session this request's cookies name, clears the
// cookies and returns the forward-auth logout URL, if any. Shared by
// POST /api/auth/logout and POST /logout.
func (a *api) endSession(w http.ResponseWriter, r *http.Request, user authedUser) (redirectTo string, hasRedirect bool) {
	ip := a.clientIP(r)
	// Revoke every token a cookie names, not just the authenticating one:
	// both cookies are cleared below, and an unrevoked one would leave a live,
	// replayable session behind.
	for _, tokenHash := range sessionCookieHashes(r) {
		info, existed := a.Sessions.Revoke(tokenHash)
		_ = a.DB.DeleteSessionByTokenHash(writeCtx(r), tokenHash)
		// Log only a session that existed: the cookie is unvalidated input,
		// and a fabricated one must not inject a session.destroyed event.
		if !existed {
			continue
		}
		a.log.Info("logged out",
			"event", "session.destroyed",
			"reason", "logout",
			"user_id", info.UserID,
			"session_id", info.SessionID,
			"sid_hash", a.sid(tokenHash),
			"ip", ip.String(),
		)
	}
	clearSessionCookies(w, r)
	if user.ViaForwardAuth && a.ForwardAuth != nil {
		return a.ForwardAuth.LogoutURL()
	}
	return "", false
}

type logoutResponse struct {
	RedirectTo     *string `json:"redirect_to"`
	ViaForwardAuth bool    `json:"via_forward_auth"`
}

// logout handles POST /api/auth/logout. A forward-auth caller has no session
// here, so redirect_to (the proxy/SSO logout URL) is how it signs out.
func (a *api) logout(w http.ResponseWriter, r *http.Request, user authedUser) {
	redirectTo, hasRedirect := a.endSession(w, r, user)
	body := logoutResponse{ViaForwardAuth: user.ViaForwardAuth}
	if hasRedirect {
		body.RedirectTo = &redirectTo
	}
	w.Header().Set("Clear-Site-Data", clearSiteData)
	writeJSON(w, http.StatusOK, body)
}

type meResponse struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	ViaSSO   bool   `json:"via_sso"`
}

// me handles GET /api/auth/me.
func (a *api) me(w http.ResponseWriter, r *http.Request, user authedUser) {
	username, found, err := a.DB.GetUsername(r.Context(), user.UserID)
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	if !found {
		writeStatus(w, http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, meResponse{ID: user.UserID, Username: username, ViaSSO: user.ViaForwardAuth})
}
