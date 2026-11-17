package server

import (
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/db"
)

// nonNil makes a nil slice marshal as [] rather than null.
func nonNil[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

// pathID parses an integer path value, answering 400 as axum's Path extractor
// does when it is not one.
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeText(w, http.StatusBadRequest, "Invalid URL: cannot parse `"+r.PathValue("id")+"` to a `i64`")
		return 0, false
	}
	return id, true
}

// listUsers handles GET /api/users.
func (a *api) listUsers(w http.ResponseWriter, r *http.Request, _ authedUser) {
	users, err := a.DB.ListUsers(r.Context())
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(users))
}

type createUserRequest struct {
	Username *string `json:"username"`
	Password *string `json:"password"`
}

// operatorFailure is why an operator could not be created or removed.
type operatorFailure int

const (
	// operatorInvalid carries a reason the caller can act on.
	operatorInvalid operatorFailure = iota + 1
	// operatorConflict means the username is taken.
	operatorConflict
	// operatorLast refuses to leave the appliance with no operator.
	operatorLast
	operatorNotFound
	operatorInternal
)

type operatorError struct {
	failure operatorFailure
	message string
}

// createUser handles POST /api/users.
func (a *api) createUser(w http.ResponseWriter, r *http.Request, user authedUser) {
	var body createUserRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Username == nil || body.Password == nil {
		missingField(w, "username")
		return
	}
	_, failure := a.createOperator(r, user.UserID, *body.Username, *body.Password)
	if failure == nil {
		writeStatus(w, http.StatusCreated)
		return
	}
	switch failure.failure {
	case operatorInvalid:
		writeAPIError(w, http.StatusBadRequest, failure.message)
	case operatorConflict:
		writeAPIError(w, http.StatusConflict, "username already exists")
	default:
		writeInternalError(w)
	}
}

// createOperator provisions another operator with full admin access. Shared by
// POST /api/users and the account page's form; both prove a password first.
func (a *api) createOperator(r *http.Request, actorUserID int64, username, password string) (int64, *operatorError) {
	normalized, ok := auth.NormalizeUsername(username)
	if !ok {
		return 0, &operatorError{failure: operatorInvalid, message: "invalid username"}
	}
	if err := auth.ValidatePolicy(password, normalized); err != nil {
		return 0, &operatorError{failure: operatorInvalid, message: err.Error()}
	}
	hash, err := a.Work.Hash(r.Context(), password)
	if err != nil {
		return 0, &operatorError{failure: operatorInternal}
	}
	id, err := a.DB.CreateUser(writeCtx(r), normalized, hash, a.Now().Unix())
	// Naming a taken username is safe: the caller is an operator who can
	// already list the users.
	if db.IsUniqueViolation(err) {
		return 0, &operatorError{failure: operatorConflict}
	}
	if err != nil {
		return 0, &operatorError{failure: operatorInternal}
	}
	a.log.Info("operator created",
		"event", "user.created",
		"user_id", actorUserID,
		"target_user_id", id,
		"target_username", logSafe(normalized),
		"ip", a.clientIP(r).String(),
	)
	return id, nil
}

// deleteUser handles DELETE /api/users/{id}.
func (a *api) deleteUser(w http.ResponseWriter, r *http.Request, user authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	switch failure := a.removeOperator(r, user.UserID, id); failure {
	case 0:
		writeStatus(w, http.StatusNoContent)
	case operatorLast:
		writeStatus(w, http.StatusConflict)
	case operatorNotFound:
		writeStatus(w, http.StatusNotFound)
	default:
		writeStatus(w, http.StatusInternalServerError)
	}
}

// removeOperator deletes an operator and their sessions. Shared by
// DELETE /api/users/{id} and the account page's form.
func (a *api) removeOperator(r *http.Request, actorUserID, id int64) operatorFailure {
	ctx := writeCtx(r)
	// The last-operator guard and the delete are atomic in the database layer,
	// so concurrent deletes cannot reach zero operators.
	outcome, err := a.DB.DeleteUser(ctx, id)
	if err != nil {
		return operatorInternal
	}
	switch outcome {
	case db.ErrLastOperator:
		return operatorLast
	case db.UserNotFound:
		return operatorNotFound
	}
	// ON DELETE CASCADE removed the session rows; the in-memory entries go
	// only now, so a failed delete never logs anyone out.
	revoked, err := a.Sessions.RevokeUserSessionsExcept(ctx, id, nil)
	if err != nil {
		a.log.Error("deleted operator but evicting their sessions failed",
			"event", "session.revoke_failed", "error", err.Error(), "target_user_id", id)
	}
	ip := a.clientIP(r).String()
	a.log.Info("revoked sessions for deleted user",
		"event", "session.destroyed",
		"reason", "user_deleted",
		"user_id", actorUserID,
		"target_user_id", id,
		"ip", ip,
		"revoked", revoked,
	)
	a.log.Info("operator deleted",
		"event", "user.deleted", "user_id", actorUserID, "target_user_id", id, "ip", ip)
	return 0
}

type changePasswordRequest struct {
	CurrentPassword *string `json:"current_password"`
	NewPassword     *string `json:"new_password"`
}

// passwordChangeFailure is why a password change was refused.
type passwordChangeFailure int

const (
	changeRateLimited passwordChangeFailure = iota + 1
	// changeRejected carries the policy message verbatim.
	changeRejected
	// changeWrongPassword is distinct from changeRejected so the operator
	// fixes the right field.
	changeWrongPassword
	changeInternal
)

type passwordChangeError struct {
	failure passwordChangeFailure
	message string
}

// passwordChange is a request to replace actor's password, proving the
// current one.
type passwordChange struct {
	actor           sessionActor
	currentPassword string
	newPassword     string
}

// changePasswordForSession changes the signed-in operator's password, revokes
// their other sessions and rotates the caller's own token. Revocation ejects a
// live stolen cookie elsewhere; rotation covers a token leaked out of band.
// Shared by POST /api/users/me/password and the account page's form; its rate
// limit, lockout and auth.failed line are what stop a stolen session grinding
// the password.
//
// The replacement session is stored before the old one is destroyed, so a
// failure leaves a working session. Once the password write commits, a
// revocation or rotation failure is only logged: the change cannot be undone,
// and a 500 would invite a retry. API keys are not revoked: one minted with a
// stolen cookie survives and must be deleted separately.
//
// It returns the new raw session token, or "" when rotation failed and the
// original cookie stays valid.
func (a *api) changePasswordForSession(r *http.Request, change passwordChange) (string, *passwordChangeError) {
	actor := change.actor
	userID := actor.userID
	ip := actor.ip
	// Throttled on sign-in's budget: it guesses the same credential from the
	// same address.
	if !a.LoginLimiter.Check(ip) {
		a.log.Warn("password change rate limited",
			"event", "auth.failed", "method", "password", "reason", "rate_limited",
			"user_id", userID, "ip", ip.String())
		return "", &passwordChangeError{failure: changeRateLimited}
	}
	a.LoginLimiter.Record(ip)

	// The username feeds zxcvbn; failing to read it only weakens that check.
	var userInputs []string
	if username, found, err := a.DB.GetUsername(r.Context(), userID); err == nil && found {
		userInputs = append(userInputs, username)
	}
	if err := auth.ValidatePolicy(change.newPassword, userInputs...); err != nil {
		return "", &passwordChangeError{failure: changeRejected, message: err.Error()}
	}
	hash, found, err := a.DB.GetUserPasswordHash(r.Context(), userID)
	if err != nil || !found {
		return "", &passwordChangeError{failure: changeInternal}
	}
	// A passwordless account never holds a session, but keep the sentinel away
	// from verification, which would fail.
	if auth.HasNoPassword(hash) {
		return "", &passwordChangeError{failure: changeWrongPassword}
	}
	if a.Lockout.IsLocked(userID) {
		a.spendVerifyCost(r, change.currentPassword)
		return "", &passwordChangeError{failure: changeWrongPassword}
	}
	valid, err := a.Work.Verify(r.Context(), change.currentPassword, hash)
	if err != nil {
		return "", &passwordChangeError{failure: changeInternal}
	}
	locked := a.Lockout.IsLocked(userID)
	if !valid {
		a.noteAccountFailure(userID, ip, "change_password")
	}
	if !acceptAfterVerify(valid, locked) {
		a.log.Warn("current password rejected",
			"event", "auth.failed", "method", "password", "reason", "change_password",
			"user_id", userID, "ip", ip.String())
		return "", &passwordChangeError{failure: changeWrongPassword}
	}
	a.Lockout.RecordSuccess(userID)

	newHash, err := a.Work.Hash(r.Context(), change.newPassword)
	if err != nil {
		return "", &passwordChangeError{failure: changeInternal}
	}
	ctx := writeCtx(r)
	if err := a.DB.UpdateUserPassword(ctx, userID, newHash); err != nil {
		return "", &passwordChangeError{failure: changeInternal}
	}
	keep := actor.tokenHash
	revoked, err := a.Sessions.RevokeUserSessionsExcept(ctx, userID, &keep)
	if err != nil {
		a.log.Error("password changed but revoking other sessions failed",
			"event", "session.revoke_failed", "error", err.Error(), "user_id", userID)
	} else {
		a.log.Info("revoked other sessions after password change",
			"event", "session.destroyed", "reason", "password_change",
			"user_id", userID, "revoked", revoked)
	}
	return a.rotateOwnSession(r, actor), nil
}

// rotateOwnSession replaces the caller's session with a fresh one and returns
// its raw token. On failure it returns "" and keeps the original session.
func (a *api) rotateOwnSession(r *http.Request, actor sessionActor) string {
	token, err := a.mintSession(r, actor.userID, "rotated session after password change", "password_change")
	if err != nil {
		a.log.Error("password changed but minting the replacement session failed",
			"event", "session.rotate_failed", "error", err.Error(), "user_id", actor.userID)
		return ""
	}
	// Evicting from memory is what stops the old token. A failed row delete is
	// logged: a restart would restore the row as live.
	info, existed := a.Sessions.Revoke(actor.tokenHash)
	if err := a.DB.DeleteSessionByTokenHash(writeCtx(r), actor.tokenHash); err != nil {
		a.log.Error("rotated session but deleting the superseded row failed",
			"event", "session.revoke_failed", "error", err.Error(), "user_id", actor.userID)
	}
	if existed {
		a.log.Info("superseded by the rotated session",
			"event", "session.destroyed", "reason", "rotated",
			"user_id", actor.userID, "session_id", info.SessionID,
			"sid_hash", a.sid(actor.tokenHash), "ip", actor.ip.String())
	}
	return token
}

// changeOwnPassword handles POST /api/users/me/password. Cookie-only: it
// rotates the caller's session.
func (a *api) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	var body changePasswordRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.CurrentPassword == nil || body.NewPassword == nil {
		missingField(w, "current_password")
		return
	}
	userID, tokenHash, ok := a.currentSession(r)
	if !ok {
		writeStatus(w, http.StatusUnauthorized)
		return
	}
	token, failure := a.changePasswordForSession(r, passwordChange{
		actor:           sessionActor{userID: userID, tokenHash: tokenHash, ip: a.clientIP(r)},
		currentPassword: *body.CurrentPassword,
		newPassword:     *body.NewPassword,
	})
	if failure != nil {
		switch failure.failure {
		case changeRateLimited:
			writeStatus(w, http.StatusTooManyRequests)
		case changeRejected:
			writeAPIError(w, http.StatusBadRequest, failure.message)
		case changeWrongPassword:
			writeStatus(w, http.StatusUnauthorized)
		default:
			writeStatus(w, http.StatusInternalServerError)
		}
		return
	}
	if token != "" {
		http.SetCookie(w, a.sessionCookie(token))
	}
	writeStatus(w, http.StatusNoContent)
}

type sessionResponse struct {
	ID        int64   `json:"id"`
	Username  string  `json:"username"`
	CreatedAt int64   `json:"created_at"`
	LastSeen  int64   `json:"last_seen"`
	IP        *string `json:"ip"`
	UserAgent *string `json:"user_agent"`
	IsCurrent bool    `json:"is_current"`
}

// listSessions handles GET /api/sessions. The cookie only marks the caller's
// own row; API-key and forward-auth callers get none.
func (a *api) listSessions(w http.ResponseWriter, r *http.Request, _ authedUser) {
	current, hasCurrent := a.liveSessionTokenHash(r)
	sessions, err := a.sessionsSnapshot(r, current, hasCurrent)
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

// sessionsSnapshot lists every session with the caller's own marked. "Last
// seen" prefers the in-memory value, which is fresher than the row. Shared by
// GET /api/sessions and the account page.
func (a *api) sessionsSnapshot(r *http.Request, current string, hasCurrent bool) ([]sessionResponse, error) {
	rows, err := a.DB.ListSessions(r.Context())
	if err != nil {
		return nil, err
	}
	out := make([]sessionResponse, 0, len(rows))
	for _, row := range rows {
		lastSeen := row.LastSeen
		if live, found := a.Sessions.Get(row.TokenHash); found {
			lastSeen = live.LastSeen
		}
		out = append(out, sessionResponse{
			ID: row.ID, Username: row.Username, CreatedAt: row.CreatedAt, LastSeen: lastSeen,
			IP: row.IP, UserAgent: row.UserAgent,
			IsCurrent: hasCurrent && row.TokenHash == current,
		})
	}
	return out, nil
}

// revokeSessionByID handles DELETE /api/sessions/{id}. Any operator may revoke
// any session, as the account page lists every operator's sessions.
func (a *api) revokeSessionByID(w http.ResponseWriter, r *http.Request, user authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	// Read before the revocation evicts the caller's own session: it only
	// decides whether the caller's cookie must be cleared.
	current, hasCurrent := a.liveSessionTokenHash(r)
	revokedOwn, failure := a.revokeSessionRow(r, user.UserID, id, current, hasCurrent)
	switch failure {
	case sessionNotFound:
		writeStatus(w, http.StatusNotFound)
	case sessionInternal:
		writeStatus(w, http.StatusInternalServerError)
	default:
		if revokedOwn {
			clearSessionCookies(w, r)
		}
		writeStatus(w, http.StatusNoContent)
	}
}

type sessionRevokeFailure int

const (
	sessionNotFound sessionRevokeFailure = iota + 1
	sessionInternal
)

// revokeSessionRow revokes one session by row id and reports whether it was
// the caller's own. Shared by DELETE /api/sessions/{id} and the account page's
// form.
func (a *api) revokeSessionRow(r *http.Request, actorUserID, id int64, current string, hasCurrent bool) (bool, sessionRevokeFailure) {
	tokenHash, found, err := a.DB.DeleteSessionByID(writeCtx(r), id)
	if err != nil {
		return false, sessionInternal
	}
	if !found {
		return false, sessionNotFound
	}
	a.Sessions.Revoke(tokenHash)
	a.log.Info("revoked session by id",
		"event", "session.destroyed",
		"reason", "revoked_by_id",
		"user_id", actorUserID,
		"session_id", id,
		"sid_hash", a.sid(tokenHash),
		"ip", a.clientIP(r).String(),
	)
	return hasCurrent && tokenHash == current, 0
}

type healthResponse struct {
	Status     string `json:"status"`
	NeedsSetup bool   `json:"needs_setup"`
	Version    string `json:"version"`
}

// needsSetup reports whether no operator exists yet. Always false under
// forward auth. It also decides whether pages send a signed-out browser to
// /setup or /login.
func (a *api) needsSetup(r *http.Request) bool {
	if a.ForwardAuth != nil {
		return false
	}
	count, err := a.DB.CountUsers(r.Context())
	return err == nil && count == 0
}

// health handles GET /api/health: unauthenticated, so monitoring and setup can
// call it before any operator exists.
func (a *api) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok", NeedsSetup: a.needsSetup(r), Version: a.Version})
}

// ServerInfo is what GET /api/server-info reports.
type ServerInfo struct {
	// DNSAddr is the address the plain-DNS listener is bound to.
	DNSAddr string `json:"dns_addr"`
	// HTTPAddr is the address the admin/DoH listener is bound to.
	HTTPAddr string `json:"http_addr"`
	// TLSEnabled is whether the HTTP listener serves TLS.
	TLSEnabled bool `json:"tls_enabled"`
}

// serverInfo handles GET /api/server-info.
func (a *api) serverInfo(w http.ResponseWriter, _ *http.Request, _ authedUser) {
	writeJSON(w, http.StatusOK, a.ServerInfo)
}

// listDohTokens handles GET /api/doh-tokens.
func (a *api) listDohTokens(w http.ResponseWriter, r *http.Request, _ authedUser) {
	tokens, err := a.DB.GetDohTokens(r.Context())
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(tokens))
}

type addDohTokenRequest struct {
	Token *string `json:"token"`
}

// addDohToken handles POST /api/doh-tokens. The token becomes a URL path
// segment, so a slash is refused.
func (a *api) addDohToken(w http.ResponseWriter, r *http.Request, _ authedUser) {
	var body addDohTokenRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Token == nil {
		missingField(w, "token")
		return
	}
	token := strings.TrimSpace(*body.Token)
	if token == "" || strings.Contains(token, "/") {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	id, err := a.DB.AddDohToken(writeCtx(r), token)
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, db.DohTokenRow{ID: id, Token: token})
}

// deleteDohToken handles DELETE /api/doh-tokens/{id}.
func (a *api) deleteDohToken(w http.ResponseWriter, r *http.Request, _ authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.DB.DeleteDohToken(writeCtx(r), id); err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	writeStatus(w, http.StatusOK)
}

// listAPIKeys handles GET /api/api-keys: the caller's own keys, metadata only.
func (a *api) listAPIKeys(w http.ResponseWriter, r *http.Request, user authedUser) {
	keys, err := a.DB.ListAPIKeysForUser(r.Context(), user.UserID)
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(keys))
}

type createAPIKeyRequest struct {
	Name      *string `json:"name"`
	ExpiresAt *int64  `json:"expires_at"`
}

type createAPIKeyResponse struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Prefix string `json:"prefix"`
	// Token is the full secret, shown only in this response.
	Token string `json:"token"`
}

const apiKeyNameMaxChars = 64

// createAPIKey handles POST /api/api-keys. It needs a recent password proof:
// an API key cannot mint another.
func (a *api) createAPIKey(w http.ResponseWriter, r *http.Request, user authedUser) {
	var body createAPIKeyRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Name == nil {
		missingField(w, "name")
		return
	}
	created, invalid, err := a.issueAPIKey(r, user.UserID, *body.Name, body.ExpiresAt)
	switch {
	case invalid:
		writeStatus(w, http.StatusBadRequest)
	case err != nil:
		writeStatus(w, http.StatusInternalServerError)
	default:
		writeJSON(w, http.StatusCreated, created)
	}
}

// issueAPIKey mints an API key and returns the only copy of its secret (only
// the hash is stored). Shared by POST /api/api-keys and the account page's
// form. invalid is true for a bad name.
func (a *api) issueAPIKey(r *http.Request, userID int64, name string, expiresAt *int64) (created createAPIKeyResponse, invalid bool, err error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > apiKeyNameMaxChars {
		return createAPIKeyResponse{}, true, nil
	}
	full, prefix, hash := auth.NewAPIKey()
	id, err := a.DB.InsertAPIKey(writeCtx(r), db.NewAPIKey{
		UserID: userID, Name: name, TokenHash: hash, Prefix: prefix,
		CreatedAt: a.Now().Unix(), ExpiresAt: expiresAt,
	})
	if err != nil {
		return createAPIKeyResponse{}, false, err
	}
	a.log.Info("api key created",
		"event", "apikey.created", "user_id", userID, "key_id", id, "prefix", prefix,
		"expires_at", expiresAt)
	return createAPIKeyResponse{ID: id, Name: name, Prefix: prefix, Token: full}, false, nil
}

// deleteAPIKey handles DELETE /api/api-keys/{id}. Another operator's key
// answers 404 like an absent one, so there is no existence oracle.
func (a *api) deleteAPIKey(w http.ResponseWriter, r *http.Request, user authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	deleted, err := a.revokeAPIKey(r, user.UserID, id)
	switch {
	case err != nil:
		writeStatus(w, http.StatusInternalServerError)
	case !deleted:
		writeStatus(w, http.StatusNotFound)
	default:
		writeStatus(w, http.StatusOK)
	}
}

// revokeAPIKey deletes one of an operator's own keys, reporting whether it
// existed. The query is scoped to userID, so another operator's key looks
// absent.
func (a *api) revokeAPIKey(r *http.Request, userID, id int64) (bool, error) {
	deleted, err := a.DB.DeleteAPIKey(writeCtx(r), id, userID)
	if err != nil || !deleted {
		return false, err
	}
	a.log.Info("api key deleted", "event", "apikey.destroyed", "user_id", userID, "key_id", id)
	return true, nil
}
