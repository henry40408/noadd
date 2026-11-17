package server

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/db"
)

const (
	hostSessionCookie  = "__Host-session"
	plainSessionCookie = "session"
	apiKeyPrefix       = "noadd_"

	// invalidSessionMaxAttempts unknown session tokens within
	// invalidSessionWindowSecs from one source are reported; a tab whose
	// session expired keeps sending its stale cookie, so the threshold sits
	// well above one.
	invalidSessionMaxAttempts = 10
	invalidSessionWindowSecs  = 60
)

// sessionCookieNames lists the cookie names to read, __Host- first.
var sessionCookieNames = [...]string{hostSessionCookie, plainSessionCookie}

// authedUser is an authenticated operator, from a session cookie, an
// "Authorization: Bearer <api key>" header or a forward-auth header.
type authedUser struct {
	UserID int64
	// ViaForwardAuth is true only when the forward-auth header authenticated
	// the request.
	ViaForwardAuth bool
	// SessionTokenHash is set when a session cookie authenticated the request.
	SessionTokenHash string
}

// sessionCookieHashes returns the token hashes of the request's session
// cookies, __Host- name first. A browser can hold both names, so callers keep
// the first that validates, not the first present, or a stale cookie shadows
// the live one. The raw token never leaves this function.
func sessionCookieHashes(r *http.Request) []string {
	var hashes []string
	for _, name := range sessionCookieNames {
		if cookie, err := r.Cookie(name); err == nil {
			hashes = append(hashes, auth.HashToken(cookie.Value))
		}
	}
	return hashes
}

// liveSessionTokenHash is the token hash of the session that authenticated
// this request. It checks membership instead of validating again, which would
// refresh last_seen and evict entries a second time.
func (a *api) liveSessionTokenHash(r *http.Request) (string, bool) {
	for _, hash := range sessionCookieHashes(r) {
		if _, live := a.Sessions.Get(hash); live {
			return hash, true
		}
	}
	return "", false
}

// validSessionFromCookies returns the first cookie session that validates.
// presented reports whether any session cookie was sent.
func (a *api) validSessionFromCookies(r *http.Request) (userID int64, tokenHash string, presented, ok bool) {
	hashes := sessionCookieHashes(r)
	for _, hash := range hashes {
		if userID, valid := a.Sessions.Validate(hash); valid {
			return userID, hash, true, true
		}
	}
	return 0, "", len(hashes) > 0, false
}

// currentSession is the session behind the request's cookies, or false after
// counting an unknown cookie.
func (a *api) currentSession(r *http.Request) (userID int64, tokenHash string, ok bool) {
	userID, tokenHash, presented, ok := a.validSessionFromCookies(r)
	if !ok && presented {
		a.noteInvalidSessionCookie(r)
	}
	return userID, tokenHash, ok
}

// noteInvalidSessionCookie counts a session cookie naming no live session and
// warns once when one source crosses the limit. Detect-only: a tab left open
// past its session's expiry keeps sending the stale cookie, and blocking would
// lock the operator out.
func (a *api) noteInvalidSessionCookie(r *http.Request) {
	ip := a.clientIP(r)
	if !a.InvalidSessionLimiter.RecordCrossing(ip) {
		return
	}
	a.log.Warn("repeated session cookies naming no live session",
		"event", "auth.failed",
		"method", "session_cookie",
		"reason", "unknown_token_burst",
		"ip", ip.String(),
		"attempts", invalidSessionMaxAttempts,
		"window_secs", invalidSessionWindowSecs,
		"user_agent", logSafe(headerLogValue(r.Header, "User-Agent")),
	)
}

// bearerToken extracts the token of an "Authorization: Bearer" header.
func bearerToken(r *http.Request) (string, bool) {
	value, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return strings.TrimSpace(value), found
}

// authenticate resolves who is calling. A zero status means success; 401 and
// 500 carry no body.
func (a *api) authenticate(r *http.Request) (authedUser, int) {
	if userID, tokenHash, presented, ok := a.validSessionFromCookies(r); ok {
		return authedUser{UserID: userID, SessionTokenHash: tokenHash}, 0
	} else if presented {
		// Counted now: an unknown session id was presented whether or not a
		// later credential authenticates the request.
		a.noteInvalidSessionCookie(r)
	}

	failedKeyPrefix := ""
	if token, found := bearerToken(r); found {
		userID, valid, err := a.DB.ValidateAPIKey(r.Context(), auth.HashToken(token), a.Now().Unix())
		if err == nil && valid {
			return authedUser{UserID: userID}, 0
		}
		if strings.HasPrefix(token, apiKeyPrefix) {
			failedKeyPrefix = logSafeText(token, failedKeyPrefixLen)
		}
	}

	if a.ForwardAuth != nil {
		if username, ok := a.ForwardAuth.Identify(r); ok {
			userID, err := a.resolveForwardAuthUser(r, username)
			if err != nil {
				a.log.Error("forward-auth operator lookup failed",
					"event", "forward_auth.lookup_failed", "error", err.Error())
				a.warnFailedKey(r, failedKeyPrefix)
				return authedUser{}, http.StatusInternalServerError
			}
			return authedUser{UserID: userID, ViaForwardAuth: true}, 0
		}
	}
	a.warnFailedKey(r, failedKeyPrefix)
	return authedUser{}, http.StatusUnauthorized
}

func (a *api) warnFailedKey(r *http.Request, prefix string) {
	if prefix == "" {
		return
	}
	a.log.Warn("api key authentication failed",
		"event", "auth.failed",
		"method", "api_key",
		"ip", a.clientIP(r).String(),
		"prefix", prefix,
	)
}

// resolveForwardAuthUser maps a forward-auth username to an operator id,
// provisioning it on first sight. A unique violation means a concurrent
// request won the insert, so it reads again.
func (a *api) resolveForwardAuthUser(r *http.Request, username string) (int64, error) {
	ctx := writeCtx(r)
	existing, found, err := a.DB.GetUserAuth(ctx, username)
	if err != nil {
		return 0, err
	}
	if found {
		return existing.ID, nil
	}
	id, err := a.DB.CreateUserNoPassword(ctx, username, a.Now().Unix())
	if err == nil {
		a.log.Info("provisioned operator from forward-auth header",
			"event", "forward_auth.provisioned", "username", username)
		return id, nil
	}
	if !db.IsUniqueViolation(err) {
		return 0, err
	}
	existing, found, rereadErr := a.DB.GetUserAuth(ctx, username)
	if rereadErr != nil {
		return 0, rereadErr
	}
	if !found {
		return 0, err
	}
	return existing.ID, nil
}

// authed runs h for an authenticated operator; otherwise it answers with the
// bare 401 or 500.
func (a *api) authed(h func(http.ResponseWriter, *http.Request, authedUser)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, status := a.authenticate(r)
		if status != 0 {
			writeStatus(w, status)
			return
		}
		h(w, r, user)
	}
}

type reauthErrorBody struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// reauthed runs h for an operator who proved the password recently, which is
// what an action that hands out durable access needs (minting an API key,
// adding or removing an operator).
//
//   - Session cookie: a password proof within auth.ReauthWindow; login counts.
//   - Forward auth: exempt, the proxy authenticated this very request and the
//     account has no password.
//   - API key: refused, it cannot present a password and could otherwise mint
//     itself a permanent successor.
func (a *api) reauthed(h func(http.ResponseWriter, *http.Request, authedUser)) http.HandlerFunc {
	return a.authed(func(w http.ResponseWriter, r *http.Request, user authedUser) {
		if user.ViaForwardAuth {
			h(w, r, user)
			return
		}
		if user.SessionTokenHash == "" {
			writeJSON(w, http.StatusForbidden, reauthErrorBody{
				Error: "this action requires a password and cannot be performed with an API key",
				Code:  "password_required",
			})
			return
		}
		if !a.Sessions.HasFreshReauth(user.SessionTokenHash) {
			writeJSON(w, http.StatusForbidden, reauthErrorBody{
				Error: "confirm your password to continue",
				Code:  "reauth_required",
			})
			return
		}
		h(w, r, user)
	})
}

// sid is the salted log identifier of a session's token hash.
func (a *api) sid(tokenHash string) string {
	return auth.SidHash(a.Sessions.Salt(), tokenHash)
}

// acceptAfterVerify decides whether a password check lets the caller through.
// The lock is checked again after the verify because requests queue for an
// Argon2 slot: each passed IsLocked before any failure was counted, so without
// this the queue depth, not the lockout, would bound how many guesses land. A
// correct guess against a now-locked account is refused like a wrong one.
func acceptAfterVerify(valid, locked bool) bool { return valid && !locked }

// noteAccountFailure counts a password failure and logs a lockout when one
// starts or extends. The event carries user_id, never the username.
func (a *api) noteAccountFailure(userID int64, ip netip.Addr, endpoint string) {
	lock := a.Lockout.RecordFailure(userID)
	if lock <= 0 {
		return
	}
	a.log.Warn("account locked after repeated password failures",
		"event", "auth.account_locked",
		"user_id", userID,
		"ip", ip.String(),
		"endpoint", endpoint,
		"locked_secs", int64(lock/time.Second),
	)
}
