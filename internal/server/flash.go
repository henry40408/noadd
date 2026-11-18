package server

import "net/http"

// flash is a one-shot notice left behind by a redirect.
//
// A closed set, not free text: only the identifier travels in the cookie, so
// it cannot break the header or carry text the server did not write. The
// wording lives in the view.
type flash string

const (
	flashNone            flash = ""
	flashWelcome         flash = "welcome"
	flashProxyLogout     flash = "proxy_logout"
	flashSettingsSaved   flash = "settings_saved"
	flashPasswordChanged flash = "password_changed"
	flashFiltersSaved    flash = "filters_saved"
	flashListsUpdating   flash = "lists_updating"
	flashAccountSaved    flash = "account_saved"
	flashSessionsRevoked flash = "sessions_revoked"
	flashLogsCleared     flash = "logs_cleared"
)

// flashCookieName is the cookie a flash rides in: a cookie rather than the
// query string, which would survive refreshes, bookmarks and shared links.
// Session-scoped (no Max-Age) on purpose.
const flashCookieName = "noadd_flash"

var knownFlashes = map[flash]bool{
	flashWelcome: true, flashProxyLogout: true, flashSettingsSaved: true,
	flashPasswordChanged: true, flashFiltersSaved: true, flashListsUpdating: true,
	flashAccountSaved: true, flashSessionsRevoked: true, flashLogsCleared: true,
}

func setFlash(w http.ResponseWriter, value flash) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    string(value),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// takeFlash reads the pending notice and clears it in the same step, so a
// rendered flash cannot survive to show again. A stale or hand-written cookie
// yields no notice and is left alone, as in Rust.
func takeFlash(w http.ResponseWriter, r *http.Request) flash {
	cookie, err := r.Cookie(flashCookieName)
	if err != nil {
		return flashNone
	}
	value := flash(cookie.Value)
	if !knownFlashes[value] {
		return flashNone
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookieName, Value: "", Path: "/", MaxAge: -1})
	return value
}
