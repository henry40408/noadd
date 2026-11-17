package server

import (
	"net/http"
	"sort"
	"strings"
)

// routeTable collects handlers by path and method, so every path can answer a
// wrong method with 405 and an Allow header instead of falling through to the
// static-file catch-all, as the Rust router did.
type routeTable struct {
	byPath map[string]map[string]http.Handler
}

func newRouteTable() *routeTable {
	return &routeTable{byPath: map[string]map[string]http.Handler{}}
}

func (t *routeTable) handle(method, path string, h http.Handler) {
	if t.byPath[path] == nil {
		t.byPath[path] = map[string]http.Handler{}
	}
	t.byPath[path][method] = h
}

func (t *routeTable) handleFunc(method, path string, h http.HandlerFunc) {
	t.handle(method, path, h)
}

// mount registers every path on mux.
func (t *routeTable) mount(mux *http.ServeMux) {
	for path, methods := range t.byPath {
		allowed := make([]string, 0, len(methods)+1)
		for method, h := range methods {
			mux.Handle(method+" "+path, h)
			allowed = append(allowed, method)
			if method == http.MethodGet {
				allowed = append(allowed, http.MethodHead)
			}
		}
		sort.Strings(allowed)
		allow := strings.Join(allowed, ", ")
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Allow", allow)
			w.WriteHeader(http.StatusMethodNotAllowed)
		})
	}
}

// registerAPIRoutes adds the admin JSON API.
func (a *api) registerAPIRoutes(t *routeTable) {
	const (
		get    = http.MethodGet
		post   = http.MethodPost
		delete = http.MethodDelete
	)
	// Sign-in, setup and health need no auth.
	t.handleFunc(post, "/api/auth/login", a.login)
	t.handleFunc(post, "/api/auth/setup", a.setup)
	// reauth and the password change stamp or rotate a session, so they read
	// the cookie themselves instead of using the generic authentication.
	t.handleFunc(post, "/api/auth/reauth", a.reauth)
	t.handleFunc(post, "/api/auth/revoke-others", a.authed(a.revokeOthers))
	t.handleFunc(post, "/api/auth/logout", a.authed(a.logout))
	t.handleFunc(get, "/api/auth/me", a.authed(a.me))
	t.handleFunc(get, "/api/health", a.health)
	t.handleFunc(get, "/api/server-info", a.authed(a.serverInfo))

	t.handleFunc(get, "/api/users", a.authed(a.listUsers))
	t.handleFunc(post, "/api/users", a.reauthed(a.createUser))
	t.handleFunc(delete, "/api/users/{id}", a.reauthed(a.deleteUser))
	t.handleFunc(post, "/api/users/me/password", a.changeOwnPassword)
	t.handleFunc(get, "/api/sessions", a.authed(a.listSessions))
	t.handleFunc(delete, "/api/sessions/{id}", a.authed(a.revokeSessionByID))

	t.handleFunc(get, "/api/doh-tokens", a.authed(a.listDohTokens))
	t.handleFunc(post, "/api/doh-tokens", a.authed(a.addDohToken))
	t.handleFunc(delete, "/api/doh-tokens/{id}", a.authed(a.deleteDohToken))
	t.handleFunc(get, "/api/api-keys", a.authed(a.listAPIKeys))
	t.handleFunc(post, "/api/api-keys", a.reauthed(a.createAPIKey))
	t.handleFunc(delete, "/api/api-keys/{id}", a.authed(a.deleteAPIKey))
}
