package server

import (
	"net/http"
	"slices"
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

// refusedMethods are answered 405 on a path that does not handle them. A
// method-less fallback pattern would conflict with wildcard routes such as
// "PUT /api/lists/{id}" next to "POST /api/lists/update", so each method gets
// its own pattern. HEAD is covered by GET.
var refusedMethods = []string{
	http.MethodGet, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodOptions,
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
		refuse := methodNotAllowed(strings.Join(allowed, ", "))
		for _, method := range refusedMethods {
			if !slices.Contains(allowed, method) {
				mux.Handle(method+" "+path, refuse)
			}
		}
	}
}

func methodNotAllowed(allow string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allow)
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
}

// registerAPIRoutes adds the admin JSON API.
func (a *api) registerAPIRoutes(t *routeTable) {
	const (
		get    = http.MethodGet
		post   = http.MethodPost
		delete = http.MethodDelete
	)
	a.registerFilterRoutes(t)
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

// registerFilterRoutes adds settings, lists, rules and upstream routes.
func (a *api) registerFilterRoutes(t *routeTable) {
	const (
		get    = http.MethodGet
		post   = http.MethodPost
		put    = http.MethodPut
		delete = http.MethodDelete
	)
	t.handleFunc(get, "/api/settings", a.authed(a.getSettings))
	t.handleFunc(put, "/api/settings", a.authed(a.putSettings))

	t.handleFunc(get, "/api/lists", a.authed(a.getLists))
	t.handleFunc(post, "/api/lists", a.authed(a.addList))
	t.handleFunc(post, "/api/lists/batch", a.authed(a.batchAddLists))
	t.handleFunc(post, "/api/lists/update", a.authed(a.triggerListUpdate))
	t.handleFunc(put, "/api/lists/{id}", a.authed(a.updateList))
	t.handleFunc(delete, "/api/lists/{id}", a.authed(a.deleteList))
	t.handleFunc(post, "/api/lists/{id}/check", a.authed(a.checkListURL))
	t.handleFunc(get, "/api/registry/filters", a.authed(a.getRegistryFilters))

	t.handleFunc(get, "/api/rules", a.authed(a.getRules))
	t.handleFunc(post, "/api/rules", a.authed(a.addRule))
	t.handleFunc(delete, "/api/rules/{id}", a.authed(a.deleteRule))
	t.handleFunc(post, "/api/filter/check", a.authed(a.filterCheck))

	t.handleFunc(get, "/api/logs", a.authed(a.getLogs))
	t.handleFunc(delete, "/api/logs", a.authed(a.deleteLogs))
	// No session: the DoH token in the path is the credential.
	t.handleFunc(get, "/api/mobileconfig/{token}", a.getMobileConfig)

	t.handleFunc(get, "/api/upstream/health", a.authed(a.upstreamHealth))
	t.handleFunc(get, "/api/upstream/latency", a.authed(a.upstreamLatency))
}
