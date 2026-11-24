# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## What this is

noadd is a single-binary, self-hosted DNS ad-blocker (plain DNS + DNS-over-HTTPS) in Go. The admin web UI is embedded at compile time (`go:embed`); all runtime state lives in one SQLite file (pure-Go `modernc.org/sqlite`, no cgo). `README.md` covers usage. **Read `ARCHITECTURE.md` before touching the filter engine, query pipeline, or storage layer.** The code was ported from a Rust implementation: each package's `PORTING.txt` records what was measured and where behaviour was pinned, and the goldens in `testdata/` and the values written inline in tests were captured from the Rust server.

## Commands

Run from the repository root. The Go version comes from `go.mod` alone (`go` + `toolchain` lines); CI and the Dockerfile install nothing version-specific.

```bash
go build -o bin/noadd ./cmd/noadd
go run ./cmd/noadd --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:8080   # NOADD_LOG_LEVEL=debug for debug logs
go test -race ./...                       # CI runs this with -mod=vendor
go test ./internal/filter -run TestParse  # one package / test
golangci-lint fmt --diff ./...            # gofmt; must print nothing
golangci-lint run ./...                   # errcheck, govet, ineffassign, staticcheck, unused
```

- **Lint (CI-enforced):** config in `.golangci.yml`; suppress with `//nolint:<linter> // reason` (`//lint:ignore` is not honoured). `run` does not check formatting, so `fmt --diff` is a separate step. The linter release comes from `golangci/golangci-lint-action` (`install-only`); dependabot tracks only the action. Run both commands in `e2e/` too.

- **Coverage (as CI):** `NOADD_COVERDIR=$PWD/covdata go test -mod=vendor -coverprofile=coverage.out ./...`, then `go tool covdata textfmt -i=covdata -o coverage-bin.out` and append it to `coverage.out` without its `mode:` line. `-coverprofile` ignores the binary that `cmd/noadd`'s tests exec; with `NOADD_COVERDIR` set they build it with `-cover`.
- **Benchmarks (user rule):** before and after a performance change run `go test -run='^$' -bench=<name> -benchmem -count=10`, compare with `go run golang.org/x/perf/cmd/benchstat@<version>` (check the version is at least 7 days old). A regression above 5% (p < 0.05) must not be committed. `scripts/bench-doh.py` and `scripts/fuzz-doh.py` load- and fuzz-test a running binary.
- **Mutation testing:** `.gremlins.yaml` holds the efficacy threshold and the `e2e/` and `vendor/` exclusions; run `go clean -testcache` first, then `GOMAXPROCS=2 go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 unleash --workers 2 .`. Never pass `--threshold-efficacy` on the command line: gremlins v0.6.0 reads it as 0 and always exits 0. Never pass `--test-cpu` either: v0.6.0 builds a single `-cpu 2` argument, every mutant's `go test` fails and counts as killed; limit CPUs with `GOMAXPROCS`. CI splits the module into seven `mutation-shard (<name>)` matrix jobs (server-api, server-pages, db, auth-upstream, filter-dnsserver, views-stats, small-packages), each on its own runner with about 250-310 mutants; the `mutation` job `needs` all of them and fails if any shard fails or is cancelled, so branch protection names only `mutation`. A shard is the whole module minus a `--exclude-files` regexp (RE2 has no lookahead, so the matrix lists the complement), which keeps coverage computed from every package's tests. Small packages share a shard so one lived mutant cannot sink a tiny shard's efficacy. Each shard must reach the 95 threshold by itself (it is not a module-wide average), and every shard keeps its own zero-mutant guard. Each shard uploads its log as an artifact. Shards scan their files fully on push and only the diff on a pull request. Keep the shard sizes balanced when packages grow.
- **Vendoring:** third-party modules are **vendored and committed** (`vendor/`, and `e2e/vendor/` for the e2e module); builds use `-mod=vendor`. To add or update a dependency: `go get <module>@<version>`, `go mod tidy`, `go mod vendor`, and commit `go.mod`, `go.sum` and `vendor/` together. CI (`deps` job) runs `go mod tidy -diff`, `go mod vendor` then `git status --porcelain -- vendor go.mod go.sum` (must print nothing), and `govulncheck`.
- **Dependency age (user rule):** a dependency (module, GitHub Action, base image) must be at least 168 hours (7 days) old. Check with `curl -s https://proxy.golang.org/<module>/@v/<version>.info` and read `Time`.
- **Licences:** `GOROOT=$(go env GOROOT) go run github.com/google/go-licenses/v2@v2.0.1 check ./... --include_tests --ignore github.com/henry40408/noadd --allowed_licenses=<list>`. The allow-list lives only in the `deps` job's `ALLOWED_LICENSES` in `.github/workflows/ci.yml`; `e2e/` also allows MPL-2.0 (godog pulls in MPL-2.0 modules), the root module must not. If a licence is unknown or disallowed, do not widen the list or swap the module without asking.
- **Golden files:** `internal/views/testdata` and `internal/db/testdata` pin markup and databases captured from the Rust server. Smaller captured values are written inline in the test that uses them: `rustGoldens` (`internal/server/server_test.go`), `openAPIRustDigest` (`api_stats_test.go`), `rustMobileConfig` (`api_logs_test.go`), `rustPasswordVectors` and `rustTokenVectors` (`internal/auth/password_test.go`), `rustPolicyVerdicts` (`internal/auth/policy_test.go`), `rustWireCases` (`internal/dns/wire_cases_test.go`), `rustFixtureLists` and `rustFixtureVerdicts` (`internal/filter/fixture_data_test.go`). Do not regenerate any of them to make a test pass; a deliberate markup or API change means regenerating the golden, and the e2e suite where it depends on that markup, together, with the reason in the commit body.
- **`internal/server/openapi.json` is maintained by hand**; a test checks that the routes and the spec agree.
- **HTML builder (`internal/views/html.go`):** text and attribute values are escaped by the builder; only values wrapped as raw markup are not. Never pass untrusted text as raw markup. `safeURL` keeps a non-`http(s)` homepage out of an `href`.
- **Env vars** carry a `NOADD_` prefix. `NOADD_LOG_LEVEL` (`debug|info|warn|error`, default `info`) is env-only; `--log-format` accepts `full` or `json`. `RUST_LOG` is retired and fails startup. **Whenever you add, rename or remove an environment variable, update `legacyEnvVars` in `cmd/noadd/env.go`**: a silently ignored variable is worse than a startup failure.
- GitHub Actions in `.github/workflows` are pinned by commit SHA with the tag as a trailing comment.

### End-to-end (admin UI)

Gherkin features (`e2e/features/*.feature`) run through `godog` and drive the Go binary in a real browser via `chromedp`. `e2e/` is a **separate Go module** with its own `go.mod` and committed `vendor/`; `go test ./...` at the root does not run it, and `e2e/go.mod` mirrors the root `go`/`toolchain` lines (CI checks it).

```bash
go build -o bin/noadd ./cmd/noadd   # the suite never rebuilds an existing bin/noadd, and the UI is embedded
cd e2e
go test -mod=vendor -count=1 -v .   # -count=1: the test cache cannot see a rebuilt binary
E2E_FEATURES=features/dashboard.feature go test -mod=vendor -count=1 .   # comma-separated list
```

- A feature's tag (`@app`, `@auth`, `@onboarding`) picks its instance; `e2e_test.go` starts one server per tag (HTTP 14100-14102, DNS = HTTP + 1000). Scenarios run one at a time, in file order.
- Needs a local Chrome or Chromium. `E2E_CHROME` pins the binary, `E2E_BINARY` the server binary, `E2E_SERVER_LOG` appends every server's stderr (the setup token and fatal errors; the slog stream goes to stdout and is discarded) to a file, so a crashed server does not show only as a refused connection.
- Run e2e one at a time, niced, and check afterwards that no `noadd` or Chrome process is left.
- Every `Expect*` helper in `e2e/internal/harness` polls for 30 s and reports the last value seen. Text is `textContent`, not rendered text: the UI uppercases badges in CSS, so assert against the markup.
- Run `golangci-lint fmt --diff` and `run` inside `e2e/` as well.
- The former Rust-only regression specs (no-JS pages, settings autosave, live tail, chart touch, statistics charts, account actions) are ported to Go in `e2e/spec_*_test.go` and run with the rest of `go test` in `e2e/`. The screenshot-capturing binary is not ported (only its seed, `e2e/internal/harness/seed_screenshots.go`); see git history before the cutover commit.

## Build-time behavior

- The version comes from `-ldflags "-X github.com/henry40408/noadd/internal/version.version=$GIT_VERSION"` when set (empty or `dev` counts as unset), else from the VCS info Go stamps, else `dev`. `.dockerignore` excludes `.git`, so Docker builds pass `--build-arg GIT_VERSION=...`.
- Releases use `gh release create --generate-notes`; never edit a manifest version, add a `CHANGELOG.md` or hand-create a tag.

## Admin UI

**Routing and authentication are server-side.** `internal/server/pages*.go` hold the handlers and page structs; the views are in `internal/views/`. Each page path — `/`, `/stats`, `/logs`, `/filters`, `/filters/registry`, `/settings`, `/account` — resolves the session *before* writing HTML, redirecting to `/login?next=…` or `/setup`. `/login` and `/setup` are real `<form method="post">` pages that work without JavaScript. Navigation is plain links; no client-side router.

Sign-in and setup need **no CSRF token**: the CSRF middleware (`internal/server/csrf.go`, wired in the admin handler chain in `server.go`) is a header-based origin guard over every unsafe method, refusing cross-origin form posts before any handler.

Password sign-in lives **only** in `startPasswordSession` (`internal/server/api_auth.go`), shared by `POST /api/auth/login` and `POST /login`; first-run account creation likewise in `createFirstOperator`. Rate limiting, constant Argon2 cost, lockout and audit events are all there — do not grow a second path.

**The shell is server-rendered** (`views.Shell`, `internal/views/layout.go`): topbar, both nav bars, status bar, one-shot notices. `app.js` must not re-derive what it decided — e.g. the active nav item is a class set from the path. The nav table is the one in `internal/views/layout.go`, driving both the desktop strip and the mobile F-key bar.

Page bodies are **vanilla-JS web components — no framework, no build step** — in `internal/assets/static/app.css` and `app.js`. No `index.html`, **no SPA fallback**: an unmatched path 404s. The directory is embedded via `go:embed` (`internal/assets`), so edit `app.js`, `app.css` or the views, then rebuild. Assets get a per-file content-hash `ETag` + `Cache-Control: no-cache`; server-rendered pages get `no-store` from the same layer, which applies only when a response declares no policy.

One-shot notices ride a **flash cookie** (`internal/server/flash.go`), cleared by the response that renders them — never the query string, which survives refreshes, bookmarks and shared links.

### Server-rendering a page body

Settings is the worked example.

- The view builds the page body and passes it to `views.Shell`; its data struct embeds `ShellData`.
- **Wrap the body in the page's custom element** (`<settings-page>…</settings-page>`), which upgrades in place; `app.js` enhances the markup and never mounts a page.
- Validation lives in **one** function shared with the JSON endpoint (`applySettings`, `internal/server/pages_settings.go` and `api_settings.go`), returning a field-tagged error so the form shows it by the input while the API returns a bare 400.
- A successful POST redirects with a flash; a rejected one re-renders **with the submitted values** at 400/401 — never 200.
- When `app.js` enhances a form it removes (not hides) the no-JS submit row (`#settings-save-row`), and any submit button it takes over must `preventDefault()`.
- **`load()` must not refill server-rendered fields**, or it overwrites what the operator typed before the response landed.

⚠️ A `querySelector` returning `null` in `connectedCallback` throws and **silently kills every binding after it**. When moving markup, check every id `app.js` reaches for still exists.

Filters — a page whose body is *a list of things*:

- **A read is a GET, a change is a POST.** The domain test is `GET /filters?test=…` (refreshable, linkable). Each mutation is its own route (`/filters/lists/{id}/toggle`, `…/edit`, `…/delete`, `/filters/rules`, …), not one endpoint switching on an action field.
- **One form per row**, since a browser posts only the submitted form.
- **Row state that needs a client lives in the URL.** `GET /filters?edit={id}` expands that row into a form filled *from storage*, never from the query string. With JavaScript the same `<a>` opens a dialog instead.
- **`.nojs-only` / `.js-only`** ship in the no-script-correct state: `app.js` removes the first and unhides the second. A client-only control (the registry modal) ships `hidden`.
- **The Impact column comes from the live engine** (`filter.Engine.UniqueRulesByList`), not storage; every list change already triggers the rebuild that recomputes it. `listImpact` (`internal/server/pages_filters.go`) and `listImpact` (`app.js`) must phrase it identically.
- **Two lists with the same rules both report "No impact"** — true for removing either alone — so the page says to turn one off at a time.
- **`app.js` redraws rows in the template's exact shape**, forms included, so one set of bindings serves both.
- Derived values (thousands separators, "5 minutes ago") are computed **server-side to match `app.js`**.

Registry browser (`/filters/registry`) — **a picker that batch-submits**:

- **Two forms, never nested**: a `method="get"` form for the three filters (state in the URL) and a `method="post"` form wrapping the rows.
- **Filtering by navigating clears the selection**; with a client, `app.js` hides rows in place so ticks and counts survive.
- **The form posts ids; the server looks up name and URL** in the registry rather than trusting the body. Read the repeated `filter_id` keys from `r.PostForm`.
- **`addListsBatch` (`internal/server/api_lists.go`) is the only batch-add path**, shared with `POST /api/lists/batch`: one concurrency cap, per-item rollback, one rebuild.
- **Full success redirects; partial failure renders**, since the per-item reasons exist only in that response.
- **An unreachable registry is a rendered state** with a retry link to the same URL — not a spinner, not a 502.
- ⚠️ **`safeURL` (`internal/server/pages.go`) keeps a `javascript:` homepage out of an `href`** — escaping does not stop navigation. Only absolute `http(s)` survives; covered by a test in `pages_registry_test.go`.

Query log — **filtering and paging**:

- **The whole view is in the URL**: `/logs?q=&action=&type=&token=&page=`. Filters are a GET form, the pager two `<a>`s; `app.js` adopts the query string on connect.
- **The pager carries every filter**: `logsQueryString` rebuilds the query with only `page` replaced.
- **A row action carries its origin** in a `next` field, validated by `safeNext`, so it returns to the same page and filter.
- **An empty table says which case it is**: the empty-log guide when unfiltered, "No logs found" when filtered.
- **Clearing lands on an unfiltered first page** whatever view it came from.
- ⚠️ **Forms cannot nest.** Clear All sits in the filters row via `form="clear-logs-form"`, pointing at an empty POST form after it; `app.js` must bind its confirmation to *that* form, not `closest('form')`.
- **The live tail is a subscription on the shell's stream** (see *The event stream*); the page owns no `EventSource`. `_prependRow` drops what arrives while the tail is off, so the listener is registered once for the page's life.
- ⚠️ **This toggle keeps its label** and carries state in a `paused` class (the dashboard's rewrites its text) — asserting `"PAUSED"` here passes against nothing.
- Relative times are the one deliberate mismatch: the server renders `"3 minutes ago"`, the client replaces it via `Intl.RelativeTimeFormat` in the browser's locale.

Dashboard — **all readings, no controls**:

- **The numbers are in the first response.** `dashboardPage` calls `stats.ComputeSummary`, `ComputeTopDomainsAndClients` and `ComputeTopUpstreams` (`internal/stats`) — the same functions the `stats` snapshot uses each tick (`ComputeSnapshot` adds `ComputeTimeline`). A failed read renders zeroes rather than an error page.
- **`app.js` redraws the same markup from pushed snapshots**; every template shape has a counterpart in `DashboardPage`, and `_apply` reads the snapshot's five bodies (summary, timeline, top domains, clients, upstreams). Number formatting is duplicated in Go to match (`formatNumAdaptive`, `percent1` and friends in `internal/server/helpers.go`), so a count never changes notation when an update lands.
- **The chart is the documented no-JS exception**: drawn client-side, and the card says so until the client replaces that text.
- ⚠️ **Merge a conditional `style` into the element's existing one.** A second `style` attribute is dropped — the chart card's `animation-delay` and `display:none` share one attribute for that reason.

Statistics — readings in a **chosen window**, and what the server cannot render:

- **Only the three charts need a calendar**, and calendar-aligned buckets need the viewer's UTC offset, which the request lacks. Everything else is a plain `now - range` window rendered server-side: highlights, both breakdowns, both ranged lists, the health grid.
- **Chart data is in the first response too**, in UTC: `<stats-page data-series>` is a `db.QuarterSeries` (per-quarter-hour counts from the same scan), and `timelineFromQuarters` / `heatmapFromQuarters` in `app.js` fold it into local hours and days — exact, since every offset in use is a whole number of quarter hours. `/api/stats/v2/timeline` and `…/heatmap` take `tz_offset` (rounded to the nearest quarter hour) for API callers. The former Rust spec that held the JS folds to them (`stats_charts.rs`) is not ported: when changing one side, check the other by hand.
- **`StatsPage` draws three charts and one date**, nothing else, and does not poll.
- **The range is in the URL**, the switcher three `<a>`s (`/stats?range=30d`). `StatsRange::label()` is the one spelling for link, parse and card titles. An unrecognised range renders the default rather than 400ing.
- **A date the server can only write in UTC ships as an ISO day plus `data-date-ts`**; `app.js` restates it in the browser's locale.
- **Measured in page misses, not milliseconds** — the appliance runs off an SD card; page counts transfer, durations do not. `BenchmarkStatsPage`, `BenchmarkDashboardPage` and `BenchmarkLogsPage` (`internal/server/pages_data_test.go`) and the `internal/db` benchmarks report time and allocations, with `BENCH_DB` pointed at a copy of a real database and `BENCH_NOW` pinning the clock for an older copy. The pure-Go SQLite driver exposes no page-miss counter, so allocations stand in for it; distrust a wall-clock reading when the two disagree.
- **One statement per rollup family.** The page's reads are `StatsScanSince` (quarter + metrics rollups) and `TrafficListsSince` (top domains, distinct-domain count, top clients) in `internal/db/stats.go`, via `stats.ComputeRangeStats`. `StatsScanSince` streams rows and folds in Go, telling its four arms apart by a leading column. A new reading is folded out of one of these, not added as a statement.
- **A total nobody can count cheaply is maintained.** `query_logs`' row count lives in `settings` (`query_log_count`), moved by the insert batch, the prune and Clear All inside their own transactions; the Database Health card and the unfiltered pager read it. A fourth write path to `query_logs` must move it too, in its own transaction (`bumpLogCount` in `internal/db`, as `DeleteAllLogs` does).
- **The rollups (`query_stats_*`, ARCHITECTURE.md *Rollups*) must always equal a recount of `query_logs`.** Inserts are covered by the `query_logs_maintain_stats` trigger; a new path that *deletes* from `query_logs` must unwind them in its own transaction, as the prune (`unwindStatsRollups`, `internal/db/maintenance.go`) and Clear All do.
- Four bar lists share **one function** (`barRow` in `internal/views/stats.go`).
- **The HTML builder writes exactly the whitespace it is given.** Goldens pin it byte for byte, so keep the spacing between inline siblings identical to them. Attribute values are always double-quoted and escaped.

Account — **actions that need a password proof**:

- **The password rides in the form that needs it** (`your_password`) for adding an operator, deleting one, and minting an API key — identical with and without JavaScript, no dialog. `POST /api/auth/reauth` remains for API callers.
- **`confirmPassword` (`internal/server/api_auth.go`; the form path wraps it in `confirmFormPassword`) is the only password check for either path** — one rate limit, one lockout, one `auth.reauthenticated` event.
- **A destructive row action expands into a named confirmation** (`GET /account?confirm_delete={id}`); `app.js` adds `confirm()` only where the server has none.
- **Creating an API key renders instead of redirecting** — the one PRG exception, since the token exists only in that response. A refresh mints a second key, which the operator can see and delete.
- **A rejected form never echoes a password.** Only username, key name and expiry are re-rendered.
- Account POSTs render as `/account` whatever path they arrived on (the shell is built for `/account`), so the nav marks the right page.

### The event stream

`GET /api/events` (`streamEvents` in `internal/server/api_events.go`, hub in `internal/events`) is the admin UI's **only** push channel; `serverEvents` in `app.js` is its single `EventSource`.

- **One connection per page.** The status indicator is on every page, and without HTTP/2 a browser gets six connections per origin. New pushes arrive as a new event name on this stream, never a second stream.
- **`ping` every tick, always** — the indicator's heartbeat. It must be a real event (SSE keep-alive comments never reach `EventSource`); the client shows OFFLINE after three missed ticks, since silence is what a dead server looks like.
- **`stats` only when asked** (`?stats=1`, dashboard only), so an idle page costs no aggregate queries per tick. The subscription drops the claim when the connection closes (the request context ends it).
- **`log` only when asked** (`?logs=1`). The tail ships *off*, so `serverEvents.setLogs()` re-opens the one connection with the subscription added; that swap is deliberately not reported as a drop, or the indicator would blink OFFLINE on a toggle click.
- **`rebuild` unasked-for, like `ping`**, since the banner is in the shell. It is an *edge*: `filter.Coordinator` (`internal/filter/rebuild.go`) publishes at start and end, so a rebuild between two ticks is still seen. `RebuildStatus` is the one shape it travels in.
- ⚠️ **A slow subscriber is dropped by the hub, and `EventSource` reconnects**, which delivers the live `rebuild` state on open. A missed tick recurs in ten seconds; a missed completion edge never would.
- **Every connection gets a `rebuild` as it opens.** The stream is the only place this state is published, so it must answer "what is happening now". Tests rely on it to wait on a rebuild that may already have finished (the e2e harness's `API` helpers in `e2e/internal/harness/api.go`).
- ⚠️ **`RebuildBanner` must not call `serverEvents.start()`.** It upgrades before `<server-status>`, and the query string is fixed at open — starting there would settle `stats=1` as false and starve the dashboard. Any future stream consumer in `<main>` inherits this rule.
- **A client disconnect ends the handler** through the request context and closes its subscription; shutdown ends every stream through `APIDeps.StopStreams`, or `Shutdown` would wait for them.
- **`ping` carries `traffic`** — whether the appliance has ever answered a query — as a state bit rather than a new event; only the onboarding notice reads it. `events.Hub` latches it one-way, so the `EXISTS` stops once true; a page render that learns the fact sets the latch too (`nextStepTarget`).
- **The snapshot is computed once per tick and shared** across clients.
- **A `stats=1` client gets a snapshot as the stream opens**, so it is never ten seconds behind the server-rendered numbers.
- **Nothing ticks while nobody is connected** (`Hub.Run` skips on `ConnectionCount() == 0`).
- The dashboard's LIVE toggle stops *applying* snapshots, not the connection, because the indicator shares it.
- ⚠️ **A `fetch` stub no longer reaches the dashboard**: pushed snapshots arrive through `EventSource`, so a test that needs fake numbers must patch `EventSource.prototype.addEventListener` and hand the listener a reconstructed `MessageEvent`, since `data` is read-only.

**The onboarding notice is the shell's, decided server-side** (`ShowNextStep` / `NextStepAddr` on `ShellData`, resolved by `nextStepTarget` in `internal/server/pages.go`), with no client fetches:

- **It is not rendered on `/`**, where the dashboard's own empty state (`dashboard-empty-state`) says the same; e2e scenarios covering the banner therefore use another tab.
- **Dismissing is `POST /onboarding/dismiss`**, a real form carrying `next` through `safeNext` and writing the `onboarding_banner_dismissed` setting the JSON API uses. `app.js` cancels the submit and removes the notice in place.
- **It removes itself on the heartbeat's `traffic` flag.**

⚠️ **The status indicator reports the stream, not the markup.** It ships `hidden` and is unhidden by its own `connectedCallback`; without JavaScript it stays hidden, since a page that cannot sense the server must not claim it is up.

⚠️ **The status bar is `position: fixed` at the bottom**, so a control near the page foot can sit under it and swallow a click ("intercepts pointer events", seen on a shorter CI window). `:root` sets `scroll-padding-bottom`; scripted clicks and `Enter` submits are the workaround in browser tests.

⚠️ **With scripting off a page is interactive as soon as it parses**, so a click can land while a `fade-in` card is still sliding. a browser test should follow a click on the range switcher with assertions that only pass if the navigation happened.

`/api/*` remains the contract for API keys and the OpenAPI spec, but the UI does not use it to decide who is signed in or which screen to show.

After any change to the UI's appearance, regenerate the affected `docs/screenshots/` by hand (the Rust screenshot generator was not ported) and commit the PNGs. Skip for non-visual edits (copy, logic, test hooks, accessibility attributes).

## Architecture essentials

Query path (`internal/dnsserver/handler.go`): **filter → cache → upstream forward**, logging async over a buffered channel. Filter runs *before* cache so new block rules take effect immediately.

- **Filter engine** (`internal/filter/engine.go`): exact-match set plus a flat reverse-domain trie, serialised into contiguous byte buffers. The live engine sits behind an atomic holder (`holder.go`); updates build a fresh engine and swap it in. Coordination in `internal/filter/rebuild.go`.
- **Storage** (`internal/db`): all schema, migrations and CRUD. Versioned by `PRAGMA user_version`, incremental and forward-only. An hourly task prunes `query_logs` and runs maintenance.
- **Async logging** (`internal/querylog`): channel → a goroutine batches to SQLite (500 entries or 1 s).
- **Upstream** (`internal/upstream`): forwarder plus strategies (Sequential / Round Robin / Lowest Latency via EMA), switchable at runtime.
- **DoH** (`internal/dnsserver/doh.go`), optionally gated by URL tokens.
- **Admin** (`internal/server`): `api_*.go` (REST, event stream, static serving), `pages_*.go` (server-rendered pages), `internal/auth` (Argon2, sessions, rate limiting, forward auth), `csrf.go`, `internal/events`, `internal/stats`.
- `cmd/noadd` wires it all together: options and env, DB path, logging, TLS (`internal/tlsserve`), serve, shutdown, background jobs.

## Diagnostic logging

Separate from the `query_logs` table: the `log/slog` stream on stdout (stderr carries the setup token and fatal errors only), configured in `cmd/noadd` (`--log-format` `full|json`, `NOADD_LOG_LEVEL`, default `info`).

**Every `Debug`/`Info`/`Warn`/`Error` call carries `"event", "domain.action"` as its first field**, every value is a field rather than interpolated, and the message is a static string:

```go
// yes
logger.Debug("failed to send response", "event", "dns.send_failed", "transport", "tcp", "stage", "flush", "client", peer, "error", err)

// no: the values are trapped in the string, and the message is the only key
logger.Debug(fmt.Sprintf("TCP flush error for %s: %v", peer, err))
```

With `--log-format json` each field is its own key, so `jq 'select(.event == "upstream.forward_failed")'` works regardless of message wording.

- **Prefer a field over a new event name.** The TCP write failures share `dns.send_failed` and differ by `stage`; UDP and TCP share `dns.listener_started` and differ by `transport`.
- **Name events `domain.action`**, past tense for things that happened (`filter.rebuild_completed`, `session.created`). Existing domains: `dns`, `querylog`, `cache`, `upstream`, `filter`, `db`, `server`, `shutdown`, `config`, `acme`, `ratelimit`, `registry`, `events`, `csrf`, plus the audit set (`auth`, `session`, `user`, `apikey`, `forward_auth`, `audit`).
- **Errors go in an `error` field** (`"error", err`), never in the message.
- Reuse an existing event name for the same event; `rg '"event", "'` is the index.
