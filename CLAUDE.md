# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## What this is

noadd is a single-binary, self-hosted DNS ad-blocker (plain DNS + DNS-over-HTTPS) in Rust 2024. The admin web UI is embedded at compile time; all runtime state lives in one SQLite file. `README.md` covers usage. **Read `ARCHITECTURE.md` before touching the filter engine, query pipeline, or storage layer.**

## Commands

```bash
cargo build                              # debug; embeds admin-ui/dist, runs build.rs
cargo nextest run                        # tests — nextest, not `cargo test` (CI uses nextest)
cargo nextest run filter_engine          # by name substring
cargo nextest run -E 'test(parse_hosts)' # nextest filter expression
cargo fmt --check                        # CI gate
cargo clippy --all-targets -- -D warnings
cargo deny check                         # advisories, licenses, bans, sources

# Local run on non-privileged ports
RUST_LOG=noadd=debug cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:8080
```

Integration tests live in `tests/` (shared helpers in `tests/common/`). Files ending `_bench.rs` are benchmark-style tests run by the normal test command.

### End-to-end (admin UI)

`cucumber` + `thirtyfour` in `e2e/`, **its own cargo workspace** so a `--workspace` coverage run never compiles the browser stack. No Node.js anywhere. The suites boot the `noadd` binary themselves, so **`cargo build` first** or the UI under test is stale.

```bash
cargo build
cd e2e
cargo test --test e2e        # the Gherkin features
cargo test --test specs      # the regression specs
cargo run --bin screenshots  # re-seeds fake traffic, re-captures docs/screenshots/
```

A local **Chrome or Chromium is required**: `WebDriver::managed` fetches a matching chromedriver but not the browser (`brew install --cask ungoogled-chromium`; CI's runner ships Chrome).

Features are in `e2e/features/`, steps in `e2e/tests/e2e/steps.rs`. A feature's tag (`@app`, `@auth`, `@onboarding`) picks its instance: `e2e/tests/e2e/main.rs` starts one server per tag and a `before` hook selects by it.

Destructive scenarios (password changes), anything needing its own login rate-limit budget, and anything needing the appliance to *answer* while a browser watches (`logs_live_tail.rs`) get a self-contained file in `e2e/tests/specs/` with dedicated ports — see `settings_autosave.rs`. Files run concurrently, capped at `available_parallelism` and four; cases *within* a file run in written order, which several depend on.

Two Playwright conveniences are rebuilt in `e2e/src/` — look there first when an assertion behaves oddly:

- **`WebDriver` does not retry.** Every `Locator::expect_*` in `src/dom.rs` polls for 30 s and reports the last value seen.
- ⚠️ **Text is `textContent`, not rendered text.** WebDriver's "Get Element Text" applies `text-transform`, and this UI uppercases badges and headings in CSS (`Blocked` reads as `BLOCKED`). `Locator::text` reads `textContent`, so assert against the markup.

**Every page has no-JS coverage** in four files using `Profile::no_js()` (`Emulation.setScriptExecutionDisabled`, 1024×600 viewport): `filters_no_js`, `logs_no_js`, `stats_no_js` and `pages_no_js` (dashboard, settings and account on one shared instance, since none seeds or empties anything). Ports 14107–14110, DNS 15107–15110. Every instance's ports live in `ports` in `e2e/src/lib.rs`; a new file takes the next free pair there.

⚠️ **`setScriptExecutionDisabled` applies to the *next* document**, so sessions are per-case and the flag is set before the first navigation. It stops only page scripts — `Execute Script` still runs — but a DOM callback such as a `TreeWalker` filter counts as page script and is refused, so `Page::has_text` walks elements itself.

⚠️ **A browser posts the whole form, so a no-JS save must satisfy every field.** A fresh appliance has no upstream, and saving settings without one is rejected outright (`apply_settings` validates before persisting), so `pages_no_js` fills the upstream first. A test that fills one field and submits is testing the rejection path.

## Build-time behavior (`build.rs`)

- Downloads six filter lists via `curl` into `OUT_DIR/lists/`; on network failure writes an empty file and warns. (Nothing in `src/` currently reads them; first-run defaults come from `DEFAULT_LISTS` in `src/filter/lists.rs`.)
- Renders `admin-ui/dist/favicon.svg` into a 180px `apple-touch-icon.png` via `resvg`.
- Stamps `GIT_VERSION` from `git describe` (env var overrides; a literal `dev` counts as unset). `.dockerignore` excludes `.git`, so image builds pass `--build-arg GIT_VERSION=...`; without it the image is labelled `dev`.

## Admin UI

**Routing and authentication are server-side.** `src/admin/pages.rs` renders `templates/` (askama). Each page path — `/`, `/stats`, `/logs`, `/filters`, `/filters/registry`, `/settings`, `/account` — resolves the session *before* writing HTML, redirecting to `/login?next=…` or `/setup`. `/login` and `/setup` are real `<form method="post">` pages that work without JavaScript. Navigation is plain links; no client-side router.

Sign-in and setup need **no CSRF token**: tower-http's `CsrfLayer` (wired in `admin_router`; documented and its rejections logged in `src/admin/csrf.rs`) is a header-based origin guard over every unsafe method, refusing cross-origin form posts before any handler.

Password sign-in lives **only** in `start_password_session` (`src/admin/api.rs`), shared by `POST /api/auth/login` and `POST /login`; first-run account creation likewise in `create_first_operator`. Rate limiting, constant Argon2 cost, lockout and audit events are all there — do not grow a second path.

**The shell is server-rendered** (`templates/shell.html`): topbar, both nav bars, status bar, one-shot notices. `app.js` must not re-derive what it decided — e.g. the active nav item is a class set from the path. The nav table is `NAV` (`src/admin/pages.rs`), driving both the desktop strip and the mobile F-key bar.

Page bodies are **vanilla-JS web components — no framework, no build step** — in `admin-ui/dist/app.css` and `app.js`. No `index.html`, **no SPA fallback**: an unmatched path 404s. The directory is embedded via `include_dir!` (`ADMIN_UI`, `src/admin/api.rs`), so edit `app.js`, `app.css` or `templates/`, then `cargo build`. Assets get a per-file content-hash `ETag` + `Cache-Control: no-cache`; server-rendered pages get `no-store` from the same layer, which applies only when a response declares no policy.

One-shot notices ride a **flash cookie** (`Flash`, `src/admin/pages.rs`), cleared by the response that renders them — never the query string, which survives refreshes, bookmarks and shared links.

### Server-rendering a page body

Settings is the worked example.

- The template `{% extends "shell.html" %}` and fills `{% block page %}`; its struct embeds `ShellData` as `shell`.
- **Wrap the body in the page's custom element** (`<settings-page>…</settings-page>`), which upgrades in place; `app.js` enhances the markup and never mounts a page.
- Validation lives in **one** function shared with the JSON endpoint (`apply_settings`), returning a field-tagged error so the form shows it by the input while the API returns a bare 400.
- A successful POST redirects with a flash; a rejected one re-renders **with the submitted values** at 400/401 — never 200.
- When `app.js` enhances a form it removes (not hides) the no-JS submit row (`#settings-save-row`), and any submit button it takes over must `preventDefault()`.
- **`load()` must not refill server-rendered fields**, or it overwrites what the operator typed before the response landed.

⚠️ A `querySelector` returning `null` in `connectedCallback` throws and **silently kills every binding after it**. When moving markup to a template, check every id `app.js` reaches for still exists.

Filters — a page whose body is *a list of things*:

- **A read is a GET, a change is a POST.** The domain test is `GET /filters?test=…` (refreshable, linkable). Each mutation is its own route (`/filters/lists/{id}/toggle`, `…/edit`, `…/delete`, `/filters/rules`, …), not one endpoint switching on an action field.
- **One form per row**, since a browser posts only the submitted form.
- **Row state that needs a client lives in the URL.** `GET /filters?edit={id}` expands that row into a form filled *from storage*, never from the query string. With JavaScript the same `<a>` opens a dialog instead.
- **`.nojs-only` / `.js-only`** ship in the no-script-correct state: `app.js` removes the first and unhides the second. A client-only control (the registry modal) ships `hidden`.
- **The Impact column comes from the live engine** (`FilterEngine::unique_rules_by_list`), not storage; every list change already triggers the rebuild that recomputes it. `list_impact` (`src/admin/pages.rs`) and `listImpact` (`app.js`) must phrase it identically.
- **Two lists with the same rules both report "No impact"** — true for removing either alone — so the page says to turn one off at a time.
- **`app.js` redraws rows in the template's exact shape**, forms included, so one set of bindings serves both.
- Derived values (thousands separators, "5 minutes ago") are computed **server-side to match `app.js`**.

Registry browser (`/filters/registry`) — **a picker that batch-submits**:

- **Two forms, never nested**: a `method="get"` form for the three filters (state in the URL) and a `method="post"` form wrapping the rows.
- **Filtering by navigating clears the selection**; with a client, `app.js` hides rows in place so ticks and counts survive.
- **The form posts ids; the server looks up name and URL** in the registry rather than trusting the body. `Form<Vec<(String, String)>>` is the shape that keeps repeated `filter_id` keys.
- **`add_lists_batch` (`src/admin/api.rs`) is the only batch-add path**, shared with `POST /api/lists/batch`: one concurrency cap, per-item rollback, one rebuild.
- **Full success redirects; partial failure renders**, since the per-item reasons exist only in that response.
- **An unreachable registry is a rendered state** with a retry link to the same URL — not a spinner, not a 502.
- ⚠️ **`safe_url` (`src/admin/pages.rs`) keeps a `javascript:` homepage out of an `href`** — escaping does not stop navigation. Only absolute `http(s)` survives; covered by `a_hostile_homepage_never_becomes_a_link`.

Query log — **filtering and paging**:

- **The whole view is in the URL**: `/logs?q=&action=&type=&token=&page=`. Filters are a GET form, the pager two `<a>`s; `app.js` adopts the query string on connect.
- **The pager carries every filter**: `logs_query_string` rebuilds the query with only `page` replaced.
- **A row action carries its origin** in a `next` field, validated by `safe_next`, so it returns to the same page and filter.
- **An empty table says which case it is**: the empty-log guide when unfiltered, "No logs found" when filtered.
- **Clearing lands on an unfiltered first page** whatever view it came from.
- ⚠️ **Forms cannot nest.** Clear All sits in the filters row via `form="clear-logs-form"`, pointing at an empty POST form after it; `app.js` must bind its confirmation to *that* form, not `closest('form')`.
- **The live tail is a subscription on the shell's stream** (see *The event stream*); the page owns no `EventSource`. `_prependRow` drops what arrives while the tail is off, so the listener is registered once for the page's life.
- ⚠️ **This toggle keeps its label** and carries state in a `paused` class (the dashboard's rewrites its text) — asserting `"PAUSED"` here passes against nothing.
- Relative times are the one deliberate mismatch: the server renders `"3 minutes ago"`, the client replaces it via `Intl.RelativeTimeFormat` in the browser's locale.

Dashboard — **all readings, no controls**:

- **The numbers are in the first response.** `dashboard_page` calls `compute_summary`, `compute_top_domains_and_clients` and `compute_top_upstreams` (`src/admin/stats.rs`) — the same functions the `stats` snapshot uses each tick (`compute_snapshot` adds `compute_timeline`). A failed read renders zeroes rather than an error page.
- **`app.js` redraws the same markup from pushed snapshots**; every template shape has a counterpart in `DashboardPage`, and `_apply` reads the snapshot's five bodies (summary, timeline, top domains, clients, upstreams). Number formatting is duplicated in Rust to match (`format_num_adaptive`, `percent1`, `share_percent`, `format_qps`), so a count never changes notation when an update lands.
- **The chart is the documented no-JS exception**: drawn client-side, and the card says so until the client replaces that text.
- ⚠️ **Merge a conditional `style` into the element's existing one.** A second `style` attribute is dropped — the chart card's `animation-delay` and `display:none` share one attribute for that reason.

Statistics — readings in a **chosen window**, and what the server cannot render:

- **Only the three charts need a calendar**, and calendar-aligned buckets need the viewer's UTC offset, which the request lacks. Everything else is a plain `now - range` window rendered server-side: highlights, both breakdowns, both ranged lists, the health grid.
- **Chart data is in the first response too**, in UTC: `<stats-page data-series>` is a `QuarterSeries` (`src/db.rs`, per-quarter-hour counts from the same scan), and `timelineFromQuarters` / `heatmapFromQuarters` in `app.js` fold it into local hours and days — exact, since every offset in use is a whole number of quarter hours. `/api/stats/v2/timeline` and `…/heatmap` take `tz_offset` (rounded to the nearest quarter hour) for API callers; `e2e/tests/specs/stats_charts.rs` holds the JS folds to them — change one and that fails.
- **`StatsPage` draws three charts and one date**, nothing else, and does not poll.
- **The range is in the URL**, the switcher three `<a>`s (`/stats?range=30d`). `StatsRange::label()` is the one spelling for link, parse and card titles. An unrecognised range renders the default rather than 400ing.
- **A date the server can only write in UTC ships as an ISO day plus `data-date-ts`**; `app.js` restates it in the browser's locale.
- **Measured in page misses, not milliseconds** — the appliance runs off an SD card; page counts transfer, durations do not. `cargo nextest run --release --no-capture --run-ignored only stats_page_miss` with `BENCH_DB` pointed at a copy of a real database reports them; `dashboard_page_miss` and `logs_page_miss` cover the dashboard (first response and tick) and the query log (every filter); `BENCH_NOW` pins the clock for an older copy. Distrust a wall-clock reading when the two disagree.
- **One statement per rollup family.** The page's reads are `stats_scan_since` (quarter + metrics rollups) and `traffic_lists_since` (top domains, distinct-domain count, top clients) in `src/db.rs`, via `compute_range_stats` (`src/admin/stats.rs`). `stats_scan_since` streams rows and folds in Rust, telling its four arms apart by a leading column. A new reading is folded out of one of these, not added as a statement.
- **A total nobody can count cheaply is maintained.** `query_logs`' row count lives in `settings` (`query_log_count`), moved by the insert batch, the prune and Clear All inside their own transactions; the Database Health card and the unfiltered pager (`count_logs`) read it. A fourth write path to `query_logs` needs a fourth `bump_log_count`.
- **The rollups (`query_stats_*`, ARCHITECTURE.md *Rollups*) must always equal a recount of `query_logs`.** Inserts are covered by the `query_logs_maintain_stats` trigger; a new path that *deletes* from `query_logs` must unwind them in its own transaction, as `prune_logs_before` (`unwind_stats_rollups`) and Clear All do.
- Four bar lists share **one askama macro** (`templates/_macros.html`); `{% call … %}` needs a matching `{% endcall %}` in askama 0.16, and `{% include %}` cannot see a loop variable.

Account — **actions that need a password proof**:

- **The password rides in the form that needs it** (`your_password`) for adding an operator, deleting one, and minting an API key — identical with and without JavaScript, no dialog. `POST /api/auth/reauth` remains for API callers.
- **`confirm_password` (`src/admin/api.rs`) is the only password check for either path** — one rate limit, one lockout, one `auth.reauthenticated` event.
- **A destructive row action expands into a named confirmation** (`GET /account?confirm_delete={id}`); `app.js` adds `confirm()` only where the server has none.
- **Creating an API key renders instead of redirecting** — the one PRG exception, since the token exists only in that response. A refresh mints a second key, which the operator can see and delete.
- **A rejected form never echoes a password.** Only username, key name and expiry are re-rendered.
- Account POSTs render as `/account` whatever path they arrived on (`ShellData::build_for("/account", …)`), so the nav marks the right page.

### The event stream

`GET /api/events` (`stream_events` in `src/admin/api.rs`, hub in `src/admin/events.rs`) is the admin UI's **only** push channel; `serverEvents` in `app.js` is its single `EventSource`.

- **One connection per page.** The status indicator is on every page, and without HTTP/2 a browser gets six connections per origin. New pushes arrive as a new event name on this stream, never a second stream.
- **`ping` every tick, always** — the indicator's heartbeat. It must be a real event (SSE keep-alive comments never reach `EventSource`); the client shows OFFLINE after three missed ticks, since silence is what a dead server looks like.
- **`stats` only when asked** (`?stats=1`, dashboard only), so an idle page costs no aggregate queries per tick. A `StatsGuard` drops the claim when the connection closes.
- **`log` only when asked** (`?logs=1`). The tail ships *off*, so `serverEvents.setLogs()` re-opens the one connection with the subscription added; that swap is deliberately not reported as a drop, or the indicator would blink OFFLINE on a toggle click.
- **`rebuild` unasked-for, like `ping`**, since the banner is in the shell. It is an *edge*: `RebuildCoordinator` (`src/filter/rebuild.rs`) publishes at start and end, so a rebuild between two ticks is still seen. `RebuildStatus` is the one shape it travels in.
- ⚠️ **A lagged `rebuild` subscriber gets the live state, not `continue`.** A missed tick recurs in ten seconds; a missed completion edge never does and leaves the banner spinning.
- **Every connection gets a `rebuild` as it opens.** The stream is the only place this state is published, so it must answer "what is happening now". Tests rely on it to wait on a rebuild that may already have finished (`Api::wait_until_rebuilt` in `e2e/src/api.rs`, `wait_for_rebuild` in `tests/admin_api_test.rs`).
- ⚠️ **`RebuildBanner` must not call `serverEvents.start()`.** It upgrades before `<server-status>`, and the query string is fixed at open — starting there would settle `stats=1` as false and starve the dashboard. Any future stream consumer in `<main>` inherits this rule.
- **A closed source retires its own arm** (`next_broadcast`) rather than ending the connection. The pump holds the `Arc<EventHub>` for the connection's life; otherwise the router's copy could be the last, and a stream without stats would see its tick source close as the handler returns.
- **`ping` carries `traffic`** — whether the appliance has ever answered a query — as a state bit rather than a new event; only the onboarding notice reads it. `EventHub` latches it one-way, so the `EXISTS` stops once true; a page render that learns the fact sets the latch too (`next_step_target`).
- **The snapshot is computed once per tick and shared** across clients.
- **A `stats=1` client gets a snapshot as the stream opens**, so it is never ten seconds behind the server-rendered numbers.
- **Nothing ticks while nobody is connected** (`run()` skips on `connection_count() == 0`).
- The dashboard's LIVE toggle stops *applying* snapshots, not the connection, because the indicator shares it.
- ⚠️ **A `fetch` stub no longer reaches the dashboard.** `override_summary` (`e2e/src/browser.rs`) patches `EventSource.prototype.addEventListener` and hands the listener a reconstructed `MessageEvent`, since `data` is read-only.

**The onboarding notice is the shell's, decided server-side** (`show_next_step` / `next_step_addr` on `ShellData`, resolved by `next_step_target` in `src/admin/pages.rs`), with no client fetches:

- **It is not rendered on `/`**, where the dashboard's own empty state (`dashboard-empty-state`) says the same; e2e scenarios covering the banner therefore use another tab.
- **Dismissing is `POST /onboarding/dismiss`**, a real form carrying `next` through `safe_next` and writing the `onboarding_banner_dismissed` setting the JSON API uses. `app.js` cancels the submit and removes the notice in place.
- **It removes itself on the heartbeat's `traffic` flag.**

⚠️ **The status indicator reports the stream, not the markup.** It ships `hidden` and is unhidden by its own `connectedCallback`; without JavaScript it stays hidden, since a page that cannot sense the server must not claim it is up.

⚠️ **The status bar is `position: fixed` at the bottom**, so a control near the page foot can sit under it and swallow a click ("intercepts pointer events", seen on a shorter CI window). `:root` sets `scroll-padding-bottom`; `e2e/tests/specs/filters_no_js.rs` submits with `Enter` and uses `Locator::click_js` for row controls for this reason.

⚠️ **With scripting off a page is interactive as soon as it parses**, so a click can land while a `fade-in` card is still sliding. `e2e/tests/specs/stats_no_js.rs` uses `Locator::click_js` on the range switcher and follows it with assertions that only pass if the navigation happened.

`/api/*` remains the contract for API keys and the OpenAPI spec, but the UI does not use it to decide who is signed in or which screen to show.

After any change to the UI's appearance, regenerate the affected `docs/screenshots/` (`cd e2e && cargo run --bin screenshots`) and commit the PNGs. Skip for non-visual edits (copy, logic, test hooks, accessibility attributes).

## Architecture essentials

One tokio runtime. Query path (`src/dns/handler.rs`): **filter → cache → upstream forward**, logging async over an mpsc channel. Filter runs *before* cache so new block rules take effect immediately.

- **Filter engine** (`src/filter/engine.rs`): FST for exact matches plus a flat reverse-domain trie, serialized into two contiguous byte buffers. The live engine sits behind `ArcSwap`; updates build a fresh engine and swap it in. Coordination in `src/filter/rebuild.rs`.
- **Storage** (`src/db.rs`): all schema, migrations and CRUD. Versioned by `PRAGMA user_version`, incremental and forward-only. An hourly task prunes `query_logs` and runs maintenance.
- **Async logging** (`src/logger.rs`): mpsc → a task batches to SQLite (500 entries or 1 s).
- **Upstream** (`src/upstream/`): forwarder plus `strategy.rs` (Sequential / Round Robin / Lowest Latency via EMA), switchable at runtime.
- **DoH** (`src/dns/doh.rs`): axum router, optionally gated by URL tokens.
- **Admin** (`src/admin/`): `api.rs` (REST, event stream, static serving), `pages.rs` (server-rendered pages), `auth.rs` (Argon2, sessions, rate limiting), `csrf.rs`, `events.rs`, `forward_auth.rs`, `stats.rs`.
- `src/main.rs` wires it all together.

`mimalloc` is the global allocator so a filter rebuild's large transient allocation returns to the OS, keeping steady-state RSS low on small devices.

## Diagnostic logging

Separate from the `query_logs` table: the `tracing` stream on stderr, configured in `src/config.rs` (`--log-format`, `RUST_LOG`, default `error,noadd=info`).

**Every `info!`/`warn!`/`error!`/`debug!` carries `event = "domain.action"` as its first field**, every value is a field rather than interpolated, and the message is a static string:

```rust
// yes
debug!(event = "dns.send_failed", transport = "tcp", stage = "flush", client = %peer, error = %e, "failed to send response");

// no — the values are trapped in the string, and the message is the only key
debug!("TCP flush error for {peer}: {e}");
```

With `--log-format json` each field is its own key, so `jq 'select(.fields.event == "upstream.forward_failed")'` works regardless of message wording.

- **Prefer a field over a new event name.** The TCP write failures share `dns.send_failed` and differ by `stage`; UDP and TCP share `dns.listener_started` and differ by `transport`.
- **Name events `domain.action`**, past tense for things that happened (`filter.rebuild_completed`, `session.created`). Existing domains: `dns`, `querylog`, `cache`, `upstream`, `filter`, `db`, `server`, `shutdown`, `config`, `acme`, `ratelimit`, `registry`, `events`, `csrf`, plus the audit set (`auth`, `session`, `user`, `apikey`, `forward_auth`, `audit`).
- **Errors go in an `error` field** (`error = %e`), never in the message.
- Reuse an existing event name for the same event; `rg 'event = "'` is the index.
