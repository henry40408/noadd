# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## What this is

noadd is a single-binary, self-hosted DNS ad-blocker (plain DNS + DNS-over-HTTPS) in Rust 2024. The admin web UI is embedded at compile time; all runtime state lives in one SQLite file. `README.md` covers usage. **Read `ARCHITECTURE.md` before touching the filter engine, query pipeline, or storage layer.**

## Commands

```bash
cargo build                              # debug; embeds admin-ui/dist, downloads lists via build.rs
cargo nextest run                        # tests — nextest, not `cargo test` (CI uses nextest)
cargo nextest run filter_engine          # by name substring
cargo nextest run -E 'test(parse_hosts)' # nextest filter expression
cargo fmt --check                        # CI gate
cargo clippy --all-targets -- -D warnings
cargo deny check                         # advisories, licenses, bans, sources

# Local run on non-privileged ports
RUST_LOG=noadd=debug cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:8080
```

Integration tests live in `tests/`, not `src/`; shared helpers in `tests/common/`. Files ending `_bench.rs` are benchmark-style tests run by the normal test command.

### End-to-end (admin UI)

Playwright-BDD in `e2e/`. Playwright boots the `noadd` binary itself, so **`cargo build` first** or the UI under test is stale.

```bash
cargo build
cd e2e && npm ci && npx playwright install chromium
npm test            # generates BDD step bindings, then runs the suite
npm run screenshots # re-seeds fake traffic, re-captures docs/screenshots/
```

Gherkin features in `e2e/features/`, steps in `e2e/steps/`. Destructive scenarios (password changes) and anything needing its own login rate-limit budget get a self-contained spec in `e2e/specs/` with dedicated ports — see `settings-autosave.spec.js`.

## Build-time behavior (`build.rs`)

- Downloads the six built-in filter lists via `curl` into `OUT_DIR/lists/`. On network failure it writes an empty file and warns rather than failing.
- Renders `admin-ui/dist/favicon.svg` into a 180px `apple-touch-icon.png` via `resvg`.
- Stamps `GIT_VERSION` from `git describe` (override via the env var; a literal `dev` counts as unset). `.dockerignore` excludes `.git`, so image builds must pass `--build-arg GIT_VERSION=...`; an arg-less `docker build` yields a working image labelled `dev`.

## Admin UI

**Routing and authentication are server-side.** `src/admin/pages.rs` renders the browser-facing HTML from `templates/` (askama, compile-time). Each page path — `/`, `/stats`, `/logs`, `/filters`, `/settings`, `/account` — resolves the session *before* writing any HTML, redirecting to `/login?next=…` or `/setup` when there is none. `/login` and `/setup` are real `<form method="post">` pages that work without JavaScript. Navigation is ordinary links with full page loads; there is no client-side router.

Sign-in and setup need **no CSRF token** — `src/admin/csrf.rs` is a header-based origin guard covering every unsafe method on the router, so a cross-origin form post is refused before it reaches a handler.

Password sign-in lives in **one** place, `start_password_session` (`src/admin/api.rs`), shared by `POST /api/auth/login` and `POST /login`; first-run account creation likewise in `create_first_operator`. Rate limiting, the constant Argon2 cost, the lockout and the audit events are all in there — do not grow a second path.

**The shell is server-rendered too** (`templates/shell.html`): topbar, both navigation bars, status bar, and any one-shot notice. `app.js` does not render it and must not re-derive what it already decided — the active nav item is a class the template set from the path it answered. Only `#page-content` is left for the client, where the page component for this path mounts. The nav table lives once, in `NAV` (`src/admin/pages.rs`), and drives both the desktop strip and the mobile F-key bar.

Page bodies are still **vanilla-JS web components — no framework, no build step**, in `admin-ui/dist/`: `app.css` and `app.js`. There is no `index.html` and **no SPA fallback** — every page path is a real route, so an unmatched path 404s. The directory is embedded via `include_dir!` in `src/admin/api.rs` (`ADMIN_UI`). Editing the UI means editing `app.js`, `app.css`, or a file under `templates/`, then `cargo build` to re-embed. Assets are served with a content-hash `ETag` + `Cache-Control: no-cache`, computed per file; server-rendered pages get `no-store` from the same layer, which keys on whether a response already declares a policy.

One-shot notices ride a **flash cookie** (`Flash` in `src/admin/pages.rs`), read and cleared by the response that renders them — never the query string, which survives refreshes, bookmarks and shared links.

### Server-rendering a page body (the P3 pattern)

Settings is the worked example; the remaining pages follow it.

- The page template `{% extends "shell.html" %}` and fills `{% block page %}`. Its struct embeds `ShellData` as a `shell` field — `shell.html` reads `shell.*`.
- **Wrap the body in the page's existing custom element** (`<settings-page>…</settings-page>`). It upgrades in place, so `app.js` enhances the rendered markup instead of replacing it. The bootstrap mounts a component only when the server left `#page-content` empty, which is how not-yet-converted pages keep working.
- Validation lives in **one** function shared with the JSON endpoint (`apply_settings`), returning a field-tagged error so the form can put the message next to the offending input while the API keeps answering a bare 400.
- A successful POST redirects with a flash; a rejected one re-renders **with the submitted values**, not the stored ones, at 400/401 — never 200.
- When `app.js` enhances a form, it removes the no-JS submit row (`#settings-save-row`) rather than hiding it, and any submit button it takes over must `preventDefault()`.
- **`load()` must not refill fields the server rendered.** Doing so overwrites what the operator typed in the window before the response lands — a real bug this pattern removed.

⚠️ A `querySelector` that returns `null` in a `connectedCallback` throws and **silently kills every binding after it**. When moving markup to a template, check that every id `app.js` reaches for still exists.

Filters adds the conventions for a page whose body is a *list of things*:

- **A read is a GET, a change is a POST.** The domain test posts nothing — it is `GET /filters?test=…`, so the verdict is refreshable, linkable, and survives the back button. Every mutation is its own route (`/filters/lists/{id}/toggle`, `…/edit`, `…/delete`, `/filters/rules`, …) rather than one endpoint switching on an action field: a form's target is the clearest statement of what it does.
- **One form per row, not one for the table.** A browser posts only the form that was submitted, so a table-wide form would have to carry every row's state and would report every row as changed.
- **Row state that needs a client lives in the URL.** Editing a list is `GET /filters?edit={id}`, which expands that row into a form the server filled *from storage* — never from the query string, so a link cannot pre-fill a form with values it carried. With JavaScript the same control is an `<a>` whose click is cancelled in favour of the dialog.
- **`.nojs-only` / `.js-only`.** Both ship in the state that is correct when the script never arrives: `app.js` removes the first and unhides the second. A control that needs a client (the registry modal) ships `hidden` rather than sitting there doing nothing.
- **`app.js` re-draws rows in the same shape the template emits**, forms included, so a redrawn row is the row the server would have sent and one set of bindings applies to either.
- Values the page derives (thousands separators, "5 minutes ago") are computed **server-side to match what `app.js` produces** for the same column — a formatting rule living in two languages drifts.

Account adds the conventions for **actions that need a password proof**:

- **The password rides in the form that needs it** (`your_password`), for adding an operator, deleting one, and minting an API key. There is no dialog and no retry-after-403: `promptForPassword` / `withReauth` are gone, and the path is identical with and without JavaScript. `POST /api/auth/reauth` still exists for API callers.
- **`confirm_password` (`src/admin/api.rs`) is the only place either path checks a password** — one rate limit, one lockout, one `auth.reauthenticated` event. Do not grow a second.
- **A destructive row action expands into a named confirmation** (`GET /account?confirm_delete={id}`) rather than putting a password field on every row. That is a better prompt than `confirm()` and it exists without scripting; `app.js` adds `confirm()` only where the server has no confirmation of its own.
- **Creating an API key renders instead of redirecting** — the one deliberate exception to PRG on these pages. The token exists in that response and nowhere else, so a redirect would discard the only copy. A refresh re-posts and mints a second key, which the operator can see and delete.
- **A rejected form never echoes a password back into the markup.** Only the non-secret fields (username, key name, expiry) are re-rendered.
- Account POSTs answer as `/account` whatever path they arrived on — `ShellData::build_for("/account", …)`, so the navigation still marks the page the operator is looking at.

⚠️ **The status bar is `position: fixed` at the bottom of the viewport**, so a control near the foot of the page can sit underneath it and swallow a click ("intercepts pointer events" — how this surfaced was an e2e run on a shorter CI window). `:root` carries `scroll-padding-bottom` so scrolling keeps clear of it; `e2e/specs/filters-no-js.spec.js` submits with `Enter` and clicks row controls through a helper for the same reason, and says so.

`/api/*` remains the contract for API keys and the OpenAPI spec, but the UI no longer consumes it to decide who is signed in or which screen to show.

After any change that alters the UI's appearance, regenerate the affected `docs/screenshots/` (`cd e2e && npm run screenshots`) and commit the PNGs alongside. Skip only for non-visual edits (copy, logic, test hooks, accessibility attributes).

## Architecture essentials

Everything runs in one tokio runtime. Query path (`src/dns/handler.rs`): **filter → cache → upstream forward**, with logging fired async over an mpsc channel. Filter runs *before* cache so new block rules take effect immediately.

- **Filter engine** (`src/filter/engine.rs`): FST for exact matches plus a flat reverse-domain trie, serialized into two contiguous byte buffers. The live engine sits behind `ArcSwap`; updates build a fresh engine and swap it in atomically. Coordination in `src/filter/rebuild.rs`.
- **Storage** (`src/db.rs`): all schema, migrations, and CRUD in one module. Versioning via `PRAGMA user_version`, applied incrementally and forward-only. An hourly task prunes `query_logs` and runs maintenance.
- **Async logging** (`src/logger.rs`): mpsc → a task batches to SQLite (500 entries or 1s) to keep the query path non-blocking.
- **Upstream** (`src/upstream/`): forwarder plus `strategy.rs` (Sequential / Round Robin / Lowest Latency via EMA), switchable at runtime.
- **DoH** (`src/dns/doh.rs`): axum router, optionally gated by user-defined URL tokens.
- **Admin** (`src/admin/`): `api.rs` (REST + static serving), `auth.rs` (Argon2, sessions, rate limiting), `csrf.rs`, `stats.rs`.
- `src/main.rs` wires it all together — the place to trace how things connect.

`mimalloc` is the global allocator specifically so a filter rebuild's large transient allocation returns to the OS, keeping steady-state RSS low on small devices.

## Diagnostic logging

Separate from the per-query `query_logs` table: this is the `tracing` stream on stderr, configured in `src/config.rs` (`--log-format`, `RUST_LOG`, default `error,noadd=info`).

**Every `info!`/`warn!`/`error!`/`debug!` carries `event = "domain.action"` as its first field**, every value is a field rather than interpolated, and the message is a static human-readable string:

```rust
// yes
debug!(event = "dns.send_failed", transport = "tcp", stage = "flush", client = %peer, error = %e, "failed to send response");

// no — the values are trapped in the string, and the message is the only key
debug!("TCP flush error for {peer}: {e}");
```

`--log-format json` emits each field as its own key, so `event` survives message rewording and fields are filterable without regex: `jq 'select(.fields.event == "upstream.forward_failed")'` works; grepping prose does not.

- **Prefer a field over a new event name.** The three TCP write failures share `dns.send_failed` and differ by `stage`; UDP and TCP share `dns.listener_started` and differ by `transport`. That keeps "all send failures" one query.
- **Name events `domain.action`**, past tense for things that happened (`filter.rebuild_completed`, `session.created`). Existing domains: `dns`, `query`/`querylog`, `cache`, `upstream`, `filter`, `db`, `server`, `shutdown`, `config`, `acme`, `ratelimit`, `registry`, plus the audit set (`auth`, `session`, `user`, `apikey`, `forward_auth`, `audit`).
- **Errors go in an `error` field** (`error = %e`), never in the message.
- Reuse an existing event name when the event is the same; `rg 'event = "'` is the index.
