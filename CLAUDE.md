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

The admin UI is **vanilla-JS web components — no framework, no build step**, split across three files in `admin-ui/dist/`: `index.html` (the document shell — just the `<head>`, `<div id="app">`, and the two asset tags), `app.css`, and `app.js` (all components plus the bootstrap). The whole directory is embedded via `include_dir!` in `src/admin/api.rs` (`ADMIN_UI`). Editing the UI means editing `app.js` or `app.css`, then `cargo build` to re-embed. Assets are served with a content-hash `ETag` + `Cache-Control: no-cache`, computed per file.

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
