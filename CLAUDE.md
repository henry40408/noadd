# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

noadd is a single-binary, self-hosted DNS ad-blocker (plain DNS + DNS-over-HTTPS) written in Rust 2024 edition. The entire admin web UI is embedded into the binary at compile time, and all runtime state lives in one SQLite file. See `README.md` for user-facing usage and `ARCHITECTURE.md` for the detailed design — read `ARCHITECTURE.md` before touching the filter engine, query pipeline, or storage layer.

## Commands

```bash
# Build (also embeds admin-ui/dist and downloads filter lists via build.rs)
cargo build                 # debug; embeds current admin UI
cargo build --release

# Tests — use nextest (CI does). Run a single test by substring:
cargo nextest run
cargo nextest run filter_engine          # one test file / name filter
cargo nextest run -E 'test(parse_hosts)' # nextest filter expression

# Lint + format (CI gate; clippy warnings are denied)
cargo fmt --check
cargo clippy -- -D warnings

# Run locally on non-privileged ports (no root)
RUST_LOG=noadd=debug cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:3000
```

Integration tests live in `tests/` (not `src/`); shared helpers are in `tests/common/`. Files ending `_bench.rs` are benchmark-style tests run by the normal test command.

### End-to-end (admin UI)

Playwright-BDD tests in `e2e/`. Playwright boots the `noadd` binary itself on throwaway ports/DBs, so **build the binary first** so the latest UI is embedded:

```bash
cargo build
cd e2e && npm ci && npx playwright install chromium
npm test            # generates BDD step bindings, then runs the suite
npm run screenshots # re-seeds fake traffic and re-captures docs/screenshots/
```

Gherkin features: `e2e/features/`; step definitions: `e2e/steps/`.

## Build-time behavior (`build.rs`)

`build.rs` does work beyond compiling — be aware when builds behave unexpectedly:
- Downloads the six built-in filter lists via `curl` into `OUT_DIR/lists/`. On network failure it writes an empty file and warns rather than failing the build.
- Renders `admin-ui/dist/favicon.svg` into `apple-touch-icon.png` (180px) via `resvg`.
- Stamps the binary with `GIT_VERSION` from `git describe` (overridable via the `GIT_VERSION` env var).

## Admin UI

`admin-ui/dist/index.html` is a **single file of vanilla-JS web components — no framework, no build step.** It is embedded via `include_dir!` at `src/admin/api.rs` (`static ADMIN_UI`). Editing the UI = editing that one HTML file, then `cargo build` to re-embed. Embedded assets are served with content-hash `ETag` + `Cache-Control: no-cache` so browsers revalidate and get `304` when unchanged.

After any change that alters the admin UI's appearance, regenerate the affected screenshots in `docs/screenshots/` (`cd e2e && npm run screenshots`) and commit the updated PNGs alongside the change. Skip this only for non-visual edits (copy, logic, accessibility attributes) that do not change what a screenshot would capture.

## Architecture essentials

All components run in one tokio runtime. Query path (`src/dns/handler.rs`): **filter → cache → upstream forward**, with logging fired async over an mpsc channel. Filter runs *before* cache so newly added block rules take effect immediately.

- **Filter engine** (`src/filter/engine.rs`): FST for exact matches + a flat reverse-domain trie (labels stored reversed, e.g. `["com","example","ads"]`) serialized into two contiguous byte buffers (~19 bytes/rule). The live engine sits behind `ArcSwap`; updates build a fresh engine and atomically swap it in (lock-free reads, zero query interruption). Rebuild coordination is in `src/filter/rebuild.rs`.
- **Storage** (`src/db.rs`): all SQLite schema, migrations, and CRUD in one module. Schema versioning uses `PRAGMA user_version`; each migration applies incrementally, new DBs get the latest schema directly. An hourly background task prunes old `query_logs` and runs maintenance (`PRAGMA optimize`, WAL checkpoint, conditional `VACUUM`).
- **Async logging** (`src/logger.rs`): mpsc channel → a task batches and flushes to SQLite (every 500 entries or 1s) to keep the query path non-blocking.
- **Upstream** (`src/upstream/`): forwarder + selection `strategy.rs` (Sequential / Round Robin / Lowest Latency via EMA), switchable at runtime.
- **DoH** (`src/dns/doh.rs`): axum router; access can be gated by user-defined URL tokens (`/dns-query/my-token`).
- **Admin** (`src/admin/`): `api.rs` (REST + static serving), `auth.rs` (Argon2 hashing, sessions, rate limiting), `stats.rs` (query statistics).
- `src/main.rs` wires every component together and is the place to trace how things connect.

`mimalloc` is the global allocator specifically so the large transient allocation from a filter rebuild is returned to the OS, keeping steady-state RSS low on small devices.
