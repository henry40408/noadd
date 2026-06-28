# Configurable Upstream DNS — Make `upstream_servers` Actually Work (Runtime, No Restart)

## Overview

The admin UI has had an "Upstream DNS" field that writes an `upstream_servers` setting to the DB, but **nothing in the Rust backend ever reads it**. The forwarder is always built from `UpstreamConfig::default()` (`1.1.1.1:53`, `9.9.9.9:53`, `tls://dns.mullvad.net:853`) at startup, `put_settings` only applies `upstream_strategy`/`dnssec_disabled`, and `UpstreamForwarder` has no way to change its server set after construction. So upstream DNS is effectively **unconfigurable** — typing in the field has no effect, even across restarts.

This makes the setting real:
1. **Startup load** — build the forwarder from the persisted `upstream_servers` (fall back to default).
2. **Runtime reconfigure** — `UpstreamForwarder` can swap its server set atomically (rebuild connection pools, reset latencies) with no restart, mirroring the `ArcSwap` pattern already used for `strategy`.
3. **API apply** — `put_settings` validates and applies `upstream_servers` on change.
4. **UI (Option A, approved via visual companion)** — a one-per-line textarea, a dedicated "Save & apply" with feedback, and a consolidated **Active upstreams** table (transport badge + health + latency) replacing the separate health/EMA views.

This also makes the DNSSEC help text shipped in v0.8.0 ("set the upstream to `tls://…`") actionable for the first time.

## Non-Goals

- No new upstream transports (UDP / DoT `tls://` / DoH `https://` already parse via `UpstreamSpec::parse`; this only wires configuration, not new protocols).
- No per-client upstreams (global only — consistent with the README Out of Scope).
- No CLI flag for upstream servers (configuration is the DB setting + UI).
- No change to selection strategies or the EMA latency tracking algorithm.

## Behaviour

### Storage & format

- Setting key `upstream_servers`. Stored as the textarea text: **one upstream per line**. Parsing also tolerates commas (so legacy comma-separated values still load).
- Each entry must parse via the existing `UpstreamSpec::parse` (`ip:port`, `tls://host[:port]`, `https://host[:port][/path]`).
- **Empty value is rejected** (a resolver with zero upstreams is non-functional); the UI keeps the previous value and shows the error.

### Startup

`main.rs` reads `upstream_servers` from the DB before building the forwarder:
- present and non-empty → parse into `UpstreamConfig.servers` (invalid syntax → log a warning and fall back to default, so a hand-corrupted DB never prevents boot);
- absent/empty → `UpstreamConfig::default()`.

### Runtime apply

`put_settings`, when `upstream_servers` is in the request:
1. Parse/validate the value **before persisting anything**. On any invalid entry (or empty), return `400` with a message naming the offending line; persist nothing, apply nothing (atomic).
2. Persist the (normalised, newline-joined) value.
3. `forwarder.reconfigure(servers).await` — rebuilds pools and swaps them in. DNS-resolution failures for individual hosts are tolerated (logged, entry left unavailable) exactly as `UpstreamForwarder::new` already does.
4. Return `200`.

## Architecture

### `UpstreamForwarder` — make the server set swappable (`src/upstream/forwarder.rs`)

Today `config`, `entries`, and `latencies` are index-aligned and fixed at construction. Group the swappable parts behind a single `ArcSwap`:

```rust
/// The reconfigurable upstream set. Swapped atomically by `reconfigure`.
struct Upstreams {
    config: UpstreamConfig,
    /// Same length/order as `config.servers`. `None` = parse/lookup failed.
    entries: Vec<Option<UpstreamEntry>>,
    /// Same length/order as `entries`. EMA latencies, bit-packed.
    latencies: Vec<AtomicU64>,
}

pub struct UpstreamForwarder {
    upstreams: ArcSwap<Upstreams>,
    strategy: ArcSwap<UpstreamStrategy>,
    rr_counter: AtomicUsize,
    dnssec_enabled: AtomicBool,
}
```

- Extract the existing pool-building loop from `new()` into `async fn build_upstreams(config: UpstreamConfig) -> Upstreams` (the concurrent `lookup_host` + `NameServerPool::from_config` logic, plus the fresh `latencies` vec). `new(config)` becomes `Self { upstreams: ArcSwap::from_pointee(build_upstreams(config).await), strategy: …, rr_counter: …, dnssec_enabled: AtomicBool::new(true) }`.
- New: `pub async fn reconfigure(&self, servers: Vec<String>)` → `let next = build_upstreams(UpstreamConfig { servers, timeout_ms: <current> }).await; self.upstreams.store(Arc::new(next));`. The current `timeout_ms` is read from the loaded `Upstreams` so it's preserved.
- Every method touching the server set loads the current snapshot first: `let up = self.upstreams.load();` then use `up.entries`, `up.config.servers`, `up.latencies`. This covers `forward`, `server_order`, `latency_ms_at`, `update_latency`, `latencies()`, `health_check`, `probe`, `probe_all`. An in-flight `forward` holding an old snapshot that writes a latency after a swap is harmless (the old `Upstreams` is simply dropped).
- `set_strategy`/`strategy`/`set_dnssec_enabled`/`dnssec_enabled` are unchanged (independent of the server set).

### Parsing helper (`src/upstream/forwarder.rs`)

```rust
/// Parse textarea/CSV upstream input into validated server strings.
/// Splits on newlines and commas, trims, drops blanks, validates each via
/// `UpstreamSpec::parse`. Errors name the first offending entry. Empty → Err.
pub fn parse_upstreams(input: &str) -> Result<Vec<String>, String>
```

Used by both `main.rs` (startup) and `put_settings` (apply).

### API (`src/admin/api.rs`)

- `put_settings`: special-case `upstream_servers` *before* the generic persist loop — validate with `parse_upstreams`; on `Err`, return `400` (persist nothing). On `Ok`, let the generic loop persist it, then call `state.forwarder.reconfigure(servers).await` near the existing `set_strategy` apply.
- `get_settings`: add `"upstream_servers"` to the known-keys allowlist (same gap class as the DNSSEC fix) so the UI can load the current value.
- Reuse existing `/api/upstream/health` (returns `server`, `ok`, `latency_ms`) for the Active-upstreams table; no new endpoint needed. (`/api/upstream/latency` EMA endpoint stays for internal/strategy use but is no longer shown as a separate table.)

### Admin UI — Option A (`admin-ui/dist/index.html`, settings component)

- Replace the single-line `#s-upstream` `<input>` with a `<textarea id="s-upstream">` (one upstream per line) plus a format hint: `ip:port`, `tls://host` (DoT), `https://host/dns-query` (DoH).
- Add a dedicated **Save & apply** button that `PUT`s only `{ upstream_servers: <textarea value> }`, shows `✔ applied · N upstreams` on success or the server's error text on `400`. Remove `upstream_servers` from the global "Save Settings" payload so there is one clear apply path.
- Replace the "Check Health" button + separate health/EMA tables with a consolidated **Active upstreams** table: columns `server | transport | health | latency`, populated from `/api/upstream/health`. Auto-load on open and refresh after a successful apply; keep a manual refresh button.
  - **Transport badge** derived client-side from the server string: `tls://` → `dot` (accent green), `https://` → `doh` (accent green), else `plain` (orange = unencrypted). Reuse `.badge`.
  - **Health** glyph ✔/✖ (reuse the `.st`/`.st-ok`/`.st-block` classes shipped with DNSSEC).
- On load, fill the textarea from `s.upstream_servers` (newline-normalised).
- Strategy and DNSSEC blocks are unchanged.
- This changes the settings page appearance → regenerate `docs/screenshots/`.

## Error Handling

- Invalid syntax / empty input on apply → `400` with the offending entry named; nothing persisted or applied; UI shows the error and keeps the prior value.
- Per-host DNS-resolution failure during `reconfigure` → tolerated (logged, entry unavailable), same as `new()` today. If every entry ends up unavailable, queries fail until a working config is set — acceptable and visible in the Active-upstreams table.
- Corrupt persisted value at startup → warn and fall back to default (never block boot).

## Testing (`cargo nextest run`)

- `parse_upstreams`: newline + comma mixed input parses; a bad entry returns `Err` naming it; empty/whitespace → `Err`; valid mix of `ip:port` / `tls://` / `https://` round-trips.
- `reconfigure`: construct a forwarder (IP literals, no DNS lookup), `reconfigure` to a different server set, assert `server_order`/`latencies()` reflect the new set and length, and that strategy/dnssec state is preserved across the swap.
- API (`tests/admin_api_test.rs`): `PUT /api/settings { upstream_servers: <valid> }` → `200` and the forwarder's active servers change; `{ upstream_servers: <invalid line> }` → `400` and the setting is unchanged; `GET /api/settings` returns `upstream_servers`.
- Startup-load path is covered indirectly by `parse_upstreams` + `reconfigure` tests (main.rs wiring verified by build).

## Documentation

- `README.md`: Features — note upstream servers are configurable at runtime (plain / DoT / DoH), switchable without restart.
- `ARCHITECTURE.md`: in the upstream section, note `upstream_servers` is loaded at startup and `UpstreamForwarder.reconfigure` swaps the pool set via `ArcSwap` with no restart.

## Pre-Implementation Verification

- `arc_swap` is already a dependency (used for `strategy` and the filter engine) — confirm `ArcSwap::from_pointee` / `store` / `load` usage matches the existing call sites.
- Confirm `NameServerPool`/`PoolContext`/`TokioRuntimeProvider` can be rebuilt inside `build_upstreams` per call (the current `new()` builds them locally, so this should lift cleanly).
- Confirm the settings component's existing instant-apply handler pattern (`#s-doh-policy`/`#s-strategy` onchange) and the global Save-Settings payload, to correctly move `upstream_servers` onto its own Save & apply path.
