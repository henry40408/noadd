# Configurable Block Response Mode — Design

Date: 2026-07-11
Branch: `feat/configurable-block-mode`

## Goal

Let the operator choose how noadd answers a query that the filter engine
blocks, matching four of AdGuardHome's five "blocking mode" options. Today the
response is hard-coded to a null IP (`0.0.0.0` / `::`) and is not configurable.

## Scope

In scope — a **global** block-mode selector with four modes:

| Mode         | A query               | AAAA query            | Other types (MX/TXT/…) |
| ------------ | --------------------- | --------------------- | ---------------------- |
| `null_ip`    | `0.0.0.0`             | `::`                  | NoError, empty answer  |
| `nxdomain`   | NXDOMAIN              | NXDOMAIN              | NXDOMAIN               |
| `refused`    | REFUSED               | REFUSED               | REFUSED                |
| `custom_ip`  | configured IPv4¹      | configured IPv6¹      | NoError, empty answer  |

¹ In `custom_ip` mode, if the IP for that record type is not configured, the
response is NoError with an empty answer section (same as `null_ip`'s
other-types behavior).

`nxdomain` and `refused` apply to **all** query types, including A/AAAA — this
matches AdGuardHome.

Out of scope (explicitly deferred, per brainstorming):

- Honoring the explicit IP from a `/etc/hosts`-style rule (e.g.
  `127.0.0.1 tracker.com`). This would require adding an IP field to
  `ParsedRule` and propagating it through the FST/trie filter engine and
  `FilterResult`. Not done here — hosts-rule IPs remain discarded.
- Per-rule or per-client block modes.

## Default & backward compatibility

Default mode is `null_ip`, which reproduces today's exact behavior. Existing
deployments upgrade with zero behavioral change. No DB migration is needed: the
`settings` table is generic key/value, and a missing key is treated as the
default.

## Data model

Three new keys in the existing `settings` table:

- `block_mode` — one of `null_ip` | `nxdomain` | `refused` | `custom_ip`.
  Absent ⇒ `null_ip`.
- `block_custom_ipv4` — used only in `custom_ip` mode; string like `192.0.2.1`.
  May be empty/absent.
- `block_custom_ipv6` — used only in `custom_ip` mode; string like `100::`.
  May be empty/absent.

## Components

### `src/dns/block.rs` (new)

Holds the block-response configuration and its parsing:

```rust
pub enum BlockMode { NullIp, Nxdomain, Refused, CustomIp }

pub struct BlockConfig {
    pub mode: BlockMode,
    pub custom_v4: Option<Ipv4Addr>,
    pub custom_v6: Option<Ipv6Addr>,
}
```

- `BlockMode` implements `FromStr` / `as_str` for the four wire values.
- `BlockConfig::from_settings(mode: Option<&str>, v4: Option<&str>, v6: Option<&str>)`
  builds the config, defaulting to `null_ip` on absent/unknown mode.
- `Default for BlockConfig` = `null_ip`, no custom IPs.

Keeping this in its own file avoids growing `handler.rs` further.

### `src/dns/handler.rs`

- New field `block_config: Arc<ArcSwap<BlockConfig>>` on `DnsHandler`, mirroring
  the lock-free `ArcSwap` pattern already used for the filter engine. Reads on
  the blocked path are lock-free; live updates atomically swap a fresh config.
- Constructors default it to `BlockConfig::default()`; add a chainable
  `with_block_config(...)` (or a setter used by `main.rs` at startup) and a
  runtime `set_block_config(&self, cfg: BlockConfig)` + `block_config()`
  accessor, mirroring the forwarder's `set_dnssec_enabled` / `dnssec_enabled`.
- `build_blocked_response` gains the `BlockConfig` (loaded from the ArcSwap at
  the call site in `handle()`) and branches per mode:
  - `null_ip` → current logic.
  - `custom_ip` → same shape as `null_ip` but with configured IPs; unconfigured
    type → empty answer.
  - `refused` → reuse the existing `build_refused_response` body (REFUSED code,
    question echoed, no answer).
  - `nxdomain` → NoError-style message but `ResponseCode::NXDomain`, no answer.
- The `FilterResult::Blocked` arm computes the TTL only for the IP-bearing
  modes; `BLOCKED_RESPONSE_TTL_SECS` stays the answer TTL for `null_ip` /
  `custom_ip`.

### `src/main.rs`

At startup, read `block_mode`, `block_custom_ipv4`, `block_custom_ipv6` from the
DB, build the initial `BlockConfig`, and install it on the handler before
listeners start.

### `src/admin/api.rs`

- `get_settings`: add `block_mode`, `block_custom_ipv4`, `block_custom_ipv6` to
  the returned key allowlist.
- `put_settings`: validate before persisting (same "validate-then-write" pattern
  as `upstream_servers` — a bad value rejects the whole request with 400 and no
  partial write):
  - `block_mode`, if present, must be one of the four legal values.
  - In effect for `custom_ip`: any non-empty `block_custom_ipv4` /
    `block_custom_ipv6` must parse as the respective IP version.
  - After persisting, build a fresh `BlockConfig` from the merged values (new
    body values falling back to stored DB values for keys not in the request)
    and call `state.handler.set_block_config(...)` for immediate effect. No
    cache flush needed — the filter runs before the cache, so blocked responses
    are never cached.

### Admin UI (`admin-ui/dist/index.html`)

Add a "Block mode" control to the settings view: a `<select>` with the four
options; when `custom_ip` is selected, reveal IPv4 and IPv6 text inputs. Reuse
the existing settings component styling and the existing save flow (`PUT
/api/settings`). Regenerate affected `docs/screenshots/` afterward
(`cd e2e && npm run screenshots`).

## Data flow

1. Query arrives → filter check → `FilterResult::Blocked`.
2. `handle()` loads the current `BlockConfig` from the `ArcSwap`.
3. `build_blocked_response(query, query_type, &config)` synthesizes the wire
   response per the table above.
4. Blocked response is returned and logged as `QueryAction::Blocked` (unchanged).

## Error handling

- Unknown `block_mode` string from the wire → 400 at `put_settings`; internally
  (e.g. a corrupted DB value at startup) → fall back to `null_ip` and log a
  warning, never panic.
- Unparseable custom IP from the wire → 400. At startup, an unparseable stored
  IP is treated as "not configured" (empty answer for that type) with a warning.

## Testing

- Unit tests for `build_blocked_response` (or the `block` module): for each of
  the four modes, assert the response code and answer section for A, AAAA, and a
  non-address type (e.g. TXT).
- `BlockConfig::from_settings` / `FromStr` parsing tests, including default
  fallback on unknown mode and empty custom IPs.
- `put_settings` validation tests: illegal `block_mode` → 400; illegal custom IP
  → 400; no partial write on rejection.
- Live-apply test: after `set_block_config`, the next blocked query reflects the
  new mode.

## Non-goals recap

No hosts-rule IP honoring, no per-rule/per-client modes, no changes to the
filter engine, parser, or `FilterResult`.
