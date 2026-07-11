# Configurable Block Response Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the operator choose how noadd answers a filter-blocked query — null IP (default), NXDOMAIN, REFUSED, or a custom IPv4/IPv6 — via a global runtime setting.

**Architecture:** A new `BlockConfig` value (mode enum + optional custom IPv4/IPv6) lives behind an `ArcSwap` on `DnsHandler`, mirroring the lock-free filter-engine pattern. `build_blocked_response` branches on it. Settings persist in the existing key/value `settings` table and apply live through `put_settings` → `handler.set_block_config`, loaded once at startup in `main.rs`.

**Tech Stack:** Rust 2024, hickory-proto (DNS wire), arc-swap, axum (admin API), vanilla-JS web components (admin UI).

## Global Constraints

- Rust edition 2024; do NOT change `rust-version` (MSRV) in `Cargo.toml`.
- Run tests with `cargo nextest run` (never `cargo test`).
- Run `cargo fmt` before every commit; `cargo clippy --all-targets -- -D warnings` must stay clean.
- All commits GPG-signed (default git config handles this — do not pass `--no-gpg-sign`).
- Stage files explicitly by name; never `git add -A` / `git add .`.
- All GitHub-facing text in English.
- Default block mode is `null_ip` — existing deployments must see zero behavioral change after upgrade.
- No new dependencies.

---

### Task 1: `BlockConfig` / `BlockMode` types and parsing

**Files:**
- Create: `src/dns/block.rs`
- Modify: `src/dns/mod.rs:1` (add `pub mod block;`)

**Interfaces:**
- Produces:
  - `pub enum BlockMode { NullIp, Nxdomain, Refused, CustomIp }` — `Copy`, `Clone`, `Debug`, `PartialEq`, `Eq`.
  - `impl BlockMode`: `pub fn as_str(&self) -> &'static str` returning `"null_ip"|"nxdomain"|"refused"|"custom_ip"`.
  - `impl FromStr for BlockMode { type Err = (); }` accepting those four strings.
  - `pub struct BlockConfig { pub mode: BlockMode, pub custom_v4: Option<Ipv4Addr>, pub custom_v6: Option<Ipv6Addr> }` — `Clone`, `Debug`, `PartialEq`, `Eq`.
  - `impl Default for BlockConfig` → `{ mode: NullIp, custom_v4: None, custom_v6: None }`.
  - `pub fn from_settings(mode: Option<&str>, v4: Option<&str>, v6: Option<&str>) -> BlockConfig` — unknown/absent mode ⇒ `NullIp`; empty/absent/unparseable IP string ⇒ `None`.

- [ ] **Step 1: Write the failing tests**

Create `src/dns/block.rs` with only the test module first:

```rust
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// (types will be added in Step 3, above this test module)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_roundtrips_through_str() {
        for (s, m) in [
            ("null_ip", BlockMode::NullIp),
            ("nxdomain", BlockMode::Nxdomain),
            ("refused", BlockMode::Refused),
            ("custom_ip", BlockMode::CustomIp),
        ] {
            assert_eq!(BlockMode::from_str(s).unwrap(), m);
            assert_eq!(m.as_str(), s);
        }
    }

    #[test]
    fn unknown_mode_string_is_err() {
        assert!(BlockMode::from_str("bogus").is_err());
    }

    #[test]
    fn from_settings_defaults_to_null_ip() {
        let cfg = from_settings(None, None, None);
        assert_eq!(cfg, BlockConfig::default());
        assert_eq!(cfg.mode, BlockMode::NullIp);
    }

    #[test]
    fn from_settings_unknown_mode_falls_back_to_null_ip() {
        assert_eq!(from_settings(Some("bogus"), None, None).mode, BlockMode::NullIp);
    }

    #[test]
    fn from_settings_parses_custom_ips() {
        let cfg = from_settings(Some("custom_ip"), Some("192.0.2.1"), Some("100::1"));
        assert_eq!(cfg.mode, BlockMode::CustomIp);
        assert_eq!(cfg.custom_v4, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(cfg.custom_v6, Some("100::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn from_settings_empty_or_bad_ip_is_none() {
        let cfg = from_settings(Some("custom_ip"), Some(""), Some("not-an-ip"));
        assert_eq!(cfg.custom_v4, None);
        assert_eq!(cfg.custom_v6, None);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail to compile**

Run: `cargo nextest run -E 'test(block::)' 2>&1 | tail -20`
Expected: compile error — `BlockMode` / `BlockConfig` / `from_settings` not found.

- [ ] **Step 3: Write the implementation**

Prepend above the `#[cfg(test)]` module in `src/dns/block.rs`:

```rust
//! Block-response configuration: how the DNS handler answers a query that the
//! filter engine blocks. Selected at runtime via the `block_mode` /
//! `block_custom_ipv4` / `block_custom_ipv6` settings.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// How a filter-blocked query is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockMode {
    /// `0.0.0.0` for A, `::` for AAAA, empty NoError for other types.
    NullIp,
    /// `NXDOMAIN` for every query type.
    Nxdomain,
    /// `REFUSED` for every query type.
    Refused,
    /// Operator-supplied IPv4 (A) / IPv6 (AAAA); empty NoError when the
    /// relevant address is unset or the query is another type.
    CustomIp,
}

impl BlockMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockMode::NullIp => "null_ip",
            BlockMode::Nxdomain => "nxdomain",
            BlockMode::Refused => "refused",
            BlockMode::CustomIp => "custom_ip",
        }
    }
}

impl FromStr for BlockMode {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "null_ip" => Ok(BlockMode::NullIp),
            "nxdomain" => Ok(BlockMode::Nxdomain),
            "refused" => Ok(BlockMode::Refused),
            "custom_ip" => Ok(BlockMode::CustomIp),
            _ => Err(()),
        }
    }
}

/// Runtime block-response configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockConfig {
    pub mode: BlockMode,
    pub custom_v4: Option<Ipv4Addr>,
    pub custom_v6: Option<Ipv6Addr>,
}

impl Default for BlockConfig {
    fn default() -> Self {
        BlockConfig {
            mode: BlockMode::NullIp,
            custom_v4: None,
            custom_v6: None,
        }
    }
}

/// Build a `BlockConfig` from raw setting strings. An absent or unrecognised
/// mode falls back to `NullIp`; an empty or unparseable IP becomes `None`.
pub fn from_settings(mode: Option<&str>, v4: Option<&str>, v6: Option<&str>) -> BlockConfig {
    let mode = mode
        .and_then(|s| BlockMode::from_str(s.trim()).ok())
        .unwrap_or(BlockMode::NullIp);
    let custom_v4 = v4.and_then(|s| s.trim().parse::<Ipv4Addr>().ok());
    let custom_v6 = v6.and_then(|s| s.trim().parse::<Ipv6Addr>().ok());
    BlockConfig {
        mode,
        custom_v4,
        custom_v6,
    }
}
```

Then add to `src/dns/mod.rs` (keep the list alphabetical — insert before `pub mod doh;`):

```rust
pub mod block;
```

Note: the `use std::str::FromStr;` at the very top of the file may be reported unused if only the test module references it — the `impl FromStr` needs the trait in scope for `BlockMode::from_str`, so it stays used. If clippy flags it, it means the top-of-file `use` duplicates the test-module `use`; remove the one inside `mod tests` (it inherits via `use super::*;`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -E 'test(block::)'`
Expected: all 6 tests PASS.

- [ ] **Step 5: fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5`
Expected: no warnings.

- [ ] **Step 6: Commit**

```bash
git add src/dns/block.rs src/dns/mod.rs
git commit -m "feat: add BlockConfig/BlockMode types for block-response modes"
```

---

### Task 2: Branch `build_blocked_response` on `BlockConfig` and wire it into `DnsHandler`

**Files:**
- Modify: `src/dns/handler.rs` (imports ~line 19; struct ~line 137; constructor ~line 192; call site ~line 320; `build_blocked_response` ~line 533; tests ~line 730)

**Interfaces:**
- Consumes: `crate::dns::block::{BlockConfig, BlockMode}` from Task 1.
- Produces:
  - `DnsHandler` field `block_config: Arc<ArcSwap<BlockConfig>>`.
  - `pub fn with_block_config(self, cfg: BlockConfig) -> Self` (chainable, used by `main.rs`).
  - `pub fn set_block_config(&self, cfg: BlockConfig)` (runtime swap, used by `put_settings`).
  - `pub fn block_config(&self) -> arc_swap::Guard<Arc<BlockConfig>>` — cheap loaded handle.
  - `build_blocked_response(query: &Message, query_type: RecordType, config: &BlockConfig) -> Result<Vec<u8>, HandlerError>`.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `src/dns/handler.rs` (after the existing helpers). This adds a query builder and one test per mode:

```rust
    use crate::dns::block::{BlockConfig, BlockMode};
    use hickory_proto::op::{MessageType, Query};

    fn make_query(domain: &str, rtype: RecordType) -> Message {
        // Mirror tests/upstream_test.rs::build_query — this repo's hickory
        // uses Message::new(id, MessageType, OpCode) and Query::query(name, rt).
        let mut msg = Message::new(42, MessageType::Query, OpCode::Query);
        let name = Name::from_ascii(domain).expect("valid domain name");
        msg.add_query(Query::query(name, rtype));
        msg
    }

    fn blocked(msg: &Message, rtype: RecordType, cfg: &BlockConfig) -> Message {
        let bytes = build_blocked_response(msg, rtype, cfg).unwrap();
        Message::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn null_ip_mode_returns_unspecified_addresses() {
        let cfg = BlockConfig::default();
        let a = blocked(&make_query("ads.example.com.", RecordType::A), RecordType::A, &cfg);
        assert_eq!(a.metadata.response_code, ResponseCode::NoError);
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].data(), &RData::A(A(Ipv4Addr::UNSPECIFIED)));

        let aaaa = blocked(&make_query("ads.example.com.", RecordType::AAAA), RecordType::AAAA, &cfg);
        assert_eq!(aaaa.answers[0].data(), &RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));

        let txt = blocked(&make_query("ads.example.com.", RecordType::TXT), RecordType::TXT, &cfg);
        assert_eq!(txt.metadata.response_code, ResponseCode::NoError);
        assert!(txt.answers.is_empty());
    }

    #[test]
    fn nxdomain_mode_returns_nxdomain_for_all_types() {
        let cfg = BlockConfig { mode: BlockMode::Nxdomain, ..BlockConfig::default() };
        for rt in [RecordType::A, RecordType::AAAA, RecordType::TXT] {
            let m = blocked(&make_query("ads.example.com.", rt), rt, &cfg);
            assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
            assert!(m.answers.is_empty());
        }
    }

    #[test]
    fn refused_mode_returns_refused_for_all_types() {
        let cfg = BlockConfig { mode: BlockMode::Refused, ..BlockConfig::default() };
        for rt in [RecordType::A, RecordType::AAAA, RecordType::TXT] {
            let m = blocked(&make_query("ads.example.com.", rt), rt, &cfg);
            assert_eq!(m.metadata.response_code, ResponseCode::Refused);
            assert!(m.answers.is_empty());
        }
    }

    #[test]
    fn custom_ip_mode_uses_configured_addresses() {
        let cfg = BlockConfig {
            mode: BlockMode::CustomIp,
            custom_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            custom_v6: Some("100::1".parse().unwrap()),
        };
        let a = blocked(&make_query("ads.example.com.", RecordType::A), RecordType::A, &cfg);
        assert_eq!(a.answers[0].data(), &RData::A(A(Ipv4Addr::new(192, 0, 2, 1))));
        let aaaa = blocked(&make_query("ads.example.com.", RecordType::AAAA), RecordType::AAAA, &cfg);
        assert_eq!(aaaa.answers[0].data(), &RData::AAAA(AAAA("100::1".parse().unwrap())));
    }

    #[test]
    fn custom_ip_mode_unset_address_gives_empty_noerror() {
        let cfg = BlockConfig { mode: BlockMode::CustomIp, custom_v4: None, custom_v6: None };
        let a = blocked(&make_query("ads.example.com.", RecordType::A), RecordType::A, &cfg);
        assert_eq!(a.metadata.response_code, ResponseCode::NoError);
        assert!(a.answers.is_empty());
    }
```

Note on field/method access: this codebase's hickory fork exposes `msg.answers` (field) and `record.data()` returning `&RData` — the existing tests use `Record::from_rdata` and `msg.add_answer`. If `.answers` is not a public field, use `msg.answers()` accessor; if `.data()` differs, mirror whatever the existing `a_record`/`cache_ttl_for_response` code path uses. Verify against the actual hickory version during Step 2 and adjust these accessors before implementing.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -E 'test(handler::)' 2>&1 | tail -20`
Expected: compile error — `build_blocked_response` takes 2 args not 3, `BlockConfig` import path. (If the `.answers`/`.data()` accessors don't compile, fix them now per the Step 1 note, re-run, and confirm the remaining failure is only the arity/signature mismatch.)

- [ ] **Step 3: Rewrite `build_blocked_response`**

Replace the whole function (currently `src/dns/handler.rs:532-574`) with:

```rust
/// Build a blocked DNS response for the given query message, according to the
/// configured `BlockConfig`.
fn build_blocked_response(
    query: &Message,
    query_type: RecordType,
    config: &BlockConfig,
) -> Result<Vec<u8>, HandlerError> {
    // REFUSED and NXDOMAIN apply uniformly to every query type.
    match config.mode {
        BlockMode::Refused => return build_refused_response(query),
        BlockMode::Nxdomain => {
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.metadata.response_code = ResponseCode::NXDomain;
            response.metadata.recursion_desired = true;
            response.metadata.recursion_available = true;
            for q in &query.queries {
                response.add_query(q.clone());
            }
            return Ok(response.to_vec()?);
        }
        BlockMode::NullIp | BlockMode::CustomIp => {}
    }

    // Address-bearing modes: NoError, with an A/AAAA answer when an address is
    // available for the query type, otherwise an empty answer section.
    let (v4, v6) = match config.mode {
        BlockMode::CustomIp => (config.custom_v4, config.custom_v6),
        // NullIp: the unspecified addresses.
        _ => (Some(Ipv4Addr::UNSPECIFIED), Some(Ipv6Addr::UNSPECIFIED)),
    };

    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.response_code = ResponseCode::NoError;
    response.metadata.recursion_desired = true;
    response.metadata.recursion_available = true;

    for q in &query.queries {
        response.add_query(q.clone());
    }

    if let Some(first_query) = query.queries.first() {
        let name = first_query.name().clone();
        match query_type {
            RecordType::A => {
                if let Some(addr) = v4 {
                    response.add_answer(Record::from_rdata(
                        name,
                        BLOCKED_RESPONSE_TTL_SECS,
                        RData::A(A(addr)),
                    ));
                }
            }
            RecordType::AAAA => {
                if let Some(addr) = v6 {
                    response.add_answer(Record::from_rdata(
                        name,
                        BLOCKED_RESPONSE_TTL_SECS,
                        RData::AAAA(AAAA(addr)),
                    ));
                }
            }
            _ => {
                // Empty answer for other types.
            }
        }
    }

    Ok(response.to_vec()?)
}
```

- [ ] **Step 4: Add the `use` for block types**

At `src/dns/handler.rs:19` area, add after the existing `crate::` imports:

```rust
use crate::dns::block::{BlockConfig, BlockMode};
```

- [ ] **Step 5: Add the ArcSwap field and accessors to `DnsHandler`**

In the struct definition (after `log_query_results: bool,` at ~line 164), add:

```rust
    /// Runtime block-response configuration (mode + optional custom IPs).
    /// Behind `ArcSwap` for lock-free reads on the blocked path and atomic
    /// live updates from the settings API.
    block_config: Arc<ArcSwap<BlockConfig>>,
```

In `with_max_inflight` (the `Self { ... }` literal at ~line 192), add the field initializer:

```rust
            block_config: Arc::new(ArcSwap::from_pointee(BlockConfig::default())),
```

Add these methods in the `impl DnsHandler` block, next to `with_log_query_results` (~line 218):

```rust
    /// Install the initial block-response configuration. Chainable during
    /// construction (used by `main.rs` to load the persisted setting).
    pub fn with_block_config(self, cfg: BlockConfig) -> Self {
        self.block_config.store(Arc::new(cfg));
        self
    }

    /// Atomically replace the block-response configuration at runtime.
    pub fn set_block_config(&self, cfg: BlockConfig) {
        self.block_config.store(Arc::new(cfg));
    }

    /// Load the current block-response configuration.
    pub fn block_config(&self) -> arc_swap::Guard<Arc<BlockConfig>> {
        self.block_config.load()
    }
```

- [ ] **Step 6: Update the call site**

At `src/dns/handler.rs:319-320` (the `FilterResult::Blocked` arm), change:

```rust
            FilterResult::Blocked { rule, list } => {
                let block_cfg = self.block_config.load();
                let response = build_blocked_response(&message, query_type, &block_cfg)?;
```

(The rest of the tuple — `BLOCKED_RESPONSE_TTL_SECS` for `min_ttl`, `QueryAction::Blocked`, etc. — is unchanged. Keeping `BLOCKED_RESPONSE_TTL_SECS` as the reported `min_ttl` is fine for all modes; it only feeds the DoH `Cache-Control` hint and is harmless for NXDOMAIN/REFUSED.)

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo nextest run -E 'test(handler::)'`
Expected: the 5 new mode tests PASS plus all pre-existing handler tests still PASS.

- [ ] **Step 8: fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5`
Expected: no warnings.

- [ ] **Step 9: Commit**

```bash
git add src/dns/handler.rs
git commit -m "feat: branch blocked-response synthesis on configurable block mode"
```

---

### Task 3: Persist, validate, load at startup, and apply live via the settings API

**Files:**
- Modify: `src/main.rs:89` area (startup load)
- Modify: `src/admin/api.rs:845-853` (get_settings allowlist), `src/admin/api.rs:888-934` (put_settings validation + apply)
- Test: `tests/` — add `tests/block_mode_settings_test.rs` (integration) OR extend an existing admin API test file. Prefer a new file for isolation.

**Interfaces:**
- Consumes: `DnsHandler::set_block_config` / `with_block_config` (Task 2), `crate::dns::block::from_settings` (Task 1).
- Produces: three recognised setting keys `block_mode`, `block_custom_ipv4`, `block_custom_ipv6`.

- [ ] **Step 1: Write the failing validation test**

Create `tests/block_mode_settings_test.rs`. Use the same harness the other admin API integration tests use — inspect an existing test in `tests/` (e.g. any file that builds `AppState` / calls `put_settings` or drives the router) and mirror its setup. The behavior to assert:

```rust
// Pseudocode shape — adapt to the repo's existing admin-API test harness.
// 1. Start the app / router with a fresh temp DB.
// 2. PUT /api/settings { "block_mode": "bogus" } -> 400, and GET shows no block_mode stored.
// 3. PUT /api/settings { "block_mode": "custom_ip", "block_custom_ipv4": "not-an-ip" } -> 400.
// 4. PUT /api/settings { "block_mode": "nxdomain" } -> 200, GET returns block_mode = "nxdomain".
// 5. PUT /api/settings { "block_mode": "custom_ip", "block_custom_ipv4": "192.0.2.1",
//    "block_custom_ipv6": "100::1" } -> 200.
```

If no HTTP-level admin test harness exists, unit-test the validation helper instead (see Step 3) and assert `get_settings`/`put_settings` behavior at the function level with a `Database` built from `Database::open`/in-memory as other `src/admin` unit tests do. Choose whichever matches existing patterns; do not invent a new harness.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -E 'test(block_mode)' 2>&1 | tail -20`
Expected: FAIL — invalid `block_mode` currently returns 200 (no validation), and `get_settings` omits the new keys.

- [ ] **Step 3: Add validation + live-apply to `put_settings`**

In `src/admin/api.rs`, in `put_settings`, add validation BEFORE the persist loop (alongside the existing `upstream_servers` pre-validation at ~line 895), so a bad value rejects the whole request with no partial write:

```rust
    // Validate block-mode settings before persisting anything.
    if let Some(mode) = body.settings.get("block_mode")
        && mode.trim().parse::<crate::dns::block::BlockMode>().is_err()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    for key in ["block_custom_ipv4", "block_custom_ipv6"] {
        if let Some(v) = body.settings.get(key) {
            let v = v.trim();
            if !v.is_empty() {
                let ok = if key == "block_custom_ipv4" {
                    v.parse::<std::net::Ipv4Addr>().is_ok()
                } else {
                    v.parse::<std::net::Ipv6Addr>().is_ok()
                };
                if !ok {
                    return Err(StatusCode::BAD_REQUEST);
                }
            }
        }
    }
```

After the persist loop, apply live if any block key was present (add near the `dnssec_disabled` apply block ~line 928). Merge request values over stored DB values so a partial update (e.g. only `block_mode`) keeps the other keys:

```rust
    if body.settings.keys().any(|k| k.starts_with("block_")) {
        // Merge: prefer the just-submitted value, else the persisted one.
        async fn merged(
            db: &crate::db::Database,
            body: &std::collections::HashMap<String, String>,
            key: &str,
        ) -> Option<String> {
            match body.get(key) {
                Some(v) => Some(v.clone()),
                None => db.get_setting(key).await.ok().flatten(),
            }
        }
        let mode = merged(&state.db, &body.settings, "block_mode").await;
        let v4 = merged(&state.db, &body.settings, "block_custom_ipv4").await;
        let v6 = merged(&state.db, &body.settings, "block_custom_ipv6").await;
        let cfg = crate::dns::block::from_settings(
            mode.as_deref(),
            v4.as_deref(),
            v6.as_deref(),
        );
        state.handler.set_block_config(cfg);
    }
```

(If a free `async fn` inside the handler body is awkward with the surrounding style, inline the three `match body.settings.get(...)` lookups instead — same logic.)

- [ ] **Step 4: Add the keys to `get_settings`**

In `src/admin/api.rs`, extend the `keys` array (~line 845) with:

```rust
        "block_mode",
        "block_custom_ipv4",
        "block_custom_ipv6",
```

- [ ] **Step 5: Load at startup in `main.rs`**

In `src/main.rs`, after the `dnssec_disabled` load block (~line 89) and before `let handler = ...` (line 100), read the three keys:

```rust
    let block_config = {
        let mode = db.get_setting("block_mode").await.ok().flatten();
        let v4 = db.get_setting("block_custom_ipv4").await.ok().flatten();
        let v6 = db.get_setting("block_custom_ipv6").await.ok().flatten();
        noadd::dns::block::from_settings(mode.as_deref(), v4.as_deref(), v6.as_deref())
    };
    tracing::info!(block_mode = block_config.mode.as_str(), "loaded block-response mode");
```

Then add `.with_block_config(block_config)` to the handler builder chain (after `.with_log_query_results(...)` at ~line 109):

```rust
        .with_log_query_results(args.log_query_results)
        .with_block_config(block_config),
```

Ensure `noadd::dns::block` is reachable — it is a public module via `pub mod block;` in `src/dns/mod.rs`, so `noadd::dns::block::from_settings` resolves without a new `use`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo nextest run -E 'test(block_mode)'`
Expected: PASS. Also run `cargo build 2>&1 | tail -5` to confirm `main.rs` compiles.

- [ ] **Step 7: fmt + clippy**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings 2>&1 | tail -5`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add src/admin/api.rs src/main.rs tests/block_mode_settings_test.rs
git commit -m "feat: persist, validate, and live-apply block-response mode via settings API"
```

---

### Task 4: Admin UI block-mode control + screenshots

**Files:**
- Modify: `admin-ui/dist/index.html` (settings view markup ~line 3806-3817; save handler ~line 3853; load handler ~line 3918-3931)
- Modify: `docs/screenshots/` (regenerated PNGs of the settings page)

**Interfaces:**
- Consumes: `GET /api/settings` returning `block_mode` / `block_custom_ipv4` / `block_custom_ipv6`; `PUT /api/settings` accepting them (Task 3).

- [ ] **Step 1: Add the markup**

In `admin-ui/dist/index.html`, insert a "Block mode" block in the settings card, right after the DNSSEC `<div class="input-row">…#s-dnssec…</div>` and before the closing `</div>` of that card (~line 3816):

```html
        <div class="card-title" style="margin-top:16px">Block mode</div>
        <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:12px">
          How blocked queries are answered. Default returns a null IP (0.0.0.0 / ::).
        </p>
        <div class="input-row">
          <label style="min-width:140px;color:var(--text-secondary);font-size:0.85rem">Response</label>
          <select id="s-block-mode">
            <option value="null_ip">Null IP (0.0.0.0 / ::)</option>
            <option value="nxdomain">NXDOMAIN</option>
            <option value="refused">REFUSED</option>
            <option value="custom_ip">Custom IP</option>
          </select>
        </div>
        <div class="input-row" id="s-block-custom" style="display:none;flex-direction:column;gap:8px;align-items:stretch">
          <input type="text" id="s-block-ipv4" placeholder="Custom IPv4 for A, e.g. 192.0.2.1">
          <input type="text" id="s-block-ipv6" placeholder="Custom IPv6 for AAAA, e.g. 100::1">
        </div>
```

- [ ] **Step 2: Wire the change/save handlers**

In the settings `save-settings` onclick object (~line 3854), add the three keys:

```javascript
        block_mode: this.querySelector('#s-block-mode').value,
        block_custom_ipv4: this.querySelector('#s-block-ipv4').value.trim(),
        block_custom_ipv6: this.querySelector('#s-block-ipv6').value.trim(),
```

Add a toggle so the custom-IP inputs show only for `custom_ip`. Place it next to the other `#s-*` `onchange` handlers (~line 3905):

```javascript
    const syncBlockCustom = () => {
      this.querySelector('#s-block-custom').style.display =
        this.querySelector('#s-block-mode').value === 'custom_ip' ? 'flex' : 'none';
    };
    this.querySelector('#s-block-mode').onchange = syncBlockCustom;
```

- [ ] **Step 3: Populate on load**

In `async load()` after the `#s-dnssec` line (~line 3930), add:

```javascript
      this.querySelector('#s-block-mode').value = s.block_mode || 'null_ip';
      if (s.block_custom_ipv4) this.querySelector('#s-block-ipv4').value = s.block_custom_ipv4;
      if (s.block_custom_ipv6) this.querySelector('#s-block-ipv6').value = s.block_custom_ipv6;
      this.querySelector('#s-block-custom').style.display =
        (s.block_mode === 'custom_ip') ? 'flex' : 'none';
```

- [ ] **Step 4: Rebuild and manually verify**

Run:
```bash
cargo build 2>&1 | tail -3
RUST_LOG=noadd=info cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:3000
```
Open http://127.0.0.1:3000 → Settings. Confirm: the Block mode select renders; choosing "Custom IP" reveals the two IP inputs; Save persists; reload keeps the value. Then Ctrl-C.

Sanity-check behavior with `doggo` / `dig` against the running server for a known-blocked domain under each mode (at least `nxdomain` and `custom_ip`):
```bash
dig @127.0.0.1 -p 5353 doubleclick.net A +noall +answer +comments | head
```
Expected: `nxdomain` mode → `status: NXDOMAIN`; `custom_ip` with `192.0.2.1` → the A answer is `192.0.2.1`.

- [ ] **Step 5: Regenerate screenshots**

Per CLAUDE.md (UI appearance changed):
```bash
cargo build
cd e2e && npm ci && npx playwright install chromium && npm run screenshots
```
Confirm the settings screenshot in `docs/screenshots/` now shows the Block mode control.

- [ ] **Step 6: Commit**

```bash
git add admin-ui/dist/index.html docs/screenshots
git commit -m "feat: add block-mode control to admin settings UI"
```

---

### Task 5: Docs + final verification

**Files:**
- Modify: `ARCHITECTURE.md` (block-response section, if one exists) and/or `README.md` (user-facing settings list)

- [ ] **Step 1: Update documentation**

Grep for where blocked responses / `0.0.0.0` are described:
```bash
rg -n "0\.0\.0\.0|blocked response|NXDOMAIN|block mode" README.md ARCHITECTURE.md
```
Add a short paragraph documenting the four block modes and the custom-IP option to whichever file describes runtime settings / the query path. Keep it to the existing doc's voice and length; do not create a new doc.

- [ ] **Step 2: Full test suite + gates**

Run:
```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo nextest run 2>&1 | tail -20
```
Expected: fmt clean, no clippy warnings, all tests PASS.

- [ ] **Step 3: Commit docs**

```bash
git add README.md ARCHITECTURE.md
git commit -m "docs: document configurable block-response modes"
```

- [ ] **Step 4: Push and open PR**

```bash
git push -u origin feat/configurable-block-mode
gh pr create --fill
```
(PR title/body in English. Do not merge without explicit user confirmation.)

---

## Self-Review Notes

- **Spec coverage:** data model (T1/T3), `BlockConfig` + live update (T1/T2), response semantics table incl. all-types NXDOMAIN/REFUSED and custom-IP-unset→empty (T2 tests), settings API + validate-then-write (T3), startup load (T3), admin UI incl. reveal-on-custom (T4), tests at each layer, docs (T5). All covered.
- **Type consistency:** `BlockMode`/`BlockConfig`/`from_settings` names identical across T1→T3; `set_block_config`/`with_block_config`/`block_config` identical across T2→T3; setting keys `block_mode`/`block_custom_ipv4`/`block_custom_ipv6` identical across T3→T4.
- **Known verification points flagged inline:** hickory `.answers`/`.data()`/`Message::query()`/`Query::new()` accessors (T2 Step 1 note) and the admin-API test harness shape (T3 Step 1) must be confirmed against the actual repo APIs during implementation — the plan says to mirror existing usage rather than assume.
