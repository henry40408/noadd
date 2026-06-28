# DNSSEC Transparency Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Force the DNSSEC-OK (DO) bit on upstream queries and surface the upstream's Authenticated Data (AD) verdict per-query in the admin UI query log, toggleable at runtime.

**Architecture:** Two touch-points on the existing `filter → cache → upstream forward` path: the forwarder upserts an EDNS OPT with DO set before sending upstream (when enabled); the handler reads the AD bit cheaply from the served response bytes and logs it. A reverse-named DB setting `dnssec_disabled` (default-on) gates the DO forcing and is switchable from the admin UI without restart. No local validation, no new dependencies.

**Tech Stack:** Rust 2024, hickory-proto 0.26 (`Edns`/`Message`), rusqlite/tokio-rusqlite, axum admin API, vanilla-JS admin UI (`admin-ui/dist/index.html`).

## Global Constraints

- Rust edition 2024; MSRV (`rust-version`) MUST NOT change.
- Run tests with `cargo nextest run` (not `cargo test`).
- `cargo fmt` before every commit; `cargo clippy --all-targets -- -D warnings` must pass.
- All commits GPG-signed; stage files explicitly by name (never `git add -A`/`.`).
- No new third-party dependencies are needed or permitted for this feature.
- Setting key is `dnssec_disabled` (reverse): absent/`"false"` ⇒ enabled; `"true"` ⇒ disabled. Default enabled.
- EDNS UDP payload advertised when forcing DO: **1232**.
- Admin UI copy in English; help-text matches existing admin-ui style.
- After any admin-UI appearance change: `cargo build` then `cd e2e && npm run screenshots`, commit updated PNGs.
- Commit message footer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: Storage — `authenticated_data` column

**Files:**
- Modify: `src/db.rs` (`init_schema` query_logs CREATE ~line 321; `run_migrations` ~line 384 + `LATEST_VERSION` line 446; `QueryLogEntry` struct ~line 66; `insert_query_logs` ~line 505; `query_logs` read ~line 536)
- Test: `src/db.rs` (`#[cfg(test)]` module — follow existing DB tests)

**Interfaces:**
- Produces: `QueryLogEntry { …, authenticated_data: bool }`; `query_logs` rows carry `authenticated_data` (SQLite INTEGER 0/1, serialized as JSON bool field `authenticated_data`).

- [ ] **Step 1: Write the failing test** — add to the db tests module:

```rust
#[tokio::test]
async fn query_log_roundtrips_authenticated_data() {
    let db = Database::open(":memory:").await.unwrap();
    let entry = QueryLogEntry {
        timestamp: 1,
        domain: "example.com".into(),
        query_type: "A".into(),
        client_ip: "127.0.0.1".into(),
        blocked: false,
        cached: false,
        response_ms: 1,
        upstream: Some("1.1.1.1:53".into()),
        doh_token: None,
        result: None,
        authenticated_data: true,
    };
    db.insert_query_logs(&[entry]).await.unwrap();
    let rows = db.query_logs(&Default::default()).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].authenticated_data);
}
```

(If `query_logs` does not take a `Default`-able params struct, match its real signature — pass the same arguments existing query_logs tests use, with no filters.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run query_log_roundtrips_authenticated_data`
Expected: FAIL — `QueryLogEntry` has no field `authenticated_data` (compile error).

- [ ] **Step 3: Add the field to `QueryLogEntry`** (after `result`):

```rust
    pub result: Option<String>,
    pub authenticated_data: bool,
}
```

- [ ] **Step 4: Add the column to `init_schema`'s query_logs CREATE TABLE** (new DBs). Add this line inside the `CREATE TABLE IF NOT EXISTS query_logs (...)` column list (e.g. after the `result` / last column, before the closing paren):

```sql
                        authenticated_data INTEGER NOT NULL DEFAULT 0,
```

- [ ] **Step 5: Add the migration** — bump `LATEST_VERSION` and add a block in `run_migrations` (existing DBs):

```rust
        if version < 7 {
            add_column_if_missing(
                conn,
                "query_logs",
                "authenticated_data",
                "INTEGER NOT NULL DEFAULT 0",
            )?;
        }
```

Change `const LATEST_VERSION: i64 = 6;` to `7`.

- [ ] **Step 6: Persist the field in `insert_query_logs`** — add the column and bind param:

```rust
"INSERT INTO query_logs (timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result, authenticated_data) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
```

and add `e.authenticated_data,` as the 11th bound value (after `e.result,`).

- [ ] **Step 7: Read the field in `query_logs`** — extend the SELECT and row mapping:

```rust
let mut sql = "SELECT timestamp, domain, query_type, client_ip, blocked, cached, response_ms, upstream, doh_token, result, authenticated_data FROM query_logs WHERE 1=1".to_string();
```

and in the row closure add `authenticated_data: row.get(10)?,` to the constructed `QueryLogEntry` (index 10 = 11th column; bool maps from INTEGER).

- [ ] **Step 8: Run test to verify it passes**

Run: `cargo nextest run query_log_roundtrips_authenticated_data`
Expected: PASS

- [ ] **Step 9: fmt + commit**

```bash
cargo fmt
git add src/db.rs
git commit -S -m "feat(db): add authenticated_data column to query_logs

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Read the AD bit and thread it through the handler/logger

**Files:**
- Modify: `src/dns/handler.rs` (add `response_authenticated`; add field to `QueryContext`; populate in both `QueryContext` constructions in `handle()`)
- Modify: `src/logger.rs` (`query_context_to_entry` ~line 82)
- Test: `src/dns/handler.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `QueryLogEntry { …, authenticated_data: bool }` (Task 1).
- Produces: `QueryContext { …, authenticated_data: bool }`; `fn response_authenticated(bytes: &[u8]) -> bool`.

- [ ] **Step 1: Write the failing test** (handler tests module):

```rust
#[test]
fn ad_bit_read_from_header_byte3() {
    // AD is bit 5 (0x20) of byte 3 of the DNS header.
    let mut hdr = vec![0u8; 12];
    assert!(!response_authenticated(&hdr));
    hdr[3] |= 0x20;
    assert!(response_authenticated(&hdr));
    // too-short buffers are not authenticated, never panic
    assert!(!response_authenticated(&[0, 1]));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run ad_bit_read_from_header_byte3`
Expected: FAIL — `response_authenticated` not defined.

- [ ] **Step 3: Add the helper** (near the other free functions in `handler.rs`):

```rust
/// True if the DNS response carries the Authenticated Data (AD) header bit.
/// AD is bit 5 (0x20) of byte 3 of the DNS header — read directly from the
/// wire bytes, no message parse (cheap enough to run on every query).
fn response_authenticated(bytes: &[u8]) -> bool {
    bytes.get(3).is_some_and(|b| b & 0x20 != 0)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run ad_bit_read_from_header_byte3`
Expected: PASS

- [ ] **Step 5: Add the field to `QueryContext`** (after `result`):

```rust
    pub result: Option<String>,
    pub authenticated_data: bool,
}
```

- [ ] **Step 6: Populate it in `handle()`** — in the rate-limited `QueryContext { … }` (the early REFUSED path) add:

```rust
                result: None,
                authenticated_data: false,
```

and in the main `QueryContext { … }` near the end of `handle()` add (after `result,`):

```rust
            result,
            authenticated_data: response_authenticated(&response_bytes),
```

- [ ] **Step 7: Map it in the logger** — in `query_context_to_entry` (`src/logger.rs`) add to the constructed `QueryLogEntry`:

```rust
        result: ctx.result,
        authenticated_data: ctx.authenticated_data,
    }
```

- [ ] **Step 8: Build + run handler tests**

Run: `cargo nextest run -E 'package(noadd)' handler`
Expected: PASS (and the crate compiles — `QueryContext` constructions are exhaustive).

- [ ] **Step 9: fmt + commit**

```bash
cargo fmt
git add src/dns/handler.rs src/logger.rs
git commit -S -m "feat(dns): read AD bit and log it per query

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Forwarder — force DO + runtime toggle

**Files:**
- Modify: `src/upstream/forwarder.rs` (add `AtomicBool` import; `ensure_dnssec_ok` helper + `DNSSEC_UDP_PAYLOAD` const; `dnssec_enabled` field on `UpstreamForwarder`; init in `new()`; `set_dnssec_enabled`/`dnssec_enabled` methods; call in `forward()`)
- Test: `src/upstream/forwarder.rs` `#[cfg(test)]`

**Interfaces:**
- Produces: `UpstreamForwarder::set_dnssec_enabled(&self, bool)`, `UpstreamForwarder::dnssec_enabled(&self) -> bool`. Default state after `new()` = enabled (`true`).

- [ ] **Step 1: Write the failing tests** (forwarder tests module):

```rust
#[test]
fn ensure_dnssec_ok_adds_opt_when_absent() {
    let mut msg = Message::query();
    msg.add_query(Query::query(Name::root(), RecordType::A));
    ensure_dnssec_ok(&mut msg);
    let edns = msg.edns.as_ref().expect("OPT added");
    assert!(edns.flags().dnssec_ok);
    assert_eq!(edns.max_payload(), 1232);
}

#[test]
fn ensure_dnssec_ok_upserts_existing_opt_without_duplicating() {
    let mut msg = Message::query();
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(4096);
    msg.set_edns(edns);
    ensure_dnssec_ok(&mut msg);
    let edns = msg.edns.as_ref().unwrap();
    assert!(edns.flags().dnssec_ok);
    // existing larger payload preserved (>= 1232)
    assert_eq!(edns.max_payload(), 4096);
}

#[tokio::test]
async fn dnssec_toggle_defaults_on_and_flips() {
    let f = make_forwarder(UpstreamStrategy::Sequential).await;
    assert!(f.dnssec_enabled());
    f.set_dnssec_enabled(false);
    assert!(!f.dnssec_enabled());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -E 'package(noadd)' dnssec`
Expected: FAIL — `ensure_dnssec_ok` / `dnssec_enabled` not defined.

- [ ] **Step 3: Add imports + const + helper.** Extend the atomics import to include `AtomicBool`:

```rust
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
```

Add the `Edns` import to the existing hickory `op` use line:

```rust
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Edns, Message, OpCode, Query, ResponseCode};
```

Add near the top-level consts:

```rust
/// EDNS UDP payload advertised when forcing DO. 1232 is the DNS-flag-day
/// recommendation that avoids IP fragmentation of larger signed responses.
const DNSSEC_UDP_PAYLOAD: u16 = 1232;

/// Upsert an EDNS(0) OPT on `msg` with the DNSSEC-OK (DO) bit set, preserving
/// any existing OPT and its options. Never produces a second OPT record.
fn ensure_dnssec_ok(msg: &mut Message) {
    match msg.edns.as_mut() {
        Some(edns) => {
            edns.set_dnssec_ok(true);
            if edns.max_payload() < DNSSEC_UDP_PAYLOAD {
                edns.set_max_payload(DNSSEC_UDP_PAYLOAD);
            }
        }
        None => {
            let mut edns = Edns::new();
            edns.set_version(0);
            edns.set_dnssec_ok(true);
            edns.set_max_payload(DNSSEC_UDP_PAYLOAD);
            msg.set_edns(edns);
        }
    }
}
```

- [ ] **Step 4: Add the field + methods.** In `struct UpstreamForwarder` add:

```rust
    /// When true, force the DO bit on upstream requests (DNSSEC transparency).
    /// Runtime-switchable so the admin-UI toggle takes effect without restart.
    dnssec_enabled: AtomicBool,
```

In `new()`, initialise it `true` in the returned `Self { … }`:

```rust
            dnssec_enabled: AtomicBool::new(true),
```

Add methods near `set_strategy`:

```rust
    /// Enable/disable forcing the DO bit on upstream requests.
    pub fn set_dnssec_enabled(&self, enabled: bool) {
        self.dnssec_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Whether DO forcing is currently enabled.
    pub fn dnssec_enabled(&self) -> bool {
        self.dnssec_enabled.load(Ordering::Relaxed)
    }
```

- [ ] **Step 5: Force DO in `forward()`.** Change the request parse to `mut` and upsert after reading the id:

```rust
        let mut request_msg = Message::from_vec(query_bytes).map_err(|_err| ForwardError::BadQuery)?;
        let client_id = request_msg.metadata.id;
        if self.dnssec_enabled() {
            ensure_dnssec_ok(&mut request_msg);
        }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo nextest run -E 'package(noadd)' dnssec`
Expected: PASS (all three).

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy --all-targets -- -D warnings
cargo fmt
git add src/upstream/forwarder.rs
git commit -S -m "feat(upstream): force DO bit on upstream queries (runtime toggle)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Wire the toggle — startup load + settings PUT

**Files:**
- Modify: `src/main.rs` (after forwarder creation / near the `upstream_strategy` load ~line 81)
- Modify: `src/admin/api.rs` (`put_settings` ~line 727, near the `upstream_strategy` apply ~line 743)

**Interfaces:**
- Consumes: `forwarder.set_dnssec_enabled(bool)` (Task 3); `db.get_setting`, `state.forwarder`.

- [ ] **Step 1: Load the setting at startup** — in `main.rs`, after the forwarder is built and the strategy is loaded, add:

```rust
    if let Ok(Some(v)) = db.get_setting("dnssec_disabled").await {
        forwarder.set_dnssec_enabled(v.trim() != "true");
        tracing::info!(dnssec_disabled = %v, "loaded DNSSEC transparency setting");
    }
```

- [ ] **Step 2: Apply on settings save** — in `put_settings`, mirror the `upstream_strategy` block:

```rust
    if let Some(v) = body.settings.get("dnssec_disabled") {
        state.forwarder.set_dnssec_enabled(v.trim() != "true");
    }
```

- [ ] **Step 3: Build + clippy**

Run: `cargo build && cargo clippy --all-targets -- -D warnings`
Expected: clean build, no warnings.

- [ ] **Step 4: Manual smoke test** — run locally and toggle:

```bash
RUST_LOG=noadd=info cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:3000
```

In another shell:
```bash
# default: enabled → forced DO → 1.1.1.1 sets AD for a signed name
dig @127.0.0.1 -p 5353 cloudflare.com +dnssec | grep -E 'flags:.*ad|^cloudflare'
# disable and confirm AD no longer forced
curl -s -X PUT 127.0.0.1:3000/api/settings -H 'content-type: application/json' -d '{"dnssec_disabled":"true"}'
```
Expected: with default settings the response header shows the `ad` flag for a signed domain; after disabling, a non-DO client query no longer gets `ad`.

- [ ] **Step 5: commit**

```bash
git add src/main.rs src/admin/api.rs
git commit -S -m "feat: wire DNSSEC transparency toggle (startup + settings)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Admin UI — query-log glyph status + DNSSEC badge + mobile client

**Files:**
- Modify: `admin-ui/dist/index.html` (CSS badges ~line 360; desktop log table header + `#log-body` row template ~line 3279; mobile `#log-cards` template ~line 3298)

**Interfaces:**
- Consumes: `l.authenticated_data` (bool) on each log row JSON (Task 1).

- [ ] **Step 1: Add CSS** — after `.badge-off { … }` (~line 363) add:

```css
.badge-dnssec { color: var(--accent); text-shadow: var(--glow); }
.st { font-size: 0.98rem; font-weight: 700; line-height: 1; display: inline-block; width: 1em; text-align: center; }
.st-ok { color: var(--green); text-shadow: var(--glow); }
.st-block { color: var(--red); text-shadow: var(--glow-red); }
```

- [ ] **Step 2: Reorder the desktop table header** — move the `status` column header to between `time` and `domain`. In the logs `<thead>` row, place `<th>Status</th>` (centered) right after the time header and remove its old position. (Keep all other headers; column count unchanged.)

- [ ] **Step 3: Update the desktop row template** (`#log-body` map, ~line 3279). Replace the row so status is a glyph right after time, and the dnssec badge is appended in the domain cell:

```js
body.innerHTML = logs.map(l => `<tr>
  <td>${timeAgo(l.timestamp)}</td>
  <td style="text-align:center"><span class="st ${l.blocked ? 'st-block' : 'st-ok'}" title="${l.blocked ? 'blocked' : 'allowed'}">${l.blocked ? '✖' : '✔'}</span></td>
  <td><div style="display:flex;align-items:center;gap:6px;max-width:300px"><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;color:var(--text-primary)" title="${esc(l.domain)}">${esc(l.domain)}</span>${l.authenticated_data ? '<span class="badge badge-dnssec" style="flex:0 0 auto">dnssec</span>' : ''}</div>${l.result ? '<div class="mono" style="font-size:0.85rem;color:var(--text-dim);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(l.result) + '">→ ' + esc(l.result) + '</div>' : ''}</td>
  <td class="mono">${esc(l.query_type)}</td>
  <td class="mono">${esc(l.client_ip)}${l.doh_token ? '<br><span style="color:var(--accent);font-size:0.85rem">' + esc(l.doh_token) + '</span>' : ''}</td>
  <td><button class="btn btn-sm log-action ${l.blocked ? 'btn-allow' : 'btn-danger'}" data-domain="${esc(l.domain)}" data-blocked="${l.blocked}">${l.blocked ? 'Allow' : 'Block'}</button></td>
  <td>${l.cached ? '<span class="badge badge-cached">cached</span>' : l.upstream ? '<span class="mono" style="font-size:0.9rem">' + esc(l.upstream) + '</span>' : '<span style="color:var(--text-dim)">-</span>'}</td>
  <td class="mono">${l.response_ms}</td>
</tr>`).join('');
```

(The empty-state `colspan` stays at the existing total column count — unchanged.)

- [ ] **Step 4: Update the mobile card template** (`#log-cards` map, ~line 3298): status→glyph, dnssec badge after domain, client into row2:

```js
cards.innerHTML = logs.map(l => `<div class="log-card">
  <div class="log-card-row1">
    <span class="st ${l.blocked ? 'st-block' : 'st-ok'}" title="${l.blocked ? 'blocked' : 'allowed'}" style="flex:0 0 auto">${l.blocked ? '✖' : '✔'}</span>
    <span class="log-card-domain" title="${esc(l.domain)}">${esc(l.domain)}</span>
    ${l.authenticated_data ? '<span class="badge badge-dnssec" style="flex:0 0 auto">dnssec</span>' : ''}
    <button class="btn btn-sm log-action ${l.blocked ? 'btn-allow' : 'btn-danger'}" data-domain="${esc(l.domain)}" data-blocked="${l.blocked}" style="flex-shrink:0">${l.blocked ? 'Allow' : 'Block'}</button>
  </div>
  ${l.result ? '<div class="mono" style="font-size:0.85rem;color:var(--text-dim);margin-bottom:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(l.result) + '">→ ' + esc(l.result) + '</div>' : ''}
  <div class="log-card-row2">
    <span class="lc-time">${timeAgo(l.timestamp)}</span>
    <span class="lc-type">${esc(l.query_type)}</span>
    <span class="lc-client" style="color:var(--text-secondary)">${esc(l.client_ip)}</span>
    ${l.cached ? '<span class="lc-cached">cached</span>' : l.upstream ? '<span class="lc-up">' + esc(l.upstream) + '</span>' : ''}
    ${l.doh_token ? '<span class="lc-token">' + esc(l.doh_token) + '</span>' : ''}
    <span class="lc-ms">${l.response_ms}ms</span>
  </div>
</div>`).join('');
```

- [ ] **Step 5: Rebuild and eyeball**

Run: `cargo build` then `RUST_LOG=noadd=info cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:3000`, open `http://127.0.0.1:3000`, generate a few queries (incl. a signed domain like `cloudflare.com`), confirm: ✔/✖ glyph in status, `dnssec` badge after authenticated domains, long domains truncate with badge+button pinned, mobile shows client in row2.
Expected: matches the approved companion mockup.

- [ ] **Step 6: commit**

```bash
git add admin-ui/dist/index.html
git commit -S -m "feat(ui): glyph status + DNSSEC badge in query log

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Admin UI — settings toggle + setup guidance (closes Task #1)

**Files:**
- Modify: `admin-ui/dist/index.html` (settings form markup near the DoH-policy block ~line 3705; load binding ~line 3788; instant-apply handlers ~line 3759)

**Interfaces:**
- Consumes: `/api/settings` GET returns `dnssec_disabled` (string); PUT accepts `{ dnssec_disabled: "true"|"false" }` (applied by Task 4).

- [ ] **Step 1: Add the control + help text** — insert a settings block (place it near the upstream settings, since it concerns upstream behaviour):

```html
        <div class="card-title" style="margin-top:16px">DNSSEC</div>
        <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:12px">
          Surfaces the upstream's DNSSEC verdict (AD flag) per query in the log. This is transparency, not local validation — for end-to-end trustworthy results: use a validating upstream (1.1.1.1 / 9.9.9.9), set the upstream to <code style="color:var(--accent);font-size:0.8rem">tls://…</code> so the verdict reaches noadd untampered, and point devices at noadd's DoH endpoint.
        </p>
        <div class="input-row">
          <label style="min-width:140px;color:var(--text-secondary);font-size:0.85rem">DNSSEC status</label>
          <select id="s-dnssec">
            <option value="on">On (surface AD)</option>
            <option value="off">Off</option>
          </select>
        </div>
```

- [ ] **Step 2: Bind on load** — in the settings `load()` where other fields are set from `s` (~line 3788), add:

```js
      this.querySelector('#s-dnssec').value = (s.dnssec_disabled === 'true') ? 'off' : 'on';
```

- [ ] **Step 3: Instant-apply on change** — near the other `onchange` handlers (~line 3759), add:

```js
    this.querySelector('#s-dnssec').onchange = async (e) => {
      await api.put('/api/settings', { dnssec_disabled: e.target.value === 'off' ? 'true' : 'false' });
    };
```

- [ ] **Step 4: Rebuild and verify the toggle**

Run: `cargo build`, run the app, open settings, flip DNSSEC off→on, confirm via `curl -s 127.0.0.1:3000/api/settings | jq .dnssec_disabled` that the value persists (`"true"`/`"false"`), and that the query log stops/starts showing `dnssec` badges accordingly for a signed domain.
Expected: toggle persists and changes behaviour without restart.

- [ ] **Step 5: Mark Task #1 complete + commit**

```bash
git add admin-ui/dist/index.html
git commit -S -m "feat(ui): DNSSEC toggle + setup guidance in settings

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

(Then mark tracked task #1 "Admin UI: explain how to get full DNSSEC protection" as completed.)

---

### Task 7: Docs + screenshots

**Files:**
- Modify: `README.md`, `ARCHITECTURE.md`
- Regenerate: `docs/screenshots/*` (logs + settings pages changed)

- [ ] **Step 1: README** — add DNSSEC transparency to the feature list: one or two lines noting noadd forces DO and surfaces the upstream AD verdict in the query log (default on, toggle in Settings), and that full hop-by-hop protection needs a `tls://` upstream + DoH to devices. Match existing README phrasing.

- [ ] **Step 2: ARCHITECTURE** — in the query-path / upstream section, add that when DNSSEC transparency is enabled the forwarder upserts an EDNS OPT with DO (bufsize 1232) before forwarding, and the handler reads the AD bit (`response_bytes[3] & 0x20`) into `query_logs.authenticated_data`. Note it is not local validation.

- [ ] **Step 3: Regenerate screenshots**

Run:
```bash
cargo build
cd e2e && npm ci && npx playwright install chromium && npm run screenshots
```
Expected: updated PNGs for the logs and settings pages.

- [ ] **Step 4: Final verification**

Run: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo nextest run`
Expected: all pass.

- [ ] **Step 5: commit**

```bash
git add README.md ARCHITECTURE.md docs/screenshots
git commit -S -m "docs: document DNSSEC transparency + refresh screenshots

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review Notes

- **Spec coverage:** force DO (Task 3) ✓; bufsize 1232 (Task 3 const) ✓; OPT upsert no-duplicate (Task 3 test) ✓; cheap AD read (Task 2) ✓; `authenticated_data` column + migration (Task 1) ✓; three AD-source paths (Task 2: blocked/rate-limited false, cache-hit preserves byte 3, miss from upstream) ✓; reverse `dnssec_disabled` default-on runtime toggle (Tasks 3/4/6) ✓; glyph status + dnssec badge + mobile client (Task 5) ✓; settings toggle + 3-segment guidance (Task 6, closes tracked Task #1) ✓; no scrubbing (not implemented — matches non-goal) ✓; no new deps ✓; docs + screenshots (Task 7) ✓.
- **Symbol:** heavy ✔/✖ per approved companion mockup.
- **No new dependencies** introduced anywhere.
