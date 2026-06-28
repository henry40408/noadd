# Configurable Upstream DNS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `upstream_servers` setting actually configure the resolver — loaded at startup and swapped at runtime with no restart — with a one-per-line textarea + consolidated Active-upstreams table in the admin UI.

**Architecture:** Group the forwarder's per-server state (`config` + `entries` + `latencies`) behind a single `ArcSwap<Upstreams>`; a new async `reconfigure(servers)` rebuilds the pools and swaps them in atomically (same pattern as the existing `strategy` ArcSwap). A pure `parse_upstreams` helper validates input. `main.rs` loads the setting at startup; `put_settings` validates + applies on save.

**Tech Stack:** Rust 2024, hickory-resolver `NameServerPool`, `arc_swap` (already a dep), axum admin API, vanilla-JS admin UI.

## Global Constraints

- Rust 2024; MSRV (`rust-version`) MUST NOT change. Tests via `cargo nextest run` (NOT `cargo test`). `cargo fmt` before commit; `cargo clippy --all-targets -- -D warnings` clean.
- All commits GPG-signed (`git commit -S`); stage files explicitly by name (never `git add -A`/`.`). Commit footer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- No new third-party dependencies.
- Setting key `upstream_servers`: one upstream per line, comma also tolerated; empty value is REJECTED; each entry must parse via `UpstreamSpec::parse`.
- Each `forward`-path method must read a single `ArcSwap` snapshot (`let up = self.upstreams.load();`) rather than per-field atomics across a reconfigure.
- Admin UI copy in English; reuse existing classes (`.badge`, `.st`/`.st-ok`/`.st-block`, `--accent`/`--orange`/`--green`/`--red`/`--glow`). Transport badge from prefix: `tls://`→`dot` (accent), `https://`→`doh` (accent), else `plain` (orange).
- After admin-UI appearance changes: `cargo build` then `cd e2e && npm run screenshots`, commit updated PNGs.

---

### Task 1: `parse_upstreams` helper

**Files:**
- Modify: `src/upstream/forwarder.rs` (add the free function near `UpstreamSpec`)
- Test: `src/upstream/forwarder.rs` `#[cfg(test)]`

**Interfaces:**
- Produces: `pub fn parse_upstreams(input: &str) -> Result<Vec<String>, String>` — splits on newlines and commas, trims, drops blanks, validates each via `UpstreamSpec::parse`; returns the cleaned server strings in order, or `Err` naming the first bad entry; empty/whitespace-only → `Err`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn parse_upstreams_accepts_newlines_and_commas() {
    let out = parse_upstreams("1.1.1.1:53\ntls://dns.mullvad.net:853, https://dns.quad9.net/dns-query").unwrap();
    assert_eq!(out, vec![
        "1.1.1.1:53".to_string(),
        "tls://dns.mullvad.net:853".to_string(),
        "https://dns.quad9.net/dns-query".to_string(),
    ]);
}

#[test]
fn parse_upstreams_rejects_empty() {
    assert!(parse_upstreams("").is_err());
    assert!(parse_upstreams("   \n  ").is_err());
}

#[test]
fn parse_upstreams_reports_bad_entry() {
    let err = parse_upstreams("1.1.1.1:53\nnot an address").unwrap_err();
    assert!(err.contains("not an address"), "error should name the bad entry: {err}");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -E 'package(noadd)' parse_upstreams`
Expected: FAIL — `parse_upstreams` not defined.

- [ ] **Step 3: Implement**

```rust
/// Parse textarea / CSV upstream input into validated server strings.
/// Splits on newlines and commas, trims, drops blanks, and validates each
/// entry via [`UpstreamSpec::parse`]. Returns the cleaned strings in order,
/// or an error naming the first offending entry. Empty input is an error —
/// a resolver with zero upstreams is non-functional.
pub fn parse_upstreams(input: &str) -> Result<Vec<String>, String> {
    let mut servers = Vec::new();
    for raw in input.split(['\n', ',']) {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        UpstreamSpec::parse(entry)?;
        servers.push(entry.to_string());
    }
    if servers.is_empty() {
        return Err("at least one upstream server is required".to_string());
    }
    Ok(servers)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -E 'package(noadd)' parse_upstreams`
Expected: PASS

- [ ] **Step 5: fmt + commit**

```bash
cargo fmt
git add src/upstream/forwarder.rs
git commit -S -m "feat(upstream): add parse_upstreams input validator

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Make the forwarder's server set swappable + `reconfigure`

**Files:**
- Modify: `src/upstream/forwarder.rs` (`UpstreamForwarder` struct ~line 211; `new` ~235; `server_order` ~380; `latency_ms_at` ~406; `update_latency` ~414; `latencies` ~439; `forward` ~458; `health_check` ~541; `probe_all` ~557)
- Test: `src/upstream/forwarder.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `parse_upstreams` (Task 1) — not directly, but the same module.
- Produces: `pub async fn reconfigure(&self, servers: Vec<String>)`; internal `struct Upstreams { config, entries, latencies }` behind `ArcSwap`; `async fn build_upstreams(config: UpstreamConfig) -> Upstreams`. Public method signatures of `forward`/`server_order`/`latencies`/`health_check`/`probe_all`/`update_latency`/`set_strategy`/`strategy`/`set_dnssec_enabled`/`dnssec_enabled` are UNCHANGED.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn reconfigure_swaps_server_set_and_preserves_modes() {
    let f = make_forwarder(UpstreamStrategy::RoundRobin).await; // 3x 10.0.0.x:53
    f.set_dnssec_enabled(false);
    assert_eq!(f.server_order().len(), 3);

    f.reconfigure(vec!["10.0.1.1:53".into(), "10.0.1.2:53".into()]).await;

    // new set is live: 2 servers, labels updated, latencies reset
    assert_eq!(f.server_order().len(), 2);
    let snap = f.latencies();
    assert!(snap.is_empty(), "latencies reset on reconfigure");
    f.update_latency(0, 5.0);
    assert!(f.latencies().contains_key("10.0.1.1:53"));
    // independent modes survive the swap
    assert_eq!(f.strategy(), UpstreamStrategy::RoundRobin);
    assert!(!f.dnssec_enabled());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -E 'package(noadd)' reconfigure_swaps_server_set`
Expected: FAIL — `reconfigure` not defined.

- [ ] **Step 3: Introduce `Upstreams` + extract `build_upstreams`.** Add the struct above `UpstreamForwarder`:

```rust
/// The reconfigurable upstream set. Swapped atomically by `reconfigure`.
/// `config.servers`, `entries`, and `latencies` are index-aligned.
struct Upstreams {
    config: UpstreamConfig,
    /// `None` for entries whose parse / DNS lookup failed at build time.
    entries: Vec<Option<UpstreamEntry>>,
    /// EMA latencies (ms), bit-packed into `AtomicU64`; `NO_LATENCY` until observed.
    latencies: Vec<AtomicU64>,
}
```

Move the body of the current `new()` that builds entries + latencies into:

```rust
/// Build the upstream pool set for `config` (concurrent host resolution +
/// one `NameServerPool` per server + a fresh latencies vec). Performs no
/// query I/O — connections are lazy.
async fn build_upstreams(config: UpstreamConfig) -> Upstreams {
    // <-- the existing new() logic from `let timeout = …` through building
    //     `entries` and `latencies` goes here verbatim, returning:
    Upstreams { config, entries, latencies }
}
```

- [ ] **Step 4: Change the struct + `new` + add `reconfigure`.**

```rust
pub struct UpstreamForwarder {
    upstreams: ArcSwap<Upstreams>,
    strategy: ArcSwap<UpstreamStrategy>,
    rr_counter: AtomicUsize,
    dnssec_enabled: AtomicBool,
}

impl UpstreamForwarder {
    pub async fn new(config: UpstreamConfig) -> Self {
        Self {
            upstreams: ArcSwap::from_pointee(build_upstreams(config).await),
            strategy: ArcSwap::from_pointee(UpstreamStrategy::default()),
            rr_counter: AtomicUsize::new(0),
            dnssec_enabled: AtomicBool::new(true),
        }
    }

    /// Atomically replace the upstream set with `servers`, with no restart and
    /// no query interruption. The current timeout is preserved. DNS-resolution
    /// failures for individual hosts are tolerated (logged, left unavailable),
    /// exactly as `new` handles them.
    pub async fn reconfigure(&self, servers: Vec<String>) {
        let timeout_ms = self.upstreams.load().config.timeout_ms;
        let next = build_upstreams(UpstreamConfig { servers, timeout_ms }).await;
        self.upstreams.store(std::sync::Arc::new(next));
    }
```

- [ ] **Step 5: Route every server-set method through a snapshot.** In each method below, add `let up = self.upstreams.load();` at the top and replace `self.entries`→`up.entries`, `self.config`→`up.config`, `self.latencies`→`up.latencies`. Apply to: `server_order`, `latency_ms_at`, `update_latency`, `latencies`, `forward`, `health_check`, `probe_all`. (`latency_ms_at`/`update_latency` take `idx` — load the snapshot, index into `up.latencies`.) Example — `forward` opening:

```rust
    pub async fn forward(&self, query_bytes: &[u8]) -> Result<(Vec<u8>, String), ForwardError> {
        let up = self.upstreams.load();
        let mut request_msg = Message::from_vec(query_bytes).map_err(|_err| ForwardError::BadQuery)?;
        let client_id = request_msg.metadata.id;
        if self.dnssec_enabled() {
            ensure_dnssec_ok(&mut request_msg);
        }
        // … unchanged, but every `self.entries[idx]` / `self.update_latency` →
        // `up.entries[idx]`; latency updates call the method (which re-loads)
        // OR write `up.latencies[idx]` directly. Keep `server_order()` as the
        // try-order source.
```

Note: `server_order()` calls `latency_ms_at` — keep that path; both now read `self.upstreams.load()` (a fresh cheap load each). `update_latency` re-loads its own snapshot; an update racing a reconfigure lands in the old (discarded) `Upstreams` harmlessly.

- [ ] **Step 6: Run the test + full forwarder tests**

Run: `cargo nextest run -E 'package(noadd)' upstream`
Expected: PASS (new reconfigure test + all existing forwarder tests: ordering, EMA, parse, dnssec).

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy --all-targets -- -D warnings
cargo fmt
git add src/upstream/forwarder.rs
git commit -S -m "feat(upstream): swap server set at runtime via ArcSwap + reconfigure

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Wire startup load + settings apply + GET allowlist

**Files:**
- Modify: `src/main.rs` (forwarder construction ~line 79, beside the `upstream_strategy` load ~81)
- Modify: `src/admin/api.rs` (`get_settings` keys allowlist ~line 702; `put_settings` ~727)
- Test: `tests/admin_api_test.rs`

**Interfaces:**
- Consumes: `parse_upstreams` (Task 1), `forwarder.reconfigure` (Task 2).

- [ ] **Step 1: Write the failing API test** (append to `tests/admin_api_test.rs`, mirroring `test_upstream_strategy_setting`):

```rust
#[tokio::test]
async fn test_upstream_servers_round_trip_and_validation() {
    let (app, _tmp) = setup().await;

    // valid → 200 and GET returns it
    let resp = app.clone().oneshot(
        Request::builder().method("PUT").uri("/api/settings")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"upstream_servers":"1.1.1.1:53\ntls://dns.mullvad.net:853"}"#)).unwrap()
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let get = app.clone().oneshot(
        Request::builder().uri("/api/settings").body(Body::empty()).unwrap()
    ).await.unwrap();
    let body = to_bytes(get.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["upstream_servers"].as_str().unwrap().contains("1.1.1.1:53"));

    // invalid → 400 and the setting is unchanged
    let bad = app.clone().oneshot(
        Request::builder().method("PUT").uri("/api/settings")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"upstream_servers":"not an address"}"#)).unwrap()
    ).await.unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}
```

(Match the exact `setup()`/auth/imports already used by neighbouring tests in the file.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run test_upstream_servers_round_trip_and_validation`
Expected: FAIL — `400` not returned / GET omits the key / not applied.

- [ ] **Step 3: `get_settings` allowlist** — add `"upstream_servers"` to the `keys` array in `get_settings` (`src/admin/api.rs`).

- [ ] **Step 4: `put_settings` validate-before-persist + apply.** At the TOP of `put_settings` (before the generic persist loop), add:

```rust
    // Validate upstream_servers before persisting anything — reject the whole
    // save on a bad entry so a broken value is never stored.
    let upstream_servers = match body.settings.get("upstream_servers") {
        Some(v) => Some(
            crate::upstream::forwarder::parse_upstreams(v)
                .map_err(|_e| StatusCode::BAD_REQUEST)?,
        ),
        None => None,
    };
```

Then after the generic persist loop and the existing `set_strategy` block, add:

```rust
    if let Some(servers) = upstream_servers {
        state.forwarder.reconfigure(servers).await;
    }
```

- [ ] **Step 5: Startup load** — in `src/main.rs`, replace the unconditional default with a DB-sourced config. Before `UpstreamForwarder::new`, add:

```rust
    let upstream_config = match db.get_setting("upstream_servers").await {
        Ok(Some(v)) if !v.trim().is_empty() => {
            match noadd::upstream::forwarder::parse_upstreams(&v) {
                Ok(servers) => UpstreamConfig { servers, ..UpstreamConfig::default() },
                Err(e) => {
                    tracing::warn!(error = %e, "invalid upstream_servers setting; using defaults");
                    UpstreamConfig::default()
                }
            }
        }
        _ => UpstreamConfig::default(),
    };
    let forwarder = Arc::new(UpstreamForwarder::new(upstream_config).await);
```

- [ ] **Step 6: Run the API test + build**

Run: `cargo nextest run test_upstream_servers_round_trip_and_validation && cargo build`
Expected: PASS + clean build.

- [ ] **Step 7: clippy + fmt + commit**

```bash
cargo clippy --all-targets -- -D warnings
cargo fmt
git add src/main.rs src/admin/api.rs tests/admin_api_test.rs
git commit -S -m "feat: load upstream_servers at startup and apply on settings save

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Admin UI — textarea + Save & apply + Active upstreams table (Option A)

**Files:**
- Modify: `admin-ui/dist/index.html` (Upstream DNS card ~line 3676; settings `load()` ~3785; global Save-Settings payload ~3724; health render ~3755)

**Interfaces:**
- Consumes: `GET /api/settings` → `upstream_servers`; `PUT /api/settings { upstream_servers }` (200/400); `GET /api/upstream/health` → `[{server, ok, latency_ms}]`.

- [ ] **Step 1: Replace the input with a textarea + Save & apply + Active upstreams container.** In the "Upstream DNS" card, swap the single `<input id="s-upstream">` block for:

```html
        <div class="card-title">Upstream DNS</div>
        <p style="color:var(--text-secondary);font-size:0.8rem;margin-bottom:6px">One server per line — <code style="color:var(--accent)">ip:port</code>, <code style="color:var(--accent)">tls://host</code> (DoT), or <code style="color:var(--accent)">https://host/dns-query</code> (DoH)</p>
        <textarea id="s-upstream" rows="4" style="width:100%;font-family:var(--font-mono);font-size:0.82rem" placeholder="1.1.1.1:53&#10;tls://dns.mullvad.net:853"></textarea>
        <div style="margin-top:8px;display:flex;align-items:center;gap:10px">
          <button class="btn btn-sm btn-primary" id="apply-upstream">${icons.refresh} Save &amp; apply</button>
          <span id="upstream-apply-msg" style="font-size:0.8rem"></span>
        </div>
        <div id="upstream-health" style="margin-top:14px"></div>
```

(Remove the old `#check-upstream` button; the table auto-loads. Keep the Strategy and DNSSEC blocks that follow.)

- [ ] **Step 2: Remove `upstream_servers` from the global Save-Settings payload** (~line 3724) so the dedicated Save & apply is the single path. Delete the `upstream_servers: this.querySelector('#s-upstream').value,` line from the `settings` object in the `#save-settings` handler.

- [ ] **Step 3: Add the Save & apply handler + the Active-upstreams renderer.** Near the other settings handlers, add:

```js
    const renderUpstreams = async () => {
      const el = this.querySelector('#upstream-health');
      try {
        const rows = await api.get('/api/upstream/health');
        const transport = s => s.startsWith('tls://') ? ['dot','var(--accent)'] : s.startsWith('https://') ? ['doh','var(--accent)'] : ['plain','var(--orange)'];
        el.innerHTML = `<div class="card-title" style="margin-bottom:6px">Active upstreams</div>
          <div class="table-wrap"><table><thead><tr><th>Server</th><th>Transport</th><th>Health</th><th>Latency</th></tr></thead><tbody>` +
          rows.map(r => { const [t,c] = transport(r.server); return `<tr>
            <td class="mono">${esc(r.server)}</td>
            <td><span class="badge" style="color:${c}">${t}</span></td>
            <td><span class="st ${r.ok ? 'st-ok' : 'st-block'}">${r.ok ? '✔' : '✖'}</span></td>
            <td class="mono">${r.ok ? r.latency_ms + 'ms' : '—'}</td></tr>`; }).join('') +
          `</tbody></table></div>`;
      } catch (e) { el.innerHTML = '<p style="color:var(--red)">Failed to load upstreams</p>'; }
    };

    this.querySelector('#apply-upstream').onclick = async () => {
      const msg = this.querySelector('#upstream-apply-msg');
      try {
        const res = await fetch('/api/settings', { method:'PUT', headers:{'content-type':'application/json'}, body: JSON.stringify({ upstream_servers: this.querySelector('#s-upstream').value }) });
        if (!res.ok) { msg.style.color = 'var(--red)'; msg.textContent = res.status === 400 ? 'Invalid upstream entry — not applied' : 'Failed to apply'; return; }
        msg.style.color = 'var(--accent)'; msg.textContent = '✔ applied';
        await renderUpstreams();
        setTimeout(() => { msg.textContent = ''; }, 2500);
      } catch (e) { msg.style.color = 'var(--red)'; msg.textContent = 'Failed to apply'; }
    };
```

(If the project's `api` helper has a `put` that throws on non-2xx without exposing the status, use the raw `fetch` shown above so the `400` is distinguishable.)

- [ ] **Step 4: Load the textarea value + render the table on open.** In `load()` where other fields are filled from `s` (~3785), add:

```js
      if (s.upstream_servers) this.querySelector('#s-upstream').value = s.upstream_servers.replace(/,\s*/g, '\n');
      renderUpstreams();
```

(`.st` glyph and `.badge` classes already exist from the DNSSEC work. Verify `renderUpstreams` is in scope where `load()` calls it — define it before `load()` runs, or attach to `this`.)

- [ ] **Step 5: Rebuild + eyeball**

Run: `cargo build`, run the app, open Settings: confirm the textarea shows current upstreams (one per line), Save & apply shows `✔ applied` for a valid set and an error for a bad line, and the Active upstreams table shows transport badges (plain/dot/doh) + health ✔/✖ + latency.
Expected: matches the approved Option A mockup.

- [ ] **Step 6: commit**

```bash
git add admin-ui/dist/index.html
git commit -S -m "feat(ui): editable upstreams textarea + Active upstreams table

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Docs + screenshots + final verification

**Files:**
- Modify: `README.md`, `ARCHITECTURE.md`
- Regenerate: `docs/screenshots/*` (settings page changed)

- [ ] **Step 1: README** — in Features, update the upstream line to note upstream servers are user-configurable at runtime (plain / DoT `tls://` / DoH `https://`), switchable without restart. Keep existing phrasing style.

- [ ] **Step 2: ARCHITECTURE** — in the upstream section, note `upstream_servers` is loaded at startup (`parse_upstreams`) and that `UpstreamForwarder` holds its server set behind `ArcSwap<Upstreams>`, swapped by `reconfigure` on settings save with no restart / no query interruption.

- [ ] **Step 3: Regenerate screenshots**

Run: `cargo build && cd e2e && npm ci && npx playwright install chromium && npm run screenshots`
Expected: updated settings-page PNG(s).

- [ ] **Step 4: Final verification**

Run: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo nextest run`
Expected: all pass.

- [ ] **Step 5: commit**

```bash
git add README.md ARCHITECTURE.md docs/screenshots
git commit -S -m "docs: document configurable upstream DNS + refresh screenshots

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review Notes

- **Spec coverage:** startup load (Task 3) ✓; runtime reconfigure via ArcSwap (Task 2) ✓; validate-before-persist atomic apply + 400 (Task 3) ✓; `get_settings` allowlist (Task 3) ✓; empty rejected / comma-tolerant parse (Task 1) ✓; textarea + Save&apply + Active-upstreams table with transport/health/latency (Task 4) ✓; EMA table consolidated away (Task 4 — table uses `/api/upstream/health`) ✓; docs + screenshots (Task 5) ✓.
- **No new dependencies**; `arc_swap` already present.
- **Type consistency:** `reconfigure(Vec<String>)`, `parse_upstreams(&str) -> Result<Vec<String>, String>`, `Upstreams { config, entries, latencies }` used consistently across Tasks 1–3.
