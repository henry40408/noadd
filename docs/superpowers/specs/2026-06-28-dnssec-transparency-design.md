# DNSSEC Transparency — Force DO, Surface the AD Verdict

## Overview

noadd forwards DNS but does nothing with DNSSEC. This feature adds **transparency**, matching AdGuardHome's `enable_dnssec`: force the DNSSEC-OK (DO) bit on upstream queries so validating upstreams perform validation and report it, then read the Authenticated Data (AD) bit from the response and surface it per-query in the admin UI query log.

This is explicitly **not** local cryptographic validation. noadd does not verify RRSIG/DNSKEY/DS chains and does not return SERVFAIL on bogus answers. The AD marker means "the upstream reported this answer as DNSSEC-validated." Trust is hop-by-hop: it is only as trustworthy as the noadd↔upstream link (use a `tls://` upstream) and the upstream's own validation. Local validating-resolver work is out of scope and is **not** scheduled as a follow-up.

## Non-Goals

- No local DNSSEC validation (no RRSIG/DNSKEY/DS verification, no trust anchor, no SERVFAIL-on-bogus).
- No scrubbing of DNSSEC records (RRSIG/NSEC) for clients that did not set DO. Forced-DO responses may carry these records to such clients; accepted as a v1 tradeoff.
- No EDNS TCP Keepalive, no DoT/DoH changes.
- No CLI flag for the toggle (it is a runtime DB setting — see below).

## Known Limitations (v1)

- **Authenticated negative answers (NXDOMAIN/NODATA) are logged as `authenticated_data = false`.** hickory 0.26 surfaces both NXDOMAIN and empty-NOERROR (NODATA) through `NetError::Dns(DnsError::NoRecordsFound(NoRecords { … }))`. The `NoRecords` struct does not carry an authentic-data flag, so the reconstructed response message in `src/upstream/forwarder.rs` cannot set the AD bit even when the upstream validated the negative answer. NODATA is common (e.g. AAAA queries for IPv4-only hosts), meaning the AD column under-reports on these paths. Fixing this requires hickory to expose AD in `NoRecords`.

## Behaviour & Configuration

### Runtime toggle (mechanism: DB setting, switchable in admin UI)

A DB-backed setting controls the feature, switchable at runtime from the admin UI with no restart — consistent with `doh_access_policy` / `upstream_strategy`.

- **Setting key: `dnssec_disabled`** (reverse semantics). Absent or `"false"` ⇒ feature **enabled**; `"true"` ⇒ disabled. A fresh DB has no key ⇒ enabled by default. The stored value is only written when the operator deviates from the recommended (enabled) state.
- **Default: enabled** (transparency active out of the box; matches AdGuardHome).
- **Admin UI label is positive**, e.g. `DNSSEC status [ on ]` — "Surface the upstream's DNSSEC (AD) verdict in the query log." UI toggle ON ⇒ `dnssec_disabled = false`. The operator never sees the reverse-named internal value.

The forwarder reads the effective flag; when disabled it does not force DO and the AD column is simply whatever the response carried (typically absent).

## Architecture

The query path (`filter → cache → upstream forward`, async logging) is unchanged except at two points on the **upstream forward** path.

### ① Force DO on the upstream request — `src/upstream/forwarder.rs`

When the feature is enabled, before sending the request to the upstream, ensure the request message carries an EDNS(0) OPT record with the DO bit set:

- **Upsert, never duplicate.** If the client query already has an OPT record, set DO on it; if not, add one. Two OPT records ⇒ upstream FORMERR. Use hickory's EDNS API (`Message::extensions_mut()` / `Edns::set_dnssec_ok(true)` — confirm exact 0.26 API in pre-implementation verification).
- **Advertise UDP payload size 1232** on that OPT record (DNS-flag-day recommendation) to avoid IP fragmentation of the larger signed responses.
- The forwarder already relays a truncated (TC) upstream response to the client, which retries over TCP — so the larger DNSSEC responses are handled by the existing TC-relay path; no new truncation logic.

The forwarder needs access to the effective `dnssec_disabled` flag. Pass it in (e.g. an `AtomicBool`/`ArcSwap` shared with the handler/admin so the runtime toggle takes effect without restart), mirroring how `upstream_strategy` is already runtime-switchable on the forwarder.

### ② Read the AD bit — `src/dns/handler.rs`

The AD flag is bit 5 of byte 3 of the DNS header. Read it directly from the served response bytes — **no message parse**:

```rust
fn response_authenticated(bytes: &[u8]) -> bool {
    bytes.get(3).is_some_and(|b| b & 0x20 != 0)
}
```

This is O(1), unlike the existing `log_query_results` full-parse, so it is **always populated** when the column exists — not gated behind a flag. It is read from the final `response_bytes` in `handle()`, which is correct for every path:

- **blocked** — locally synthesised (`build_blocked_response`); AD bit is 0 ⇒ `false`. No marker.
- **rate-limited / SERVFAIL** — AD 0 ⇒ `false`.
- **cache hit** — `prepare_cached_response` overwrites only bytes[0..2] (the ID); byte 3 (AD) is preserved, so the bit reflects the response as originally fetched (with DO forced).
- **cache miss → forward** — re-encoded upstream response preserves the AD header bit.

Add `authenticated_data: bool` to `QueryContext` and populate it from `response_authenticated(&response_bytes)`.

### Storage — `src/db.rs`, `src/logger.rs`

- New `query_logs` column `authenticated_data INTEGER NOT NULL DEFAULT 0` via an incremental `PRAGMA user_version` migration; new DBs get it in the latest schema.
- `insert_query_logs` writes the new field; the logger batch carries it through.
- The log-read query (`query_logs`) selects and returns it so the admin API/UI can show it.

## Admin UI

Two surfaces change. **This alters the query-log appearance and the settings page → regenerate `docs/screenshots/` (`cd e2e && npm run screenshots`) and commit the PNGs.**

### Query-log status → glyph, plus the DNSSEC marker

The query-log status indicator changes from a text badge to a compact glyph, on **both** desktop and mobile (decided via the visual companion):

- **Status glyph:** `✔` (allowed, `--green` + glow) / `✖` (blocked, `--red` + glow-red), `title` attribute carrying the word for hover/long-press. Symbol set: **heavy ✔/✖** (selected in companion; alt-cross ✓/✕ is the fallback if it reads too strong).
- **Desktop column order:** `time | status(glyph) | domain | type | client | action | upstream | ms`. The status column **moves to between `time` and `domain`** (was a later badge column) and becomes the centered glyph.
- **DNSSEC marker:** a `badge badge-dnssec` (accent green + glow, uppercase `dnssec`) rendered **after the domain name**, shown only when `authenticated_data` is true.
  - Desktop: inside the domain cell as a flex row — domain name truncates with ellipsis, the badge is `flex:0` and stays pinned/visible. (`table-layout: fixed`, domain column takes remaining width.)
  - Mobile row1: `[status glyph] domain(flex:1, truncates) [dnssec badge (flex:0)] [Allow/Block]`.
- **Mobile row2 gains `client`:** `time · type · client · upstream · ms` (the client IP was previously omitted on mobile). `dnssec` stays in row1 after the domain, not in row2.
- New CSS: `.badge-dnssec { color: var(--accent); text-shadow: var(--glow); }` and the status-glyph classes; reuse existing `--green`/`--red`/`--glow`.

### Settings page — toggle + setup guidance (Task #1)

- A **positive-labelled toggle** bound to the `dnssec_disabled` setting (ON ⇒ `dnssec_disabled=false`), following the existing settings-form pattern (`/api/settings` get/set, like `doh_access_policy`).
- A **short, precise help text** beside it explaining how to get end-to-end-trustworthy DNSSEC results — framed as the 3-segment chain, honest about the boundary:
  1. **Validating upstream** (authoritative → upstream): use a validating resolver (1.1.1.1 / 9.9.9.9 both validate) — this is what produces the AD that noadd shows.
  2. **`tls://` upstream** (upstream → noadd): set the upstream to `tls://…` (DoT) instead of plain `1.1.1.1`, so the validated result reaches noadd untampered and the AD is trustworthy.
  3. **DoH to devices** (noadd → device): point devices at noadd's DoH endpoint so that hop is TLS-protected too.
  - State the boundary: this is hop-by-hop trust + transparency (noadd surfaces the upstream's AD verdict), **not** local cryptographic validation.
  - Keep copy tight; match existing admin-ui help-text style.

## Error Handling / Failure Modes

- **Larger responses / more TCP fallback** for signed zones — handled by the existing TC-relay path; cost is extra latency/load, not failure. Mitigated by advertising bufsize 1232 (avoids fragmentation).
- **DO-conditional-validating upstreams** could newly SERVFAIL DNSSEC-misconfigured domains once DO is forced. The common upstreams (1.1.1.1/9.9.9.9/Mullvad) validate regardless of DO, so they introduce no new failures. The toggle is the safety valve: disable in the admin UI (no restart) if a specific upstream misbehaves.
- **Non-EDNS clients** receive responses carrying OPT/DNSSEC records they did not request (no scrubbing in v1) — harmless for modern clients, strictly non-conformant; documented.
- **Malformed OPT (double OPT)** must be avoided via upsert — covered by tests.

## Testing

`cargo nextest run`.

- **forwarder:** with feature enabled, the outgoing request has DO set and bufsize 1232; with an existing client OPT, DO is set on it and there is exactly one OPT (no duplicate); with feature disabled, DO is not forced.
- **AD read:** `response_authenticated` returns true/false for header bytes with/without the 0x20 bit; boundary (short buffers) returns false.
- **handler:** `QueryContext.authenticated_data` is false for blocked/rate-limited, reflects the cached bytes on a cache hit, and reflects the upstream response on a miss.
- **db/logger:** migration adds the column; `insert_query_logs` persists it; the log-read query returns it.
- **toggle:** flipping `dnssec_disabled` at runtime changes whether DO is forced.

## Documentation

- `README.md`: note the DNSSEC transparency feature, the default-on toggle, and a one-line pointer to the in-UI guidance on getting full (hop-by-hop) protection.
- `ARCHITECTURE.md`: in the query-path section, note DO is forced on the upstream forward (when enabled) and the AD bit is surfaced into `query_logs`.

## Pre-Implementation Verification

- hickory 0.26: exact API to **upsert** EDNS on a `Message` and set DO + max UDP payload (`extensions_mut`, `Edns::set_dnssec_ok`, payload-size setter), and where in `forward()` to apply it before `pool.send()`.
- Confirm the AD bit is byte 3 / mask `0x20` against a hickory-encoded response that has `authentic_data` set (cross-check by building a `Message` with AD and encoding).
- Existing admin settings-form pattern for a boolean toggle (how `doh_access_policy` is read/written through `/api/settings`) to mirror for the `dnssec_disabled` toggle.
