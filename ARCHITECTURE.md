# Architecture

## Overview

noadd is a single-binary DNS ad-blocker. All components run in one async tokio runtime.

```
                    ┌──────────────────────────────────────────┐
                    │                 noadd                     │
                    │                                          │
Clients ──────────► │  UDP/TCP Listener ──┐                    │
                    │                     ├──► DNS Handler     │
DoH Clients ──────► │  DoH (axum) ────────┘       │            │
                    │                         ┌───┴───┐        │
                    │                         │Filter │        │
                    │                         │Engine │        │
                    │                         └───┬───┘        │
                    │                     blocked │ allowed    │
                    │                       │     │            │
                    │                  0.0.0.0  Cache ──► Upstream
                    │                             │     Forwarder
                    │                         ┌───┴───┐        │
Browser ──────────► │  Admin API + Web UI     │Logger │        │
                    │                         └───┬───┘        │
                    │                          SQLite          │
                    └──────────────────────────────────────────┘
```

## Query Flow

1. DNS query arrives (UDP, TCP, or DoH)
2. Reject requests we don't implement — non-`Query` opcodes get NOTIMP, unsupported EDNS versions get BADVERS (see Unsupported Requests below)
3. Filter engine checks the domain (allowlist > blocklist > filter lists)
4. If blocked: synthesize a response per the configured block mode (see below)
5. If allowed: check cache, then forward to upstream DNS if cache miss
6. Log query asynchronously via mpsc channel
7. On the **UDP** path only, the reply is fit to the client's advertised buffer before it is sent (see UDP Truncation below)

Filter runs **before** cache so newly added block rules take effect immediately.

Every synthesized response — blocked, REFUSED, SERVFAIL, NXDOMAIN/NODATA, NOTIMP, BADVERS — copies the **RD (Recursion Desired)** bit from the client's query rather than assuming it was set, per RFC 1035 §4.1.1. RA (Recursion Available) is always advertised, since noadd is a forwarding resolver.

### Unsupported Requests

Before the filter, cache, or upstream are touched, `handle` (`src/dns/handler.rs`) rejects requests it cannot serve:

- **Non-`Query` opcodes** (STATUS/NOTIFY/UPDATE/…) → **NOTIMP** via `build_notimp_response`, which echoes the request's opcode, ID, and question. A forwarding resolver implements only standard queries.
- **Unsupported EDNS version** (OPT version > 0) → **BADVERS** via `build_badvers_response` (RFC 6891 §6.1.3). The extended RCODE 16 is split across the header and OPT — hickory does this automatically on encode when an OPT is present — and the OPT is emitted at version 0 to advertise the highest version supported.

Neither path is logged or rate-limited: both are rejected early and carry no domain to attribute.

### Block-Response Modes

When the filter engine blocks a query, `build_blocked_response` (`src/dns/handler.rs`) synthesizes the reply according to the runtime `block_mode` setting:

- **`null_ip`** (default, reproduces prior behavior) — `0.0.0.0` for A, `::` for AAAA, empty `NoError` for other query types.
- **`nxdomain`** — `NXDOMAIN` for every query type.
- **`refused`** — `REFUSED` for every query type.
- **`custom_ip`** — the operator-supplied `block_custom_ipv4` / `block_custom_ipv6` address for A / AAAA respectively; an empty `NoError` answer when the relevant address is unset, or for other query types.

`block_mode`, `block_custom_ipv4`, and `block_custom_ipv6` are runtime settings, validated and applied live via the settings API with no restart.

### DNSSEC Transparency

When DNSSEC transparency is enabled (the default, toggled via the `dnssec_disabled` runtime setting in the Settings page), the upstream forwarder clones the client request, then upserts an EDNS OPT record with the DO (DNSSEC OK) bit set and a UDP payload size of 1232 on the upstream-only copy. Before replying, it restores the original client's EDNS/DO profile: DNSSEC security records are removed unless the client set DO, the Authenticated Data (AD) bit is cleared for clients that did not request DNSSEC (RFC 6840 §5.7), and an OPT is returned if and only if the client sent one. The forwarder captures the upstream resolver's AD verdict from its response **before** this tailoring and returns it alongside the bytes; the handler stores it in `query_logs.authenticated_data` (and in the cache entry, so cache hits log the same verdict). Reading the verdict at the source rather than from the client-facing wire response is what lets the log surface the true upstream result even for non-DO clients whose AD bit was stripped. This is **transparency, not local validation** — noadd does not verify DNSSEC signatures; the AD bit reflects the upstream resolver's verdict. Full hop-by-hop DNSSEC protection requires a `tls://` upstream and DoH to client devices. **Known limitation (v1):** NXDOMAIN and NODATA (empty-NOERROR) responses that hickory surfaces via `NoRecordsFound` are logged as `authenticated_data = false` even when the upstream validated the negative answer, because the `NoRecordsFound` struct in hickory 0.26 does not expose an authentic-data field.

### Negative Responses (NXDOMAIN / NODATA)

hickory reports an authoritative negative answer as a `NoRecordsFound` error rather than a `Message`, so the forwarder reconstructs the wire response in `build_negative_response` (`src/upstream/forwarder.rs`). It carries over the upstream's **authority section** — the SOA plus any DNSSEC NSEC/RRSIG records — so clients can negative-cache the answer per [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308); without the SOA, resolvers such as iOS/mDNSResponder fall back to a short default negative TTL and re-query the name on nearly every connection (costly for IPv4-only hosts whose AAAA/HTTPS lookups are always NODATA). An EDNS OPT is echoed only when the client's request carried one, per [RFC 6891 §6.1.1](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.1). The AD bit remains unset (see the DNSSEC limitation above).

Because the DNS cache stores client-ready wire responses, its key includes the client's EDNS presence, DO bit, and CD bit plus the active upstream DNSSEC policy in addition to domain and query type. This prevents a response containing OPT/RRSIG/NSEC records from being reused for a client that did not advertise those capabilities (or the inverse), and keeps a late response from the previous policy generation isolated across a runtime toggle. Changing the runtime DNSSEC policy also invalidates the cache immediately.

### UDP Truncation

Because noadd forces a 1232-byte EDNS payload **upstream** (see DNSSEC Transparency), an upstream answer can be larger than what the client is willing to receive over UDP. Before the UDP listener sends a reply, `truncate_for_udp` (`src/dns/handler.rs`) fits it to the client's advertised buffer: the EDNS OPT payload size floored at 512 ([RFC 6891 §6.2.3](https://www.rfc-editor.org/rfc/rfc6891#section-6.2.3)), or 512 when the client sent no OPT ([RFC 1035 §4.2.1](https://www.rfc-editor.org/rfc/rfc1035)). This 512-byte case is the common one for Apple's mDNSResponder, which sends no EDNS OPT on ordinary lookups. When the reply exceeds that size, `Message::truncate` drops the answer/authority/additional sections (keeping the header, question, and any OPT) and sets the **TC (truncated)** bit, so the client retries the query over TCP and receives the full answer. Responses that already fit are returned untouched with no re-parse. This only runs on the UDP path — TCP has no 512-byte limit, and truncation is applied at send time (not cached), so the cache always holds the complete response.

## Source Layout

```
src/
├── main.rs              # Entry point, wires everything together
├── lib.rs               # Module declarations
├── config.rs            # CLI argument parsing (clap)
├── db.rs                # SQLite schema, migrations, all CRUD operations
├── cache.rs             # TTL-based DNS response cache (moka)
├── logger.rs            # Async query logger (mpsc → batch SQLite writes)
├── shutdown.rs          # Graceful shutdown signal handling
├── tls.rs               # TLS config loading (rustls)
├── dns/
│   ├── handler.rs       # Core query pipeline: filter → cache → forward
│   ├── udp.rs           # UDP listener (port 53)
│   ├── tcp.rs           # TCP listener (port 53, RFC 7766)
│   └── doh.rs           # DNS-over-HTTPS endpoints (RFC 8484)
├── filter/
│   ├── parser.rs        # Rule parsing (AdGuard/ABP, hosts, domain list)
│   ├── engine.rs        # FST + flat reverse-domain trie matching
│   └── lists.rs         # List download, storage, and filter rebuild
├── upstream/
│   ├── forwarder.rs     # UpstreamForwarder: transport, ArcSwap<Upstreams>, reconfigure
│   ├── strategy.rs      # UpstreamStrategy enum (Sequential / RoundRobin / LowestLatency)
│   └── mod.rs           # Module re-exports
└── admin/
    ├── api.rs           # REST API routes + static file serving
    ├── auth.rs          # Argon2 password hashing, sessions, rate limiting
    └── stats.rs         # Query statistics computation
```

## Key Design Decisions

### Filter Engine

Uses two data structures for domain matching:

- **FST (finite state transducer)** for exact domain lookups — compact sorted-set/map representation via the `fst` crate, sharing common prefixes and suffixes across domains.
- **Flat reverse-domain trie** for subdomain matching — domain `sub.ads.example.com` is stored as labels `["com", "example", "ads", "sub"]`. Walking the trie, if any node is a terminal, the domain is blocked. The trie is serialized into two contiguous byte buffers (node index + label pool) instead of heap-allocated tree nodes, reducing per-rule overhead to ~19 bytes.

The engine is behind `ArcSwap` for lock-free reads. Filter updates build a new engine and atomically swap it in.

`FilterEngine::new` partitions the rules first (exact vs subdomain), then builds the trie and the FST on separate threads via `std::thread::scope` — the two touch disjoint data and cost roughly the same on a large blocklist, so the rebuild pays for the slower one instead of their sum. The transient tree used to construct the trie hashes its labels with `FxHash` rather than the `std` default: its keys come from operator-configured blocklists (never from query traffic) and it is discarded before any query reaches the engine, so `SipHash`'s DoS resistance buys nothing at a million-plus hashes per rebuild.

### Async Query Logging

The DNS handler sends log events through a `tokio::sync::mpsc` channel. A dedicated task batches entries and flushes to SQLite (every 500 entries or every 1 second). This keeps the query path non-blocking.

The logger also fans each entry out to a `tokio::sync::broadcast` channel that backs the admin UI's live tail (`GET /api/logs/stream`, Server-Sent Events). The broadcast fires *before* the batch flush, so the tail is real-time, and is gated on `receiver_count()` so there is zero clone/allocation cost when nobody is watching. Slow SSE clients that lag past the buffer skip the missed entries rather than stalling the logger.

### Schema Migrations

SQLite schema versioning uses `PRAGMA user_version`. Each migration checks the current version and applies changes incrementally. New databases get the latest schema directly from `CREATE TABLE` statements.

### Upstream DNS

`upstream_servers` is loaded from the database at startup and parsed via `parse_upstreams` (splits on newlines and commas, validates each entry). Accepted formats: `ip:port` (plain UDP/TCP), `tls://host[:port]` (DNS-over-TLS, default port 853), `https://host[:port][/path]` (DNS-over-HTTPS, default port 443 / path `/dns-query`).

`UpstreamForwarder` holds the live server set behind `ArcSwap<Upstreams>`. When settings are saved via the admin API, the validated server list is passed to `reconfigure(servers)`, which builds a fresh `Upstreams` (resolves hostnames, constructs `NameServerPool`s, resets EMA latencies) and atomically swaps it in — no restart, zero query interruption. In-flight queries hold an `Arc` to the old snapshot and complete normally; the old snapshot is dropped when the last in-flight query releases it. Strategy (`Sequential` / `Round Robin` / `Lowest Latency`) and DNSSEC-transparency mode are stored outside the swapped snapshot and survive `reconfigure` unchanged.

### DoH Token Auth

DoH access can be restricted with user-defined tokens. Each token becomes a URL path: `/dns-query/my-token`. The access policy (`allow`/`deny`) controls whether unauthenticated `/dns-query` is permitted. Tokens are always valid regardless of policy.

### Admin UI

A single `index.html` file using vanilla JS web components. No framework, no build step. Embedded in the binary at compile time via `include_dir`. Embedded assets are served with a content-hash `ETag` and `Cache-Control: no-cache`, so browsers revalidate on each load and receive `304 Not Modified` when nothing changed — reloads avoid re-transferring the ~146 KB page, while a rebuilt binary (new content, new ETag) updates clients immediately. The dashboard polls the API every 10 seconds with a toggleable LIVE mode. Login is username + password; sessions are bound to a user and individually revocable.

The `session` cookie is `HttpOnly` and `SameSite=Lax`, which is what stands in for CSRF tokens here: `Lax` withholds the cookie from every cross-site `POST`/`PUT`/`DELETE`, and since all of this API's mutations use those methods and no `CorsLayer` is installed, a cross-origin caller can neither forge a state change nor read a response. The one thing `Lax` permits that `Strict` would not — a cross-site top-level `GET` navigation carrying the cookie — is harmless here because no `GET` handler writes, and the attacker cannot read the response of a navigation they have left. `Strict` therefore buys no additional protection over `Lax` for this API — the two differ only on that one case — so `Lax` is chosen as the weakest setting that is still load-bearing, and the cookie survives deep links followed from outside the site. `Secure` is resolved once at startup by `config::resolve_cookie_secure`: it follows whether noadd is terminating TLS itself (user-supplied certs or ACME), which is a runtime fact rather than a config string that can be wrong. Deployments where a reverse proxy terminates TLS see only plain HTTP and must opt in with `--cookie-secure`; it is not forced on by default because a browser silently discards a `Secure` cookie delivered over HTTP, which would lock those operators out with no visible error.

### API Authentication

Most `/api/*` endpoints accept either the browser `session` cookie or an `Authorization: Bearer <api key>` header; both paths are unified behind the `AuthedUser` axum extractor, so handlers don't need to distinguish how the caller authenticated. A few endpoints are cookie-only by design because they act on the browser session itself: session management (`GET /api/sessions`, `DELETE /api/sessions/{id}`, `POST /api/auth/logout`), changing your own password (`POST /api/users/me/password`), and the URL-token-authenticated `GET /api/mobileconfig/{token}`. API keys are BLAKE2b-hashed at rest (only the hash is stored) and are bound to an operator via `ON DELETE CASCADE`, inheriting that operator's permissions — a key is only as powerful as the account that minted it. Keys are managed via `GET/POST/DELETE /api/api-keys`, driven from the admin UI's Account page (the full token is shown once, on creation, and never again). An OpenAPI 3.1 spec is served at `GET /api/openapi.json`, with an interactive Scalar reference at `GET /api/docs`; both require an authenticated operator (session or API key) — they expose only the schema shape, never data, but this security appliance still minimizes pre-auth recon — and cover a core subset of endpoints.

`AuthedUser` tries a third path if the first two fail: a username header injected by a reverse proxy (`src/admin/forward_auth.rs`), honoured only when the TCP peer matches `--forward-auth-trusted-proxies` — a separate, non-loopback-trusting allow-list from `src/net.rs`'s `TrustedProxies`, since a forged forward-auth header (unlike a forged `X-Forwarded-For`) grants full admin access. A username seen for the first time is JIT-provisioned with a `NULL` `password_hash`, which makes password login for that account impossible by construction; the cookie-only endpoints above stay unavailable to a forward-auth identity since there is neither a session nor a password to act on.

## Data Storage

Everything is in a single SQLite file (`noadd.sqlite3` by default; a legacy `noadd.db` from an older release is used automatically when present):

| Table | Purpose |
|-------|---------|
| `settings` | Key-value config (upstream DNS, log retention, access policy) |
| `query_logs` | DNS query history with timestamps, domains, actions, cache hits, and upstream DNSSEC AD bit (`authenticated_data`) |
| `filter_lists` | Registered filter lists (name, URL, enabled, rule count) |
| `filter_list_content` | Raw downloaded list content |
| `custom_rules` | User-defined allow/block rules |
| `doh_tokens` | DoH access tokens |
| `users` | Operator accounts (username, Argon2 password hash) |
| `sessions` | Active admin sessions (token, user_id, ip, user agent, timestamps) |
| `api_keys` | Programmatic API keys (BLAKE2b hash, owning user_id, `ON DELETE CASCADE`) |

`query_logs` is indexed on `timestamp` and on the composite `(domain, timestamp)`. The composite index lets the dashboard's domain aggregations (top domains, unique domains) be served from a covering index with the time-window filter pushed in, instead of scanning the whole domain index.

### Retention & Maintenance

A background task runs hourly: it prunes query logs older than the configured retention window, then runs maintenance — `PRAGMA optimize` to keep planner statistics fresh, a truncating WAL checkpoint, and a `VACUUM` (only when freed pages exceed 20% of the file, since VACUUM rewrites the whole database under a write lock).

## Dependencies

Key crates:

| Crate | Role |
|-------|------|
| `tokio` | Async runtime |
| `axum` + `axum-server` | HTTP server (DoH + admin API + TLS) |
| `hickory-proto` | DNS wire format parsing |
| `tokio-rusqlite` | Async SQLite (dedicated thread) |
| `moka` | TTL-based cache |
| `fst` | Compact finite state transducer for exact-match filter sets |
| `arc-swap` | Lock-free atomic pointer swap |
| `argon2` | Password hashing |
| `rustls` | TLS |
