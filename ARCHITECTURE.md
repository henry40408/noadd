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
2. Filter engine checks the domain (allowlist > blocklist > filter lists)
3. If blocked: return `0.0.0.0` / `::` immediately
4. If allowed: check cache, then forward to upstream DNS if cache miss
5. Log query asynchronously via mpsc channel

Filter runs **before** cache so newly added block rules take effect immediately.

### DNSSEC Transparency

When DNSSEC transparency is enabled (the default, toggled via the `dnssec_disabled` runtime setting in the Settings page), the upstream forwarder upserts an EDNS OPT record with the DO (DNSSEC OK) bit set and a UDP payload size of 1232 before forwarding each query. The handler then reads the Authenticated Data (AD) bit from byte 3 of the upstream response (`response_bytes[3] & 0x20`) and stores it in `query_logs.authenticated_data`. This is **transparency, not local validation** — noadd does not verify DNSSEC signatures; the AD bit reflects the upstream resolver's verdict. Full hop-by-hop DNSSEC protection requires a `tls://` upstream and DoH to client devices. **Known limitation (v1):** NXDOMAIN and NODATA (empty-NOERROR) responses that hickory surfaces via `NoRecordsFound` are logged as `authenticated_data = false` even when the upstream validated the negative answer, because the `NoRecordsFound` struct in hickory 0.26 does not expose an authentic-data field.

### Negative Responses (NXDOMAIN / NODATA)

hickory reports an authoritative negative answer as a `NoRecordsFound` error rather than a `Message`, so the forwarder reconstructs the wire response in `build_negative_response` (`src/upstream/forwarder.rs`). It carries over the upstream's **authority section** — the SOA plus any DNSSEC NSEC/RRSIG records — so clients can negative-cache the answer per [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308); without the SOA, resolvers such as iOS/mDNSResponder fall back to a short default negative TTL and re-query the name on nearly every connection (costly for IPv4-only hosts whose AAAA/HTTPS lookups are always NODATA). An EDNS OPT is echoed only when the client's request carried one, per [RFC 6891 §6.1.1](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.1). The AD bit remains unset (see the DNSSEC limitation above).

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

### Async Query Logging

The DNS handler sends log events through a `tokio::sync::mpsc` channel. A dedicated task batches entries and flushes to SQLite (every 500 entries or every 1 second). This keeps the query path non-blocking.

### Schema Migrations

SQLite schema versioning uses `PRAGMA user_version`. Each migration checks the current version and applies changes incrementally. New databases get the latest schema directly from `CREATE TABLE` statements.

### Upstream DNS

`upstream_servers` is loaded from the database at startup and parsed via `parse_upstreams` (splits on newlines and commas, validates each entry). Accepted formats: `ip:port` (plain UDP/TCP), `tls://host[:port]` (DNS-over-TLS, default port 853), `https://host[:port][/path]` (DNS-over-HTTPS, default port 443 / path `/dns-query`).

`UpstreamForwarder` holds the live server set behind `ArcSwap<Upstreams>`. When settings are saved via the admin API, the validated server list is passed to `reconfigure(servers)`, which builds a fresh `Upstreams` (resolves hostnames, constructs `NameServerPool`s, resets EMA latencies) and atomically swaps it in — no restart, zero query interruption. In-flight queries hold an `Arc` to the old snapshot and complete normally; the old snapshot is dropped when the last in-flight query releases it. Strategy (`Sequential` / `Round Robin` / `Lowest Latency`) and DNSSEC-transparency mode are stored outside the swapped snapshot and survive `reconfigure` unchanged.

### DoH Token Auth

DoH access can be restricted with user-defined tokens. Each token becomes a URL path: `/dns-query/my-token`. The access policy (`allow`/`deny`) controls whether unauthenticated `/dns-query` is permitted. Tokens are always valid regardless of policy.

### Admin UI

A single `index.html` file using vanilla JS web components. No framework, no build step. Embedded in the binary at compile time via `include_dir`. Embedded assets are served with a content-hash `ETag` and `Cache-Control: no-cache`, so browsers revalidate on each load and receive `304 Not Modified` when nothing changed — reloads avoid re-transferring the ~146 KB page, while a rebuilt binary (new content, new ETag) updates clients immediately. The dashboard polls the API every 10 seconds with a toggleable LIVE mode. Login is username + password; sessions are bound to a user and individually revocable.

### API Authentication

Most `/api/*` endpoints accept either the browser `session` cookie or an `Authorization: Bearer <api key>` header; both paths are unified behind the `AuthedUser` axum extractor, so handlers don't need to distinguish how the caller authenticated. A few endpoints are cookie-only by design because they act on the browser session itself: session management (`GET /api/sessions`, `DELETE /api/sessions/{id}`, `POST /api/auth/logout`), changing your own password (`POST /api/users/me/password`), and the URL-token-authenticated `GET /api/mobileconfig/{token}`. API keys are BLAKE2b-hashed at rest (only the hash is stored) and are bound to an operator via `ON DELETE CASCADE`, inheriting that operator's permissions — a key is only as powerful as the account that minted it. Keys are managed via `GET/POST/DELETE /api/api-keys`, driven from the admin UI's Account page (the full token is shown once, on creation, and never again). An OpenAPI 3.1 spec is served at `GET /api/openapi.json`, with an interactive Scalar reference at `GET /api/docs`; both require an authenticated operator (session or API key) — they expose only the schema shape, never data, but this security appliance still minimizes pre-auth recon — and cover a core subset of endpoints.

## Data Storage

Everything is in a single SQLite file (`noadd.db` by default):

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
