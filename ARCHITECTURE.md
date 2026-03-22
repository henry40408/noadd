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
│   ├── engine.rs        # HashMap + reverse domain trie matching
│   └── lists.rs         # List download, storage, and filter rebuild
├── upstream/
│   └── forwarder.rs     # UDP forwarding with failover
└── admin/
    ├── api.rs           # REST API routes + static file serving
    ├── auth.rs          # Argon2 password hashing, sessions, rate limiting
    └── stats.rs         # Query statistics computation
```

## Key Design Decisions

### Filter Engine

Uses two data structures for domain matching:

- **HashMap** for exact domain lookups (O(1))
- **Reverse domain trie** for subdomain matching — domain `sub.ads.example.com` is stored as labels `["com", "example", "ads", "sub"]`. Walking the trie, if any node is a terminal, the domain is blocked.

The engine is behind `ArcSwap` for lock-free reads. Filter updates build a new engine and atomically swap it in.

### Async Query Logging

The DNS handler sends log events through a `tokio::sync::mpsc` channel. A dedicated task batches entries and flushes to SQLite (every 500 entries or every 1 second). This keeps the query path non-blocking.

### Schema Migrations

SQLite schema versioning uses `PRAGMA user_version`. Each migration checks the current version and applies changes incrementally. New databases get the latest schema directly from `CREATE TABLE` statements.

### DoH Token Auth

DoH access can be restricted with user-defined tokens. Each token becomes a URL path: `/dns-query/my-token`. The access policy (`allow`/`deny`) controls whether unauthenticated `/dns-query` is permitted. Tokens are always valid regardless of policy.

### Admin UI

A single `index.html` file using vanilla JS web components. No framework, no build step. Embedded in the binary at compile time via `include_dir`. The dashboard polls the API every 10 seconds with a toggleable LIVE mode.

## Data Storage

Everything is in a single SQLite file (`noadd.db` by default):

| Table | Purpose |
|-------|---------|
| `settings` | Key-value config (upstream DNS, log retention, access policy, sessions) |
| `query_logs` | DNS query history with timestamps, domains, actions, cache hits |
| `filter_lists` | Registered filter lists (name, URL, enabled, rule count) |
| `filter_list_content` | Raw downloaded list content |
| `custom_rules` | User-defined allow/block rules |
| `doh_tokens` | DoH access tokens |

## Dependencies

Key crates:

| Crate | Role |
|-------|------|
| `tokio` | Async runtime |
| `axum` + `axum-server` | HTTP server (DoH + admin API + TLS) |
| `hickory-proto` | DNS wire format parsing |
| `tokio-rusqlite` | Async SQLite (dedicated thread) |
| `moka` | TTL-based cache |
| `arc-swap` | Lock-free atomic pointer swap |
| `argon2` | Password hashing |
| `rustls` | TLS |
