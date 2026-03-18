# noadd — DNS-over-HTTPS Adblock DNS Server

## Overview

A self-hosted DNS server written in Rust that blocks ads and trackers at the DNS level. Supports DNS-over-HTTPS (DoH) and plain DNS (UDP/TCP), with a web-based admin UI for configuration and monitoring.

**Target use case:** Personal/home deployment, single binary, minimal resource usage.

## Architecture

Single binary, all-in-one deployment. One async runtime (tokio) drives all subsystems.

```
┌─────────────────────────────────────────────┐
│                  noadd                       │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │ Plain DNS│  │   DoH    │  │ Admin API  │  │
│  │ (UDP 53) │  │ (HTTPS)  │  │ + Web UI   │  │
│  └────┬─────┘  └────┬─────┘  └─────┬─────┘  │
│       │              │              │         │
│       └──────┬───────┘              │         │
│              ▼                      │         │
│  ┌───────────────────┐              │         │
│  │   Filter Engine   │◄─────────────┘         │
│  │ (domain matching) │                        │
│  └────────┬──────────┘                        │
│           │ allowed                           │
│           ▼                                   │
│  ┌───────────────────┐                        │
│  │ Upstream Forwarder│                        │
│  │ (DoH/DoT/UDP)    │                        │
│  └───────────────────┘                        │
│                                              │
│  ┌───────────────────┐  ┌─────────────────┐  │
│  │    Query Logger    │  │    SQLite DB    │  │
│  │  (async channel)  │──▶│ (config+logs)  │  │
│  └───────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────┘
```

## Components

### 1. DNS Listeners

**Plain DNS (UDP 53):**
- `tokio::net::UdpSocket` listener
- `hickory-proto` for DNS packet parsing/serialization
- Each query spawns a tokio task

**DoH (RFC 8484):**
- axum routes: `GET /dns-query?dns={base64url}` and `POST /dns-query`
- Content-Type: `application/dns-message`
- Shares the same query handler as plain DNS

### 2. Filter Engine

**Data structures:**
- `HashMap<String, ()>` for exact domain matching
- Reverse domain trie for subdomain matching (e.g., `com → example → ads`)

**Supported rule formats:**
- AdGuard/ABP syntax: `||domain.com^`
- Hosts format: `0.0.0.0 domain.com` / `127.0.0.1 domain.com`
- Domain list: one domain per line
- Comments: lines starting with `#` or `!`

**Blocking response:**
- A records → `0.0.0.0`
- AAAA records → `::`
- Configurable via Admin UI (NXDOMAIN or custom IP)

**Custom rules (priority: allowlist > blocklist > list rules):**
- Allowlist: `@@||domain.com^` — force allow
- Blocklist: user-added block rules

**Hot-swap:** New filter structure built on update, atomically swapped via `ArcSwap`. Zero query interruption.

### 3. Upstream Forwarder

**Default upstreams (privacy-focused):**

| Upstream | Why |
|----------|-----|
| Cloudflare `1.1.1.1` | 24-hour log deletion, third-party audited |
| Quad9 `9.9.9.9` | Swiss non-profit, Swiss privacy law, no personal data logging, built-in malware blocking |
| Mullvad DNS `100.64.0.7` | Swedish, no-log policy, GDPR compliant |

**Supported upstream protocols:** UDP, DoH, DoT (configurable via Admin UI).

**Failover:** Primary upstream timeout (2s) triggers fallback to next upstream.

**Response cache:** In-memory TTL-based cache using `moka`.

### 4. Query Flow

```
Receive query → Parse DNS packet → Check cache
  → Cache hit → Return cached result
  → Cache miss → Filter Engine check
    → Blocked → Return 0.0.0.0/::
    → Allowed → Forward to upstream → Cache response → Return result
  → Async log query event
```

### 5. Query Logger & Statistics

**Async logging architecture:**
- Query handler sends log events via `tokio::sync::mpsc` channel
- Dedicated writer task batch-writes to SQLite (flush every 500 entries or every 1 second)
- Zero blocking on the query path

**Stored fields:**

| Field | Description |
|-------|-------------|
| timestamp | Query time |
| client_ip | Source IP |
| domain | Queried domain |
| query_type | A / AAAA / CNAME etc. |
| action | allowed / blocked |
| upstream | Upstream used (if forwarded) |
| response_time_ms | Response time |
| matched_rule | Matched rule (if blocked) |
| matched_list | Matched list name (if blocked) |

**Statistics (via Admin API):**
- Total queries / blocked / block ratio (today, 7 days, 30 days)
- Top queried domains (overall + blocked)
- Top clients
- Timeline data (hourly / daily aggregation)
- Upstream response time stats

**Retention:** Default 7 days, configurable via Admin UI. Background task prunes expired records.

### 6. Admin API (REST)

| Endpoint | Description |
|----------|-------------|
| `POST /api/auth/login` | Login |
| `GET /api/stats/summary` | Summary statistics |
| `GET /api/stats/timeline` | Timeline trend data |
| `GET /api/stats/top-domains` | Top queried/blocked domains |
| `GET /api/stats/top-clients` | Top clients |
| `GET /api/logs` | Query logs (paginated, filterable) |
| `GET /api/settings` | Get all settings |
| `PUT /api/settings` | Update settings |
| `GET /api/lists` | Get filter lists and status |
| `POST /api/lists` | Add custom list |
| `PUT /api/lists/:id` | Update list (enable/disable) |
| `DELETE /api/lists/:id` | Delete custom list |
| `POST /api/lists/update` | Trigger manual list update |
| `GET /api/rules/allowlist` | Get allowlist |
| `POST /api/rules/allowlist` | Add allowlist rule |
| `DELETE /api/rules/allowlist/:id` | Delete allowlist rule |
| `GET /api/rules/blocklist` | Get custom blocklist |
| `POST /api/rules/blocklist` | Add blocklist rule |
| `DELETE /api/rules/blocklist/:id` | Delete blocklist rule |

**Authentication:**
- First launch requires setting an admin password
- Session-based auth (cookie)
- Admin UI listens on `127.0.0.1` by default, configurable to LAN

### 7. Web UI

- Static SPA, embedded in binary at compile time via `include_dir`
- Pages: Dashboard (stats overview), Query Log, Filter Lists, Custom Rules, Settings
- Technology to be decided during implementation (using frontend-design skill)

### 8. TLS

- Optional built-in TLS termination via `rustls`
- Optional Let's Encrypt auto-certificate via `instant-acme`
- Can also run behind a reverse proxy (nginx, Caddy) without TLS

### 9. Adblock Lists (compiled-in defaults)

| List | Purpose |
|------|---------|
| AdGuard DNS Filter | Ads + tracking |
| EasyList | Ads |
| Peter Lowe's List | Ads + tracking |
| OISD (basic) | Comprehensive filtering |
| Steven Black's Unified Hosts | Ads + malware |
| URLhaus Malware Filter | Malicious URLs |

**Update mechanism:**
- Background scheduler pulls latest lists every 24 hours (configurable)
- Hot-swap via `ArcSwap` — zero downtime
- Manual trigger via Admin UI
- Enable/disable individual lists via Admin UI
- Add custom lists via Admin UI

## Dependencies

All crates use `default-features = false` unless noted, enabling only required features.

| Crate | Features | Purpose |
|-------|----------|---------|
| `tokio` | `rt-multi-thread`, `net`, `time`, `sync`, `macros`, `signal` | Async runtime |
| `axum` | default | HTTP server |
| `hickory-proto` | (no dnssec) | DNS packet parsing |
| `hickory-resolver` | `dns-over-https-rustls`, `dns-over-tls-rustls` | Upstream forwarding |
| `rusqlite` | `bundled` | SQLite |
| `moka` | `future` | Memory cache |
| `arc-swap` | default | Atomic filter swap |
| `rustls` | default | TLS |
| `instant-acme` | default | Let's Encrypt |
| `reqwest` | `rustls-tls`, `gzip` | HTTP client for list downloads |
| `serde` | `derive` | Serialization |
| `serde_json` | default | JSON |
| `tracing` | default | Structured logging |
| `tracing-subscriber` | default | Log output |
| `include_dir` | default | Embed frontend assets |
| `clap` | `derive` | CLI arguments |

## Project Structure

```
noadd/
├── Cargo.toml
├── build.rs              # Download/embed default adblock lists
├── src/
│   ├── main.rs           # Entry point, CLI args
│   ├── config.rs         # Settings management (read/write SQLite)
│   ├── db.rs             # SQLite schema and access layer
│   ├── dns/
│   │   ├── mod.rs
│   │   ├── handler.rs    # Query processing flow
│   │   ├── plain.rs      # UDP 53 listener
│   │   └── doh.rs        # DoH endpoint
│   ├── filter/
│   │   ├── mod.rs
│   │   ├── engine.rs     # Filter engine (trie + hashmap)
│   │   ├── parser.rs     # Rule parsing (adblock/hosts formats)
│   │   └── lists.rs      # List management and updates
│   ├── upstream/
│   │   ├── mod.rs
│   │   └── forwarder.rs  # Upstream forwarding + failover
│   ├── cache.rs          # DNS response cache
│   ├── logger.rs         # Async query logger
│   ├── admin/
│   │   ├── mod.rs
│   │   ├── api.rs        # REST API routes
│   │   ├── auth.rs       # Authentication
│   │   └── stats.rs      # Statistics queries
│   └── tls.rs            # TLS + ACME management
├── admin-ui/             # Frontend SPA source
│   └── ...
└── lists/                # Compile-time embedded default lists
    └── ...
```

## Storage

All configuration and logs stored in a single SQLite database file. Location configurable via CLI argument (`--db-path`), defaulting to `./noadd.db`.

## Non-Goals (for initial release)

- Recursive DNS resolution (forward-only)
- DNSSEC validation
- DNS-over-QUIC (DoQ)
- Multi-user / role-based access
- Clustering / high availability
