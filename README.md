# noadd

> A self-hosted DNS ad-blocker with DNS-over-HTTPS support, built in Rust.

[![CI](https://github.com/henry40408/noadd/actions/workflows/ci.yml/badge.svg)](https://github.com/henry40408/noadd/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/henry40408/noadd/graph/badge.svg)](https://codecov.io/gh/henry40408/noadd)
[![Release](https://img.shields.io/github/v/release/henry40408/noadd)](https://github.com/henry40408/noadd/releases/latest)
[![License](https://img.shields.io/github/license/henry40408/noadd)](LICENSE.txt)
[![Rust toolchain](https://img.shields.io/badge/dynamic/toml?url=https://raw.githubusercontent.com/henry40408/noadd/main/rust-toolchain.toml&query=$.toolchain.channel&label=rust%20toolchain&logo=rust)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue.svg)](https://ghcr.io/henry40408/noadd)
[![Casual Maintenance Intended](https://casuallymaintained.tech/badge.svg)](https://casuallymaintained.tech/)
[![Vibe Coded](https://img.shields.io/badge/vibe_coded-Claude-d97757?logo=anthropic&logoColor=white)](https://claude.com/claude-code)

Blocks ads and trackers at the DNS level using community-maintained filter lists. Ships as a single binary with an embedded web admin UI.

The admin UI is embedded in the binary — dark/light follows your OS preference, and the layout adapts to phones with a bottom tab bar.

![Dashboard — live stat cards, 24h query timeline, top domains, sources and upstreams (dark theme)](docs/screenshots/dashboard-dark.png)

![Statistics — 7d/30d/90d query trends, block & cache rate, weekday-by-hour activity heatmap, query type and outcome breakdowns, database health (dark theme)](docs/screenshots/statistics-dark.png)

![Query log — searchable DNS history with per-query outcome, latency and one-click Allow/Block (dark theme)](docs/screenshots/query-log-dark.png)

![Filters — filter list management with rule counts, custom allow/block rules and a live domain test (dark theme)](docs/screenshots/filters-dark.png)

<table>
  <tr>
    <td width="56%"><img src="docs/screenshots/statistics-light.png" alt="Statistics page in the light theme"></td>
    <td width="22%"><img src="docs/screenshots/dashboard-mobile.png" alt="Dashboard on a 375px phone viewport with bottom tab navigation"></td>
    <td width="22%"><img src="docs/screenshots/query-log-mobile.png" alt="Query log on mobile, rows rendered as cards"></td>
  </tr>
  <tr>
    <td align="center">Light theme</td>
    <td align="center" colspan="2">Mobile layout with bottom tab bar</td>
  </tr>
</table>

## Features

- **Plain DNS** (UDP + TCP, port 53) and **DNS-over-HTTPS** (RFC 8484)
- **Filter engine** with FST + flat trie — 390K rules in ~7 MB RAM (~19 bytes/rule), 50K+ QPS
- **Built-in filter lists** — AdGuard DNS, EasyList, Peter Lowe's, OISD Basic, Steven Black, URLhaus
- **Custom rules** — unified API with auto-detection of block/allow syntax
- **Domain test** — check if a domain is allowed or blocked with matched rule details
- **Configurable upstream DNS** — user-configurable at runtime (plain `ip:port`, DoT `tls://`, DoH `https://`), applied live on save with no restart; strategy (Sequential / Round Robin / Lowest Latency EMA) switchable independently
- **Configurable block response** — choose how blocked queries are answered: `0.0.0.0`/`::` (default), `NXDOMAIN`, `REFUSED`, or an operator-supplied custom IP for A/AAAA; runtime setting, applied live with no restart
- **Admin web UI** — dashboard with live stats, statistics page (7d/30d/90d trends, weekday×hour heatmap, query type & result breakdowns, DB health), query log with quick Allow/Block actions, filter management
- **Mobile-friendly** — responsive layout with bottom tab navigation and card-based views
- **DoH token auth** — restrict DoH access with user-defined URL tokens (`/dns-query/my-token`)
- **Apple mobileconfig** — generate iOS/macOS DNS profiles for DoH tokens
- **TLS support** — manual certificates or automatic Let's Encrypt via ACME
- **SQLite storage** — config, query logs, and stats in a single file
- **Hot-swap filters** — update lists without restarting, zero query interruption
- **DNSSEC transparency** — forces the DO (DNSSEC OK) bit on upstream queries, surfaces the upstream's Authenticated Data (AD) verdict as a badge in the query log, and tailors OPT/DNSSEC records to each client's original EDNS/DO profile (default on, toggle in Settings); full hop-by-hop protection requires a `tls://` upstream and DoH to devices
- **Low resident memory** — mimalloc allocator returns the filter-rebuild working set to the OS, keeping steady-state RSS low on small devices (e.g. Raspberry Pi)

## Out of Scope

noadd intentionally keeps a narrow focus. The following are **not** supported, and most are not currently planned:

- **Encrypted inbound DNS beyond DoH** — no DoT, DoQ, or DNSCrypt server. Clients connect over plain UDP/TCP or DoH. (DoT *is* supported for upstream forwarding via `tls://`.)
- **Local DNSSEC validation** — noadd surfaces the upstream's AD verdict (see Features) but does not verify signatures itself or return SERVFAIL on bogus answers. Trust is hop-by-hop.
- **Recursive resolution** — noadd is a forwarder, not a recursive resolver; it relies on configured upstreams rather than resolving from the root.
- **Per-client / per-device policies** — filtering and rules are global; there is no AdGuard-style per-client filtering.

## Quick Start

```bash
cargo build --release

# Start with default settings (DNS on 0.0.0.0:53, HTTP on 127.0.0.1:8080)
sudo ./target/release/noadd

# Or use custom ports (no root needed)
./target/release/noadd --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:8080
```

Open `http://127.0.0.1:8080` to create your operator account (username + password) and access the dashboard. Additional operators and active sessions are managed from the Account page.

### Docker

```bash
docker run -d \
  --name noadd \
  -p 53:53/udp -p 53:53/tcp -p 8080:8080 \
  -v noadd-data:/data \
  ghcr.io/henry40408/noadd
```

The container runs from `/data`, so the database is stored there as
`noadd.sqlite3`. Deployments created before this default carried a
`noadd.db` in the same volume; it is picked up automatically on upgrade
(rename it to `noadd.sqlite3` to silence the startup warning).

## Usage

```
noadd [OPTIONS]

Options:
      --db-path <DB_PATH>            SQLite database path [default: noadd.sqlite3] [env: NOADD_DB_PATH]
      --dns-addr <DNS_ADDR>          DNS listener (UDP + TCP) [default: 0.0.0.0:53] [env: NOADD_DNS_ADDR]
      --http-addr <HTTP_ADDR>        HTTP/DoH listener [default: 127.0.0.1:8080] [env: NOADD_HTTP_ADDR]
      --tls-cert <TLS_CERT>          TLS certificate file [env: NOADD_TLS_CERT]
      --tls-key <TLS_KEY>            TLS private key file [env: NOADD_TLS_KEY]
      --acme-domain <ACME_DOMAIN>    Let's Encrypt domain(s), comma-separated [env: NOADD_ACME_DOMAIN]
      --acme-email <ACME_EMAIL>      Let's Encrypt contact email [env: NOADD_ACME_EMAIL]
      --acme-cache <ACME_CACHE>      ACME certificate cache directory [default: acme-cache] [env: NOADD_ACME_CACHE]
      --acme-prod                    Use Let's Encrypt production (default: staging) [env: NOADD_ACME_PROD]
      --cookie-secure [<COOKIE_SECURE>]
                                     Set Secure on the admin session cookie [default: on when noadd
                                     terminates TLS] [env: NOADD_COOKIE_SECURE]
      --forward-auth-header <FORWARD_AUTH_HEADER>
                                     Reverse-proxy username header, e.g. Remote-User [env: NOADD_FORWARD_AUTH_HEADER]
      --forward-auth-trusted-proxies <FORWARD_AUTH_TRUSTED_PROXIES>
                                     CIDRs allowed to set the forward-auth header [env: NOADD_FORWARD_AUTH_TRUSTED_PROXIES]
  -h, --help                         Print help
```

## Testing DNS

```bash
# Plain DNS
dig @127.0.0.1 -p 5353 example.com A

# DNS-over-HTTPS (with token)
doggo example.com A @https://127.0.0.1:8080/dns-query/my-token

# Verify ad blocking
dig @127.0.0.1 -p 5353 ads.google.com A
# Expected: 0.0.0.0
```

## TLS Setup

### Manual certificates

```bash
mkcert -install
mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1

./target/release/noadd \
  --dns-addr 127.0.0.1:5353 \
  --http-addr 127.0.0.1:3443 \
  --tls-cert cert.pem \
  --tls-key key.pem
```

### Let's Encrypt (ACME)

```bash
./target/release/noadd \
  --http-addr 0.0.0.0:443 \
  --acme-domain dns.example.com \
  --acme-email you@example.com \
  --acme-prod
```

## Reverse proxy authentication

noadd can trust an operator identity set by a fronting proxy (Authelia,
Authentik, oauth2-proxy, ...) instead of its own login form. Set
`--forward-auth-header` to the injected header (e.g. `Remote-User`) **and**
`--forward-auth-trusted-proxies` to the proxy's CIDR — both required
together, and unlike `--trusted-proxies` above, loopback is **not** trusted
implicitly: a forged header grants full admin access. Unknown usernames are
auto-provisioned password-less; password login and API keys keep working.
The HTTP listener must not be reachable except through the proxy.

```bash
./target/release/noadd --forward-auth-header Remote-User \
  --forward-auth-trusted-proxies 172.18.0.0/16
```

Example nginx (Authelia-style):

```nginx
auth_request_set $user $upstream_http_remote_user;
proxy_set_header Remote-User $user;
```

### Paths to exclude from the proxy's authentication

Forward auth is meant to protect the admin UI and its `/api/*` data
endpoints, and the browser flow needs **no exceptions**: the proxy
authenticates the request before it reaches noadd, then noadd trusts the
injected `Remote-User` header. What *does* break is any client that cannot
complete an interactive SSO login — DNS resolvers, health probes, devices
fetching a config profile, API-key CLIs. Those endpoints authenticate
themselves and must be excluded from the proxy's auth (`policy: bypass`):

| Path | Used by | Note |
| --- | --- | --- |
| `/dns-query`, `/dns-query/{token}` | DoH resolvers | **Mandatory** — gating this breaks all DNS-over-HTTPS. Authenticated by URL token / the DoH access policy, never the admin session. |
| `/api/health` | Uptime / container health probes | No auth by design. |
| `/api/mobileconfig/{token}` | A device downloading the Apple config profile | Token-authenticated. |

Programmatic clients that authenticate with an API key
(`Authorization: Bearer …`) under `/api/*` also cannot do SSO — either
exclude those routes too, or configure the proxy to let requests carrying a
Bearer token through.

Example Authelia `access_control` (bypass the non-interactive endpoints,
require login for everything else):

```yaml
access_control:
  default_policy: two_factor
  rules:
    # noadd endpoints used by clients that can't complete an SSO login
    - domain: dns.example.com
      resources:
        - '^/dns-query(/.*)?$'
        - '^/api/health$'
        - '^/api/mobileconfig/.*$'
      policy: bypass
    # admin UI + the rest of /api/* stay behind login
    - domain: dns.example.com
      policy: two_factor
```

## Programmatic API

Most `/api/*` endpoints accept an **API key** in addition to the browser
session. Create one on the **Account** page (the full token is shown once — copy
it then). A key inherits its operator's permissions. Session-management
(`/api/sessions`, `/api/auth/logout`) and password-change (`/api/users/me/password`)
endpoints remain cookie-only by design, since they act on the browser session itself.

```bash
curl -H "Authorization: Bearer noadd_XXXXXXXX…" \
     https://noadd.example.com/api/rules
```

Interactive reference (OpenAPI / Scalar): open **`/api/docs`** on your instance;
the raw spec is at **`/api/openapi.json`**. Both require the same
authentication (session or API key) as the rest of the API.

## Development

```bash
# Run tests
cargo nextest run

# Check formatting + lints
cargo fmt --check
cargo clippy -- -D warnings

# Run in dev mode
RUST_LOG=noadd=debug cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:8080
```

### End-to-end tests

Browser-based BDD tests for the admin UI live in [`e2e/`](e2e/), built with
[playwright-bdd](https://github.com/vitalets/playwright-bdd). Playwright starts
the `noadd` binary itself (on throwaway ports and SQLite files), so build the
binary first:

```bash
cargo build                       # embeds the admin UI into the binary
cd e2e
npm ci
npx playwright install chromium
npm test                          # generates step bindings, then runs the suite
```

Gherkin features are in `e2e/features/`; step definitions in `e2e/steps/`. The
suite also runs in CI via the `e2e` job.

### Regenerating README screenshots

The images in `docs/screenshots/` are produced by a repeatable pipeline that
seeds a throwaway database with ~90 days of fake traffic, boots `noadd` on
throwaway ports, and re-captures every page with Playwright. Re-run it after
any admin-UI change and commit the updated PNGs:

```bash
cargo build                       # embeds the current admin UI into the binary
cd e2e
npm ci && npx playwright install chromium   # first time only
npm run screenshots
```

## License

MIT
