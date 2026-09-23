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

The admin UI follows your OS's dark/light preference and adapts to phones with a bottom tab bar. It is rendered on the server, so every page works with JavaScript disabled — signing in, settings, filters, the query log, operators and API keys. The charts and the log's live tail are the exceptions, and say so where they sit.

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
- **Filter lists** — AdGuard DNS filter enabled out of the box (AdAway seeded but off); add more from the AdGuard HostlistsRegistry browser or by URL; lists refresh daily
- **Custom rules** — unified API with auto-detection of block/allow syntax
- **Domain test** — check whether a domain is allowed or blocked, with the matching rule
- **Configurable upstream DNS** — plain `ip[:port]` (port 53 assumed), DoT `tls://`, DoH `https://`; applied live on save; strategy (Sequential / Round Robin / Lowest Latency EMA) switchable independently
- **Configurable block response** — `0.0.0.0`/`::` (default), `NXDOMAIN`, `REFUSED`, or a custom IP for A/AAAA; applied live
- **Admin web UI** — live dashboard, statistics (7d/30d/90d trends, weekday×hour heatmap, query type & outcome breakdowns, DB health), query log with one-click Allow/Block, filter management
- **Mobile-friendly** — responsive layout with bottom tab navigation and card-based views
- **DoH token auth** — restrict DoH access with user-defined URL tokens (`/dns-query/my-token`)
- **Apple mobileconfig** — generate iOS/macOS DNS profiles for DoH tokens
- **TLS support** — manual certificates or automatic Let's Encrypt via ACME
- **SQLite storage** — config, query logs, and stats in a single file
- **Hot-swap filters** — update lists without restarting, zero query interruption
- **DNSSEC transparency** — sets DO on upstream queries, shows the upstream's AD verdict as a badge in the query log, and tailors OPT/DNSSEC records to each client's own EDNS/DO profile (default on, toggle in Settings); hop-by-hop protection needs a `tls://` upstream and DoH to devices
- **Low resident memory** — mimalloc returns the filter-rebuild working set to the OS, keeping RSS low on small devices (e.g. Raspberry Pi)

## Out of Scope

noadd intentionally keeps a narrow focus. The following are **not** supported, and most are not currently planned:

- **Encrypted inbound DNS beyond DoH** — no DoT, DoQ, or DNSCrypt server. Clients connect over plain UDP/TCP or DoH. (DoT *is* supported for upstream forwarding via `tls://`.)
- **Local DNSSEC validation** — noadd surfaces the upstream's AD verdict (see Features) but does not verify signatures itself or return SERVFAIL on bogus answers. Trust is hop-by-hop.
- **Recursive resolution** — noadd is a forwarder, not a recursive resolver; it relies on configured upstreams rather than resolving from the root.
- **Per-client / per-device policies** — filtering and rules are global; there is no AdGuard-style per-client filtering.
- **Built-in MFA / passkeys** — the admin login is a password only. Put a proxy that does MFA in front and point noadd at it with `--forward-auth-header`; see [Multi-factor authentication](#multi-factor-authentication).
- **A separate listen address for the admin UI** — one HTTP listener serves both DoH and the admin UI. Restricting one without the other is a routing rule on the reverse proxy that publishes noadd; see [Publishing DoH without publishing the admin UI](#publishing-doh-without-publishing-the-admin-ui).

## Quick Start

```bash
cargo build --release

# Start with default settings (DNS on 0.0.0.0:53, HTTP on 127.0.0.1:8080)
sudo ./target/release/noadd

# Or use custom ports (no root needed)
./target/release/noadd --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:8080
```

Open `http://127.0.0.1:8080` to create your operator account (username + password). Passwords must be 12–128 characters and pass a [zxcvbn](https://github.com/shssoichiro/zxcvbn-rs) guessability check — noadd has no second factor, so the password is the whole defence. Common passwords, keyboard runs and anything built from your username are refused with the reason; a few unrelated words clears the bar easily. The check runs offline. Further operators and active sessions are managed on the Account page.

### Docker

```bash
docker run -d \
  --name noadd \
  -p 53:53/udp -p 53:53/tcp -p 8080:8080 \
  -v noadd-data:/data \
  ghcr.io/henry40408/noadd
```

The container runs from `/data`, so the database is `/data/noadd.sqlite3`. A
legacy `noadd.db` from older releases is picked up automatically (rename it to
`noadd.sqlite3` to silence the startup warning).

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
      --hsts [<HSTS>]                Send Strict-Transport-Security [default: on when noadd
                                     terminates TLS] [env: NOADD_HSTS]
      --hsts-max-age <HSTS_MAX_AGE>  max-age in seconds for Strict-Transport-Security
                                     [default: 31536000] [env: NOADD_HSTS_MAX_AGE]
      --log-format <LOG_FORMAT>      Diagnostic log format: full, compact, pretty, json
                                     [default: full] [env: LOG_FORMAT]
      --max-inflight-queries <MAX_INFLIGHT_QUERIES>
                                     Max concurrent in-flight DNS queries across UDP/TCP/DoH; 0
                                     disables [default: 2048] [env: NOADD_MAX_INFLIGHT_QUERIES]
      --rate-limit-qps <RATE_LIMIT_QPS>
                                     Per-client-IP steady-state query rate (queries/sec); 0 disables
                                     [default: 100] [env: NOADD_RATE_LIMIT_QPS]
      --rate-limit-burst <RATE_LIMIT_BURST>
                                     Per-client-IP burst allowance [default: 200]
                                     [env: NOADD_RATE_LIMIT_BURST]
      --log-query-results            Record the answer in the query log's result column, at the cost
                                     of an extra DNS-message parse per query
                                     [env: NOADD_LOG_QUERY_RESULTS]
      --trusted-proxies <TRUSTED_PROXIES>
                                     CIDRs of reverse-proxy hops permitted to set X-Forwarded-For /
                                     X-Real-IP [env: NOADD_TRUSTED_PROXIES]
      --forward-auth-header <FORWARD_AUTH_HEADER>
                                     Reverse-proxy username header, e.g. Remote-User [env: NOADD_FORWARD_AUTH_HEADER]
      --forward-auth-trusted-proxies <FORWARD_AUTH_TRUSTED_PROXIES>
                                     CIDRs allowed to set the forward-auth header [env: NOADD_FORWARD_AUTH_TRUSTED_PROXIES]
      --forward-auth-logout-url <FORWARD_AUTH_LOGOUT_URL>
                                     Proxy/SSO logout URL to send the browser to on logout [env: NOADD_FORWARD_AUTH_LOGOUT_URL]
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

### HSTS

When noadd terminates TLS itself (`--tls-cert`/`--tls-key` or `--acme-domain`),
it sends `Strict-Transport-Security` by default. `--hsts` / `NOADD_HSTS` lets a
reverse-proxy deployment opt in (or a self-terminated one opt out with
`--hsts=false`); `--hsts-max-age` sets `max-age`.

**Warning:** HSTS is sticky. A browser that has seen it refuses plain HTTP to
that host for `max-age` seconds (default one year). With HTTPS still working you
can retract it by serving `--hsts --hsts-max-age 0` for a while, but a host that
has lost HTTPS cannot — the retraction must itself arrive over HTTPS, and
clients that do not revisit keep the old pin. Enable HSTS only once TLS is
there to stay.

## Client IP behind a reverse proxy

noadd rate-limits logins and DoH queries per client IP, watches for session-ID
guessing per IP, and records the IP in the query log, so it must find the real
client behind any proxy. `--trusted-proxies` takes a comma-separated CIDR list of
the proxies in the chain; loopback (127.0.0.0/8, `::1`) is always trusted, so a
same-host proxy needs no configuration.

`X-Forwarded-For` is read **right to left**, and the first hop that is not a
configured proxy is the client. Most proxies (nginx's usual
`$proxy_add_x_forwarded_for`, Cloudflare) *append*, so a client's own forged
`X-Forwarded-For` stays leftmost; trusting it would let anyone mint a fresh
rate-limit bucket per request and forge query-log entries.

So **list every proxy in the chain**, not just the one noadd talks to. A missing
hop ends the walk and is taken as the client — traffic is attributed to that
proxy, which is imprecise but not something a client can aim.

The dangerous mistake is the opposite: **list proxies only, never a range
clients also live in.** The walk skips every hop the list covers, so
`192.168.1.0/24` meant as "my LAN" steps over the real client onto whatever it
forged. Prefer the proxy's own address (`--trusted-proxies 192.168.1.5`) over
its subnet.

```bash
# SWAG/nginx in another container on the Docker bridge
./target/release/noadd --trusted-proxies 172.18.0.0/16
```

Behind Cloudflare, also list Cloudflare's published ranges, since the edge is
the hop your proxy appends:

```bash
./target/release/noadd --trusted-proxies 172.18.0.0/16,173.245.48.0/20,103.21.244.0/22,…
```

Alternatively, have the fronting proxy collapse the chain to one trustworthy
value. With Caddy, `trusted_proxies` and `client_ip_headers` are **global
options in the `servers` block** — without the former, `{client_ip}` silently
falls back to the direct peer, which behind Cloudflare is the edge:

```caddyfile
{
	servers {
		# Cloudflare's published ranges — see https://www.cloudflare.com/ips/
		# (both families; noadd and Caddy match v4 and v6 separately).
		trusted_proxies static 173.245.48.0/20 103.21.244.0/22 … 2400:cb00::/32 2606:4700::/32 …
		client_ip_headers CF-Connecting-IP
	}
}

dns.example.com {
	reverse_proxy 127.0.0.1:8080 {
		header_up X-Forwarded-For {client_ip}
	}
}
```

noadd then sees a one-entry chain from a loopback peer and needs no
`--trusted-proxies`. `X-Real-IP` is only consulted when `X-Forwarded-For` is
absent or unreadable.

The HTTP listener must be reachable only through the proxy: a client that can
reach noadd (or the proxy) directly, bypassing Cloudflare, can send these
headers itself.

## The `Host` header behind a reverse proxy

Have the proxy forward `Host` exactly as the browser sent it, port included.
Current browsers send `Sec-Fetch-Site`, which the CSRF guard decides on alone,
but for one that does not (Safari before 16.4) the guard requires `Origin` to
match `Host`, host and port. A proxy that rewrites `Host` gets those users'
sign-ins and saves refused with `403`, logged as `csrf.rejected` with `reason`
`origin_mismatch`. nginx defaults to the upstream's name and its `$host` drops
the port, so:

```nginx
proxy_set_header Host $http_host;
```

Caddy and Traefik forward `Host` unchanged by default.

## Publishing DoH without publishing the admin UI

One HTTP listener (`--http-addr`) serves both DoH and the admin UI. There is
no separate admin port: splitting them is a routing rule on the reverse proxy
you already need to publish anything, and a second listener would mean a second
TLS identity, certificate, and cookie/HSTS rules to get wrong.

So **publishing noadd for DoH publishes the login page too**, unless the proxy
says otherwise. The paths divide cleanly, so a proxy can publish only DoH:

| Path | Publish |
| --- | --- |
| `/dns-query`, `/dns-query/{token}` | yes — this is the service |
| `/api/mobileconfig/{token}` | only if devices enrol over the internet |
| everything else (`/`, `/api/*`) | no, or behind [forward auth](#reverse-proxy-authentication) |

nginx — a prefix match, so it covers the `/dns-query/{token}` form too:

```nginx
location ^~ /dns-query { proxy_pass http://noadd:8080; }
location / { return 404; }
```

Caddy:

```caddyfile
dns.example.com {
    @doh path /dns-query /dns-query/*
    handle @doh {
        reverse_proxy noadd:8080
    }
    handle {
        respond 404
    }
}
```

The admin UI is still served on noadd's own `--http-addr` to whatever network
that address is bound to — the proxy just stops publishing it. Bind noadd to a
LAN or VPN address rather than `0.0.0.0` to have the host enforce that too.

To publish the admin UI as well, put it behind forward auth (below) rather than
relying on the password alone.

### What noadd does on its own

The admin login is not bare. Passwords are 12–128 characters, rejected if
zxcvbn finds them guessable, and hashed with Argon2id. Login, password change
and re-authentication share a five-attempts-per-minute throttle per source
address **and** a per-account backoff. Sessions have both an idle and an
absolute expiry and are stored hashed. Minting an API key and adding or removing
an operator require your password again, so a stolen session cookie cannot
quietly become permanent access.

The per-account backoff is what a botnet hits: a thousand addresses get a
thousand IP budgets but share one account budget. The first three consecutive
failures are free; each further one locks the account for twice as long as the
last, from one second up to fifteen minutes, reset after an hour of quiet or on
the right password.

The ceiling is deliberate: with no password-reset flow, a permanent lock would
be a denial of service anyone could trigger against a guessable username. DNS
resolution is never affected, and restarting noadd clears the state if a live
attack locks you out.

What noadd does **not** have is a second factor — see below.

## Reverse proxy authentication

noadd can trust an operator identity set by a fronting proxy (Authelia,
Authentik, oauth2-proxy, ...) instead of its own login form. Set
`--forward-auth-header` to the injected header (e.g. `Remote-User`) **and**
`--forward-auth-trusted-proxies` to the proxy's CIDR — both are required, and
unlike `--trusted-proxies`, loopback is **not** trusted implicitly: a forged
header grants full admin access. Unknown usernames are provisioned without a
password; password login and API keys keep working. The HTTP listener must be
reachable only through the proxy.

noadd holds no session for a forward-auth caller, so logout has nothing to
revoke. Set `--forward-auth-logout-url` to the proxy/SSO logout endpoint (e.g.
Authelia's `/logout`) and logging out sends the browser there. Without it,
logout only clears noadd's own state — the proxy re-injects the header on the
next request, so the user must log out at the proxy.

```bash
./target/release/noadd --forward-auth-header Remote-User \
  --forward-auth-trusted-proxies 172.18.0.0/16
```

Example nginx (Authelia-style):

```nginx
auth_request_set $user $upstream_http_remote_user;
proxy_set_header Remote-User $user;
```

### Multi-factor authentication

noadd has no built-in MFA; add it here. Authelia, Authentik and Cloudflare
Access all offer TOTP, WebAuthn and push in front of `--forward-auth-header`,
with one login across every self-hosted service.

Built into noadd it would be worse: WebAuthn needs a secure context, which the
plain-HTTP internal deployments noadd supports do not have — exactly the ones
least likely to have a proxy — and a passkey is bound to one origin, while a
self-hosted box is often reached by IP, `.local`, a tailnet name and a domain.

What a second factor adds is protection against **password reuse**: throttling
does not help when the attacker has your password from someone else's breach.
If the admin UI is reachable from the internet, put an MFA-capable proxy in
front of it.

### Paths to exclude from the proxy's authentication

The browser flow needs **no exceptions**: the proxy authenticates the request
and noadd trusts the injected header. What breaks is any client that cannot
complete an interactive SSO login — DNS resolvers, health probes, devices
fetching a config profile, API-key CLIs. These endpoints authenticate
themselves and must bypass the proxy's auth (`policy: bypass`):

| Path | Used by | Note |
| --- | --- | --- |
| `/dns-query`, `/dns-query/{token}` | DoH resolvers | **Mandatory** — gating this breaks all DNS-over-HTTPS. Authenticated by URL token / the DoH access policy, never the admin session. |
| `/api/health` | Uptime / container health probes | No auth by design. |
| `/api/mobileconfig/{token}` | A device downloading the Apple config profile | Token-authenticated. |

API-key clients (`Authorization: Bearer …`) cannot do SSO either — exclude
their routes too, or let the proxy pass requests carrying a Bearer token.

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

Most `/api/*` endpoints accept an **API key** as well as the browser session.
Create one on the **Account** page (the full token is shown once). A key
inherits its operator's permissions. Changing your own password
(`POST /api/users/me/password`) is cookie-only, since it acts on the browser
session itself.

Three endpoints also require a password confirmed within the last five minutes:
creating an API key (`POST /api/api-keys`) and adding or removing an operator
(`POST /api/users`, `DELETE /api/users/{id}`). Signing in counts; otherwise
confirm with `POST /api/auth/reauth` (`403` with `"code": "reauth_required"`
until you do). The admin UI simply asks for your password in the form for each
of these actions. **API keys cannot perform them at all** (`403`,
`"code": "password_required"`): a key has no password to confirm, and could
otherwise issue itself a permanent successor. Forward-auth operators are exempt
— the proxy authenticates every request, and they have no password.

```bash
curl -H "Authorization: Bearer noadd_XXXXXXXX…" \
     https://noadd.example.com/api/rules
```

An interactive reference (OpenAPI / Scalar) is at **`/api/docs`**, the raw spec
at **`/api/openapi.json`**; both require authentication (session or API key).

## Development

```bash
# Run tests
cargo nextest run

# Check formatting + lints
cargo fmt --check
cargo clippy --all-targets -- -D warnings

# Run in dev mode
RUST_LOG=noadd=debug cargo run -- --dns-addr 127.0.0.1:5353 --http-addr 127.0.0.1:8080
```

### End-to-end tests

Browser tests for the admin UI live in [`e2e/`](e2e/), built with
[cucumber](https://github.com/cucumber-rs/cucumber) and
[thirtyfour](https://github.com/stevepryde/thirtyfour). `e2e/` is its own cargo
workspace, and the suites start the `noadd` binary themselves (throwaway ports
and databases), so build it first:

```bash
cargo build                  # embeds the admin UI into the binary
cd e2e
cargo test --test e2e        # the Gherkin features
cargo test --test specs      # the regression specs
```

A local Chrome or Chromium is required: the driver manager downloads a matching
chromedriver on demand, but not the browser.

Gherkin features are in `e2e/features/` with steps in `e2e/tests/e2e/steps.rs`;
regression specs are in `e2e/tests/specs/`. Both run in CI's `e2e` job.

### Regenerating README screenshots

`docs/screenshots/` is produced by seeding a throwaway database with ~90 days of
fake traffic, booting `noadd`, and capturing every page in a real browser.
Re-run it after any visual admin-UI change and commit the PNGs:

```bash
cargo build                  # embeds the current admin UI into the binary
cd e2e
cargo run --bin screenshots
```

## License

MIT
