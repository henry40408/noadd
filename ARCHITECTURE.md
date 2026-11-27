# Architecture

## Overview

noadd is a single-binary DNS ad-blocker. All components run as goroutines in one process; shared state is behind atomic pointers, channels and small mutexes.

```
                    ┌──────────────────────────────────────────┐
                    │                 noadd                     │
                    │                                          │
Clients ──────────► │  UDP/TCP Listener ──┐                    │
                    │                     ├──► DNS Handler     │
DoH Clients ──────► │  DoH (net/http) ─────┘       │            │
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
2. Unsupported requests are rejected: non-`Query` opcodes get NOTIMP, unsupported EDNS versions get BADVERS (see below)
3. Filter engine checks the domain (allowlist > blocklist > filter lists)
4. If blocked: synthesize a response per the configured block mode
5. If allowed: check cache, then forward upstream on a miss
6. Log the query asynchronously via an mpsc channel
7. On the **UDP** path only, fit the reply to the client's advertised buffer (see UDP Truncation)

Filter runs **before** cache so new block rules take effect immediately.

Every synthesized response copies the client's **RD** bit rather than assuming it was set (RFC 1035 §4.1.1). RA is always set, since noadd is a forwarding resolver.

### Unsupported Requests

`Handler.Handle` (`internal/dnsserver/handler.go`) rejects these before the filter, cache or upstream are touched:

- **Non-`Query` opcodes** → **NOTIMP** (`dns.BuildNotimp`), echoing opcode, ID and question.
- **EDNS version > 0** → **BADVERS** (RFC 6891 §6.1.3). The extended RCODE 16 is split across header and OPT; the OPT is emitted at version 0 to advertise the highest supported version.

Neither is logged or rate-limited: they carry no domain to attribute.

### Block-Response Modes

The handler answers a blocked query per the runtime `block_mode` setting (`internal/dns/block.go`):

- **`null_ip`** (default) — `0.0.0.0` for A, `::` for AAAA, empty `NoError` otherwise.
- **`nxdomain`** / **`refused`** — that RCODE for every query type.
- **`custom_ip`** — `block_custom_ipv4` / `block_custom_ipv6` for A / AAAA; empty `NoError` when the relevant address is unset or for other types.

All three settings are validated and applied live via the settings API.

The mode is global — none per rule or per client. The IP in a hosts-style rule (`127.0.0.1 tracker.com`) is discarded, since `ParsedRule` carries none; honouring it would thread an address through the parser, engine and `FilterResult`.

### DNSSEC Transparency

When enabled (the default; `dnssec_disabled` setting), the forwarder sends upstream a copy of the request whose EDNS OPT carries DO and a 1232-byte payload size. Before replying it restores the client's own EDNS/DO profile: DNSSEC records are stripped unless the client set DO, AD is cleared for clients that did not ask for DNSSEC (RFC 6840 §5.7), and an OPT is returned iff the client sent one.

The upstream's AD verdict is captured **before** that tailoring and stored in `query_logs.authenticated_data` (and in the cache entry, so hits log the same verdict) — which is how the log shows the true upstream result even for non-DO clients. This is transparency, not validation: noadd verifies no signatures, and hop-by-hop protection needs a `tls://` upstream and DoH to devices. **Known limitation:** NXDOMAIN/NODATA answers are logged `authenticated_data = false` even when validated upstream, because the upstream client's negative-answer path carries no AD field.

The setting is negative on purpose: an absent key means enabled, so a fresh database is on by default and a row exists only when the operator deviates; the UI shows the positive form. Forcing DO can make an upstream that validates only on DO SERVFAIL domains with broken DNSSEC, where it previously answered; the defaults validate regardless, and the toggle is the escape hatch — it applies live and flushes the cache on a real flip.

### Negative Responses (NXDOMAIN / NODATA)

`buildNegativeResponse` (`internal/upstream`) rebuilds the wire response from the upstream's NODATA/NXDOMAIN reply, carrying over the upstream's **authority section** (SOA plus any NSEC/RRSIG) so clients can negative-cache per [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308). Without the SOA, resolvers such as iOS's mDNSResponder fall back to a short default negative TTL and re-query constantly — costly for IPv4-only hosts whose AAAA/HTTPS lookups are always NODATA. An OPT is echoed only if the request carried one ([RFC 6891 §6.1.1](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.1)).

The cache stores client-ready wire responses, so its key includes the client's EDNS presence, DO and CD bits and the active DNSSEC policy alongside domain and type. That keeps an OPT/RRSIG-bearing response from reaching a client that did not advertise support (or the inverse) and isolates late responses across a policy toggle; changing the policy also clears the cache.

### UDP Truncation

Because noadd advertises 1232 bytes **upstream**, an answer can exceed what the client accepts over UDP. `dns.TruncateForUDP` (`internal/dns/truncate.go`) fits the reply to the client's buffer: its OPT payload size floored at 512 ([RFC 6891 §6.2.3](https://www.rfc-editor.org/rfc/rfc6891#section-6.2.3)), or 512 with no OPT ([RFC 1035 §4.2.1](https://www.rfc-editor.org/rfc/rfc1035)) — the common case for mDNSResponder. An oversize reply keeps header, question and OPT, drops the other sections, and sets **TC** so the client retries over TCP; a reply that fits is returned without a re-parse. Truncation happens at send time, never in the cache, and never on TCP.

### Cache Entry Memory

A cache entry holds its response in an exact-size `[]byte` (`internal/cache`): packing a message reserves spare capacity whatever the answer's size and a typical A response is under 100 bytes, so a larger slice would pin the difference for the entry's life. The shrink is one memcpy on a path that has already been to the network.

**Serving a hit allocates nothing lasting.** At insert, `dns.TTLOffsets` (`internal/dns/ttl.go`) walks the wire format once and records where each TTL sits; a hit is a copy plus writes at those offsets and the transaction ID (`dns.ApplyElapsed`) — no parse, re-encode, snapshot or lock. The client gets the upstream's own bytes, so name compression and record order are preserved.

⚠️ **Two record types carry something other than a TTL in the TTL field; the walk must skip both.** OPT's are the extended RCODE, EDNS version and DO flag ([RFC 6891 §6.1.3](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.3)) — decrementing them corrupts DNSSEC signalling while still parsing cleanly. TSIG's must be sent as 0 ([RFC 8945 §4.2](https://www.rfc-editor.org/rfc/rfc8945#section-4.2)). `internal/dns/ttl_test.go` covers both, plus compression pointers, unknown types, and malformed messages that must serve unchanged rather than panic.

`BenchmarkCacheMemory` and the memory tests in `internal/cache` measure these claims over a fill whose record-type mix follows published resolver traffic. On 10,000 entries (106-byte average payload) a served entry costs ~499 bytes and serving adds ~0.2 bytes per entry; the remainder is the shard bookkeeping and the key. ⚠️ The allocation count comes from its own fill: bytes are measured with responses built inside the window (the encoder's reservation is part of an entry's cost, and temporaries net out of a live-byte reading), but a freed allocation still counts as one that happened. The non-benchmark tests assert relationships, not numbers, so they encode nothing about the container's internals.

The cache is bounded by **resident bytes, not entry count** — `cache.Config{CapacityBytes: dnsCacheCapacityBytes}`, 5 MiB, in `cmd/noadd/serve.go` — because responses range from tens of bytes to tens of kilobytes, and an entry bound let large DNSSEC/TXT answers grow memory without limit. 5 MiB holds roughly 10,000 ordinary entries.

`cache.Weight` charges the response, domain, offsets table and `EntryOverheadBytes` (list node, map entry, key). That constant is **measured**: `BenchmarkCacheMemory` reports it every run, so a change in entry shape shows up as drift. 

## Source Layout

```
cmd/noadd/               # Entry point: options and env, DB path, logging, serve, shutdown, background jobs
internal/
├── db/                  # SQLite schema, migrations, all CRUD (modernc.org/sqlite, pure Go)
├── cache/               # Byte-bounded sharded LRU DNS response cache
├── dns/                 # Wire-format helpers: TTL offsets, UDP truncation, block responses, single-flight
├── dnsserver/           # Query pipeline (filter -> cache -> forward), UDP/TCP listeners, DoH, per-client rate limit
├── filter/              # Rule parser, engine (sorted exact sets + flat reverse-domain tries), lists, rebuild coordinator
├── upstream/            # Forwarder, strategies (Sequential / RoundRobin / LowestLatency), DNSSEC handling
├── querylog/            # Async query logger (channel -> batched SQLite writes)
├── events/              # Event-stream hub (ping, stats, log, rebuild)
├── stats/               # Query statistics computation
├── registry/            # AdGuard HostlistsRegistry client
├── auth/                # Argon2, sessions, rate limiting, lockout, forward auth, setup token
├── netx/                # Client-IP resolution behind trusted proxies
├── server/              # Admin HTTP: REST API, pages, CSRF, headers, static assets, OpenAPI
├── views/               # Server-rendered page builders (escaping HTML builder)
├── assets/              # Embedded app.js / app.css / icons
├── tlsserve/            # Manual and ACME TLS
├── logging/             # slog setup
└── version/             # Version stamping
```

Each package's `PORTING.txt` records what was measured and decided when it was ported from the Rust implementation.

## Key Design Decisions

### Filter Engine

- **Sorted packed arena** for exact domains — domains, offsets and list indexes in contiguous slices, searched by binary search.
- **Flat reverse-domain trie** for subdomain rules — `sub.ads.example.com` is stored as `["com", "example", "ads", "sub"]`, and any terminal node on the walk blocks. It is serialized into two contiguous buffers (node index + label pool) rather than heap nodes, ~19 bytes per rule.

The engine sits behind an atomic holder (`internal/filter/holder.go`) for lock-free reads; updates build a new engine and swap it in.

`filter.Build` partitions rules (exact vs subdomain), then builds the tries and the exact sets in separate goroutines, so a rebuild costs the slowest of them rather than their sum. The tries are built without maps: rules are sorted label by label from the right and written out in one recursive pass.

The same build computes the unique rules: per list, the rules no other loaded list provides — the filters page's Impact column. It must read the partitioned string rules because the exact sets and tries keep only the winning list per domain.

Coverage is asymmetric: only a subdomain rule can stand in for a subdomain rule, while an exact rule can be replaced by either kind. Lists are tracked in a 64-bit mask; past 64 lists the indices share the top bit, so a shared rule can read as unique — over-reporting impact, the safe direction. Two lists with identical rules both report zero, which is true of removing either alone; the page tells the operator to turn one off at a time.

### Async Query Logging

The DNS handler sends log events over a buffered channel; a goroutine batches them to SQLite (500 entries or 1 s), keeping the query path non-blocking.

The logger also publishes each entry to the event hub, which feeds the query log's live tail (`log` events on `GET /api/events?logs=1`). It publishes *before* the batch flush so the tail is real-time, only when a subscriber is connected so an unwatched tail costs nothing, and a slow subscriber is dropped (its `EventSource` reconnects) rather than stalling the logger.

### Schema Migrations

Versioned by `PRAGMA user_version`, forward-only. Each step is a file `internal/db/migrations/<version>_<description>.sql`, embedded in the binary; a new database runs them all. `0001_initial.sql` is the schema of the first release, which stored version 4, so versions 2 to 4 have no file.

On start `migrate` applies the files newer than the database, in order, each in one `BEGIN IMMEDIATE` transaction together with the version, so a failure leaves neither behind. It refuses a database newer than the latest file, and a non-empty one at version 0, where nothing says what has run.

Rules for a new file:

- Never edit a released file; add one with the next number.
- Make it safe to run twice where SQLite allows it: `CREATE` and `DROP` take `IF (NOT) EXISTS`, and a data change leaves the data alone the second time. A restored `.dump` gets its version back by hand and may get it too low. `ADD COLUMN` has no such guard: let it fail.
- No `BEGIN` or `COMMIT`; the runner owns the transaction.
- Rebuilding a table that foreign keys point to (`users`) deletes its child rows: foreign keys stay on inside the transaction (`PRAGMA foreign_keys` has no effect there), so `DROP TABLE` cascades without an error. Preserve the child rows in the same file.

### Upstream DNS

`ParseUpstreams` splits `upstream_servers` on newlines and commas and validates each entry: `ip[:port]` (plain, default 53), `tls://host[:port]` (DoT, default 853), `https://host[:port][/path]` (DoH, default 443 and `/dns-query`).

A bare IP is tried as `SocketAddr`, then as `IpAddr` with port 53. The two never both succeed, and going through `IpAddr` rather than looking for `:` keeps a bare IPv6 literal from being misread as carrying a port. `inet_aton` shorthand and octal forms stay errors; bare hostnames are invalid (no transport to infer).

Entries are stored in **canonical form** — explicit port and path, bracketed IPv6 — and deduplicated. Upstreams are keyed by label for health checks and latency EMAs, so `1.1.1.1` and `1.1.1.1:53` must not become two upstreams. Older non-canonical values keep parsing and are rewritten on the next settings save.

`upstream.Forwarder` holds the live set behind an atomic pointer; a settings save calls `Reconfigure(ctx, servers)`, which builds a fresh server set (resolves hostnames, resets EMAs) and swaps it in. In-flight queries finish on the old snapshot. Strategy and DNSSEC mode live outside the snapshot and survive `Reconfigure`.

An empty list is rejected (zero upstreams is a non-functional resolver), and a bad value is refused before anything is persisted. A corrupt stored value at startup falls back to the defaults with a warning rather than blocking boot. If every entry fails to resolve on `reconfigure`, queries fail until a working set is saved — accepted, since the health table shows it.

### DoH Token Auth

Each user-defined token is a URL path, `/dns-query/my-token`. The access policy (`allow`/`deny`) decides whether the bare `/dns-query` is served; tokens always work.

`GET /api/mobileconfig/{token}` renders the token's DoH URL as an Apple profile (`com.apple.dnsSettings.managed`). It declares top-level `PayloadScope: System`: from macOS 26.1 a scope-less DNS Settings profile fails with "The 'VPN Service' payload could not be installed", because encrypted DNS is built on `NetworkExtension` and is otherwise evaluated as a user-scoped VPN. iOS ignores the key.

### Admin UI

Routing, authentication and every page body are server-side; vanilla-JS web components (no framework, no build step) enhance the rendered markup in place.

`internal/server/pages*.go` hold the handlers and the views live in `internal/views/`. Every page path resolves the session before writing anything, redirecting to `/login?next=…` (or `/setup` when no operator exists). `/login` and `/setup` are plain `<form method="post">` pages that work without JavaScript; navigation is ordinary links.

Password sign-in exists once, in `startPasswordSession` (`internal/server/api_auth.go`), called by both `POST /api/auth/login` and `POST /login`. The rate limit, the constant Argon2 cost that makes an unknown username indistinguishable from a wrong password, the per-account lockout and the audit events all live there; a second copy is how one path silently loses the timing padding. `createFirstOperator` is the same for setup.

A `next` destination must be an absolute same-origin path (`safe_next`): an off-origin redirect after sign-in would make noadd's own URL phishing bait. `//host` and `/\host` (which browsers normalise to it) are refused too.

`views::layout::shell` renders the shell — topbar, both nav bars, status bar, one-shot notices — and each page view wraps its body in the page's custom element, which upgrades in place. `app.js` builds no page and re-derives nothing the template decided (e.g. the active nav item).

The no-JavaScript exceptions — the dashboard's 24-hour chart, the statistics charts, and the query log's live tail — each say so in place. The statistics charts bucket by the *viewer's* calendar, which needs a UTC offset the request does not carry, so the page ships quarter-hour counts on UTC boundaries and `app.js` folds them (exact, since every offset in use is a whole number of quarter hours). One-shot notices ride a flash cookie cleared by the response that renders them, never a query parameter that survives refreshes and shared links.

There is no `index.html` and no SPA fallback; an unmatched path 404s.

`internal/assets/static/` (`app.css`, `app.js`) is embedded with `go:embed` and served with a per-file content-hash `ETag` and `Cache-Control: no-cache`, so browsers revalidate and get `304` when unchanged. Server-rendered pages get `no-store` from the `no_store` layer.

All pushes ride one connection, `GET /api/events`: a `ping` heartbeat for the status indicator, `rebuild` edges for the rebuild banner, a `stats` snapshot every 10 s for the dashboard (`?stats=1`), and the live tail (`?logs=1`). One connection because the indicator is on every page and a browser without HTTP/2 gets only six per origin.

**Session tokens are never stored.** `sessions.token_hash` and the in-memory `SessionStore` key hold an unsalted BLAKE2b digest (`internal/auth/tokens.go`); the raw token exists only in `Set-Cookie` and `Cookie`, so a copied database yields no usable credential. Unsalted is deliberate: the token is 64 random alphanumerics, so there is no dictionary to defend against, and a presented cookie needs an indexed equality lookup. Hashing happens only in `sessionCookieHashes` (`internal/server/helpers.go`) — reading the session cookie directly would reintroduce plaintext. This is distinct from the salted session log ID, which is salted and truncated so a log line cannot be matched to a stolen row. The `user_version` 9 migration dropped every existing session (SQLite cannot hash in SQL, and rehashing in application code would leave plaintext in freelist pages and the WAL); an older binary against a migrated database silently rejects every session.

Sessions expire on two layers: absolute, 7 days (`SESSION_MAX_AGE_SECS`), and idle, 48 hours from `last_seen` (`SESSION_IDLE_TIMEOUT_SECS`). 48 hours is far above OWASP's suggestion on purpose — an appliance tab left open overnight should still be signed in; what matters is that an idle timeout exists. `Manager.Validate` enforces both lazily; `PruneExpired` (memory) and `DB.PurgeExpiredSessions` (table) sweep the rest. `PurgeExpiredSessions` and the startup `LoadSessions` share one SQL predicate, so a session dead to `validate_session` cannot survive a restart. The sweep runs every tenth 60-second `last_seen` flush tick (~10 min), always *after* the flush, or the SQL predicate could purge a session memory still considers alive.

The session cookie is `HttpOnly` and `SameSite=Lax`. `Lax` withholds it from every cross-site `POST`/`PUT`/`DELETE`, all mutations use those methods, and no `CorsLayer` is installed. The one case `Lax` allows over `Strict` — a cross-site top-level `GET` — is harmless because no `GET` handler writes, and `Lax` keeps deep links from outside working. `Secure` is resolved at startup by `config::resolve_cookie_secure` from whether noadd terminates TLS; proxy-terminated deployments opt in with `--cookie-secure`, since a `Secure` cookie over HTTP is silently dropped and would lock operators out. With `Secure` on, the cookie is named `__Host-session` (browser-enforced `Path=/`, no `Domain`, no subdomain overwrite); both names are accepted on read, `__Host-` preferred, so flipping the setting does not invalidate live sessions.

On top of that sits a stateless origin check, a header-based origin guard (`internal/server/csrf.go`), applied to the admin handler chain only — DoH authenticates by URL token and legitimately receives cross-origin `POST /dns-query`. The comments in `csrf.go` document it. For every method but `GET`/`HEAD`/`OPTIONS` it returns `403` to any request a browser marks cross-origin:

- **`Sec-Fetch-Site`** decides when present: `same-origin` and `none` pass, everything else is refused — including `same-site`, which only says the registrable domain matches. That closes `SameSite`'s gap: a sibling subdomain or co-hosted app is same-site and *does* get the cookie (`TestSameSitePostFromASiblingSubdomainIsRefused`). Falling back to an `Origin`/`Host` comparison there would not suffice, since behind a port-dropping proxy another service on the host can match `Host` (`TestSameSitePostIsRefusedEvenWhenOriginMatchesHost`).
- **Without it** (Safari before 16.4), the `Origin` authority — host *and port* — must byte-match the request's (request-target authority, else `Host`); a mismatch or `Origin: null` is refused. Matching the port stops another service on the same host; ignoring scheme lets a TLS-terminating proxy's `Host` match an `https://` `Origin`. It fails behind a proxy that drops the port (nginx's `$host` on a non-default port), which README → *The `Host` header behind a reverse proxy* warns about.
- **Neither header** means a non-browser client (API key, `curl`, the OS resolver) that sends no ambient cookie; it passes.

There is no synchronizer CSRF token, even for the server-rendered forms: a cross-origin form post arrives labelled `cross-site`/`same-site` or with a mismatched `Origin` and is refused before any handler. A token would only add protection against an attacker able to forge those headers, which browsers do not allow, and there is no signing secret to derive one from.

A rejection logs `csrf.rejected` with method, path, and all three inputs (`Sec-Fetch-Site`, `Origin`, `Host`) — telling a real attack from a `Host`-rewriting proxy needs every one. `csrf::log_rejection`, layered just outside `CsrfLayer`, captures the inputs on the way in and pairs them with the `ProtectionError` on the `403`; `host` is the authority the layer compared. `reason` is `cross_site`, `same_site_cross_origin` (a current browser delivering the cookie to another origin — an attack, not a proxy problem), `opaque_origin`, or `origin_mismatch` (the fallback, where a misconfigured proxy shows up). No threshold applies: DoH never reaches this layer (it is merged as a sibling router in `main`) and non-browser clients pass, so there is no benign high-volume twin. The 403 stays bodyless.

### API Authentication

Most `/api/*` endpoints accept the `session` cookie or `Authorization: Bearer <api key>`, unified behind the `AuthedUser` extractor. Session management (`GET /api/sessions`, `DELETE /api/sessions/{id}`) goes through `AuthedUser` too; the cookie is only read to flag `is_current` and to clear it after a self-revoke. Changing your own password (`POST /api/users/me/password`) is the cookie-only endpoint. `GET /api/mobileconfig/{token}` uses its URL token as the sole credential.

A password change revokes the caller's *other* sessions — only that operator's (`RevokeUserSessionsExcept`, `DB.DeleteUserSessionsExcept`), so containing one account never signs out the team — and **rotates the caller's own token**. The two cover different attackers: revocation ejects live browsers, rotation covers a token leaked through a log, shell history or screenshot. The replacement is stored before the old token is destroyed, so a failure leaves a working session, and the endpoint answers 204 either way (the password write has already committed). Both cookies come from one `sessionCookie`, shared with login, so rotation cannot drop `HttpOnly` or `Secure`. There is no periodic rotation: it buys little over the absolute timeout and races with in-flight requests. `POST /api/auth/revoke-others` stays global across operators on purpose — it is the "sign everyone else out" panic button.

API keys are BLAKE2b-hashed at rest and tied to an operator by `ON DELETE CASCADE`, inheriting that operator's permissions; they are managed at `GET/POST/DELETE /api/api-keys` from the Account page (token shown once). Minting a key and adding or removing an operator require `ReauthedUser`: a session must have proved its password within `REAUTH_WINDOW_SECS` (5 min; login counts), forward-auth callers are exempt, and API keys are refused with `password_required`. An OpenAPI 3.1 spec is at `GET /api/openapi.json` with Scalar at `GET /api/docs`; both require authentication to limit pre-auth recon, and cover a core subset of endpoints.

`AuthedUser` has a third path: a username header from a reverse proxy (`internal/auth/forward.go`), honoured only when the TCP peer matches `--forward-auth-trusted-proxies` — an allow-list separate from `netx.TrustedProxies` (`internal/netx`) that does **not** trust loopback, since a forged header means full admin access. A first-seen username is provisioned with `auth.NoPasswordSentinel` (the `/etc/shadow` `!` convention), checked explicitly on login before the hash is parsed so no password can match. Password change is unavailable to such identities; session management is not.

Signing out has two front doors onto `endSession` (`internal/server/api_session.go`), which holds the revoke-every-named-cookie rule: the shell's `POST /logout` form (`logoutSubmit`, `internal/server/pages_auth.go`; a POST so no prefetcher trips it) and `POST /api/auth/logout`. The JSON endpoint accepts any `AuthedUser` path, including forward auth, and returns `{ redirect_to, via_forward_auth }`; `redirect_to` is `--forward-auth-logout-url` for a forward-auth caller (`null` if unset) and always `null` for a session user. The form issues that redirect itself; for forward auth with no logout URL it redirects to `/` with a flash explaining that the session must be ended at the proxy.

Logout responses carry `Clear-Site-Data: "cache", "cookies", "storage"`, omitting `"executionContexts"`, which would reload the page before a JSON caller reads `redirect_to`. The proxy-logout flash path sends no `Clear-Site-Data`, which would delete the flash cookie. **Caveat:** `"cookies"` clears the whole registrable domain — logging out at `dns.example.com` also drops cookies for `example.com` and its subdomains, including a forward-auth proxy's session. That is intended for the forward-auth topology and unannounced collateral on a domain shared with unrelated apps. **Caveat:** without a logout URL, a forward-auth user is not really logged out — the proxy re-injects the header on the next request.

Session and API-key lifecycle events are logged with a structured `event`: `session.created`, `session.destroyed` (`reason`: `logout`, `revoked_by_id`, `revoked_others`, `password_change`, `rotated`, `user_deleted`, `expired_absolute`, `expired_idle`, `swept`), `apikey.created`, `apikey.destroyed`, `auth.failed`, `forward_auth.provisioned`. Events naming one session (`session.created`, and `logout`/`revoked_by_id`/`rotated`/`expired_*`) carry `sid_hash` from the salted session log ID — a salted, truncated digest of the stored token hash that correlates lines without being replayable; bulk reasons carry a count instead. A password change emits `password_change` (other devices) and `rotated` (the caller's old session), which never overlap, plus `session.created` with `reason = "password_change"`. The salt lives in `settings.session_log_salt`, generated once so `sid_hash` survives restarts. Per-request validation and API-key use are not logged (the latter shows in `api_keys.last_used_at`).

`auth.failed`'s `method` is `password`, `api_key` or `session_cookie`. The last detects session-ID guessing: a cookie naming no live session is counted per source IP (the invalid-session limiter, `internal/server`), and crossing `INVALID_SESSION_MAX_ATTEMPTS` within `INVALID_SESSION_WINDOW_SECS` warns once per window. It is **detect-only** — an expired tab reconnecting its event stream walks the same path, so blocking would lock operators out. A request with no session cookie is not counted.

Every admin response carries `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'` and `X-Content-Type-Options: nosniff` (`securityHeaders`, `internal/server/headers.go`). The two framing headers cover old and new browsers; neither depends on TLS, since a plain-HTTP LAN appliance is exactly what an attacker frames. The CSP holds *only* `frame-ancestors`: there is no inline `<script>` or `on*` handler, so `script-src 'self'` would hold, but about 200 inline `style` attributes (templates and `app.js`) would force `style-src 'unsafe-inline'`. Tightening `script-src` (or nonces, now that every page renders per request) is open for its own change. `nosniff` guards against a future wrong `Content-Type`. `Referrer-Policy`, `Permissions-Policy` and cross-origin isolation headers are deliberately absent — nothing needs them.

The `noStore` middleware (`internal/server/headers.go`) adds `Cache-Control: no-cache, no-store, must-revalidate, max-age=0` (plus `Pragma`/`Expires` for HTTP/1.0) to any admin response that sets no `Cache-Control` of its own. Keying on absence rather than path gives the exceptions for free: the embedded assets keep their `no-cache` + `ETag` revalidation, and the SSE stream keeps its own `no-cache`. Everything else — JSON, the mobileconfig plist, extractor and CSRF rejections — gets `no-store`.

### Client IP Resolution

`netx.ClientIP` (`internal/netx/clientip.go`) feeds the login limiter, the DoH query limiter and the query log, so steering it would mint rate-limit buckets and forge log attribution. Two checks guard it: the **peer** must be loopback or in `--trusted-proxies` before any header is read, and the **header** is walked right-to-left, returning the first hop that is not a configured proxy.

Right-to-left matters because common proxies (nginx's `$proxy_add_x_forwarded_for`, Cloudflare) *append*, so `XFF: <forged>, <real client>` arrives through a trustworthy proxy; the leftmost entry is attacker-chosen.

An unreadable entry ends the walk too, since skipping it would reach entries no proxy vouched for. `parseForwardedHop` normalises the forms real proxies emit — `1.2.3.4:53821` (Azure, IIS ARR), bracketed IPv6, RFC 7239 `for=` — so they are read rather than ending the walk early.

The trust list must therefore name every hop; an unlisted hop is reported as the client — imprecise, but not aimable. A range that also covers clients (`192.168.1.0/24` for "my LAN") is unsafe: the walk steps over the real client onto whatever it wrote. The list means "only proxies hold these addresses".

## Data Storage

Everything is in one SQLite file (`noadd.sqlite3` by default; a legacy `noadd.db` is opened instead when it exists and `noadd.sqlite3` does not):

| Table | Purpose |
|-------|---------|
| `settings` | Key-value config (upstream DNS, log retention, access policy) and counters |
| `query_logs` | DNS query history: timestamp, domain, action, cache hit, upstream AD bit (`authenticated_data`) |
| `filter_lists` | Registered filter lists (name, URL, enabled, rule count) |
| `filter_list_content` | Raw downloaded list content |
| `custom_rules` | User-defined allow/block rules |
| `doh_tokens` | DoH access tokens |
| `users` | Operator accounts (username, Argon2 password hash) |
| `sessions` | Admin sessions (token hash, user_id, IP, user agent, timestamps) |
| `api_keys` | API keys (BLAKE2b hash, owning user_id, `ON DELETE CASCADE`) |
| `query_stats_quarter`, `query_stats_{domain,client,upstream,metrics}_hour` | Rollups of `query_logs` — see *Rollups* |

`query_logs` has five indexes (since version 17). No statistic reads them; they serve the query log and the rollup readers' table arms:

| Index | Serves |
| --- | --- |
| `timestamp` | rollup readers' table arms; the query log's unfiltered and domain-contains pages |
| `(domain, timestamp)` | the query log's domain search |
| `(doh_token, timestamp)` | the token filter |
| `(blocked, timestamp)` | the blocked/allowed filter |
| `(query_type, blocked, timestamp)` | the type filter, alone or with a verdict |

`(domain, timestamp)` keeps a domain prefix search off the table: without it, searching a prefix nobody queried read 12 170 pages against 3. Measure an index's size with `dbstat`, not the file-size delta of `CREATE INDEX`, which understates it whenever a freelist absorbs the new pages.

### Query log filters

A timestamp-first index can only serve a filter by walking the window: on a 1.48 M-row database the newest page of a quiet DoH token read 1 200 pages (its count 23 130), and a quiet record type 9 812. Each filter now leads its own index with the value it matches: 28, 15 and 19 pages.

`(query_type, blocked, timestamp)` puts `blocked` in the middle so type + verdict is one seek. A type alone then does not come back in timestamp order as one range, so `query_logs` reads it as two runs, one per verdict, each newest-first and cut at `offset + limit`, and merges them. The runs carry only `id` and `timestamp` (both in the index) and the table is read for the page's rows alone — carrying every column read each skipped row (290 pages for page 20 against 22). the query-type filter paging test in `internal/db` holds the merge to the plain statement for every page size and offset `/api/logs` accepts.

`(blocked, timestamp)` replaces what the dropped metrics index did for the verdict filter (page 20: 102/57 pages without it, 18/12 with).

Across the Rust `logs_page_miss_bench`'s 42 readings (no Go counterpart: the pure-Go driver has no page-miss counter) the query log went from 368 963 page misses to 159 649 on the 1.48 M-row database. Migrating it takes ~3 s on an SSD and leaves a 25% freelist, past `VACUUM_FREELIST_RATIO`, so the first hourly maintenance rewrites the file once — measure on the appliance before relying on either figure there.

The tests in `internal/db` bound each filter's reads (`queries_test.go`) and check that the fixtures at versions 4, 8 and 15 upgrade to the version 17 structure, indexes included (`migrate_test.go`).

### Rollups

An index is still one entry per query, and with seven-day retention the Statistics windows and the dashboard's 30-day summary span the whole table. Version 16 adds five `WITHOUT ROWID` rollup tables, one row per key per unit of time: `query_stats_quarter` (blocked, cached; count and summed response time per quarter hour), and hourly `query_stats_domain_hour`, `query_stats_client_hour`, `query_stats_upstream_hour` (count and summed response time) and `query_stats_metrics_hour` (the grain the outcome, query-type and latency folds read). The unit leads the key, so a window is one range and writes land at the newest end. On the 1.48 M-row database they are 3 631 pages of 111 282.

The quarter hour is the finest chart bucket and the unit every UTC offset in use is a whole multiple of; nothing else needs finer than an hour. `doh_token` is `''` for plain DNS, since a key column cannot be `NULL`.

**The rollups must always equal a recount of `query_logs`.** Inserts maintain them through the `AFTER INSERT` trigger `query_logs_maintain_stats`, not the logger, so rows written any other way (the e2e fixtures use the `sqlite3` CLI) count too; its write cost is within 0.1% of a grouped upsert per batch.

Deletes are not a trigger — that would unwind a prune row by row and disable SQLite's truncate optimisation for Clear All. Clear All empties the five tables in its own transaction, and the prune (`internal/db/maintenance.go`) calls `unwindStatsRollups` first: whole units before the cutoff are dropped, and the one quarter and one hour containing the cutoff are recounted and subtracted, so retention keeps its exact cutoff. The rollup test in `internal/db` compares every table to a recount after batches, a direct SQL insert, prunes inside and on a unit boundary, and Clear All.

The version-16 migration fills the rollups from existing rows, replacing rather than adding, so an interrupted migration is safe to rerun.

A reader takes whole units from the first one inside its window (`firstWholeUnit`) from a rollup, and only the partial unit the window starts inside from `query_logs` via `idx_query_logs_timestamp`. The newest unit needs no table read, since rollups are written in the rows' own transaction. Both halves are one statement, so one snapshot. `summary_multi_since` tells its three windows apart by which arm a table row came from. `timeline_since` reads `query_stats_quarter` when its bucket is a whole number of quarters and the table otherwise (only while the log is a few hours old).

The dashboard reads only rollups — `SummaryMultiSince`, `TimelineSince`, `TrafficListsSince`, `TopUpstreamsSince`, and `DomainStatsSince` for domain suggestions; a tick went from 10 774 page misses to 227. `TestDashboardReadingsEqualARecountOfTheTable` (`internal/db/rust_stats_test.go`) holds each to a direct table count for windows starting before the data, on an hour, on a quarter, inside each, and after it.

`StatsScanSince` serves the Statistics page as one statement of four arms — `query_stats_quarter` from the earlier window's first whole quarter, `query_stats_metrics_hour` from the range's first whole hour, and the table rows each window starts inside — distinguished by a leading column, so a table row both windows start inside counts once per window. The API-only readers fold the same tables: `window_metrics_since` the metrics rollup, `timeline_multi_since` and `hourly_heatmap_since` the quarter rollup whenever bucket and offset are whole quarters. That is why the API rounds `tz_offset` to the nearest quarter hour; an off-grid offset would count the table. A 30-day visit went from 11 641 page misses to 3 644. `TestStatisticsReadingsEqualARecountOfTheTable` guards it, including offsets for India, Nepal, and a seven-minute one that takes the table path.

### Measuring these queries

Index work is measured in **page misses** (`SQLITE_DBSTATUS_CACHE_MISS`, 4 KiB pages fetched from the file), not milliseconds: development runs on an SSD, the appliance off an SD card, and a whole-table read can look free on one and take seconds on the other. (`outcome_breakdown_since` stayed uncovered through version 11 because a wall-clock reading hid a 12 173-vs-2 157 page difference.) The page benchmarks in `internal/server/pages_data_test.go` and `internal/db` report time and allocations against `BENCH_DB`, with `BENCH_NOW` pinning the clock for an older copy; the pure-Go driver exposes no page-miss counter, so allocations stand in for it. Distrust a wall-clock reading when the two disagree.

The Rust build measured these with `Database::read_page_cache_stats` and `Database::reset_read_page_accounting`, which the Go build does not have. The latter turned `mmap_size` off: pages read through the 256 MiB mapping bypass the pager cache and would report almost no misses, though the appliance still faults them in from the card.

### One scan per rollup family, not one per reading

`StatsScanSince` and `TrafficListsSince` (`internal/db/stats.go`) are the Statistics page's two reads; every reading, charts included, is folded out of one of them (`stats.ComputeRangeStats`). `StatsScanSince` streams rows and folds in Go rather than grouping in SQL, because a grain carrying both quarter and `response_ms` approaches one group per row. `TrafficListsSince` answers top domains, the distinct-domain count and top clients from one statement. The single-purpose `/api/stats/*` readers are separate statements over the same rollups; `DomainStatsSince` breaks ties by name like `TrafficListsSince`, so the two agree.

**Not collected:** `query_logs` does not record which list or rule blocked a query, so there is no blocked-by-list breakdown (it needs a new column and migration); the only per-list figure is the filters page's Impact column, from the live engine. Upstream failure rates and cache internals (entries, evictions, TTL spread) are not collected either.

The Database Health card's row count is not a scan: `SELECT COUNT(*)` walks an index end to end, so the count lives in `settings.query_log_count`, seeded by the version-13 migration and moved inside their own transactions by the only three writes that change the row count — the logger's batch, the hourly prune and Clear All. `TotalLogCount` falls back to counting if the row is missing. The query log's pager reads the same counter (`readLogCount`, via `CountLogs`) whenever no filter is applied.

`INDEXED BY` is on every statement that reads `query_logs` through an index: the type runs name `idx_query_logs_type_blocked_ts` so each run is the seek the merge depends on; the rollup readers' table arms and the heatmap's table path name `idx_query_logs_timestamp` (the arms read at most one unit, so the rowid lookups are cheap).

Every index migration runs `ANALYZE`: the planner keeps its old plan until `sqlite_stat1` is refreshed, and the hourly `PRAGMA optimize` lets it drift.

The heatmap's table path derives weekday and hour with integer arithmetic on the millisecond timestamp rather than `strftime`, which formats two strings per row; `TestHeatmapMatchesStrftimeAcrossAFullWeek` pins the two together.

### Read pool and SQLite global state

Admin and stats reads use a pool of four read-only connections (`ReadPoolSize`), each its own `database/sql` connection, so concurrent reads do not queue behind one another or the writer.

The Go pool (`openPool`, `internal/db/db.go`) holds read-only `database/sql` connections that run in parallel. The Rust implementation had to disable `SQLITE_CONFIG_MEMSTATUS` for the pool to scale; the pure-Go driver has no such switch, and the contention benchmarks that justified it were not ported (see `internal/db/PORTING.txt`).

This is unrelated to threading mode: `SQLITE_CONFIG_MULTITHREAD` only clears the per-connection mutex, which `SQLITE_OPEN_NOMUTEX` (on every connection here) already skips. Only `SQLITE_CONFIG_SINGLETHREAD` drops the static mutex, and it is unusable with a threaded pool.

### Retention & Maintenance

An hourly task prunes query logs older than the retention window, then runs `PRAGMA optimize`, a truncating WAL checkpoint, and `VACUUM` only when free pages exceed 20% of the file (`VACUUM_FREELIST_RATIO`), since VACUUM rewrites the database under a write lock.

## Dependencies

| Module | Role |
|--------|------|
| `net/http` (standard library) | HTTP server (DoH + admin API + TLS) |
| `github.com/miekg/dns` | DNS wire format / upstream transports |
| `modernc.org/sqlite` | Pure-Go SQLite driver (no cgo) |
| `golang.org/x/crypto` | Argon2, BLAKE2b, ACME (`autocert`) |
| `github.com/ccojocar/zxcvbn-go` | Password guessability check |
| `github.com/google/uuid` | UUIDs for mobileconfig profiles |

The response cache, filter engine, rate limiters, event hub and HTML builder are in-repo, so the binary stays small and a filter rebuild's transient allocation is returned to the OS by the Go runtime.
