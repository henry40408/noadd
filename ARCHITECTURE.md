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
├── headers.rs           # Response-header middleware (no-store, HSTS)
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

A session token is never stored. What noadd keeps — in `sessions.token_hash` and as the in-memory `SessionStore` key — is its unsalted `BLAKE2b` digest (`hash_session_token`, `src/admin/auth.rs`), the same construction API keys have always used; the raw token exists only in the `Set-Cookie` on the way out and the `Cookie` header on the way back. So a copy of the database — a backup, a stray WAL file, a discarded SD card — yields no usable credential, where previously it handed over every live session. Unsalted deliberately: the token is 64 random alphanumeric characters, so there is no dictionary to defend against and nothing for Argon2 to buy, while an equality lookup against the column's index is what a presented cookie needs. The hashing happens in exactly one place, `session_cookie_hashes` (`src/admin/api.rs`), which is what confines the plaintext to the cookie boundary — a future call site reaching for `jar.get(SESSION_COOKIE)` directly would quietly reintroduce it. This is distinct from `session_log_id`, which is salted and truncated for log correlation and cannot be looked up; the salt is what keeps a log line from being matchable against a stolen row. Upgrading rewrites the table (`user_version` 9) and **drops every existing session, so operators sign in once more**: the old rows hold plaintext that SQLite cannot hash in SQL, and rehashing them in Rust would leave the plaintext behind in freelist pages and the WAL regardless, claiming a protection it had not delivered. The migration is forward-only — an older binary run against a migrated database compares cookies to hashes and silently rejects every session.

A session expires on two independent layers. The absolute one — 7 days from creation (`SESSION_MAX_AGE_SECS`) — has always existed; alongside it sits a 48-hour idle window measured from `last_seen` (`SESSION_IDLE_TIMEOUT_SECS`, `src/admin/auth.rs`). 48 hours is nowhere near OWASP's 15-30 minute suggestion, deliberately: noadd is a self-hosted appliance whose operators expect a browser tab left open overnight to still be signed in the next morning, so the property this layer buys is that an idle timeout exists at all, not that it lands on any particular figure. Both timeouts are enforced lazily by `validate_session` on the request that first lands past either cutoff, backstopped for sessions nobody ever touches again by `prune_expired` (in-memory) and `Database::purge_expired_sessions` (the `sessions` table). `purge_expired_sessions` and `load_sessions` — the startup restore — share one SQL predicate, so a session already dead to `validate_session` cannot outlive a restart by satisfying only one of the two checks in the database. The periodic sweep runs from the same 60-second tick that flushes `last_seen` to disk, once every ten ticks (roughly ten minutes), and always *after* that tick's flush: the row on disk otherwise lags the in-memory value by up to a flush interval, and sweeping first could let the SQL predicate purge a session the in-memory side still considers alive.

The `session` cookie is `HttpOnly` and `SameSite=Lax`, which is what stands in for CSRF tokens here: `Lax` withholds the cookie from every cross-site `POST`/`PUT`/`DELETE`, and since all of this API's mutations use those methods and no `CorsLayer` is installed, a cross-origin caller can neither forge a state change nor read a response. The one thing `Lax` permits that `Strict` would not — a cross-site top-level `GET` navigation carrying the cookie — is harmless here because no `GET` handler writes, and the attacker cannot read the response of a navigation they have left. `Strict` therefore buys no additional protection over `Lax` for this API — the two differ only on that one case — so `Lax` is chosen as the weakest setting that is still load-bearing, and the cookie survives deep links followed from outside the site. `Secure` is resolved once at startup by `config::resolve_cookie_secure`: it follows whether noadd is terminating TLS itself (user-supplied certs or ACME), which is a runtime fact rather than a config string that can be wrong. Deployments where a reverse proxy terminates TLS see only plain HTTP and must opt in with `--cookie-secure`; it is not forced on by default because a browser silently discards a `Secure` cookie delivered over HTTP, which would lock those operators out with no visible error. When `Secure` is on, the cookie is also named `__Host-session` rather than `session`, which makes the browser itself enforce `Path=/` and no `Domain` and blocks a subdomain from overwriting it; the name is conditional on `cookie_secure` for the same reason `Secure` is, and both names are accepted on read (`__Host-` preferred) so a runtime flip of `cookie_secure` does not invalidate sessions already in flight.

Layered on top of `SameSite=Lax` is a stateless first-line CSRF check, `csrf_origin_guard` (`src/admin/csrf.rs`), applied as a single `axum::middleware::from_fn` layer over the admin router only (DoH is left untouched — it authenticates by URL token, not a cookie, and legitimately receives cross-origin `POST /dns-query`). On every unsafe-method request it rejects, with `403`, any caller a browser proves is cross-site: `Sec-Fetch-Site` (sent by all current browsers) is authoritative and only `cross-site` is refused; absent that header, the `Origin` host is compared against the request `Host` (host only, scheme/port ignored so a TLS-terminating proxy's forwarded `Host` still matches), and a mismatch or an opaque `Origin: null` is refused. A request carrying neither header is a non-browser client (API-key/bearer CLI, `curl`, the OS resolver) that does not send the ambient session cookie, so it is passed through — the SPA's same-origin `fetch` and every programmatic caller are unaffected. This closes the one gap `SameSite` misses: it is scoped to the registrable domain (eTLD+1), not the origin, so a malicious *same-site, cross-origin* page (a sibling subdomain, or another app co-hosted on the same host) is treated as same-site and *does* receive the cookie; the origin guard rejects it on the `Origin`-host mismatch. A synchronizer (per-session) CSRF token is deliberately **not** added: the admin surface is a pure same-origin fetch/JSON SPA with no server-rendered forms to carry a hidden field, the session token is unsigned and there is no HMAC/secret subsystem to derive a token from, and `SameSite=Lax` + the JSON content-type barrier + this origin guard already cover the (Low-severity) residual risk — a token would be disproportionate ceremony. **Caveat:** if a reverse proxy rewrites `Host` to an internal name that differs from the public origin host *and* the client is an ancient browser that omits `Sec-Fetch-Site`, the `Origin`/`Host` fallback could 403; modern browsers hit the authoritative `Sec-Fetch-Site` path and are unaffected.

### API Authentication

Most `/api/*` endpoints accept either the browser `session` cookie or an `Authorization: Bearer <api key>` header; both paths are unified behind the `AuthedUser` axum extractor, so handlers don't need to distinguish how the caller authenticated. Session management (`GET /api/sessions`, `DELETE /api/sessions/{id}`) is authorized through `AuthedUser` like most other endpoints — the session cookie there is only consulted to flag which listed session is the caller's own device (`is_current`) and to clear that cookie after a self-revoke, never as a precondition for the request. Changing your own password (`POST /api/users/me/password`) is the endpoint that actually is cookie-only by design, since it acts on the browser session itself and has no notion of "your own session" outside a session cookie; the URL-token-authenticated `GET /api/mobileconfig/{token}` is unauthenticated by any `AuthedUser` path at all, using the URL token itself as the sole credential. Changing your own password revokes that operator's other sessions but deliberately leaves every other operator's sessions alone — `revoke_user_sessions_except` and `Database::delete_user_sessions_except` filter on `user_id`, so containing one compromised account never collaterally signs out the rest of the team. `POST /api/auth/revoke-others` stays global (every session but the caller's, across all operators) rather than being narrowed the same way: it predates this filtering and serves a different job, a blunt "something is wrong, sign everyone else out everywhere" control rather than a response to one credential changing, and narrowing it would quietly remove that panic-button use case. API keys are BLAKE2b-hashed at rest (only the hash is stored) and are bound to an operator via `ON DELETE CASCADE`, inheriting that operator's permissions — a key is only as powerful as the account that minted it. Keys are managed via `GET/POST/DELETE /api/api-keys`, driven from the admin UI's Account page (the full token is shown once, on creation, and never again). An OpenAPI 3.1 spec is served at `GET /api/openapi.json`, with an interactive Scalar reference at `GET /api/docs`; both require an authenticated operator (session or API key) — they expose only the schema shape, never data, but this security appliance still minimizes pre-auth recon — and cover a core subset of endpoints.

`AuthedUser` tries a third path if the first two fail: a username header injected by a reverse proxy (`src/admin/forward_auth.rs`), honoured only when the TCP peer matches `--forward-auth-trusted-proxies` — a separate, non-loopback-trusting allow-list from `src/net.rs`'s `TrustedProxies`, since a forged forward-auth header (unlike a forged `X-Forwarded-For`) grants full admin access. A username seen for the first time is JIT-provisioned with a sentinel `password_hash` (`src/admin/auth.rs`'s `NO_PASSWORD_SENTINEL`, the `/etc/shadow` convention) that no password can ever verify against, checked explicitly on the login path before the hash is parsed; the password-change endpoint above stays unavailable to a forward-auth identity since there is neither a session token nor a password to act on, while session management remains reachable via the forward-auth path like any other `AuthedUser` endpoint.

`POST /api/auth/logout` is the one exception to "cookie-only acts on the session": it accepts any `AuthedUser` path, including forward auth, so a proxied caller is no longer 401'd trying to log out. It revokes and clears the `session` cookie when one is present (a no-op for forward auth, which holds no session to revoke) and always returns `{ redirect_to, via_forward_auth }`: `via_forward_auth` reports which path authenticated the request. For a forward-auth caller, `redirect_to` echoes `--forward-auth-logout-url` / `NOADD_FORWARD_AUTH_LOGOUT_URL` (`None` if unset) for the SPA to send the browser to, ending the upstream proxy/SSO session; for a cookie/password user, `redirect_to` is always `null` since their session is already revoked server-side. The response also carries `Clear-Site-Data: "cache", "cookies", "storage"` — deliberately omitting `"executionContexts"`, which would reload the browsing context before the SPA can read `redirect_to` from this same response and hand off to the forward-auth logout URL. **Caveat:** `"cookies"` is not origin-scoped — per the Clear-Site-Data spec it clears cookies for the request's registrable domain, so logging out of noadd at `dns.example.com` also drops cookies for `example.com` and every sibling subdomain, including the forward-auth proxy's own session at `auth.example.com`. For that forward-auth topology the collateral sign-out is arguably intended, since the SPA immediately sends the browser to the proxy's own logout URL anyway; deployed on a domain shared with an unrelated co-hosted app, it is unannounced collateral sign-out, and an operator putting noadd on a shared domain should know that before they do. **Caveat:** for a forward-auth user without that URL configured, clearing noadd's own state does not truly log out — the proxy re-injects the identity header on their very next request — so they must log out at the proxy or SSO provider directly; the admin UI surfaces this with a notice rather than silently pretending the session ended.

Every session and API-key lifecycle transition is logged via `tracing` with a structured `event` field rather than free text, so an operator can grep or filter for a fact instead of a phrase: `session.created`, `session.destroyed` (carrying a `reason` — `logout`, `revoked_by_id`, `revoked_others`, `password_change`, `user_deleted`, `expired_absolute`, `expired_idle`, or `swept`), `apikey.created`, `apikey.destroyed`, `auth.failed`, and `forward_auth.provisioned`. `session.created` and a `session.destroyed` naming one specific session (`reason` of `logout`, `revoked_by_id`, `expired_absolute`, or `expired_idle`) additionally carry `sid_hash`: a salted, truncated BLAKE2b digest of the session's stored token hash (`session_log_id`, `src/admin/auth.rs`), never the token itself — enough to correlate the same session across separate log lines without a token disclosed in a log ever being replayable. The bulk `session.destroyed` reasons — `revoked_others`, `password_change`, `user_deleted`, and `swept` — name no individual session and carry a count instead, so there is no single token to hash. The salt lives in `settings.session_log_salt`, generated once on first run rather than re-rolled per process, so `sid_hash` values keep correlating across a restart instead of every reboot starting a fresh, unlinkable identifier space. Deliberately absent from this vocabulary is a successful per-request session validation: that path runs on every authenticated request, so logging it would drown the audit trail without adding anything a lifecycle audit needs — only a session's creation and destruction are events worth recording, not its use. A successful API-key use is likewise untracked per-call; it is already reflected in `api_keys.last_used_at`.

`auth.failed` distinguishes what was rejected via its `method` field — `password`, `api_key`, or `session_cookie`. The last is the session-ID guessing detector: a request presenting a session cookie that names no live session is counted per source IP (`invalid_session_limiter`, `src/admin/api.rs`), and crossing `INVALID_SESSION_MAX_ATTEMPTS` within `INVALID_SESSION_WINDOW_SECS` emits the warning once per window rather than once per request. It is deliberately **detect-only** — no 429, no lockout. The identical code path is walked by a wholly legitimate browser whose session expired while its tab stayed open, since the SPA keeps polling with the now-stale cookie, so blocking on this counter would lock operators out of their own appliance on the strength of a benign event; the threshold exists for the same reason, as a single occurrence carries no signal. A request carrying no session cookie at all is not counted: it is an ordinary unauthenticated request, not a guess, and counting it would drown the burst it exists to surface.

Every admin response additionally passes through the `no_store` middleware (`src/headers.rs`), which stamps `Cache-Control: no-cache, no-store, must-revalidate, max-age=0` (plus `Pragma: no-cache` and `Expires: 0` for HTTP/1.0 intermediaries) whenever a response does not already declare its own caching policy. It keys on the *absence* of `Cache-Control` rather than on the request path, which is what lets the two exceptions fall out for free instead of needing special-casing: the embedded SPA assets (see Admin UI, above) set their own `no-cache` plus a content-hash `ETag`, so they keep their revalidate/304 behaviour untouched — there is no session or query data in the shell for `no-store` to protect anyway — and `GET /api/logs/stream`'s `Sse` response sets its own `Cache-Control: no-cache`, so it lands on that instead, which is fine since an event stream is not a cacheable representation to begin with. Everything else — every `/api/*` JSON body, the mobileconfig plist, and the 401/403 rejections raised by extractors and the CSRF guard — sets nothing on its own and therefore always picks up `no-store`, so a shared or browser cache never retains a copy of session or query data.

### Client IP Resolution

`src/net.rs`'s `extract_client_ip` produces the address that the login limiter (`src/admin/api.rs`), the DoH query limiter (`src/dns/handler.rs`) and the query log all key on, so a caller who can steer it can mint a rate-limit bucket per request and forge log attribution. Two separate checks guard it. The **peer** must be loopback or match `--trusted-proxies` before any header is read at all. The **header** is then walked right-to-left, returning the first hop that is not itself a configured proxy.

The right-to-left walk is the non-obvious half. Trusting the peer says nothing about the *contents* of `X-Forwarded-For`, because the common proxy configurations append to the client's value rather than replace it — nginx's `$proxy_add_x_forwarded_for` and Cloudflare both do — so `XFF: <forged>, <real client>` arrives with an entirely trustworthy proxy in front of it. Reading the leftmost entry, as noadd did before, hands the attacker the result directly.

An entry the walk cannot read ends it too. Stepping over an unreadable hop would carry the walk into entries no proxy vouched for, and the encodings that fail a bare `IpAddr` parse are ones real proxies emit — `1.2.3.4:53821` from Azure's gateways and IIS ARR, bracketed IPv6, RFC 7239 `for=` syntax leaking across from `Forwarded` — so `parse_forwarded_hop` normalises those rather than leaving the walk to skip past them.

The cost of the walk is that the trust list must name every hop, not just the peer noadd talks to; an unlisted hop terminates the walk and is reported as the client, over-attributing traffic to a proxy. That direction is imprecise but not aimable. The reverse — a range wide enough to cover client addresses, `192.168.1.0/24` written to mean "my LAN" — is not safe at all: the walk skips every hop the list covers, so it steps over the real client onto whatever that client wrote, restoring exactly the primitive the leftmost read had. The list is a statement that only proxies hold these addresses.

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
