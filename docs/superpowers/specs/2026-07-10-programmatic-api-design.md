# Programmatic API — API keys + OpenAPI docs — Design

Date: 2026-07-10
Status: Approved

## Goal

Let scripts, CI, and other automation call noadd's existing `/api/*` REST API
without a browser login session, and give them an **interactive, Swagger-style
API reference** to work against.

Two deliverables:

1. **API-key authentication** — long-lived bearer tokens, each bound to an
   operator (`user`) and inheriting that operator's permissions. A request
   authenticated by an API key is indistinguishable, downstream, from the same
   operator's browser session.
2. **OpenAPI + Scalar docs** — an OpenAPI 3.1 document generated from code
   annotations (`utoipa`) and a self-hosted interactive UI (`utoipa-scalar`),
   covering a **core programmatic subset** of endpoints (not all ~50 today).

## Scope

In scope:

- New `api_keys` table; keys are **hashed** at rest (BLAKE2b), shown in full
  **once** at creation, never recoverable.
- Bearer-token auth (`Authorization: Bearer noadd_…`) unified with the existing
  cookie-session path behind one auth entry point. Downstream handlers unchanged.
- API-key management endpoints (list / create / revoke), scoped to the caller.
- `utoipa` annotations on a **core subset** (~16 operations, listed below) plus
  the three new `api_keys` endpoints.
- Interactive docs at `/api/docs` (Scalar) and the raw spec at `/api/openapi.json`.

Out of scope (YAGNI — explicitly not built):

- Independent per-key permission scopes / read-only keys. Keys inherit the full
  permissions of their owning operator (matches the no-role-tiers decision from
  the multi-user design).
- Annotating **every** endpoint. The 14 stats endpoints, `sessions`, `users`,
  `doh-tokens`, `mobileconfig`, and the icon route are intentionally left out of
  the initial OpenAPI surface; `#[utoipa::path]` is incremental, so they can be
  added later without rework.
- Retrofitting hashing onto the existing plaintext `sessions` / `doh_tokens`
  tables. Sessions are short-lived (7-day expiry); API keys are long-lived, which
  is why only they get hashed at rest. No change to existing token storage.
- Per-key rate limiting, IP allow-lists, key rotation UX.

## Decisions & rationale

- **Hashed at rest (BLAKE2b), unlike sessions/doh_tokens.** Existing tokens are
  stored plaintext; that is acceptable for a 7-day session but not for a
  credential that may live for months. If the DB leaks, a leaked session expires
  within a week — a leaked plaintext API key does not. The token is a
  high-entropy (40-char alphanumeric ≈ 238-bit) random value, so a fast
  cryptographic hash (BLAKE2b) is sufficient — no Argon2/salt needed, and a hash
  column is directly indexable for O(1) lookup.
- **BLAKE2b, zero new dependencies.** `blake2 0.10` is already in the tree (via
  `argon2 → blake2`). Using it adds no crate; SHA-256 would pull in `sha2`. For a
  single-binary project with a `cargo deny` gate, zero-new-dep wins and the
  security properties are equivalent for this use.
- **DB lookup per request, no in-memory cache.** Unlike sessions (in-memory
  `HashMap`), API-key validation hits SQLite each call. API-key traffic is low
  (scripts/CI, never the DNS hot path), so a `prepare_cached` lookup on the
  indexed `token_hash` is cheap, and **revocation is immediate** with zero
  cache-invalidation logic.
- **Bearer header, not a cookie or custom header.** `Authorization: Bearer …` is
  the universal programmatic convention, keeps API keys off the cookie path (no
  CSRF surface, no collision with sessions), and is what the Scalar "Authorize"
  button expects out of the box.
- **Keys inherit owner permissions; scoped to owner in the UI.** A key resolves
  to a `user_id` and is treated as that operator. `GET /api/api-keys` lists only
  the caller's own keys.
- **Docs generated from code, not hand-written.** `utoipa` keeps the spec in sync
  with handlers (annotations live on the functions). `utoipa-scalar` is a single
  crate with no build script and no bundled multi-file asset tree (unlike
  `utoipa-swagger-ui`), which suits the single-binary / small-footprint ethos.
  `utoipa-axum` is **not** used — annotations are attached and collected manually
  into one `ApiDoc`, avoiding an extra 0.x dependency and leaving the existing
  `.route(...)` registrations untouched.
- **Docs endpoints are unauthenticated but data-free.** `/api/docs` and
  `/api/openapi.json` expose only the API *shape* (paths, schemas), never data,
  and every underlying endpoint still enforces auth. Open access is the point for
  a "programmatic usage" reference. (Reviewer may opt to gate these; noted as an
  open point below.)

## Dependencies

| Crate | Version (pin at impl time, ≥7 days old) | Why |
|-------|------------------------------------------|-----|
| `utoipa` | 5.x (5.5.0, 2026-05-04) | Derive `ToSchema` + `#[utoipa::path]`; build `ApiDoc`. |
| `utoipa-scalar` | 0.3.0 (2025-01-16), `axum` feature | Serve interactive docs + spec JSON. |
| `blake2` | already in tree (0.10) | Token hashing. Promote from transitive to direct dep. |

No `sha2`, no `utoipa-swagger-ui`, no `utoipa-axum`.

## Data model

Schema version bumps `7 → 8`. One new table:

```sql
CREATE TABLE api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,          -- human label, e.g. "ci-deploy"
    token_hash   TEXT    NOT NULL UNIQUE,   -- BLAKE2b-256 hex of the full token
    prefix       TEXT    NOT NULL,          -- display only, e.g. "noadd_ab12"
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,                   -- NULL until first use; throttled
    expires_at   INTEGER                    -- NULL = never expires
);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
```

`ON DELETE CASCADE`: deleting an operator revokes their keys. `token_hash` is
`UNIQUE` and thus indexed for validation lookups. `name`: trimmed, non-empty,
1–64 chars.

### Token format & hashing

- Full token: `noadd_` + 40 alphanumeric chars (`generate_token`-style sampling).
- `prefix`: literal `noadd_` + first 4 body chars (e.g. `noadd_ab12`) — enough to
  identify a key in a list, not enough to use it.
- `token_hash`: BLAKE2b-256 of the **full token string**, lower-hex encoded.
- Validation: hash the presented bearer token, look up `token_hash`, check
  `expires_at` (if set) against now. Constant-time concerns are moot — the lookup
  keys on the hash via an index, not on the secret.

## Migration (user_version 8)

1. `CREATE TABLE api_keys (…)` + `CREATE INDEX idx_api_keys_user`.
2. Bump `LATEST_VERSION` 7 → 8.

Fresh DBs get `api_keys` from the top-level `CREATE TABLE IF NOT EXISTS` block
(same idempotent pattern as the other tables); existing DBs get it via the
`version < 8` migration step. No data changes to any other table.

## Auth flow changes

Today every mutating handler calls `require_auth(&state, &jar)?`, and
`current_session(state, jar)` resolves the `session` cookie to a `user_id`.

Introduce a single principal resolver that accepts **both** sources:

```
resolve_principal(state, jar, headers) -> Result<(user_id, AuthKind), 401>:
    1. session cookie present?      -> validate_session      -> (user_id, Session)
    2. else Authorization: Bearer?  -> validate_api_key(db)  -> (user_id, ApiKey)
    3. else                         -> 401
```

- **Preferred mechanism: an axum `AuthedUser` extractor** implementing
  `FromRequestParts`. It pulls the `CookieJar` and `HeaderMap` off the request
  parts itself and runs `resolve_principal`, so a handler just adds one
  `auth: AuthedUser` parameter (exposing `auth.user_id`) and drops its manual
  `require_auth(&state, &jar)?` call — no `HeaderMap` threading, uniform 401.
  `validate_api_key` is async, so the extractor is async (allowed for
  `FromRequestParts`).
- `current_session` stays for the handlers that specifically need the current
  session **token** (e.g. `is_current` in the session list, cookie clearing on
  self-logout); those are session-only by nature and unaffected by API keys.
- `validate_api_key` hashes the token, looks up `api_keys` by `token_hash`,
  rejects if missing or `expires_at` elapsed, and returns `user_id`.
- **`last_used_at` is throttled**: updated only if unset or older than 60 s, to
  avoid a DB write on every request (mirrors the spirit of `flush_last_seen`).
- Endpoints that must stay session-only: none required, but **API-key management
  endpoints below are reachable by either auth kind** (you can bootstrap keys from
  the browser, or manage them with an existing key).
- `login`, `setup`, `health` remain unauthenticated as today.

## API endpoints (new)

All require auth (session or API key); a key resolves to its owning operator.

| Method | Path | Behavior |
|--------|------|----------|
| GET | `/api/api-keys` | List the **caller's own** keys: `{id, name, prefix, created_at, last_used_at, expires_at}`. Never returns the secret or hash. |
| POST | `/api/api-keys` | Create `{name, expires_at?}` for the caller. Returns `{id, name, prefix, token}` — `token` is the **only** time the full secret is shown. 400 on invalid name. |
| DELETE | `/api/api-keys/{id}` | Revoke one of the caller's keys. 404 if the id is not owned by the caller (no cross-operator revocation, no existence oracle). |

## OpenAPI surface (core subset)

Annotate these existing handlers with `#[utoipa::path]` and their request/response
structs with `#[derive(ToSchema)]`. Chosen for the "automate rules/lists + check
health" programmatic story; ~16 operations + the 3 new key endpoints:

- `GET /api/health`, `GET /api/server-info`
- `GET /api/settings`, `PUT /api/settings`
- `GET /api/lists`, `POST /api/lists`, `PUT /api/lists/{id}`, `DELETE /api/lists/{id}`
- `GET /api/rules`, `POST /api/rules`, `DELETE /api/rules/{id}`
- `POST /api/filter/check`
- `GET /api/stats/summary`
- `GET/POST /api/api-keys`, `DELETE /api/api-keys/{id}`

Everything else (all v1/v2 stats, `sessions`, `users`, `doh-tokens`,
`mobileconfig`, icon) is **omitted from the spec for now** — annotations are
additive and can be filled in later.

`ApiDoc` (a `#[derive(OpenApi)]` struct) declares:

- `paths(...)` — the annotated handlers above.
- `components(schemas(...))` — the DTOs (`AddListRequest`, `AddRuleRequest`,
  `FilterCheckRequest/Response`, `StatsSummary`, `AddApiKeyRequest`,
  `ApiKeyRow`, …).
- A **bearer `SecurityScheme`** (`http`, scheme `bearer`) named e.g. `api_key`, so
  Scalar renders an Authorize button and marks protected operations.

Serving (merged into `admin_router`, no change to existing routes):

- `GET /api/openapi.json` → `ApiDoc::openapi()` as JSON.
- `GET /api/docs` → Scalar UI (via `utoipa-scalar`'s axum integration).

## Admin UI (`admin-ui/dist/index.html`)

Single vanilla-JS web-components file; reuse existing classes (`card`,
`card-title`, `input-row`, `table-wrap`, `btn*`, `badge`, `.mono`). Extend the
existing **Account** page (added by the multi-user work) with an **API Keys**
card, mirroring the DoH-tokens UI:

- Table: name / prefix (`.mono`) / created / last used / expires / revoke.
- "Create API Key" form: name (+ optional expiry). On create, show the full token
  **once** in a copy-to-clipboard callout with an explicit "you won't see this
  again" warning; it disappears on dismiss.
- A small link to `/api/docs` ("Interactive API reference").

## Testing

- DB layer: `api_keys` insert (stores hash + prefix, not plaintext), lookup by
  hash, list-by-user, delete-by-(id,user), unique `token_hash`, `expires_at`
  handling, `ON DELETE CASCADE` when a user is deleted.
- Auth: valid bearer → resolves to owner `user_id`; unknown/expired/garbage token
  → 401; bearer and cookie both absent → 401; a key of user A cannot act as user
  B; downstream handler behaves identically under key vs session auth.
- Endpoints: create returns full token once (and only once), list never leaks
  secret/hash, revoke removes and 404s cross-operator ids, invalid name → 400.
- `last_used_at` throttling: updated on first use, not rewritten within 60 s.
- Migration: v7→v8 creates `api_keys` + index, preserves all other tables' rows.
- OpenAPI: `GET /api/openapi.json` is valid JSON, includes the core paths and the
  bearer security scheme; `GET /api/docs` returns 200 HTML.
- e2e (if feasible): create a key in the UI, use it via `Authorization: Bearer`
  against `GET /api/rules`, then revoke and confirm 401.

## Documentation & screenshots

- `ARCHITECTURE.md`: add `api_keys` to the storage table list; note the dual auth
  model (cookie session + bearer API key) and the `/api/docs` endpoint.
- `README.md`: add a short "Programmatic API" section — how to mint a key, the
  `Authorization: Bearer` header, and a link to `/api/docs`.
- Regenerate affected `docs/screenshots/` (Account page with the API Keys card)
  via `cd e2e && npm run screenshots` and commit the PNGs.

## Resolved decisions

1. **Docs endpoints stay open** (unauthenticated). `/api/docs` and
   `/api/openapi.json` expose only the API shape, no data; every underlying
   endpoint still enforces auth. (Later changed: both endpoints now require
   an authenticated operator, to minimize pre-auth recon.)
2. **Key expiry is optional, UI defaults to "never"** (`expires_at` NULL).
3. **Token shape**: `noadd_` prefix + 40 alphanumeric chars; the stored/displayed
   `prefix` is `noadd_` + the first 4 body chars.
