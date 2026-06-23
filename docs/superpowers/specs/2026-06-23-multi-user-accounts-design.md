# Multi-user admin accounts — Design

Date: 2026-06-23
Status: Approved (pending spec review)

## Goal

Replace noadd's single password-only admin login with **multiple named operator
accounts**. Each operator logs in with a username + password, has an independent
session, and can manage other operators and active sessions from the admin UI.

This is "direction A" (web login accounts), explicitly chosen over "direction B"
(AdGuard-style per-client filtering policies). Direction B is out of scope.

## Scope

In scope:

- Multiple operator accounts, each `username` + Argon2 password hash.
- No role tiers — every operator has full admin access (matches AdGuard Home).
- Full account CRUD in the admin UI: list, add, delete operators.
- Change **own** password.
- Manageable sessions: list all active sessions across all operators, and revoke
  any individual session; keep "revoke all".

Out of scope (YAGNI — explicitly not built):

- Role / permission tiers (admin vs read-only).
- Per-client filtering policies (direction B).
- Resetting **another** operator's password.
- Login / account audit log.

## Decisions & rationale

- **No default account on upgrade.** A predictable default username (e.g. fixed
  `admin`) halves brute-force search space — the classic default-credential
  weakness. On upgrade the existing credential is dropped and the instance
  re-enters first-boot setup so the operator picks their own username. **No
  business data is lost** (query logs, filter lists, custom rules, DoH tokens,
  and all other settings are preserved) — only the login credential resets.
- **Keep Argon2.** noadd already hashes with Argon2; we do not switch to bcrypt.
- **Dedicated `sessions` table** replaces the `settings.sessions` string blob, so
  sessions carry a `user_id` and can be revoked per-user (needed for "delete
  operator → drop their sessions" and the session-management UI).
- **Tokens are never returned to the client.** The session list is keyed to the
  client by a surrogate `id`; exposing raw tokens would equal session hijacking
  if the list leaked.

## Data model

Schema version bumps `5 → 6`. Two new tables:

```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,      -- case-sensitive, unique
    password_hash TEXT NOT NULL,             -- Argon2
    created_at    INTEGER NOT NULL
);

CREATE TABLE sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT NOT NULL UNIQUE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    ip          TEXT,
    user_agent  TEXT
);
```

`username` validation: trimmed, non-empty, 1–64 chars, unique. Password: min 8
chars (existing `MIN_PASSWORD_LENGTH`).

## Migration (user_version 6)

1. Create `users` and `sessions` tables.
2. Delete `settings` keys `admin_password_hash` and `sessions`.

Result: `users` is empty → instance reports `needs_setup` → first-boot setup
wizard creates the first operator. All other tables untouched.

## In-memory session store

`SessionStore` changes from `HashMap<token, created_at>` to
`HashMap<token, SessionInfo { session_id, user_id, created_at, last_seen }>`,
still behind the existing `Mutex`.

- On login: insert a `sessions` row (with `ip` from the existing `client_ip`
  helper and `user_agent` from the request header) and the in-memory entry.
- On revoke / logout / delete-user: remove the row(s) and in-memory entries.
- `last_seen` is updated in memory during `validate_session` and flushed to the
  DB on the existing periodic/persist path. `validate_session` runs only on
  admin API requests, **never on the DNS query path**, so there is zero query
  performance impact.
- On startup, sessions are loaded from the `sessions` table (joined to `users`);
  expired sessions (older than `SESSION_MAX_AGE_SECS`) are discarded.

## Authentication flow changes

- `needs_setup` is now `COUNT(*) FROM users == 0` (was: `admin_password_hash`
  absent).
- `POST /api/auth/setup` body becomes `{username, password}`; allowed only when
  there are zero users; creates the first operator. Returns 409 if already
  configured.
- `POST /api/auth/login` body becomes `{username, password}`; look up user by
  username, verify hash, create a session bound to `user_id`. Returns a generic
  `401` whether the username is unknown or the password is wrong (no user
  enumeration). Per-IP `RateLimiter` is unchanged and still applied.

## API endpoints

All require `require_auth` except `setup`, `login`, and `health`.

| Method | Path | Behavior |
|--------|------|----------|
| GET | `/api/auth/me` | Current operator `{id, username}` (for UI display + gating change-password). |
| GET | `/api/users` | List operators `{id, username, created_at}`. Never returns hashes. |
| POST | `/api/users` | Create operator `{username, password}`. 409 on duplicate username; 400 on invalid username/short password. |
| DELETE | `/api/users/{id}` | Delete operator. **409 if it is the last remaining operator.** Cascades to that operator's sessions (in-memory entries removed too). |
| POST | `/api/users/me/password` | Change own password `{current_password, new_password}`. Verifies current password; 400 on short new password. |
| GET | `/api/sessions` | List all active sessions: `{id, username, created_at, last_seen, ip, user_agent, is_current}`. Never returns tokens. `is_current` is computed server-side by matching the request's cookie token. |
| DELETE | `/api/sessions/{id}` | Revoke a specific session (own or anyone's). If it is the caller's current session, also clears the session cookie. |
| POST | `/api/auth/revoke-all` | Existing "log out everywhere" (revoke all sessions). |
| POST | `/api/auth/logout` | Existing single-session logout (current token). |

Deleting your own (non-last) account revokes your session; the frontend detects
the resulting `401` and returns to the login screen.

## Admin UI (`admin-ui/dist/index.html`)

Single vanilla-JS web-components file; reuse existing classes (`card`,
`card-title`, `input-row`, `table-wrap`, `btn`/`btn-primary`/`btn-danger`/
`btn-sm`, `badge badge-allowed`, `.mono`, `login-box boot`, `boot-log`,
`login-line`, `boot-submit`). Validated against real CSS in the brainstorm
companion.

- **Setup page**: add a `username:` `login-line` above password; keep `confirm:`;
  boot-log shows `admin account ...... none`.
- **Login page**: add a `username:` `login-line` above password.
- **New "Account" nav page** with three cards:
  1. **This Account** — shows `Signed in as <username>`; Change Password form
     (current / new / confirm).
  2. **Operators** — `table-wrap` table (username / created / delete); current
     operator row tagged with a `badge` and its delete button disabled; the last
     remaining operator's delete is also disabled. Add Operator form: username /
     password / confirm password (password entered twice).
  3. **Active Sessions** — table (operator / ip / browser / signed in / last
     seen / revoke); current session tagged "this device"; "Revoke All Other
     Sessions" button.
- The existing **Sessions** card in the Settings page (its "Revoke All Sessions"
  button) is folded into the Account page and removed from Settings.

## Testing

- DB layer: `users` CRUD; `sessions` CRUD; unique-username constraint; delete
  user cascades sessions; last-user-delete guarded at the API layer.
- Migration: v5→v6 creates tables, deletes `admin_password_hash` + old `sessions`
  blob, and preserves other tables' rows (logs, lists, rules, tokens, settings).
- Auth endpoints: setup requires empty users and sets `{username,password}`;
  login verifies username+password and returns generic 401 on bad creds;
  `needs_setup` reflects user count.
- Users endpoints: create (dup → 409, short pw → 400), list (no hashes), delete
  (last → 409, cascades sessions), change-own-password (wrong current → reject).
- Sessions endpoints: list (no tokens, `is_current` correct), revoke individual
  (own current clears cookie; others' revoked), revoke-all.

## Documentation & screenshots

- `ARCHITECTURE.md`: add `users` and `sessions` to the storage table list; note
  the auth model change.
- `README.md`: update any single-password login references to username+password
  and the first-boot flow.
- Regenerate affected `docs/screenshots/` (login, setup, new Account page) via
  `cd e2e && npm run screenshots` and commit the PNGs.
- e2e: update login/setup BDD steps to supply a username; add steps for operator
  add/delete and session revoke if feasible.
