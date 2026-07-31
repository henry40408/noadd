use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use blake2::{Blake2b512, Digest};
use parking_lot::Mutex;
use rand::RngExt;
use rand::distr::Alphanumeric;

/// Wrapper around `rand::rngs::OsRng` that implements `rand_core` 0.6 traits
/// needed by `password-hash`'s `SaltString::generate`.
struct OsRngCompat;

impl argon2::password_hash::rand_core::RngCore for OsRngCompat {
    fn next_u32(&mut self) -> u32 {
        rand::random()
    }
    fn next_u64(&mut self) -> u64 {
        rand::random()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill_with(rand::random);
    }
    fn try_fill_bytes(
        &mut self,
        dest: &mut [u8],
    ) -> Result<(), argon2::password_hash::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl argon2::password_hash::rand_core::CryptoRng for OsRngCompat {}

/// Session expiry in seconds (7 days).
pub const SESSION_MAX_AGE_SECS: i64 = 7 * 86400;

/// Idle (inactivity) expiry in seconds (48 hours). Deliberately the same order
/// of magnitude as [`SESSION_MAX_AGE_SECS`] rather than OWASP's 15-30 minute
/// suggestion: noadd is a self-hosted appliance whose operators expect a
/// long-lived admin tab, and the requirement being satisfied here is that both
/// an idle layer and an absolute layer exist — not a specific figure.
///
/// This window measures time since the last *request* this device made, not
/// time since a human last looked at the screen — a conventional
/// simplification for a server-side idle timeout, but narrower than it
/// sounds in practice: the admin SPA polls `/api/filter/rebuild-status`
/// every 2s and the dashboard every 10s while a tab is open, and both trips
/// refresh `last_seen` via `validate_session`, so this layer only actually
/// expires sessions whose browser tab was closed (or whose machine slept).
///
/// `last_seen` is only flushed to disk every 60s (see `flush_last_seen`), so a
/// value reloaded after a restart can lag reality by up to that long. Against
/// a 48h window that's a 0.03% error and requires no compensation. If a future
/// maintainer lowers this constant to the same order of magnitude as the flush
/// interval (e.g. below ~15 minutes), the flush interval must be shortened — or
/// a `flush_last_seen` call added to the graceful shutdown path — first.
pub const SESSION_IDLE_TIMEOUT_SECS: i64 = 2 * 86400;

/// In-memory session metadata. Persisted to the `sessions` table on creation
/// and revocation; `last_seen` is flushed periodically (see `flush_last_seen`).
#[derive(Debug, Clone, Copy)]
pub struct SessionInfo {
    pub session_id: i64,
    pub user_id: i64,
    pub created_at: i64,
    pub last_seen: i64,
}

/// Thread-safe session store. Maps **token hash** (see [`hash_session_token`])
/// -> session metadata.
///
/// Keyed by the hash rather than the token so that the raw token exists in
/// exactly two places — the `Set-Cookie` header on the way out and the
/// `Cookie` header on the way back in — and nowhere in noadd's own state.
/// The store and the `sessions` table therefore agree on one identifier, which
/// is what lets a row deleted by id be evicted from memory by the value the
/// DELETE returned.
pub type SessionStore = Arc<Mutex<HashMap<String, SessionInfo>>>;

/// Create a new, empty session store.
pub fn new_session_store() -> SessionStore {
    Arc::new(Mutex::new(HashMap::new()))
}

use crate::now_unix as now_secs;

/// Generate a fresh 64-character alphanumeric session token.
pub fn generate_token() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

/// Session cookie name on a plain-HTTP deployment.
pub const SESSION_COOKIE: &str = "session";

/// Session cookie name when the cookie carries `Secure`. The `__Host-` prefix
/// makes the browser itself enforce `Secure` + `Path=/` + no `Domain`, and
/// blocks a subdomain from overwriting it (session fixation).
pub const SESSION_COOKIE_HOST: &str = "__Host-session";

/// The cookie name to *emit*. Conditional on `cookie_secure`: a browser
/// silently rejects a `__Host-`-prefixed cookie that is not `Secure` and not
/// delivered over HTTPS, so emitting it unconditionally would make login
/// appear to succeed and then fail on the next request — on exactly the
/// HTTP-only internal deployments `resolve_cookie_secure` exists to support.
/// The reverse move (an HTTPS deployment dropped back to HTTP) is not covered
/// by this fallback: a browser holding `__Host-session` will not send it over
/// plain HTTP, so that operator has to log in again once.
pub fn session_cookie_name(cookie_secure: bool) -> &'static str {
    if cookie_secure {
        SESSION_COOKIE_HOST
    } else {
        SESSION_COOKIE
    }
}

/// Prefix identifying a noadd programmatic API key (useful for secret scanners).
const API_KEY_PREFIX: &str = "noadd_";
/// Random body length; 40 alphanumeric chars ≈ 238 bits of entropy.
const API_KEY_BODY_LEN: usize = 40;

/// BLAKE2b-512 of `secret`, lower-hex encoded. Fast one-way hash with no salt:
/// every secret hashed here is high-entropy random, so there is no dictionary
/// to defend against and nothing for Argon2 to buy, while the hex digest stays
/// directly indexable for an equality lookup.
fn blake2b_hex(secret: &str) -> String {
    use std::fmt::Write as _;
    let mut hasher = Blake2b512::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Hash of an API key, as stored in `api_keys.token_hash`.
pub fn hash_api_key(token: &str) -> String {
    blake2b_hex(token)
}

/// Hash of a session token, as stored in `sessions.token_hash` and used as the
/// [`SessionStore`] key.
///
/// Same construction as [`hash_api_key`], and for the same reason: a copy of
/// the database — a backup, a stray WAL file, a snapshot on a disposed SD card
/// — must not hand over live credentials. Before this, API keys were hashed
/// while session tokens sat in the same file in plaintext, so the weaker of
/// the two set the real bar.
///
/// This is *not* [`session_log_id`]: that one is salted and truncated for log
/// correlation and cannot be looked up. This one must be deterministic and
/// unsalted precisely so a presented cookie can find its row.
pub fn hash_session_token(token: &str) -> String {
    blake2b_hex(token)
}

/// Process-wide salt for [`session_log_id`]. Installed once at startup from the
/// value persisted in `settings` (see [`load_or_create_session_log_salt`]) so
/// log identifiers stay correlatable across restarts. If it is never
/// installed (unit tests), a random salt is generated on first use — never an
/// empty or fixed one, so an unsalted digest can never reach a log.
static SESSION_LOG_SALT: OnceLock<[u8; 16]> = OnceLock::new();

/// Settings key holding the hex-encoded audit-log salt.
pub const SESSION_LOG_SALT_KEY: &str = "session_log_salt";

/// Install the process-wide audit salt. The first call wins; later calls are
/// no-ops other than a warning. Must run before any session event of any kind
/// is logged: a `sid_hash` computed before this call would be salted with a
/// temporary random value instead of the persisted one, and would then never
/// correlate with anything logged afterwards under the real salt.
pub fn init_session_log_salt(salt: [u8; 16]) {
    if SESSION_LOG_SALT.set(salt).is_err() {
        tracing::warn!(
            event = "audit.salt_reinit_ignored",
            "audit salt already initialised; session log ids will not correlate across restarts"
        );
    }
}

/// Read the persisted audit salt from `settings`, generating and storing one
/// on first run.
pub async fn load_or_create_session_log_salt(
    db: &crate::db::Database,
) -> Result<[u8; 16], crate::db::DbError> {
    if let Some(hex) = db.get_setting(SESSION_LOG_SALT_KEY).await?
        && let Some(salt) = decode_hex_salt(&hex)
    {
        return Ok(salt);
    }
    let mut salt = [0u8; 16];
    salt.fill_with(rand::random);
    use std::fmt::Write as _;
    let hex = salt.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    });
    db.set_setting(SESSION_LOG_SALT_KEY, &hex).await?;
    Ok(salt)
}

/// Decode a 32-character lower-hex string into 16 bytes, or `None` if it is
/// the wrong length or contains non-hex characters — a corrupted or
/// hand-edited setting falls back to generating a fresh salt rather than
/// panicking.
fn decode_hex_salt(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// Salted, truncated `BLAKE2b` digest of a session's token hash: a stable,
/// non-reversible identifier safe to write to logs, so session events can be
/// correlated without ever disclosing the token. Never log the token itself.
///
/// Takes the hash rather than the raw token — that is the only identifier the
/// logging call sites still hold (see [`hash_session_token`]) — and the salt
/// is what keeps this distinct from the stored `token_hash`, so a log line can
/// never be matched against a stolen database row.
///
/// Deliberately not called for a successful session validation: that path
/// runs on every request, so logging it there would drown the audit log
/// without adding anything an audit needs — only a session's creation and
/// destruction are lifecycle events worth recording. A successful API key use
/// is likewise not logged per-call; it is already tracked via
/// `api_keys.last_used_at`.
pub fn session_log_id(token_hash: &str) -> String {
    let salt = SESSION_LOG_SALT.get_or_init(|| {
        let mut s = [0u8; 16];
        s.fill_with(rand::random);
        s
    });
    session_log_id_with(salt, token_hash)
}

/// [`session_log_id`]'s digest under an explicit salt, split out so the
/// salting property itself is directly testable — a test driving the
/// process-wide `OnceLock` can only ever exercise one salt value per process.
fn session_log_id_with(salt: &[u8; 16], token_hash: &str) -> String {
    let mut hasher = Blake2b512::new();
    hasher.update(salt);
    hasher.update(token_hash.as_bytes());
    use std::fmt::Write as _;
    // 16 hex chars (64 bits) is far more than enough to correlate the handful
    // of sessions one appliance ever has, and keeps log lines readable.
    hasher.finalize()[..8]
        .iter()
        .fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// Mint a fresh API key. Returns `(full_token, display_prefix, token_hash)`.
/// The full token is shown to the user exactly once; only the hash is stored.
pub fn generate_api_key() -> (String, String, String) {
    let body: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(API_KEY_BODY_LEN)
        .map(char::from)
        .collect();
    let full = format!("{API_KEY_PREFIX}{body}");
    let prefix = format!("{API_KEY_PREFIX}{}", &body[..4]);
    let hash = hash_api_key(&full);
    (full, prefix, hash)
}

/// Record a session in the in-memory store, keyed by its token hash.
pub fn store_session(store: &SessionStore, token_hash: &str, info: SessionInfo) {
    store.lock().insert(token_hash.to_string(), info);
}

/// Validate a presented session by its token hash. Returns the owning
/// `user_id` and refreshes `last_seen`, or `None` if missing/expired (expired
/// entries are dropped).
pub fn validate_session(store: &SessionStore, token_hash: &str) -> Option<i64> {
    let now = now_secs();
    // Reason for eviction, resolved under the lock and logged after it is
    // dropped so no log formatting happens while the store is held.
    let mut expired: Option<(i64, &'static str)> = None;
    {
        let mut map = store.lock();
        if let Some(info) = map.get_mut(token_hash) {
            // Order matters: the idle check must read `last_seen` *before*
            // this request refreshes it, otherwise it can never fire. A clock
            // going backwards just makes these subtractions negative, which
            // compares as "not expired" rather than misfiring.
            let reason = if now - info.created_at >= SESSION_MAX_AGE_SECS {
                Some("expired_absolute")
            } else if now - info.last_seen >= SESSION_IDLE_TIMEOUT_SECS {
                Some("expired_idle")
            } else {
                None
            };
            match reason {
                None => {
                    info.last_seen = now;
                    return Some(info.user_id);
                }
                Some(r) => {
                    expired = Some((info.session_id, r));
                    map.remove(token_hash);
                }
            }
        }
    }
    if let Some((session_id, reason)) = expired {
        tracing::info!(
            event = "session.destroyed",
            reason,
            session_id,
            sid_hash = %session_log_id(token_hash),
            "session expired"
        );
    }
    None
}

/// Drop in-memory sessions that have hit either timeout. Returns how many were
/// evicted. `validate_session` expires lazily (only on access), so a session
/// nobody touches stays in the map until this runs.
pub fn prune_expired(store: &SessionStore) -> usize {
    let now = now_secs();
    let mut map = store.lock();
    let before = map.len();
    map.retain(|_, info| {
        now - info.created_at < SESSION_MAX_AGE_SECS
            && now - info.last_seen < SESSION_IDLE_TIMEOUT_SECS
    });
    before - map.len()
}

/// Revoke a single session token (logout this device only).
///
/// Leaves every other session intact. Persistence to the database is the
/// caller's responsibility (see `delete_session_by_token_hash`). Returns the
/// evicted session's info, or `None` if `token_hash` did not name a live
/// session — callers that log a `session.destroyed` event must gate on `Some`
/// so an unvalidated/fabricated token (e.g. read from a client-supplied
/// cookie) cannot inject a destruction event for a session that never existed.
pub fn revoke_session(store: &SessionStore, token_hash: &str) -> Option<SessionInfo> {
    store.lock().remove(token_hash)
}

/// Load persisted sessions from the `sessions` table into the store.
/// Expired rows are purged by `Database::load_sessions`.
pub async fn load_sessions_from_db(
    store: &SessionStore,
    db: &crate::db::Database,
) -> Result<(), crate::db::DbError> {
    let now = now_secs();
    let loaded = db
        .load_sessions(SESSION_MAX_AGE_SECS, SESSION_IDLE_TIMEOUT_SECS, now)
        .await?;
    let mut map = store.lock();
    for s in loaded {
        map.insert(
            s.token_hash,
            SessionInfo {
                session_id: s.id,
                user_id: s.user_id,
                created_at: s.created_at,
                last_seen: s.last_seen,
            },
        );
    }
    Ok(())
}

/// Flush in-memory `last_seen` values to the database.
pub async fn flush_last_seen(
    store: &SessionStore,
    db: &crate::db::Database,
) -> Result<(), crate::db::DbError> {
    let entries: Vec<(String, i64)> = store
        .lock()
        .iter()
        .map(|(token_hash, info)| (token_hash.clone(), info.last_seen))
        .collect();
    db.flush_sessions_last_seen(&entries).await
}

/// Sweep expired sessions from both the in-memory store and the `sessions`
/// table. Returns `(evicted_from_memory, deleted_rows)`.
///
/// The caller must flush `last_seen` first (see `flush_last_seen`): the DB
/// predicate reads `last_seen`, which lags memory by up to one flush interval.
/// With a 48 h idle window a 60 s lag is immaterial, but flushing first keeps
/// the two views from diverging on principle.
pub async fn sweep_expired(
    store: &SessionStore,
    db: &crate::db::Database,
) -> Result<(usize, usize), crate::db::DbError> {
    let evicted = prune_expired(store);
    let now = now_secs();
    let deleted = db
        .purge_expired_sessions(SESSION_MAX_AGE_SECS, SESSION_IDLE_TIMEOUT_SECS, now)
        .await?;
    Ok((evicted, deleted))
}

/// Revoke every session except the one whose token hash is `keep` (log out
/// other devices, staying signed in on the current one). When `keep` is `None`
/// — e.g. a forward-auth caller that holds no session cookie — every session is
/// revoked, since none of them is the caller's own device. Returns the number
/// of sessions revoked, for the caller's audit log.
pub async fn revoke_other_sessions(
    store: &SessionStore,
    db: &crate::db::Database,
    keep: Option<&str>,
) -> Result<usize, crate::db::DbError> {
    if let Some(keep_hash) = keep {
        store.lock().retain(|hash, _| hash == keep_hash);
        db.delete_sessions_except(keep_hash).await
    } else {
        store.lock().clear();
        db.delete_all_sessions().await
    }
}

/// Revoke every session owned by `user_id` except the one whose token hash is
/// `keep` (the caller's own device). `keep = None` revokes all of that user's
/// sessions. Unlike
/// [`revoke_other_sessions`], other operators are unaffected — which is the
/// required semantics after a password change, where only the account whose
/// credential changed may be logged out.
///
/// Returns the number of sessions actually evicted from the in-memory store —
/// the in-memory `retain` below is what actually terminates authentication,
/// not the row count the DB delete returns, and the two can diverge in both
/// directions: a lazily-expired session's row lingers in the DB until the
/// periodic sweep (counted in rows, not evicted from memory), while a session
/// already swept from the DB can still be live in memory (evicted here, not
/// counted in rows). For "how many devices did this action sign out?", the
/// in-memory count is the number an operator actually reads it as.
pub async fn revoke_user_sessions_except(
    store: &SessionStore,
    db: &crate::db::Database,
    user_id: i64,
    keep: Option<&str>,
) -> Result<usize, crate::db::DbError> {
    db.delete_user_sessions_except(user_id, keep).await?;
    let mut map = store.lock();
    let before = map.len();
    map.retain(|hash, info| info.user_id != user_id || keep == Some(hash.as_str()));
    Ok(before - map.len())
}

/// Hash a password using Argon2 with a random salt.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRngCompat);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2 hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Stored in `users.password_hash` for operators provisioned from a trusted
/// forward-auth header. `!` is not a valid PHC string, so it can never match a
/// real Argon2 hash — the same convention `/etc/shadow` uses to mark an account
/// as having no usable password, and it keeps the column `NOT NULL` so no
/// schema migration is needed.
///
/// Every password-verifying path checks this explicitly rather than relying on
/// the PHC parse failing: [`verify_password`] reports an unparseable stored hash
/// as an `Err`, which callers surface as a 500. That is the right answer for a
/// corrupted row, but the wrong answer for a passwordless account, which must be
/// an ordinary 401.
pub const NO_PASSWORD_SENTINEL: &str = "!";

/// True when the stored hash marks an account that cannot authenticate with a
/// password (see [`NO_PASSWORD_SENTINEL`]).
pub fn has_no_password(hash: &str) -> bool {
    hash == NO_PASSWORD_SENTINEL
}

/// How many unknown session tokens one client may present within
/// [`INVALID_SESSION_WINDOW_SECS`] before the burst is reported. A browser
/// whose session expired legitimately keeps presenting its stale cookie on
/// every poll (the admin SPA polls every 2s), so a threshold well above one
/// is what separates "somebody's tab went stale" from "somebody is guessing
/// session IDs" — the single-occurrence event would be pure noise.
pub const INVALID_SESSION_MAX_ATTEMPTS: u32 = 10;

/// Sliding window for [`INVALID_SESSION_MAX_ATTEMPTS`].
pub const INVALID_SESSION_WINDOW_SECS: u64 = 60;

/// Simple IP-based sliding-window counter, used both to rate-limit login
/// attempts and to detect bursts of unknown session tokens.
///
/// Tracks the number of attempts per IP within a sliding window. Instances are
/// per-signal: sharing one across signals would let an attacker guessing
/// session cookies consume a legitimate operator's login budget from the same
/// NAT address.
pub struct RateLimiter {
    attempts: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    max_attempts: u32,
    window_secs: u64,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// - `max_attempts`: maximum allowed attempts within the window
    /// - `window_secs`: the time window in seconds
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
            window_secs,
        }
    }

    /// Check if the given IP is allowed to make another attempt.
    ///
    /// Returns `true` if allowed, `false` if rate limited.
    pub fn check(&self, ip: IpAddr) -> bool {
        let map = self.attempts.lock();
        if let Some((count, started)) = map.get(&ip) {
            if started.elapsed().as_secs() >= self.window_secs {
                // Window expired, allow
                return true;
            }
            *count < self.max_attempts
        } else {
            true
        }
    }

    /// Record an attempt from the given IP.
    pub fn record(&self, ip: IpAddr) {
        let mut map = self.attempts.lock();
        let entry = map.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed().as_secs() >= self.window_secs {
            // Reset window
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
        }
    }

    /// Record an attempt and report whether it is the one that *reached*
    /// `max_attempts` in the current window.
    ///
    /// Returns `true` on exactly one attempt per window, which is what makes
    /// this usable to drive a log line: a caller that instead tested
    /// `count >= max` would re-emit on every further attempt, and the burst
    /// being reported is precisely the case where further attempts keep
    /// arriving.
    pub fn record_crossing(&self, ip: IpAddr) -> bool {
        let mut map = self.attempts.lock();
        let entry = map.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed().as_secs() >= self.window_secs {
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
        }
        entry.0 == self.max_attempts
    }

    /// Drop entries whose window has already elapsed, returning how many were
    /// removed. Without this the map retains one entry per source IP forever,
    /// which a scanner cycling through addresses (trivial from a /64 of IPv6)
    /// turns into unbounded memory growth.
    ///
    /// Unlike `IpRateLimiter::prune`, this takes no `max_age`: an entry whose
    /// window has elapsed carries no information at all here — both `check`
    /// and `record` already treat it as a fresh start — so there is nothing
    /// for a caller to tune, and a too-short `max_age` could otherwise
    /// discard a live window.
    pub fn prune(&self) -> usize {
        let mut map = self.attempts.lock();
        let before = map.len();
        map.retain(|_, (_, started)| started.elapsed().as_secs() < self.window_secs);
        before - map.len()
    }

    /// Current number of tracked IPs. Exposed for observability / tests.
    pub fn tracked_ips(&self) -> usize {
        self.attempts.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_shape_and_prefix() {
        let (full, prefix, hash) = generate_api_key();
        assert!(full.starts_with("noadd_"));
        assert_eq!(full.len(), "noadd_".len() + 40);
        assert!(prefix.starts_with("noadd_"));
        assert_eq!(prefix.len(), "noadd_".len() + 4);
        assert!(full.starts_with(&prefix));
        // hash is deterministic hex of the full token
        assert_eq!(hash, hash_api_key(&full));
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_is_stable_and_distinct() {
        assert_eq!(hash_api_key("noadd_abc"), hash_api_key("noadd_abc"));
        assert_ne!(hash_api_key("noadd_abc"), hash_api_key("noadd_abd"));
    }

    #[test]
    fn has_no_password_only_matches_the_sentinel() {
        assert!(has_no_password(NO_PASSWORD_SENTINEL));
        assert!(!has_no_password(&hash_password("whatever").unwrap()));
        assert!(!has_no_password(""));
    }

    #[test]
    fn verify_password_rejects_the_sentinel_as_unparseable() {
        // This is exactly why callers must check `has_no_password` before
        // calling `verify_password`: the sentinel is not a valid PHC string,
        // so verifying against it fails to parse rather than returning
        // `Ok(false)`, and a caller that mapped `Err` to 500 would turn a
        // passwordless account's login attempt into a server error instead
        // of an ordinary 401.
        assert!(verify_password("anything", NO_PASSWORD_SENTINEL).is_err());
    }

    #[test]
    fn session_log_id_with_actually_depends_on_the_salt() {
        // An unsalted `blake2b(token)` would pass every determinism/distinctness/
        // shape assertion the integration test makes just as well as a salted
        // one — the only thing that proves salting is happening at all is that
        // two different salts over the *same* token produce different ids.
        let token = "same-token-both-times";
        let salt_a = [0x11u8; 16];
        let salt_b = [0x22u8; 16];
        let id_a = session_log_id_with(&salt_a, token);
        let id_b = session_log_id_with(&salt_b, token);
        assert_ne!(id_a, id_b);
        for id in [&id_a, &id_b] {
            assert_eq!(id.len(), 16);
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            );
        }
    }

    #[test]
    fn record_crossing_fires_exactly_once_per_window() {
        let rl = RateLimiter::new(3, 60);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!rl.record_crossing(ip));
        assert!(!rl.record_crossing(ip));
        assert!(rl.record_crossing(ip), "the 3rd attempt reaches the limit");
        // The burst continues; the caller must not be told about it again, or
        // one attacker would produce one log line per request.
        assert!(!rl.record_crossing(ip));
        assert!(!rl.record_crossing(ip));
        // A different IP has its own window.
        assert!(!rl.record_crossing("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn prune_drops_entries_whose_window_elapsed() {
        // A zero-second window makes every entry look elapsed immediately.
        let rl = RateLimiter::new(5, 0);
        rl.record("10.0.0.1".parse().unwrap());
        rl.record("10.0.0.2".parse().unwrap());
        assert_eq!(rl.tracked_ips(), 2);
        assert_eq!(rl.prune(), 2);
        assert_eq!(rl.tracked_ips(), 0);
    }

    #[test]
    fn prune_keeps_entries_whose_window_is_still_live() {
        let rl = RateLimiter::new(5, 3600);
        rl.record("10.0.0.1".parse().unwrap());
        assert_eq!(rl.prune(), 0);
        assert_eq!(rl.tracked_ips(), 1);
    }

    #[test]
    fn decode_hex_salt_round_trips_a_valid_hex_string() {
        let salt: [u8; 16] = std::array::from_fn(|i| i as u8);
        use std::fmt::Write as _;
        let hex = salt.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });
        assert_eq!(decode_hex_salt(&hex), Some(salt));
    }

    #[test]
    fn decode_hex_salt_rejects_the_wrong_length() {
        let too_short = "a".repeat(31);
        let too_long = "a".repeat(33);
        assert_eq!(decode_hex_salt(&too_short), None);
        assert_eq!(decode_hex_salt(&too_long), None);
    }

    #[test]
    fn decode_hex_salt_rejects_non_hex_characters() {
        let non_hex = "g".repeat(32);
        assert_eq!(decode_hex_salt(&non_hex), None);
    }
}
