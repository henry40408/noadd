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

/// Thread-safe session store. Maps token -> session metadata.
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

/// BLAKE2b-512 hash of an API key, lower-hex encoded. Fast one-way hash — the
/// token is high-entropy random, so no salt/Argon2 is needed, and the hex digest
/// is directly indexable for lookup.
pub fn hash_api_key(token: &str) -> String {
    use std::fmt::Write as _;
    let mut hasher = Blake2b512::new();
    hasher.update(token.as_bytes());
    hasher.finalize().iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
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
/// no-ops. Must run before any session event is logged — in particular,
/// before `load_sessions_from_db`, whose startup restore can otherwise emit
/// expiry events under a different (temporary random) salt than everything
/// logged afterwards.
pub fn init_session_log_salt(salt: [u8; 16]) {
    let _ = SESSION_LOG_SALT.set(salt);
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

/// Salted, truncated `BLAKE2b` digest of a session token: a stable,
/// non-reversible identifier safe to write to logs, so session events can be
/// correlated without ever disclosing the token. Never log the token itself.
///
/// Deliberately not called for a successful session validation: that path
/// runs on every request, so logging it there would drown the audit log
/// without adding anything an audit needs — only a session's creation and
/// destruction are lifecycle events worth recording. A successful API key use
/// is likewise not logged per-call; it is already tracked via
/// `api_keys.last_used_at`.
pub fn session_log_id(token: &str) -> String {
    let salt = SESSION_LOG_SALT.get_or_init(|| {
        let mut s = [0u8; 16];
        s.fill_with(rand::random);
        s
    });
    let mut hasher = Blake2b512::new();
    hasher.update(salt);
    hasher.update(token.as_bytes());
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

/// Record a session in the in-memory store.
pub fn store_session(store: &SessionStore, token: &str, info: SessionInfo) {
    store.lock().insert(token.to_string(), info);
}

/// Validate a token. Returns the owning `user_id` and refreshes `last_seen`,
/// or `None` if missing/expired (expired entries are dropped).
pub fn validate_session(store: &SessionStore, token: &str) -> Option<i64> {
    let now = now_secs();
    // Reason for eviction, resolved under the lock and logged after it is
    // dropped so no log formatting happens while the store is held.
    let mut expired: Option<(i64, &'static str)> = None;
    {
        let mut map = store.lock();
        if let Some(info) = map.get_mut(token) {
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
                    map.remove(token);
                }
            }
        }
    }
    if let Some((session_id, reason)) = expired {
        tracing::info!(
            event = "session.destroyed",
            reason,
            session_id,
            sid_hash = %session_log_id(token),
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
/// caller's responsibility (see `delete_session_by_token`).
pub fn revoke_session(store: &SessionStore, token: &str) {
    store.lock().remove(token);
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
            s.token,
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
        .map(|(token, info)| (token.clone(), info.last_seen))
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

/// Revoke every session except `keep` (log out other devices, staying signed
/// in on the current one). When `keep` is `None` — e.g. a forward-auth caller
/// that holds no session cookie — every session is revoked, since none of them
/// is the caller's own device. Returns the number of sessions revoked, for
/// the caller's audit log.
pub async fn revoke_other_sessions(
    store: &SessionStore,
    db: &crate::db::Database,
    keep: Option<&str>,
) -> Result<usize, crate::db::DbError> {
    if let Some(token) = keep {
        store.lock().retain(|t, _| t == token);
        db.delete_sessions_except(token).await
    } else {
        store.lock().clear();
        db.delete_all_sessions().await
    }
}

/// Revoke every session owned by `user_id` except `keep` (the caller's own
/// device). `keep = None` revokes all of that user's sessions. Unlike
/// [`revoke_other_sessions`], other operators are unaffected — which is the
/// required semantics after a password change, where only the account whose
/// credential changed may be logged out.
pub async fn revoke_user_sessions_except(
    store: &SessionStore,
    db: &crate::db::Database,
    user_id: i64,
    keep: Option<&str>,
) -> Result<usize, crate::db::DbError> {
    let removed = db.delete_user_sessions_except(user_id, keep).await?;
    store
        .lock()
        .retain(|t, info| info.user_id != user_id || keep == Some(t.as_str()));
    Ok(removed)
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

/// Simple IP-based rate limiter for login attempts.
///
/// Tracks the number of attempts per IP within a sliding window.
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
}
