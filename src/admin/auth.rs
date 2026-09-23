use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use blake2::{Blake2b512, Digest};
use parking_lot::Mutex;
use rand::RngExt;
use rand::distr::Alphanumeric;

/// Session expiry in seconds (7 days).
pub const SESSION_MAX_AGE_SECS: i64 = 7 * 86400;

/// Idle (inactivity) expiry in seconds (48 hours). Long rather than OWASP's
/// 15-30 minutes: operators of a self-hosted appliance expect a long-lived tab,
/// and the requirement is that an idle layer exists alongside the absolute one.
///
/// Measured from the last *request*. An open tab holds one `GET /api/events`,
/// validated only when it connects, so a tab left open past this window does
/// expire and its next navigation or reconnect lands on `/login`.
///
/// `last_seen` is flushed to disk every 60s (see [`flush_last_seen`]), so a
/// restored value can lag by that much — immaterial at 48h. Lowering this
/// toward the flush interval requires shortening the flush (or flushing on
/// shutdown) first.
pub const SESSION_IDLE_TIMEOUT_SECS: i64 = 2 * 86400;

/// In-memory session metadata. Persisted to the `sessions` table on creation
/// and revocation; `last_seen` is flushed periodically (see [`flush_last_seen`]).
#[derive(Debug, Clone, Copy)]
pub struct SessionInfo {
    pub session_id: i64,
    pub user_id: i64,
    pub created_at: i64,
    pub last_seen: i64,
    /// When this session last proved the account's password (login or a later
    /// reauth). Sensitive actions require it within [`REAUTH_WINDOW_SECS`]; see
    /// [`has_fresh_reauth`].
    ///
    /// Deliberately **not** persisted: it goes stale in minutes, and
    /// [`load_sessions_from_db`] falls back to `created_at`, which is the safe
    /// direction — login is what created the session.
    pub last_reauth_at: i64,
}

/// Thread-safe session store: **token hash** (see [`hash_session_token`]) ->
/// session metadata.
///
/// Keyed by the hash so the raw token never lives in noadd's own state, and so
/// the store and the `sessions` table share one identifier — a row deleted by
/// id is evicted from memory by the hash the DELETE returned.
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

/// The cookie name to *emit*. A browser silently drops a `__Host-` cookie that
/// lacks `Secure` or arrives over plain HTTP, so on HTTP deployments login
/// would appear to succeed and then fail. Moving a deployment from HTTPS back
/// to HTTP costs one fresh login, since `__Host-session` is never sent over HTTP.
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

/// BLAKE2b-512 of `secret`, lower-hex. Unsalted and fast on purpose: every
/// input is high-entropy random (no dictionary to defend against), and the
/// digest must stay indexable for an equality lookup.
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
/// Same construction as [`hash_api_key`]: a copy of the database (backup, stray
/// WAL, disposed SD card) must not hand over live credentials. Deterministic
/// and unsalted so a presented cookie can find its row — unlike
/// [`session_log_id`], which is salted for logs and cannot be looked up.
pub fn hash_session_token(token: &str) -> String {
    blake2b_hex(token)
}

/// Process-wide salt for [`session_log_id`], installed at startup from
/// `settings` (see [`load_or_create_session_log_salt`]) so log ids correlate
/// across restarts. If never installed (unit tests), a random one is generated
/// on first use, so an unsalted digest never reaches a log.
static SESSION_LOG_SALT: OnceLock<[u8; 16]> = OnceLock::new();

/// Settings key holding the hex-encoded audit-log salt.
pub const SESSION_LOG_SALT_KEY: &str = "session_log_salt";

/// Install the process-wide audit salt; the first call wins, later ones only
/// warn. Must run before any session event is logged, or those `sid_hash`es are
/// salted with a throwaway value and never correlate with later ones.
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

/// Decode 32 hex chars into 16 bytes; `None` on a malformed setting, which then
/// gets a fresh salt instead of a panic.
fn decode_hex_salt(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// Salted, truncated `BLAKE2b` digest of a session's token hash: a stable
/// identifier for correlating session events in logs. Never log the token.
///
/// The salt keeps it distinct from the stored `token_hash`, so a log line
/// cannot be matched against a stolen database row.
///
/// Only creation and destruction are logged, not each successful validation
/// (every request) — likewise API key use, tracked in `api_keys.last_used_at`.
pub fn session_log_id(token_hash: &str) -> String {
    let salt = SESSION_LOG_SALT.get_or_init(|| {
        let mut s = [0u8; 16];
        s.fill_with(rand::random);
        s
    });
    session_log_id_with(salt, token_hash)
}

/// [`session_log_id`] under an explicit salt, so tests can vary the salt (the
/// process-wide `OnceLock` holds only one).
fn session_log_id_with(salt: &[u8; 16], token_hash: &str) -> String {
    let mut hasher = Blake2b512::new();
    hasher.update(salt);
    hasher.update(token_hash.as_bytes());
    use std::fmt::Write as _;
    // 64 bits is plenty for one appliance's sessions and keeps log lines short.
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
    // Logged after the lock is dropped.
    let mut expired: Option<(i64, &'static str)> = None;
    {
        let mut map = store.lock();
        if let Some(info) = map.get_mut(token_hash) {
            // The idle check must read `last_seen` before this request refreshes
            // it. A backwards clock yields negative deltas, i.e. "not expired".
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

/// Drop in-memory sessions past either timeout; returns how many. Needed
/// because [`validate_session`] only expires sessions on access.
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

/// How recently a session must have proved the password before a sensitive
/// action (mint an API key, add or remove an operator).
///
/// Short on purpose: it bounds how long a *stolen session cookie* can be used
/// to make a compromise permanent. Login counts as a proof, so an operator
/// rarely pays more than one extra password entry.
pub const REAUTH_WINDOW_SECS: i64 = 300;

/// Record that this session has just proved the account's password. Returns
/// `false` if the token names no live session.
pub fn mark_reauthenticated(store: &SessionStore, token_hash: &str) -> bool {
    let now = now_secs();
    let mut map = store.lock();
    if let Some(info) = map.get_mut(token_hash) {
        info.last_reauth_at = now;
        return true;
    }
    false
}

/// Whether this session proved the password within [`REAUTH_WINDOW_SECS`].
/// An unknown token is not fresh. A backwards clock reads as "not yet stale",
/// the same direction the session expiry checks take.
pub fn has_fresh_reauth(store: &SessionStore, token_hash: &str) -> bool {
    let now = now_secs();
    store
        .lock()
        .get(token_hash)
        .is_some_and(|info| now - info.last_reauth_at < REAUTH_WINDOW_SECS)
}

/// Revoke one session (log out this device only). The caller persists it
/// (`delete_session_by_token_hash`). Callers logging `session.destroyed` must
/// gate on `Some`, so a fabricated cookie cannot inject a destruction event.
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
                // Not persisted; see the field's doc comment.
                last_reauth_at: s.created_at,
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
/// Flush first ([`flush_last_seen`]): the DB predicate reads `last_seen`,
/// which otherwise lags memory by up to one flush interval.
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

/// Revoke every session except `keep` (log out other devices). `None` — e.g. a
/// forward-auth caller with no session cookie — revokes all. Returns the count
/// revoked, for the audit log.
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

/// Revoke `user_id`'s sessions except `keep` (`None` revokes all of them).
/// Unlike [`revoke_other_sessions`], other operators are unaffected — the
/// semantics a password change needs.
///
/// Returns the count evicted from memory, not the DB row count: eviction is
/// what ends authentication, and the two diverge (rows of lazily-expired
/// sessions linger until the sweep).
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
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes())?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2 hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Argon2 hash of a fixed, unusable string with the real parameters, so
/// verifying against it costs what a real verification does.
static DUMMY_PASSWORD_HASH: OnceLock<String> = OnceLock::new();

/// Spend the Argon2 work a real password verification would, and discard the
/// answer.
///
/// Closes the user-enumeration timing oracle in `start_password_session`
/// (`src/admin/api.rs`): without it an unknown username answers before any
/// hashing while a known one pays Argon2 first.
///
/// Generated lazily rather than hard-coded as a PHC literal so it tracks
/// [`Argon2::default`] if the parameters ever change. The DB lookup before it
/// still differs slightly between hit and miss, orders of magnitude below the
/// Argon2 cost.
pub fn spend_verify_cost(password: &str) {
    let hash = DUMMY_PASSWORD_HASH.get_or_init(|| {
        hash_password("noadd::timing-equalisation::not-a-real-password")
            .expect("hashing a fixed string with default Argon2 parameters cannot fail")
    });
    // The verdict is meaningless by construction — the work is the product.
    let _ = verify_password(password, hash);
}

/// Stored in `users.password_hash` for operators provisioned from a trusted
/// forward-auth header. `!` is not a valid PHC string, so it never matches
/// (the `/etc/shadow` convention) and the column stays `NOT NULL`.
///
/// Password paths must check this explicitly: [`verify_password`] returns `Err`
/// for an unparseable hash, which callers surface as a 500, whereas a
/// passwordless account must get an ordinary 401.
pub const NO_PASSWORD_SENTINEL: &str = "!";

/// True when the stored hash marks an account that cannot authenticate with a
/// password (see [`NO_PASSWORD_SENTINEL`]).
pub fn has_no_password(hash: &str) -> bool {
    hash == NO_PASSWORD_SENTINEL
}

/// How many unknown session tokens one client may present within
/// [`INVALID_SESSION_WINDOW_SECS`] before the burst is reported. A tab whose
/// session expired keeps presenting its stale cookie, so the threshold sits
/// well above one to separate that from someone guessing session ids.
pub const INVALID_SESSION_MAX_ATTEMPTS: u32 = 10;

/// Sliding window for [`INVALID_SESSION_MAX_ATTEMPTS`].
pub const INVALID_SESSION_WINDOW_SECS: u64 = 60;

/// Consecutive password failures allowed before any delay (ordinary mistyping).
pub const LOCKOUT_FREE_ATTEMPTS: u32 = 3;

/// Ceiling on the exponential backoff; see [`AccountLockout`] for why there is
/// a ceiling rather than a permanent lock.
pub const LOCKOUT_MAX_SECS: u64 = 900;

/// Quiet period after which an account's failure count is forgotten, so old
/// typos do not carry a backoff months later.
pub const LOCKOUT_RESET_SECS: u64 = 3600;

/// Per-account exponential backoff on password failures.
///
/// The IP limiter bounds one source address; this bounds one *account*, as
/// OWASP asks, so a botnet gets many IP budgets but one account budget.
///
/// **Backoff, not lockout.** Past [`LOCKOUT_FREE_ATTEMPTS`] each failure
/// doubles the lock, capped at [`LOCKOUT_MAX_SECS`]. A hard lock would be an
/// on-demand denial of service with no password-reset flow to escape it. Only
/// admin login is gated, never DNS, and the state is in-memory on purpose: a
/// restart clears it.
///
/// **Keyed by `user_id`, only ever one that resolved**, so the map is bounded
/// by the number of accounts. `start_password_session` (`src/admin/api.rs`)
/// answers a locked account with the same Argon2 cost and generic 401 as a
/// wrong password, so the lockout never reveals whether an account exists.
pub struct AccountLockout {
    /// `user_id` -> (consecutive failures, when the last one happened).
    failures: Mutex<HashMap<i64, (u32, Instant)>>,
}

impl Default for AccountLockout {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountLockout {
    pub fn new() -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// How long `failures` consecutive failures lock an account for, or `None`
    /// while still inside the free allowance.
    fn penalty(failures: u32) -> Option<Duration> {
        let over = failures.checked_sub(LOCKOUT_FREE_ATTEMPTS)?;
        if over == 0 {
            return None;
        }
        // 1s, 2s, 4s, … saturating: `over` is attacker-driven and an
        // oversized shift must not wrap.
        let secs = 1u64
            .checked_shl(over - 1)
            .unwrap_or(LOCKOUT_MAX_SECS)
            .min(LOCKOUT_MAX_SECS);
        Some(Duration::from_secs(secs))
    }

    /// Whether this account is currently refusing password attempts.
    pub fn is_locked(&self, user_id: i64) -> bool {
        let map = self.failures.lock();
        let Some(&(failures, last)) = map.get(&user_id) else {
            return false;
        };
        if last.elapsed().as_secs() >= LOCKOUT_RESET_SECS {
            return false;
        }
        Self::penalty(failures).is_some_and(|p| last.elapsed() < p)
    }

    /// Count one password failure. Returns the lock now in force, or `None` if
    /// the account is still inside its free allowance.
    pub fn record_failure(&self, user_id: i64) -> Option<Duration> {
        let mut map = self.failures.lock();
        let entry = map.entry(user_id).or_insert((0, Instant::now()));
        if entry.1.elapsed().as_secs() >= LOCKOUT_RESET_SECS {
            *entry = (1, Instant::now());
        } else {
            entry.0 = entry.0.saturating_add(1);
            entry.1 = Instant::now();
        }
        Self::penalty(entry.0)
    }

    /// Forget an account's failures after a successful password check.
    pub fn record_success(&self, user_id: i64) {
        self.failures.lock().remove(&user_id);
    }

    /// Number of accounts currently carrying failures. Exposed for tests.
    pub fn tracked_accounts(&self) -> usize {
        self.failures.lock().len()
    }
}

/// Per-IP windowed attempt counter, used to rate-limit logins and to detect
/// bursts of unknown session tokens.
///
/// One instance per signal: sharing one would let a cookie guesser spend an
/// operator's login budget from the same NAT address.
pub struct RateLimiter {
    attempts: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    max_attempts: u32,
    window_secs: u64,
}

impl RateLimiter {
    /// Allow `max_attempts` per `window_secs` per IP.
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
            window_secs,
        }
    }

    /// Whether the IP may make another attempt (`false` = rate limited).
    pub fn check(&self, ip: IpAddr) -> bool {
        let map = self.attempts.lock();
        if let Some((count, started)) = map.get(&ip) {
            if started.elapsed().as_secs() >= self.window_secs {
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
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
        }
    }

    /// Record an attempt; `true` only for the one that *reaches* `max_attempts`
    /// in this window — once per window, so it can drive a single log line.
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

    /// Drop entries whose window has elapsed; returns how many. Without it a
    /// scanner cycling addresses (trivial across an IPv6 /64) grows the map
    /// without bound. Takes no `max_age` (unlike `IpRateLimiter::prune`): an
    /// elapsed entry already reads as a fresh start.
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
        // Why callers must check `has_no_password` first: this is `Err`, not
        // `Ok(false)`, and would otherwise surface as a 500.
        assert!(verify_password("anything", NO_PASSWORD_SENTINEL).is_err());
    }

    #[test]
    fn session_log_id_with_actually_depends_on_the_salt() {
        // Only differing salts over the *same* token prove salting happens; an
        // unsalted digest passes every other assertion.
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
    fn lockout_leaves_ordinary_mistyping_alone() {
        let lockout = AccountLockout::new();
        for i in 1..=LOCKOUT_FREE_ATTEMPTS {
            assert!(
                lockout.record_failure(1).is_none(),
                "failure {i} is inside the free allowance and must not lock"
            );
            assert!(!lockout.is_locked(1));
        }
    }

    #[test]
    fn lockout_doubles_and_then_stops_doubling() {
        // The shape is the security property: doubling, then capped.
        let secs = |n: u32| AccountLockout::penalty(n).map(|d| d.as_secs());
        assert_eq!(secs(LOCKOUT_FREE_ATTEMPTS), None);
        assert_eq!(secs(LOCKOUT_FREE_ATTEMPTS + 1), Some(1));
        assert_eq!(secs(LOCKOUT_FREE_ATTEMPTS + 2), Some(2));
        assert_eq!(secs(LOCKOUT_FREE_ATTEMPTS + 3), Some(4));
        assert_eq!(secs(LOCKOUT_FREE_ATTEMPTS + 10), Some(512));
        // Capped from here on, however many failures pile up.
        assert_eq!(secs(LOCKOUT_FREE_ATTEMPTS + 11), Some(LOCKOUT_MAX_SECS));
        assert_eq!(secs(LOCKOUT_FREE_ATTEMPTS + 40), Some(LOCKOUT_MAX_SECS));
        // An oversized shift saturates to the cap rather than wrapping.
        assert_eq!(secs(u32::MAX), Some(LOCKOUT_MAX_SECS));
    }

    #[test]
    fn lockout_actually_locks_once_the_allowance_is_spent() {
        let lockout = AccountLockout::new();
        for _ in 0..LOCKOUT_FREE_ATTEMPTS {
            lockout.record_failure(7);
        }
        assert!(!lockout.is_locked(7));
        assert_eq!(
            lockout.record_failure(7).map(|d| d.as_secs()),
            Some(1),
            "the first failure past the allowance locks for one second"
        );
        assert!(lockout.is_locked(7));
    }

    #[test]
    fn lockout_is_per_account() {
        // One account under attack must not lock any other operator out.
        let lockout = AccountLockout::new();
        for _ in 0..=LOCKOUT_FREE_ATTEMPTS {
            lockout.record_failure(1);
        }
        assert!(lockout.is_locked(1));
        assert!(!lockout.is_locked(2));
    }

    #[test]
    fn a_correct_password_clears_the_history() {
        let lockout = AccountLockout::new();
        for _ in 0..=LOCKOUT_FREE_ATTEMPTS {
            lockout.record_failure(1);
        }
        assert!(lockout.is_locked(1));
        lockout.record_success(1);
        assert!(!lockout.is_locked(1));
        assert_eq!(lockout.tracked_accounts(), 0);
        // And the backoff starts over rather than resuming where it stopped.
        assert!(lockout.record_failure(1).is_none());
    }

    #[test]
    fn an_untouched_account_is_never_locked() {
        let lockout = AccountLockout::new();
        assert!(!lockout.is_locked(42));
        assert_eq!(lockout.tracked_accounts(), 0);
    }

    #[test]
    fn record_crossing_fires_exactly_once_per_window() {
        let rl = RateLimiter::new(3, 60);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!rl.record_crossing(ip));
        assert!(!rl.record_crossing(ip));
        assert!(rl.record_crossing(ip), "the 3rd attempt reaches the limit");
        // Not again for the rest of the burst.
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
