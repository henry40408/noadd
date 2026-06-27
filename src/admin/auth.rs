use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
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

/// Record a session in the in-memory store.
pub fn store_session(store: &SessionStore, token: &str, info: SessionInfo) {
    store.lock().insert(token.to_string(), info);
}

/// Validate a token. Returns the owning `user_id` and refreshes `last_seen`,
/// or `None` if missing/expired (expired entries are dropped).
pub fn validate_session(store: &SessionStore, token: &str) -> Option<i64> {
    let now = now_secs();
    let mut map = store.lock();
    if let Some(info) = map.get_mut(token) {
        if now - info.created_at < SESSION_MAX_AGE_SECS {
            info.last_seen = now;
            return Some(info.user_id);
        }
        map.remove(token);
    }
    None
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
    let loaded = db.load_sessions(SESSION_MAX_AGE_SECS, now).await?;
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

/// Revoke all sessions (logout everywhere): clear the store and the table.
pub async fn revoke_all_sessions(
    store: &SessionStore,
    db: &crate::db::Database,
) -> Result<(), crate::db::DbError> {
    store.lock().clear();
    db.delete_all_sessions().await
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
