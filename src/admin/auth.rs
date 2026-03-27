use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::Rng;
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

/// Thread-safe session store. Maps token -> created_at (unix seconds).
pub type SessionStore = Arc<Mutex<HashMap<String, i64>>>;

/// Create a new, empty session store.
pub fn new_session_store() -> SessionStore {
    Arc::new(Mutex::new(HashMap::new()))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Load persisted sessions from the database into the session store.
/// Expired sessions are discarded during load.
pub async fn load_sessions_from_db(
    store: &SessionStore,
    db: &crate::db::Database,
) -> Result<(), crate::db::DbError> {
    if let Some(data) = db.get_setting("sessions").await? {
        let now = now_secs();
        let mut map = store.lock().unwrap();
        for entry in data.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            // Format: "token:created_at"
            if let Some((token, ts_str)) = entry.split_once(':')
                && let Ok(ts) = ts_str.parse::<i64>()
                && now - ts < SESSION_MAX_AGE_SECS
            {
                map.insert(token.to_string(), ts);
            }
        }
    }
    Ok(())
}

/// Persist all sessions from the store to the database.
pub async fn save_sessions_to_db(
    store: &SessionStore,
    db: &crate::db::Database,
) -> Result<(), crate::db::DbError> {
    let entries: Vec<String> = store
        .lock()
        .unwrap()
        .iter()
        .map(|(token, ts)| format!("{token}:{ts}"))
        .collect();
    db.set_setting("sessions", &entries.join(";")).await
}

/// Revoke all sessions (logout everywhere).
pub async fn revoke_all_sessions(
    store: &SessionStore,
    db: &crate::db::Database,
) -> Result<(), crate::db::DbError> {
    store.lock().unwrap().clear();
    db.set_setting("sessions", "").await
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

/// Create a new session, storing it in the session store.
/// Returns a 64-character alphanumeric token.
pub fn create_session(store: &SessionStore) -> String {
    let token: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    store.lock().unwrap().insert(token.clone(), now_secs());
    token
}

/// Validate whether a session token exists and is not expired.
pub fn validate_session(store: &SessionStore, token: &str) -> bool {
    let mut map = store.lock().unwrap();
    if let Some(&created_at) = map.get(token) {
        if now_secs() - created_at < SESSION_MAX_AGE_SECS {
            return true;
        }
        // Expired — remove it
        map.remove(token);
    }
    false
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
        let map = self.attempts.lock().unwrap();
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
        let mut map = self.attempts.lock().unwrap();
        let entry = map.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed().as_secs() >= self.window_secs {
            // Reset window
            *entry = (1, Instant::now());
        } else {
            entry.0 += 1;
        }
    }
}
