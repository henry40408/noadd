use std::net::{IpAddr, Ipv4Addr};

use noadd::admin::auth::{
    RateLimiter, SESSION_IDLE_TIMEOUT_SECS, SESSION_MAX_AGE_SECS, SessionInfo, generate_token,
    hash_password, new_session_store, prune_expired, revoke_session, store_session,
    validate_session, verify_password,
};

fn info_at(user_id: i64, created_at: i64, last_seen: i64) -> SessionInfo {
    SessionInfo {
        session_id: 1,
        user_id,
        created_at,
        last_seen,
    }
}

fn info(user_id: i64) -> SessionInfo {
    let now = noadd::now_unix();
    info_at(user_id, now, now)
}

#[test]
fn test_password_hash_and_verify() {
    let password = "my_secure_password_123";
    let hash = hash_password(password).unwrap();

    // Correct password should verify
    assert!(verify_password(password, &hash).unwrap());

    // Wrong password should not verify
    assert!(!verify_password("wrong_password", &hash).unwrap());

    // Hash should be a valid PHC string
    assert!(hash.starts_with("$argon2"));
}

#[test]
fn test_session_create_and_validate() {
    let store = new_session_store();
    let token = generate_token();
    assert_eq!(token.len(), 64);
    assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));

    store_session(&store, &token, info(42));
    assert_eq!(validate_session(&store, &token), Some(42));
    assert_eq!(validate_session(&store, "nope"), None);
}

#[test]
fn test_revoke_session_removes_only_that_token() {
    let store = new_session_store();
    let t1 = generate_token();
    let t2 = generate_token();
    store_session(&store, &t1, info(1));
    store_session(&store, &t2, info(2));
    revoke_session(&store, &t1);
    assert_eq!(validate_session(&store, &t1), None);
    assert_eq!(validate_session(&store, &t2), Some(2));
}

#[test]
fn session_expires_after_idle_timeout() {
    let store = new_session_store();
    let token = generate_token();
    let now = noadd::now_unix();
    // Absolute timeout not reached (created_at = now), but idle window is.
    store_session(
        &store,
        &token,
        info_at(1, now, now - SESSION_IDLE_TIMEOUT_SECS - 1),
    );
    assert_eq!(validate_session(&store, &token), None);
}

#[test]
fn idle_session_is_removed_from_the_store() {
    let store = new_session_store();
    let token = generate_token();
    let now = noadd::now_unix();
    store_session(
        &store,
        &token,
        info_at(1, now, now - SESSION_IDLE_TIMEOUT_SECS - 1),
    );
    assert_eq!(validate_session(&store, &token), None);
    // Second call sees no entry at all (already evicted), not just "still idle".
    assert_eq!(validate_session(&store, &token), None);
    assert!(store.lock().is_empty());
}

#[test]
fn active_session_survives_past_the_idle_window() {
    let store = new_session_store();
    let token = generate_token();
    let now = noadd::now_unix();
    store_session(
        &store,
        &token,
        info_at(1, now, now - SESSION_IDLE_TIMEOUT_SECS + 600),
    );
    assert_eq!(validate_session(&store, &token), Some(1));
    // last_seen was refreshed, so a second call (re-evaluated from "now") still passes.
    assert_eq!(validate_session(&store, &token), Some(1));
}

#[test]
fn session_expires_after_absolute_timeout_even_when_active() {
    let store = new_session_store();
    let token = generate_token();
    let now = noadd::now_unix();
    // last_seen is fresh (idle check would pass), but created_at is past the
    // absolute limit — proves the two layers are independent.
    store_session(
        &store,
        &token,
        info_at(1, now - SESSION_MAX_AGE_SECS - 1, now),
    );
    assert_eq!(validate_session(&store, &token), None);
}

#[test]
fn prune_expired_evicts_only_expired_entries() {
    let store = new_session_store();
    let now = noadd::now_unix();
    store_session(&store, &generate_token(), info_at(1, now, now)); // active
    store_session(
        &store,
        &generate_token(),
        info_at(2, now, now - SESSION_IDLE_TIMEOUT_SECS - 1), // idle-expired
    );
    store_session(
        &store,
        &generate_token(),
        info_at(3, now - SESSION_MAX_AGE_SECS - 1, now), // absolute-expired
    );
    assert_eq!(prune_expired(&store), 2);
    assert_eq!(store.lock().len(), 1);
}

#[test]
fn test_rate_limiter_allows_under_limit() {
    let limiter = RateLimiter::new(3, 60);
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

    // First check should be allowed (no prior attempts)
    assert!(limiter.check(ip));

    // Record attempts under the limit
    limiter.record(ip);
    assert!(limiter.check(ip));

    limiter.record(ip);
    assert!(limiter.check(ip));
}

#[test]
fn test_rate_limiter_blocks_over_limit() {
    let limiter = RateLimiter::new(3, 60);
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let other_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Record max attempts
    limiter.record(ip);
    limiter.record(ip);
    limiter.record(ip);

    // Should be blocked now
    assert!(!limiter.check(ip));

    // Other IPs should still be allowed
    assert!(limiter.check(other_ip));
}
