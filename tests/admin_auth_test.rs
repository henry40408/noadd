use std::net::{IpAddr, Ipv4Addr};

use noadd::admin::auth::{
    RateLimiter, SessionInfo, generate_token, hash_password, new_session_store, revoke_session,
    store_session, validate_session, verify_password,
};

fn info(user_id: i64) -> SessionInfo {
    SessionInfo {
        session_id: 1,
        user_id,
        created_at: noadd::now_unix(),
        last_seen: noadd::now_unix(),
    }
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
