use std::net::{IpAddr, Ipv4Addr};

use noadd::admin::auth::{
    create_session, hash_password, new_session_store, validate_session, verify_password,
    RateLimiter,
};

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

    // Create a session
    let token = create_session(&store);

    // Token should be 64 characters
    assert_eq!(token.len(), 64);

    // Token should be alphanumeric
    assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));

    // Token should be valid
    assert!(validate_session(&store, &token));

    // Random token should not be valid
    assert!(!validate_session(&store, "nonexistent_token"));

    // Multiple sessions should all be valid
    let token2 = create_session(&store);
    assert!(validate_session(&store, &token));
    assert!(validate_session(&store, &token2));
    assert_ne!(token, token2);
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
