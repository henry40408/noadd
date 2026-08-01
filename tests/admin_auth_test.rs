use std::net::{IpAddr, Ipv4Addr};

use noadd::admin::auth::{
    RateLimiter, SESSION_IDLE_TIMEOUT_SECS, SESSION_MAX_AGE_SECS, SessionInfo, generate_token,
    hash_password, new_session_store, prune_expired, revoke_session, session_log_id,
    spend_verify_cost, store_session, sweep_expired, validate_session, verify_password,
};
use noadd::db::Database;
use tempfile::tempdir;

async fn test_db() -> Database {
    let dir = tempdir().unwrap();
    // Persist the tempdir (no Drop cleanup) so it lives for the duration of the test.
    let path = dir.keep().join("test.db");
    let path_str = path.to_str().unwrap().to_string();
    Database::open(&path_str).await.unwrap()
}

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

/// `spend_verify_cost` exists to make a login against an unknown username cost
/// what a login against a known one costs, so the two cannot be told apart by
/// response time. That property is a *duration*, so it is the duration this
/// asserts — a test that only called the function would pass just as happily
/// against an empty body.
///
/// The comparison is deliberately loose. Argon2's ~50 ms dwarfs the scheduling
/// noise a shared CI runner adds, and the regression being guarded against is
/// the function being emptied out or the call site dropped, which turns ~50 ms
/// into microseconds — three orders of magnitude, not the factor of three this
/// allows. Medians rather than means, so one descheduled sample cannot swing
/// the verdict.
#[test]
fn spend_verify_cost_costs_what_a_real_verification_costs() {
    use std::time::{Duration, Instant};

    fn median_of<F: FnMut()>(samples: usize, mut f: F) -> Duration {
        let mut times: Vec<Duration> = (0..samples)
            .map(|_| {
                let start = Instant::now();
                f();
                start.elapsed()
            })
            .collect();
        times.sort_unstable();
        times[times.len() / 2]
    }

    let hash = hash_password("a genuine stored password").unwrap();

    // Warm up both paths first: the very first `spend_verify_cost` also pays
    // to generate its process-wide dummy hash, and measuring that one-off
    // would flatter the result rather than test it.
    spend_verify_cost("warm up");
    let _ = verify_password("warm up", &hash).unwrap();

    let real = median_of(5, || {
        assert!(!verify_password("the wrong password", &hash).unwrap());
    });
    let dummy = median_of(5, || spend_verify_cost("the wrong password"));

    assert!(
        dummy * 3 >= real,
        "the padded path ({dummy:?}) must not be meaningfully cheaper than a \
         real verification ({real:?}) — an unknown username would be \
         distinguishable by response time"
    );
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
fn session_log_id_is_stable_and_distinct() {
    let token = generate_token();
    let other_token = generate_token();

    let id = session_log_id(&token);
    // Deterministic for the same token...
    assert_eq!(id, session_log_id(&token));
    // ...but distinct across tokens.
    assert_ne!(id, session_log_id(&other_token));

    // 16 hex chars (64 bits).
    assert_eq!(id.len(), 16);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    // Whether salting actually happens (as opposed to, say, an unsalted
    // `blake2b(token)[..8]`, which would pass every assertion above just as
    // well) is exercised directly against `session_log_id_with` in
    // `src/admin/auth.rs`'s unit tests, using two explicit salts over the
    // same token — that property is not observable through this process-wide
    // `session_log_id`, which only ever runs under one salt per test binary.
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
    let stale_last_seen = now - SESSION_IDLE_TIMEOUT_SECS + 600;
    store_session(&store, &token, info_at(1, now, stale_last_seen));
    assert_eq!(validate_session(&store, &token), Some(1));
    // The 600s of headroom before the idle window means a second call would
    // pass regardless of whether the first refreshed `last_seen` — that
    // wouldn't distinguish "refresh happened" from "refresh is a no-op", so
    // assert the refresh directly: `last_seen` must have moved forward from
    // the fixture's stale value to (at least) `now`.
    let refreshed_last_seen = store.lock().get(&token).unwrap().last_seen;
    assert!(refreshed_last_seen > stale_last_seen);
    assert!(refreshed_last_seen >= now);
    // With the refresh confirmed, a second call re-evaluated from "now" still passes.
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

#[tokio::test]
async fn sweep_expired_reports_both_counts() {
    let db = test_db().await;
    let uid = db.create_user("judy", "h", 0).await.unwrap();
    let now = noadd::now_unix();

    // Persist matching rows in the DB so purge_expired_sessions (which reads
    // last_seen from disk) agrees with what the in-memory store holds.
    //
    // The literals stand in for token *hashes* — both the store key and
    // `sessions.token_hash` are digests now (see `hash_session_token`), and
    // nothing here goes through a cookie, so any consistent pair of strings
    // exercises the same code path a real digest would.
    db.insert_session("active", uid, now - 1_000, now, None, None)
        .await
        .unwrap();
    db.insert_session(
        "idle",
        uid,
        now - 1_000,
        now - SESSION_IDLE_TIMEOUT_SECS - 1,
        None,
        None,
    )
    .await
    .unwrap();

    let store = new_session_store();
    store_session(&store, "active", info_at(uid, now - 1_000, now));
    store_session(
        &store,
        "idle",
        info_at(uid, now - 1_000, now - SESSION_IDLE_TIMEOUT_SECS - 1),
    );

    let (evicted, deleted) = sweep_expired(&store, &db).await.unwrap();
    assert_eq!(evicted, 1);
    assert_eq!(deleted, 1);

    assert_eq!(validate_session(&store, "active"), Some(uid));
    assert_eq!(validate_session(&store, "idle"), None);

    let remaining = db.list_sessions().await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].token_hash, "active");
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
