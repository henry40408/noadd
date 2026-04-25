//! Per-client-IP token bucket rate limiter for incoming DNS queries.
//!
//! One noisy device (misconfigured, infected, running a scanner) can easily
//! emit hundreds of queries per second. Without isolation, it starves the
//! shared DNS cache of space for other clients' records and burns the
//! upstream provider's per-source quota. This module bounds each IP's rate
//! independently so a single client's excess traffic can't harm the rest.
//!
//! The bucket fills at `qps` tokens/sec up to `burst` tokens. Each query
//! consumes one token; a query arriving with no tokens is rejected (the
//! caller should respond with DNS REFUSED or drop it).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

/// Per-IP token bucket. `qps == 0` disables the limiter entirely.
pub struct IpRateLimiter {
    qps: f64,
    burst: f64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl IpRateLimiter {
    /// Create a new limiter.
    ///
    /// - `qps`: steady-state refill rate in tokens/sec per IP
    /// - `burst`: maximum tokens a single IP may accumulate
    ///
    /// Passing `qps == 0` yields a limiter that allows every query (useful
    /// for tests and opt-out deployments).
    pub fn new(qps: u32, burst: u32) -> Self {
        Self {
            qps: qps as f64,
            burst: burst as f64,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` and consumes one token when the caller is allowed.
    /// Returns `false` when the bucket for this IP is empty.
    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        if self.qps == 0.0 {
            return true;
        }
        let now = Instant::now();
        let mut map = self.buckets.lock();
        let bucket = map.entry(ip).or_insert_with(|| Bucket {
            tokens: self.burst,
            last_refill: now,
            last_seen: now,
        });
        // Refill based on elapsed wall time.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.qps).min(self.burst);
        bucket.last_refill = now;
        bucket.last_seen = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop buckets for IPs unseen for longer than `max_age`. Call
    /// periodically from a background task to stop the map growing without
    /// bound on a public-facing deployment.
    pub fn prune(&self, max_age: Duration) -> usize {
        let now = Instant::now();
        let mut map = self.buckets.lock();
        let before = map.len();
        map.retain(|_, b| now.duration_since(b.last_seen) < max_age);
        before - map.len()
    }

    /// Current number of tracked IPs. Exposed for observability / tests.
    pub fn tracked_ips(&self) -> usize {
        self.buckets.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn disabled_limiter_always_allows() {
        let rl = IpRateLimiter::new(0, 0);
        for _ in 0..10_000 {
            assert!(rl.try_acquire(ip(1)));
        }
    }

    #[test]
    fn burst_allows_initial_spike_then_blocks() {
        let rl = IpRateLimiter::new(1, 5);
        // Full bucket: first 5 must succeed back to back.
        for i in 0..5 {
            assert!(rl.try_acquire(ip(1)), "burst token {i} should be allowed");
        }
        // 6th exhausts — refill at 1 qps hasn't had time to kick in.
        assert!(!rl.try_acquire(ip(1)), "6th query should be rejected");
    }

    #[test]
    fn per_ip_isolation() {
        let rl = IpRateLimiter::new(1, 2);
        // Drain ip(1).
        assert!(rl.try_acquire(ip(1)));
        assert!(rl.try_acquire(ip(1)));
        assert!(!rl.try_acquire(ip(1)));
        // ip(2) is untouched — must still be served.
        assert!(rl.try_acquire(ip(2)));
        assert!(rl.try_acquire(ip(2)));
    }

    #[test]
    fn refill_after_wait() {
        let rl = IpRateLimiter::new(1000, 1);
        assert!(rl.try_acquire(ip(1)));
        assert!(!rl.try_acquire(ip(1)));
        // 5ms at 1000 qps = ~5 tokens, more than enough for one query.
        std::thread::sleep(Duration::from_millis(5));
        assert!(rl.try_acquire(ip(1)));
    }

    #[test]
    fn prune_drops_inactive_ips() {
        let rl = IpRateLimiter::new(10, 10);
        rl.try_acquire(ip(1));
        rl.try_acquire(ip(2));
        assert_eq!(rl.tracked_ips(), 2);
        // Zero-duration max_age forces every bucket to look stale.
        let removed = rl.prune(Duration::from_secs(0));
        assert_eq!(removed, 2);
        assert_eq!(rl.tracked_ips(), 0);
    }
}
