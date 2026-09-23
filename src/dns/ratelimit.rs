//! Per-client-IP token bucket rate limiter for incoming DNS queries.
//!
//! Keeps one noisy device from starving the shared cache and upstream quota.
//! Each IP's bucket fills at `qps` tokens/sec up to `burst`; a query with no
//! token is rejected (the handler answers REFUSED).

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
    /// `qps`: refill rate per IP; `burst`: bucket capacity. `qps == 0` allows
    /// every query.
    pub fn new(qps: u32, burst: u32) -> Self {
        Self {
            qps: qps as f64,
            burst: burst as f64,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Consume a token for `ip`; `false` when its bucket is empty.
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

    /// Drop buckets unseen for `max_age`; call periodically to bound the map.
    pub fn prune(&self, max_age: Duration) -> usize {
        let now = Instant::now();
        let mut map = self.buckets.lock();
        let before = map.len();
        map.retain(|_, b| now.duration_since(b.last_seen) < max_age);
        before - map.len()
    }

    /// Number of tracked IPs.
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
