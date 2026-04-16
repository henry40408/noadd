use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use thiserror::Error;
use tokio::sync::{Semaphore, mpsc};
use tracing::warn;

use crate::cache::{CacheKey, DnsCache};
use crate::dns::ratelimit::IpRateLimiter;
use crate::filter::engine::{FilterEngine, FilterResult};
use crate::upstream::forwarder::{ForwardError, UpstreamForwarder};

/// Default TTL (seconds) used when no answer records are present in the response.
const DEFAULT_TTL_SECS: u64 = 300;

/// Maximum TTL (seconds) we will keep a *negative* response (NXDOMAIN or
/// NoError with empty answer section). Caps RFC 2308 SOA-derived TTLs which
/// can otherwise be hours long for some TLDs and cause prolonged "host not
/// found" symptoms after a single transient upstream hiccup.
const NEGATIVE_TTL_CAP_SECS: u64 = 60;

/// Errors that can occur during DNS query handling.
#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("failed to parse DNS query: {0}")]
    Parse(#[from] hickory_proto::ProtoError),
    #[error("no queries in message")]
    NoQuery,
    #[error("upstream error: {0}")]
    Upstream(#[from] ForwardError),
}

/// Context for a single DNS query, sent to the async logger.
#[derive(Debug, Clone)]
pub struct QueryContext {
    pub timestamp: i64,
    pub client_ip: String,
    pub domain: String,
    pub query_type: String,
    pub action: String,
    pub cached: bool,
    pub upstream: Option<String>,
    pub response_time_ms: i64,
    pub matched_rule: Option<String>,
    pub matched_list: Option<String>,
    pub doh_token: Option<String>,
    pub result: Option<String>,
}

/// Extract a short summary of the DNS answer section from response bytes.
/// Returns the first few records as a comma-separated string.
fn extract_result_summary(response_bytes: &[u8]) -> Option<String> {
    let msg = Message::from_bytes(response_bytes).ok()?;
    let parts: Vec<String> = msg
        .answers()
        .iter()
        .take(3)
        .map(|r| match r.data() {
            RData::A(a) => a.0.to_string(),
            RData::AAAA(aaaa) => aaaa.0.to_string(),
            RData::CNAME(cname) => cname.0.to_string(),
            RData::MX(mx) => format!("{} {}", mx.preference(), mx.exchange()),
            RData::NS(ns) => ns.0.to_string(),
            RData::PTR(ptr) => ptr.0.to_string(),
            RData::TXT(txt) => txt
                .iter()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(""),
            RData::SOA(soa) => format!("{} {}", soa.mname(), soa.rname()),
            RData::SRV(srv) => {
                format!(
                    "{}:{} p={} w={}",
                    srv.target(),
                    srv.port(),
                    srv.priority(),
                    srv.weight()
                )
            }
            RData::CAA(caa) => {
                format!("{} {}", caa.tag(), String::from_utf8_lossy(caa.raw_value()))
            }
            other => other.to_string(),
        })
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

/// Core DNS query handler implementing the filter-cache-forward pipeline.
///
/// Shared across all listener tasks (UDP, TCP, DoH) behind `Arc<DnsHandler>`.
pub struct DnsHandler {
    filter: Arc<ArcSwap<FilterEngine>>,
    cache: DnsCache,
    forwarder: Arc<UpstreamForwarder>,
    log_tx: mpsc::Sender<QueryContext>,
    /// Tracks cache keys currently being refreshed in the background,
    /// preventing duplicate refresh tasks for the same stale entry.
    refreshing: Arc<Mutex<HashSet<CacheKey>>>,
    /// Bounds concurrent in-flight `handle()` calls across all listeners
    /// (UDP/TCP/DoH). Prevents a single noisy client from exhausting the
    /// tokio runtime with unbounded spawned tasks. `None` = unlimited.
    inflight: Option<Arc<Semaphore>>,
    /// Monotonic count of log events dropped because the async logger
    /// channel was full. A non-zero value means the logger can't keep up
    /// with query volume and some query logs were lost.
    log_drop_count: Arc<AtomicU64>,
    /// Per-client-IP token bucket. `None` means no per-IP limiting.
    rate_limiter: Option<Arc<IpRateLimiter>>,
}

impl DnsHandler {
    /// Create a handler with no in-flight limit. Suitable for tests.
    pub fn new(
        filter: Arc<ArcSwap<FilterEngine>>,
        cache: DnsCache,
        forwarder: Arc<UpstreamForwarder>,
        log_tx: mpsc::Sender<QueryContext>,
    ) -> Self {
        Self::with_max_inflight(filter, cache, forwarder, log_tx, 0)
    }

    /// Create a handler that caps concurrent `handle()` calls at `max_inflight`.
    /// A value of `0` disables the limit.
    pub fn with_max_inflight(
        filter: Arc<ArcSwap<FilterEngine>>,
        cache: DnsCache,
        forwarder: Arc<UpstreamForwarder>,
        log_tx: mpsc::Sender<QueryContext>,
        max_inflight: usize,
    ) -> Self {
        let inflight = if max_inflight == 0 {
            None
        } else {
            Some(Arc::new(Semaphore::new(max_inflight)))
        };
        Self {
            filter,
            cache,
            forwarder,
            log_tx,
            refreshing: Arc::new(Mutex::new(HashSet::new())),
            inflight,
            log_drop_count: Arc::new(AtomicU64::new(0)),
            rate_limiter: None,
        }
    }

    /// Attach a per-client-IP rate limiter. Chainable during construction.
    pub fn with_rate_limiter(mut self, limiter: Arc<IpRateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Cumulative number of log events dropped because the async logger
    /// channel was full.
    pub fn log_drop_count(&self) -> u64 {
        self.log_drop_count.load(Ordering::Relaxed)
    }

    /// Handle a DNS query. Takes raw query bytes, client IP, and optional DoH token name.
    /// Returns raw response bytes.
    pub async fn handle(
        &self,
        query_bytes: &[u8],
        client_ip: IpAddr,
        doh_token: Option<String>,
    ) -> Result<Vec<u8>, HandlerError> {
        let start = Instant::now();

        // 0. Acquire in-flight permit. Held until this function returns, so
        // the total number of queries actively consuming upstream / cache /
        // filter resources is bounded — regardless of how many tasks upstream
        // listeners have spawned.
        let _permit = match &self.inflight {
            Some(sem) => Some(
                sem.clone()
                    .acquire_owned()
                    .await
                    .expect("in-flight semaphore is never closed"),
            ),
            None => None,
        };

        // 1. Parse query
        let message = Message::from_bytes(query_bytes)?;
        let query = message.queries().first().ok_or(HandlerError::NoQuery)?;
        let domain = query.name().to_ascii();
        // Strip trailing dot for filter matching
        let domain_clean = domain.trim_end_matches('.');
        let query_type = query.query_type();
        let query_id = message.id();

        // 2a. Per-IP rate limit. Token drained here protects upstream and
        // cache from a single noisy client. REFUSED (rcode 5) is the
        // semantically correct response; it tells the client the server
        // is unwilling, not broken (as SERVFAIL would).
        if let Some(limiter) = &self.rate_limiter
            && !limiter.try_acquire(client_ip)
        {
            let response_bytes = build_refused_response(&message)?;
            let elapsed = start.elapsed().as_millis() as i64;
            let ctx = QueryContext {
                timestamp: chrono_timestamp_ms(),
                client_ip: client_ip.to_string(),
                domain: domain_clean.to_string(),
                query_type: format!("{query_type}"),
                action: "rate_limited".to_string(),
                cached: false,
                upstream: None,
                response_time_ms: elapsed,
                matched_rule: None,
                matched_list: None,
                doh_token,
                result: None,
            };
            if let Err(e) = self.log_tx.try_send(ctx) {
                self.log_drop_count.fetch_add(1, Ordering::Relaxed);
                warn!("failed to send log event: {e}");
            }
            return Ok(response_bytes);
        }

        // 2b. Check filter
        let filter_guard = self.filter.load();
        let filter_result = filter_guard.check(domain_clean);

        let (response_bytes, action, was_cached, upstream, matched_rule, matched_list) =
            match filter_result {
                FilterResult::Blocked { rule, list } => {
                    let response = build_blocked_response(&message, query_type)?;
                    (
                        response,
                        "blocked".to_string(),
                        false,
                        None,
                        Some(rule),
                        Some(list),
                    )
                }
                FilterResult::Allowed { .. } => {
                    let cache_key: CacheKey = (domain_clean.to_lowercase(), query_type.into());

                    // 3. Check cache
                    if let Some(cached) = self.cache.get(&cache_key).await {
                        // Decrement TTL by elapsed time since insertion
                        let elapsed = cached.elapsed().as_secs() as u32;
                        let mut bytes = decrement_ttl(&cached.bytes, elapsed);

                        // Patch DNS ID to match the query
                        let id_bytes = query_id.to_be_bytes();
                        if bytes.len() >= 2 {
                            bytes[0] = id_bytes[0];
                            bytes[1] = id_bytes[1];
                        }

                        if cached.is_stale() {
                            // Optimistic: serve stale, refresh in background.
                            // Deduplicate: only spawn if no refresh is already in flight.
                            let should_refresh =
                                self.refreshing.lock().unwrap().insert(cache_key.clone());

                            if should_refresh {
                                let forwarder = self.forwarder.clone();
                                let cache = self.cache.clone();
                                let refreshing = self.refreshing.clone();
                                let query_owned = query_bytes.to_vec();
                                let key = cache_key.clone();
                                tokio::spawn(async move {
                                    // RAII guard ensures the in-flight marker is
                                    // always cleared, even if the task panics or
                                    // is cancelled — otherwise a single bad
                                    // refresh could permanently block future
                                    // refreshes for this key.
                                    let _guard = RefreshGuard {
                                        set: refreshing,
                                        key: key.clone(),
                                    };
                                    match forwarder.forward(&query_owned).await {
                                        Ok((response, _)) => {
                                            if let Some(ttl) = cache_ttl_for_response(&response) {
                                                cache.insert(key, response, ttl).await;
                                            } else {
                                                tracing::debug!(
                                                    "stale refresh got non-cacheable response"
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            tracing::debug!(
                                                error = %e,
                                                "stale refresh failed"
                                            );
                                        }
                                    }
                                });
                            }
                        }

                        (bytes, "allowed".to_string(), true, None, None, None)
                    } else {
                        // 4. Forward upstream
                        let (response, upstream_addr) = self.forwarder.forward(query_bytes).await?;
                        // Only cache cacheable responses (skip SERVFAIL etc.,
                        // and apply a capped negative TTL for NXDOMAIN/empty
                        // NoError) to prevent transient failures from
                        // poisoning the cache.
                        if let Some(ttl) = cache_ttl_for_response(&response) {
                            self.cache.insert(cache_key, response.clone(), ttl).await;
                        }
                        (
                            response,
                            "allowed".to_string(),
                            false,
                            Some(upstream_addr),
                            None,
                            None,
                        )
                    }
                }
            };

        let elapsed = start.elapsed().as_millis() as i64;

        // 5. Send log context (non-blocking)
        let result = extract_result_summary(&response_bytes);
        let ctx = QueryContext {
            timestamp: chrono_timestamp_ms(),
            client_ip: client_ip.to_string(),
            domain: domain_clean.to_string(),
            query_type: format!("{query_type}"),
            action,
            cached: was_cached,
            upstream,
            response_time_ms: elapsed,
            matched_rule,
            matched_list,
            doh_token,
            result,
        };
        if let Err(e) = self.log_tx.try_send(ctx) {
            self.log_drop_count.fetch_add(1, Ordering::Relaxed);
            warn!("failed to send log event: {e}");
        }

        Ok(response_bytes)
    }
}

/// Build a DNS REFUSED response for the given query message. Used when a
/// client exceeds its per-IP rate limit. Preserves the query ID and
/// question section so the caller can correlate the answer.
fn build_refused_response(query: &Message) -> Result<Vec<u8>, HandlerError> {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(ResponseCode::Refused);
    response.set_recursion_desired(true);
    response.set_recursion_available(true);
    for q in query.queries() {
        response.add_query(q.clone());
    }
    Ok(response.to_vec()?)
}

/// Build a blocked DNS response for the given query message.
fn build_blocked_response(
    query: &Message,
    query_type: RecordType,
) -> Result<Vec<u8>, HandlerError> {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(ResponseCode::NoError);
    response.set_recursion_desired(true);
    response.set_recursion_available(true);

    // Copy the query section
    for q in query.queries() {
        response.add_query(q.clone());
    }

    // Add answer based on query type
    if let Some(first_query) = query.queries().first() {
        let name = first_query.name().clone();
        match query_type {
            RecordType::A => {
                let record = Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::UNSPECIFIED)));
                response.add_answer(record);
            }
            RecordType::AAAA => {
                let record =
                    Record::from_rdata(name, 300, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
                response.add_answer(record);
            }
            _ => {
                // Empty answer for other types
            }
        }
    }

    Ok(response.to_vec()?)
}

/// Extract the minimum TTL from a DNS response as a `Duration`.
///
/// Examines the answer section; if no answers are present, falls back to the
/// SOA minimum field from the authority section, or `DEFAULT_TTL_SECS`.
pub fn extract_min_ttl(response_bytes: &[u8]) -> Duration {
    let ttl_secs = Message::from_bytes(response_bytes)
        .ok()
        .and_then(|msg| {
            // Try answer section first
            let from_answers = msg.answers().iter().map(|r| r.ttl()).min();
            if from_answers.is_some() {
                return from_answers;
            }
            // Fall back to SOA minimum in authority section
            msg.name_servers()
                .iter()
                .filter_map(|r| match r.data() {
                    RData::SOA(soa) => Some(soa.minimum()),
                    _ => None,
                })
                .min()
        })
        .unwrap_or(DEFAULT_TTL_SECS as u32);

    Duration::from_secs(ttl_secs as u64)
}

/// Decrement the TTL of every resource record in a DNS response by `elapsed`
/// seconds. Returns the patched wire-format bytes. If parsing fails, the
/// original bytes are returned unchanged. TTL is clamped to a minimum of 1
/// to avoid clients treating 0 as "do not cache" and re-querying immediately.
pub fn decrement_ttl(response_bytes: &[u8], elapsed_secs: u32) -> Vec<u8> {
    let Ok(msg) = Message::from_bytes(response_bytes) else {
        return response_bytes.to_vec();
    };

    let patch = |records: Vec<Record>| -> Vec<Record> {
        records
            .into_iter()
            .map(|mut r| {
                let new_ttl = r.ttl().saturating_sub(elapsed_secs).max(1);
                r.set_ttl(new_ttl);
                r
            })
            .collect()
    };

    let mut patched = msg.clone();
    let answers = patch(msg.answers().to_vec());
    let ns = patch(msg.name_servers().to_vec());
    let additionals = patch(msg.additionals().to_vec());

    *patched.answers_mut() = answers;
    *patched.name_servers_mut() = ns;
    *patched.additionals_mut() = additionals;

    patched.to_vec().unwrap_or_else(|_| response_bytes.to_vec())
}

/// Decide whether and for how long a DNS response should be cached.
///
/// Returns `Some(ttl)` if the response is cacheable, `None` if it must not
/// be cached (e.g. SERVFAIL or other server errors). The goal is to prevent
/// transient upstream failures from poisoning the cache and producing
/// long-lived `NXDOMAIN`/empty answers.
///
/// Rules:
/// - SERVFAIL / Refused / FormErr / NotImp etc. → `None`
/// - NoError with non-empty answer section → positive TTL from answers
/// - NoError with empty answers → negative TTL (SOA min, capped)
/// - NXDOMAIN → negative TTL (SOA min, capped)
/// - Unparseable response → `None`
pub fn cache_ttl_for_response(response_bytes: &[u8]) -> Option<Duration> {
    let msg = Message::from_bytes(response_bytes).ok()?;
    match msg.response_code() {
        ResponseCode::NoError => {
            if msg.answers().is_empty() {
                Some(negative_ttl_from_soa(&msg))
            } else {
                let ttl_secs = msg
                    .answers()
                    .iter()
                    .map(|r| r.ttl())
                    .min()
                    .unwrap_or(DEFAULT_TTL_SECS as u32);
                Some(Duration::from_secs(ttl_secs as u64))
            }
        }
        ResponseCode::NXDomain => Some(negative_ttl_from_soa(&msg)),
        // Do not cache SERVFAIL, Refused, FormErr, NotImp, etc.
        _ => None,
    }
}

/// Compute the negative-cache TTL from a response's SOA authority section,
/// capped by `NEGATIVE_TTL_CAP_SECS`.
fn negative_ttl_from_soa(msg: &Message) -> Duration {
    let soa_min = msg
        .name_servers()
        .iter()
        .filter_map(|r| match r.data() {
            RData::SOA(soa) => Some(soa.minimum()),
            _ => None,
        })
        .min()
        .unwrap_or(NEGATIVE_TTL_CAP_SECS as u32);
    Duration::from_secs((soa_min as u64).min(NEGATIVE_TTL_CAP_SECS))
}

/// Build a DNS SERVFAIL response from raw query bytes.
///
/// Tries to parse the query to preserve ID and question section. Falls back
/// to a minimal SERVFAIL with just the ID copied from raw bytes.
pub fn build_servfail(query_bytes: &[u8]) -> Vec<u8> {
    if let Ok(query) = Message::from_bytes(query_bytes) {
        let mut response = Message::new();
        response.set_id(query.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_response_code(ResponseCode::ServFail);
        response.set_recursion_desired(true);
        response.set_recursion_available(true);
        for q in query.queries() {
            response.add_query(q.clone());
        }
        if let Ok(bytes) = response.to_vec() {
            return bytes;
        }
    }

    let id0 = query_bytes.first().copied().unwrap_or(0);
    let id1 = query_bytes.get(1).copied().unwrap_or(0);
    vec![
        id0, id1, 0x81, 0x82, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

/// RAII guard that removes a key from the in-flight refresh set on drop.
struct RefreshGuard {
    set: Arc<Mutex<HashSet<CacheKey>>>,
    key: CacheKey,
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = self.set.lock() {
            s.remove(&self.key);
        }
    }
}

/// Returns the current Unix timestamp in milliseconds.
///
/// Uses a simple approach without pulling in chrono.
fn chrono_timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Name;
    use hickory_proto::rr::rdata::SOA;
    use std::str::FromStr;

    fn make_response(rcode: ResponseCode, answers: Vec<Record>, soa_min: Option<u32>) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(rcode);
        for a in answers {
            msg.add_answer(a);
        }
        if let Some(min) = soa_min {
            let name = Name::from_str("example.com.").unwrap();
            let soa = SOA::new(
                Name::from_str("ns.example.com.").unwrap(),
                Name::from_str("hostmaster.example.com.").unwrap(),
                1,
                3600,
                600,
                86400,
                min,
            );
            let rec = Record::from_rdata(name, 3600, RData::SOA(soa));
            msg.add_name_server(rec);
        }
        msg.to_vec().unwrap()
    }

    fn a_record(ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        )
    }

    #[test]
    fn servfail_is_not_cached() {
        let bytes = make_response(ResponseCode::ServFail, vec![], None);
        assert!(cache_ttl_for_response(&bytes).is_none());
    }

    #[test]
    fn refused_is_not_cached() {
        let bytes = make_response(ResponseCode::Refused, vec![], None);
        assert!(cache_ttl_for_response(&bytes).is_none());
    }

    #[test]
    fn positive_response_uses_min_answer_ttl() {
        let bytes = make_response(
            ResponseCode::NoError,
            vec![a_record(120), a_record(60), a_record(900)],
            None,
        );
        assert_eq!(
            cache_ttl_for_response(&bytes),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn nxdomain_with_huge_soa_min_is_capped() {
        // SOA minimum 3600s should be clamped to NEGATIVE_TTL_CAP_SECS (60).
        let bytes = make_response(ResponseCode::NXDomain, vec![], Some(3600));
        assert_eq!(
            cache_ttl_for_response(&bytes),
            Some(Duration::from_secs(NEGATIVE_TTL_CAP_SECS))
        );
    }

    #[test]
    fn nxdomain_with_small_soa_min_used_as_is() {
        let bytes = make_response(ResponseCode::NXDomain, vec![], Some(15));
        assert_eq!(
            cache_ttl_for_response(&bytes),
            Some(Duration::from_secs(15))
        );
    }

    #[test]
    fn empty_noerror_uses_negative_ttl() {
        let bytes = make_response(ResponseCode::NoError, vec![], Some(86400));
        assert_eq!(
            cache_ttl_for_response(&bytes),
            Some(Duration::from_secs(NEGATIVE_TTL_CAP_SECS))
        );
    }

    #[test]
    fn empty_noerror_without_soa_falls_back_to_cap() {
        let bytes = make_response(ResponseCode::NoError, vec![], None);
        assert_eq!(
            cache_ttl_for_response(&bytes),
            Some(Duration::from_secs(NEGATIVE_TTL_CAP_SECS))
        );
    }

    #[test]
    fn unparseable_response_is_not_cached() {
        assert!(cache_ttl_for_response(&[0xff, 0xff]).is_none());
    }

    #[test]
    fn refresh_guard_removes_key_on_drop() {
        let set: Arc<Mutex<HashSet<CacheKey>>> = Arc::new(Mutex::new(HashSet::new()));
        let key: CacheKey = ("example.com".to_string(), 1);
        set.lock().unwrap().insert(key.clone());
        {
            let _g = RefreshGuard {
                set: set.clone(),
                key: key.clone(),
            };
        }
        assert!(!set.lock().unwrap().contains(&key));
    }
}
