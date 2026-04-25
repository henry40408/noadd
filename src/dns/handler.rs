use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use thiserror::Error;
use tokio::sync::{Semaphore, mpsc};
use tracing::warn;

use crate::cache::{CacheKey, DnsCache};
use crate::dns::inflight::{BeginResult, InflightUpstream};
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

/// TTL (seconds) used for synthesised blocked-domain responses. Long enough
/// that clients don't re-query the blocked name on every request, short
/// enough that an unblock takes effect without restart.
const BLOCKED_RESPONSE_TTL_SECS: u32 = 300;

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

/// Outcome of `DnsHandler::handle`. Carries the response bytes plus
/// metadata that downstream callers (DoH adapter, listeners) would
/// otherwise have to recompute by re-parsing the response.
#[derive(Debug, Clone)]
pub struct HandleOutcome {
    pub bytes: Vec<u8>,
    /// Lowest TTL observed in the served response, in seconds. Used by
    /// the DoH adapter for the `Cache-Control: max-age` header so it
    /// doesn't have to re-parse the response a fourth time.
    pub min_ttl: u32,
}

/// What action the handler took on a query. Replaces the previous
/// stringly-typed `action: String` field — typos no longer compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryAction {
    Allowed,
    Blocked,
    RateLimited,
}

/// Context for a single DNS query, sent to the async logger.
///
/// `client_ip` and `query_type` are kept in their native form here
/// (`IpAddr`, `u16`) and stringified once per logger flush rather
/// than once per query — the conversion only matters at the DB
/// boundary.
#[derive(Debug, Clone)]
pub struct QueryContext {
    pub timestamp: i64,
    pub client_ip: IpAddr,
    pub domain: String,
    pub query_type: u16,
    pub action: QueryAction,
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
    /// Sharded via `DashMap` so concurrent stale hits for different keys
    /// don't serialise on a single mutex.
    refreshing: Arc<DashMap<CacheKey, ()>>,
    /// Coalesces concurrent cold-miss upstream queries for the same key:
    /// N simultaneous clients produce one upstream request, not N.
    inflight_fetches: Arc<InflightUpstream>,
    /// Bounds concurrent `handle()` calls across all listeners (UDP/TCP/DoH).
    /// Prevents a single noisy client from exhausting the tokio runtime with
    /// unbounded spawned tasks. `None` = unlimited.
    concurrency_limit: Option<Arc<Semaphore>>,
    /// Monotonic count of log events dropped because the async logger
    /// channel was full. A non-zero value means the logger can't keep up
    /// with query volume and some query logs were lost.
    log_drop_count: Arc<AtomicU64>,
    /// Per-client-IP token bucket. `None` means no per-IP limiting.
    rate_limiter: Option<Arc<IpRateLimiter>>,
    /// When true, parse every successful response a third time to populate
    /// the admin-UI `result` column. Off by default — the column is a
    /// nice-to-have and this is the largest single overhead on the
    /// cache-hit path (~10us / cache hit).
    log_query_results: bool,
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
        let concurrency_limit = if max_inflight == 0 {
            None
        } else {
            Some(Arc::new(Semaphore::new(max_inflight)))
        };
        Self {
            filter,
            cache,
            forwarder,
            log_tx,
            refreshing: Arc::new(DashMap::new()),
            inflight_fetches: Arc::new(InflightUpstream::new()),
            concurrency_limit,
            log_drop_count: Arc::new(AtomicU64::new(0)),
            rate_limiter: None,
            log_query_results: false,
        }
    }

    /// Attach a per-client-IP rate limiter. Chainable during construction.
    pub fn with_rate_limiter(mut self, limiter: Arc<IpRateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Enable per-query result-summary extraction for the admin-UI log view.
    /// Off by default; turn on only when the query log's `result` column is
    /// actually consumed.
    pub fn with_log_query_results(mut self, enabled: bool) -> Self {
        self.log_query_results = enabled;
        self
    }

    /// Cumulative number of log events dropped because the async logger
    /// channel was full.
    pub fn log_drop_count(&self) -> u64 {
        self.log_drop_count.load(Ordering::Relaxed)
    }

    /// Handle a DNS query. Takes raw query bytes, client IP, and optional DoH token name.
    /// Returns the response bytes plus metadata downstream callers would
    /// otherwise have to recompute (e.g. min TTL for the DoH `Cache-Control`).
    pub async fn handle(
        &self,
        query_bytes: &[u8],
        client_ip: IpAddr,
        doh_token: Option<String>,
    ) -> Result<HandleOutcome, HandlerError> {
        let start = Instant::now();

        // 0. Acquire in-flight permit. Held until this function returns, so
        // the total number of queries actively consuming upstream / cache /
        // filter resources is bounded — regardless of how many tasks upstream
        // listeners have spawned.
        let _permit = match &self.concurrency_limit {
            Some(sem) => Some(
                sem.clone()
                    .acquire_owned()
                    .await
                    .expect("concurrency-limit semaphore is never closed"),
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
        let query_type_u16: u16 = query_type.into();
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
                timestamp: crate::now_unix_ms(),
                client_ip,
                domain: domain_clean.to_string(),
                query_type: query_type_u16,
                action: QueryAction::RateLimited,
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
            // REFUSED is not cacheable downstream.
            return Ok(HandleOutcome {
                bytes: response_bytes,
                min_ttl: 0,
            });
        }

        // 2b. Check filter
        let filter_guard = self.filter.load();
        let filter_result = filter_guard.check(domain_clean);

        let (response_bytes, min_ttl, action, was_cached, upstream, matched_rule, matched_list) =
            match filter_result {
                FilterResult::Blocked { rule, list } => {
                    let response = build_blocked_response(&message, query_type)?;
                    // build_blocked_response sets every record's TTL to
                    // BLOCKED_RESPONSE_TTL_SECS — keep this in sync.
                    (
                        response,
                        BLOCKED_RESPONSE_TTL_SECS,
                        QueryAction::Blocked,
                        false,
                        None,
                        Some(rule),
                        Some(list),
                    )
                }
                FilterResult::Allowed { .. } => {
                    let cache_key: CacheKey = (domain_clean.to_lowercase(), query_type_u16);

                    // 3. Check cache
                    if let Some(cached) = self.cache.get(&cache_key).await {
                        let bytes = prepare_cached_response(&cached, query_id);
                        let remaining = remaining_ttl_secs(&cached);

                        if cached.is_stale() {
                            // Optimistic: serve stale, refresh in background.
                            // Deduplicate: only spawn if no refresh is already in flight.
                            // `insert` returns the previous value if any, so
                            // `is_none()` ⇒ this caller is the first.
                            let should_refresh =
                                self.refreshing.insert(cache_key.clone(), ()).is_none();

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

                        (
                            bytes,
                            remaining,
                            QueryAction::Allowed,
                            true,
                            None,
                            None,
                            None,
                        )
                    } else {
                        // 4. Forward upstream, coalescing concurrent misses.
                        //    If another task is already fetching this key,
                        //    subscribe to its Notify, re-check cache once it
                        //    fires, and only fall back to our own forward if
                        //    the original fetcher failed.
                        let fetcher_guard = match self.inflight_fetches.begin(&cache_key) {
                            BeginResult::Fetcher(g) => Some(g),
                            BeginResult::Waiter(notify) => {
                                // Subscribe BEFORE checking cache so we don't
                                // miss `notify_waiters` fired between our
                                // cache read and our await.
                                let fut = notify.notified();
                                tokio::pin!(fut);
                                fut.as_mut().enable();
                                if self.cache.get(&cache_key).await.is_none() {
                                    // 3s cap in case the fetcher is wedged
                                    // (bug or stuck upstream); we'll fall
                                    // through and do our own forward.
                                    let _ = tokio::time::timeout(Duration::from_secs(3), fut).await;
                                }
                                None
                            }
                        };

                        if let Some(cached) = self.cache.get(&cache_key).await {
                            // Fetcher populated the cache — treat like a
                            // cache hit (TTL decrement + ID patch).
                            let bytes = prepare_cached_response(&cached, query_id);
                            let remaining = remaining_ttl_secs(&cached);
                            (
                                bytes,
                                remaining,
                                QueryAction::Allowed,
                                true,
                                None,
                                None,
                                None,
                            )
                        } else {
                            // We are the fetcher, OR a waiter whose fetcher
                            // failed / timed out. Forward ourselves.
                            let (response, upstream_addr) =
                                self.forwarder.forward(query_bytes).await?;
                            // Only cache cacheable responses (skip SERVFAIL
                            // etc., and apply a capped negative TTL for
                            // NXDOMAIN/empty NoError) to prevent transient
                            // failures from poisoning the cache.
                            let cache_ttl = cache_ttl_for_response(&response);
                            if let Some(ttl) = cache_ttl {
                                self.cache
                                    .insert(cache_key.clone(), response.clone(), ttl)
                                    .await;
                            }
                            // For DoH max-age: cacheable responses use the
                            // same TTL we just stored; non-cacheable
                            // (SERVFAIL etc.) tell downstream not to cache.
                            let min_ttl = cache_ttl.map(|d| d.as_secs() as u32).unwrap_or(0);
                            // Drop guard (if we hold one) — notifies waiters
                            // after the cache insert is observable.
                            drop(fetcher_guard);
                            (
                                response,
                                min_ttl,
                                QueryAction::Allowed,
                                false,
                                Some(upstream_addr),
                                None,
                                None,
                            )
                        }
                    }
                }
            };

        let elapsed = start.elapsed().as_millis() as i64;

        // 5. Send log context (non-blocking)
        let result = if self.log_query_results {
            extract_result_summary(&response_bytes)
        } else {
            None
        };
        let ctx = QueryContext {
            timestamp: crate::now_unix_ms(),
            client_ip,
            domain: domain_clean.to_string(),
            query_type: query_type_u16,
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

        Ok(HandleOutcome {
            bytes: response_bytes,
            min_ttl,
        })
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
                let record = Record::from_rdata(
                    name,
                    BLOCKED_RESPONSE_TTL_SECS,
                    RData::A(A(Ipv4Addr::UNSPECIFIED)),
                );
                response.add_answer(record);
            }
            RecordType::AAAA => {
                let record = Record::from_rdata(
                    name,
                    BLOCKED_RESPONSE_TTL_SECS,
                    RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
                );
                response.add_answer(record);
            }
            _ => {
                // Empty answer for other types
            }
        }
    }

    Ok(response.to_vec()?)
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

/// Remaining TTL of a cached entry, in seconds, clamped to a minimum of 0.
/// Used as the DoH `Cache-Control: max-age` so downstream clients don't keep
/// a response past the upstream TTL.
fn remaining_ttl_secs(cached: &crate::cache::CacheValue) -> u32 {
    cached
        .ttl()
        .saturating_sub(cached.elapsed())
        .as_secs()
        .min(u32::MAX as u64) as u32
}

/// Produce a cache-hit response: decrement TTLs by how long the entry has been
/// cached, then overwrite the DNS transaction ID with the client's query ID.
///
/// Within a single integer-second window the decremented bytes are identical
/// across all callers, so we cache them on the entry itself. The fast path is
/// then a single `Vec<u8>` clone instead of parse + walk + reencode (~30-50us
/// saved per cache hit after the first one in the window).
fn prepare_cached_response(cached: &crate::cache::CacheValue, query_id: u16) -> Vec<u8> {
    let elapsed = cached.elapsed().as_secs() as u32;
    let mut bytes = match cached.try_patched_bytes(elapsed) {
        Some(cached_bytes) => cached_bytes,
        None => {
            let fresh = decrement_ttl(cached.bytes(), elapsed);
            cached.store_patched_bytes(elapsed, fresh.clone());
            fresh
        }
    };
    let id_bytes = query_id.to_be_bytes();
    if bytes.len() >= 2 {
        bytes[0] = id_bytes[0];
        bytes[1] = id_bytes[1];
    }
    bytes
}

/// RAII guard that removes a key from the in-flight refresh set on drop.
struct RefreshGuard {
    set: Arc<DashMap<CacheKey, ()>>,
    key: CacheKey,
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.set.remove(&self.key);
    }
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
        let set: Arc<DashMap<CacheKey, ()>> = Arc::new(DashMap::new());
        let key: CacheKey = ("example.com".to_string(), 1);
        set.insert(key.clone(), ());
        {
            let _g = RefreshGuard {
                set: set.clone(),
                key: key.clone(),
            };
        }
        assert!(!set.contains_key(&key));
    }
}
