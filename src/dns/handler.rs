use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use hickory_proto::op::{Edns, Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use thiserror::Error;
use tokio::sync::{Semaphore, mpsc};
use tracing::error;

use crate::cache::{CacheKey, ClientResponseProfile, DnsCache};
use crate::dns::block::{BlockConfig, BlockMode};
use crate::dns::inflight::{BeginResult, InflightUpstream};
use crate::dns::ratelimit::IpRateLimiter;
use crate::dns::ttl;
use crate::filter::engine::{FilterEngine, FilterResult};
use crate::upstream::forwarder::{ForwardError, UpstreamForwarder};

/// Fallback positive TTL (seconds) when no answer TTL can be read.
const DEFAULT_TTL_SECS: u64 = 300;

/// Cap (seconds) on caching a negative response (NXDOMAIN or empty `NoError`).
/// RFC 2308 SOA-derived TTLs can be hours long, turning one transient upstream
/// hiccup into a prolonged "host not found".
const NEGATIVE_TTL_CAP_SECS: u64 = 60;

/// TTL (seconds) of synthesised blocked responses: long enough to stop
/// re-queries, short enough that an unblock takes effect soon.
const BLOCKED_RESPONSE_TTL_SECS: u32 = 300;

/// RFC 1035 §4.2.1 UDP message size, and the RFC 6891 §6.2.3 floor for any
/// EDNS-advertised payload. A client sending no OPT (e.g. Apple's
/// mDNSResponder) is limited to this.
const MIN_UDP_SIZE: usize = 512;

/// Errors that can occur during DNS query handling.
#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("failed to parse DNS query: {0}")]
    Parse(#[from] hickory_proto::serialize::binary::DecodeError),
    #[error("failed to encode DNS message: {0}")]
    Encode(#[from] hickory_proto::ProtoError),
    #[error("no queries in message")]
    NoQuery,
    #[error("upstream error: {0}")]
    Upstream(#[from] ForwardError),
}

/// Outcome of `DnsHandler::handle`: the response bytes plus metadata callers
/// would otherwise re-parse the response for.
#[derive(Debug, Clone)]
pub struct HandleOutcome {
    pub bytes: Vec<u8>,
    /// Lowest TTL in the served response, in seconds; the `DoH` adapter's
    /// `Cache-Control: max-age`.
    pub min_ttl: u32,
}

/// What action the handler took on a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryAction {
    Allowed,
    Blocked,
    RateLimited,
}

/// Context for a single DNS query, sent to the async logger.
///
/// `client_ip` and `query_type` stay native and are stringified at flush,
/// off the query path.
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
    pub authenticated_data: bool,
}

/// Summarise the first three answer records as a comma-separated string.
fn extract_result_summary(response_bytes: &[u8]) -> Option<String> {
    let msg = Message::from_bytes(response_bytes).ok()?;
    let parts: Vec<String> = msg
        .answers
        .iter()
        .take(3)
        .map(|r| match &r.data {
            RData::A(a) => a.0.to_string(),
            RData::AAAA(aaaa) => aaaa.0.to_string(),
            RData::CNAME(cname) => cname.0.to_string(),
            RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange),
            RData::NS(ns) => ns.0.to_string(),
            RData::PTR(ptr) => ptr.0.to_string(),
            RData::TXT(txt) => txt
                .txt_data
                .iter()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<String>(),
            RData::SOA(soa) => format!("{} {}", soa.mname, soa.rname),
            RData::SRV(srv) => {
                format!(
                    "{}:{} p={} w={}",
                    srv.target, srv.port, srv.priority, srv.weight
                )
            }
            RData::CAA(caa) => {
                format!("{} {}", caa.tag, String::from_utf8_lossy(&caa.value))
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
/// Shared across all listener tasks (UDP, TCP, `DoH`) behind `Arc<DnsHandler>`.
pub struct DnsHandler {
    filter: Arc<ArcSwap<FilterEngine>>,
    cache: DnsCache,
    forwarder: Arc<UpstreamForwarder>,
    log_tx: mpsc::Sender<QueryContext>,
    /// Keys with a background stale refresh in flight, so each gets one task.
    /// `DashMap` so stale hits on different keys don't share a mutex.
    refreshing: Arc<DashMap<CacheKey, ()>>,
    /// Coalesces concurrent cold misses for one key into one upstream request.
    inflight_fetches: Arc<InflightUpstream>,
    /// Bounds concurrent `handle()` calls across all listeners, so a flood
    /// cannot exhaust the runtime. `None` = unlimited.
    concurrency_limit: Option<Arc<Semaphore>>,
    /// Per-client-IP token bucket. `None` means no per-IP limiting.
    rate_limiter: Option<Arc<IpRateLimiter>>,
    /// Parse every response again to fill the query log's `result` column.
    /// Off by default: it is the largest single cost on the cache-hit path.
    log_query_results: bool,
    /// Block-response configuration; `ArcSwap` for lock-free reads and live
    /// updates from settings.
    block_config: Arc<ArcSwap<BlockConfig>>,
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
            rate_limiter: None,
            log_query_results: false,
            block_config: Arc::new(ArcSwap::from_pointee(BlockConfig::default())),
        }
    }

    /// Attach a per-client-IP rate limiter. Chainable during construction.
    pub fn with_rate_limiter(mut self, limiter: Arc<IpRateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Enable result-summary extraction for the query log's `result` column.
    pub fn with_log_query_results(mut self, enabled: bool) -> Self {
        self.log_query_results = enabled;
        self
    }

    /// Install the initial (persisted) block-response configuration.
    pub fn with_block_config(self, cfg: BlockConfig) -> Self {
        self.block_config.store(Arc::new(cfg));
        self
    }

    /// Atomically replace the block-response configuration at runtime.
    pub fn set_block_config(&self, cfg: BlockConfig) {
        self.block_config.store(Arc::new(cfg));
    }

    /// Load the current block-response configuration.
    pub fn block_config(&self) -> arc_swap::Guard<Arc<BlockConfig>> {
        self.block_config.load()
    }

    /// Handle a raw DNS query from `client_ip`, with the `DoH` token name if any.
    pub async fn handle(
        &self,
        query_bytes: &[u8],
        client_ip: IpAddr,
        doh_token: Option<String>,
    ) -> Result<HandleOutcome, HandlerError> {
        let start = Instant::now();

        // Held for the whole call, bounding active queries however many tasks
        // the listeners spawned.
        let _permit = match &self.concurrency_limit {
            Some(sem) => Some(
                sem.clone()
                    .acquire_owned()
                    .await
                    .expect("concurrency-limit semaphore is never closed"),
            ),
            None => None,
        };

        let message = Message::from_bytes(query_bytes)?;

        // Non-standard opcodes get NOTIMP and EDNS version > 0 gets BADVERS
        // (RFC 6891 §6.1.3), before filter, cache or upstream. Neither is
        // logged or rate-limited.
        if message.metadata.op_code != OpCode::Query {
            return Ok(HandleOutcome {
                bytes: build_notimp_response(&message)?,
                min_ttl: 0,
            });
        }
        if message.edns.as_ref().is_some_and(|edns| edns.version() > 0) {
            return Ok(HandleOutcome {
                bytes: build_badvers_response(&message)?,
                min_ttl: 0,
            });
        }

        let query = message.queries.first().ok_or(HandlerError::NoQuery)?;
        let domain = query.name().to_ascii();
        let domain_clean = domain.trim_end_matches('.');
        let query_type = query.query_type();
        let query_type_u16: u16 = query_type.into();
        let query_id = message.metadata.id;
        let response_profile = ClientResponseProfile {
            has_edns: message.edns.is_some(),
            dnssec_ok: message
                .edns
                .as_ref()
                .is_some_and(|edns| edns.flags().dnssec_ok),
            checking_disabled: message.metadata.checking_disabled,
            upstream_dnssec_enabled: self.forwarder.dnssec_enabled(),
        };

        // REFUSED says "unwilling", not "broken" as SERVFAIL would.
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
                authenticated_data: false,
            };
            if let Err(e) = self.log_tx.try_send(ctx) {
                error!(
                    event = "querylog.dropped",
                    error = %e,
                    "query log event dropped, logger cannot keep up"
                );
            }
            // REFUSED is not cacheable downstream.
            return Ok(HandleOutcome {
                bytes: response_bytes,
                min_ttl: 0,
            });
        }

        let filter_guard = self.filter.load();
        let filter_result = filter_guard.check(domain_clean);

        let (
            response_bytes,
            min_ttl,
            action,
            was_cached,
            upstream,
            matched_rule,
            matched_list,
            authenticated,
        ) = match filter_result {
            FilterResult::Blocked { rule, list } => {
                let block_cfg = self.block_config.load();
                let response = build_blocked_response(&message, query_type, &block_cfg)?;
                // Must match the TTL build_blocked_response writes.
                (
                    response,
                    BLOCKED_RESPONSE_TTL_SECS,
                    QueryAction::Blocked,
                    false,
                    None,
                    Some(rule),
                    Some(list),
                    // Locally-synthesised block, never validated upstream.
                    false,
                )
            }
            FilterResult::Allowed { .. } => {
                // Skip to_lowercase()'s pass for the common all-lowercase name.
                let domain_lower = if domain_clean.bytes().any(|b| b.is_ascii_uppercase()) {
                    domain_clean.to_lowercase()
                } else {
                    domain_clean.to_string()
                };
                let cache_key = CacheKey::new(domain_lower, query_type_u16, response_profile);

                if let Some(cached) = self.cache.get(&cache_key).await {
                    let bytes = prepare_cached_response(&cached, query_id);
                    let remaining = remaining_ttl_secs(&cached);

                    if cached.is_stale() {
                        // Serve stale, refresh in the background — once per key.
                        let should_refresh =
                            self.refreshing.insert(cache_key.clone(), ()).is_none();

                        if should_refresh {
                            let forwarder = self.forwarder.clone();
                            let cache = self.cache.clone();
                            let refreshing = self.refreshing.clone();
                            let query_owned = query_bytes.to_vec();
                            let key = cache_key.clone();
                            tokio::spawn(async move {
                                // Clears the marker even on panic or cancel,
                                // or one bad refresh would block the key forever.
                                let _guard = RefreshGuard {
                                    set: refreshing,
                                    key: key.clone(),
                                };
                                match forwarder.forward(&query_owned).await {
                                    Ok((response, _, authenticated)) => {
                                        if let Some(ttl) = cache_ttl_for_response(&response) {
                                            cache.insert(key, response, ttl, authenticated).await;
                                        } else {
                                            tracing::debug!(
                                                event = "cache.stale_refresh_uncacheable",
                                                "stale refresh got non-cacheable response"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            event = "cache.stale_refresh_failed",
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
                        cached.authenticated_data(),
                    )
                } else {
                    // Coalesce misses: a waiter re-checks the cache once the
                    // fetcher finishes and forwards itself only if it failed.
                    let fetcher_guard = match self.inflight_fetches.begin(&cache_key) {
                        BeginResult::Fetcher(g) => Some(g),
                        BeginResult::Waiter(notify) => {
                            // Subscribe before the cache check, or a
                            // `notify_waiters` in between is lost.
                            let fut = notify.notified();
                            tokio::pin!(fut);
                            fut.as_mut().enable();
                            if self.cache.get(&cache_key).await.is_none() {
                                // Cap in case the fetcher is wedged; then
                                // forward ourselves.
                                let _ = tokio::time::timeout(Duration::from_secs(3), fut).await;
                            }
                            None
                        }
                    };

                    if let Some(cached) = self.cache.get(&cache_key).await {
                        // Fetcher filled the cache: serve as a hit.
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
                            cached.authenticated_data(),
                        )
                    } else {
                        // Fetcher, or a waiter whose fetcher failed/timed out.
                        let (response, upstream_addr, upstream_ad) =
                            self.forwarder.forward(query_bytes).await?;
                        let cache_ttl = cache_ttl_for_response(&response);
                        if let Some(ttl) = cache_ttl {
                            self.cache
                                .insert(cache_key.clone(), response.clone(), ttl, upstream_ad)
                                .await;
                        }
                        // DoH max-age: the stored TTL, or 0 if uncacheable.
                        let min_ttl = cache_ttl.map_or(0, |d| d.as_secs() as u32);
                        // Wake waiters only once the insert is visible.
                        drop(fetcher_guard);
                        (
                            response,
                            min_ttl,
                            QueryAction::Allowed,
                            false,
                            Some(upstream_addr),
                            None,
                            None,
                            upstream_ad,
                        )
                    }
                }
            }
        };

        let elapsed = start.elapsed().as_millis() as i64;

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
            authenticated_data: authenticated,
        };
        // Logging is non-blocking, but a dropped entry makes every statistic
        // under-report for good — a fault, hence `error!`.
        if let Err(e) = self.log_tx.try_send(ctx) {
            error!(
                event = "querylog.dropped",
                error = %e,
                "query log event dropped, logger cannot keep up"
            );
        }

        Ok(HandleOutcome {
            bytes: response_bytes,
            min_ttl,
        })
    }
}

/// Build a REFUSED response echoing the query's ID, question and RD bit.
fn build_refused_response(query: &Message) -> Result<Vec<u8>, HandlerError> {
    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.response_code = ResponseCode::Refused;
    // RFC 1035 §4.1.1: RD is set by the client and copied into the response.
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    for q in &query.queries {
        response.add_query(q.clone());
    }
    Ok(response.to_vec()?)
}

/// Build a blocked response according to `config`.
fn build_blocked_response(
    query: &Message,
    query_type: RecordType,
    config: &BlockConfig,
) -> Result<Vec<u8>, HandlerError> {
    // REFUSED and NXDOMAIN apply uniformly to every query type.
    match config.mode {
        BlockMode::Refused => return build_refused_response(query),
        BlockMode::Nxdomain => {
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.metadata.response_code = ResponseCode::NXDomain;
            response.metadata.recursion_desired = query.metadata.recursion_desired;
            response.metadata.recursion_available = true;
            for q in &query.queries {
                response.add_query(q.clone());
            }
            return Ok(response.to_vec()?);
        }
        BlockMode::NullIp | BlockMode::CustomIp => {}
    }

    // Address modes: NoError, with an A/AAAA answer when an address exists for
    // the query type, else no answer.
    let (v4, v6) = match config.mode {
        BlockMode::CustomIp => (config.custom_v4, config.custom_v6),
        _ => (Some(Ipv4Addr::UNSPECIFIED), Some(Ipv6Addr::UNSPECIFIED)),
    };

    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.response_code = ResponseCode::NoError;
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;

    for q in &query.queries {
        response.add_query(q.clone());
    }

    if let Some(first_query) = query.queries.first() {
        let name = first_query.name().clone();
        match query_type {
            RecordType::A => {
                if let Some(addr) = v4 {
                    response.add_answer(Record::from_rdata(
                        name,
                        BLOCKED_RESPONSE_TTL_SECS,
                        RData::A(A(addr)),
                    ));
                }
            }
            RecordType::AAAA => {
                if let Some(addr) = v6 {
                    response.add_answer(Record::from_rdata(
                        name,
                        BLOCKED_RESPONSE_TTL_SECS,
                        RData::AAAA(AAAA(addr)),
                    ));
                }
            }
            _ => {}
        }
    }

    Ok(response.to_vec()?)
}

/// How long to cache a response, or `None` if it must not be cached, so
/// transient upstream failures cannot poison the cache.
///
/// - SERVFAIL / Refused / `FormErr` / `NotImp` etc. → `None`
/// - `NoError` with non-empty answer section → positive TTL from answers
/// - `NoError` with empty answers → negative TTL (SOA min, capped)
/// - NXDOMAIN → negative TTL (SOA min, capped)
/// - Unparseable response → `None`
pub fn cache_ttl_for_response(response_bytes: &[u8]) -> Option<Duration> {
    let msg = Message::from_bytes(response_bytes).ok()?;
    match msg.metadata.response_code {
        ResponseCode::NoError => {
            if msg.answers.is_empty() {
                Some(negative_ttl_from_soa(&msg))
            } else {
                let ttl_secs = msg
                    .answers
                    .iter()
                    .map(|r| r.ttl)
                    .min()
                    .unwrap_or(DEFAULT_TTL_SECS as u32);
                Some(Duration::from_secs(ttl_secs as u64))
            }
        }
        ResponseCode::NXDomain => Some(negative_ttl_from_soa(&msg)),
        _ => None,
    }
}

/// Compute the negative-cache TTL from a response's SOA authority section,
/// capped by `NEGATIVE_TTL_CAP_SECS`.
fn negative_ttl_from_soa(msg: &Message) -> Duration {
    let soa_min = msg
        .authorities
        .iter()
        .filter_map(|r| match &r.data {
            RData::SOA(soa) => Some(soa.minimum),
            _ => None,
        })
        .min()
        .unwrap_or(NEGATIVE_TTL_CAP_SECS as u32);
    Duration::from_secs((soa_min as u64).min(NEGATIVE_TTL_CAP_SECS))
}

/// Build a SERVFAIL from raw query bytes, echoing ID, question and RD; if the
/// query does not parse, a bare header carrying only the raw ID.
pub fn build_servfail(query_bytes: &[u8]) -> Vec<u8> {
    if let Ok(query) = Message::from_bytes(query_bytes) {
        let mut response = Message::response(query.metadata.id, OpCode::Query);
        response.metadata.response_code = ResponseCode::ServFail;
        response.metadata.recursion_desired = query.metadata.recursion_desired;
        response.metadata.recursion_available = true;
        for q in &query.queries {
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

/// Build a NOTIMP response for a non-`Query` opcode, echoing opcode, ID,
/// question and RD bit.
fn build_notimp_response(query: &Message) -> Result<Vec<u8>, HandlerError> {
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.response_code = ResponseCode::NotImp;
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    for q in &query.queries {
        response.add_query(q.clone());
    }
    Ok(response.to_vec()?)
}

/// Build a BADVERS response for an unsupported EDNS version (RFC 6891 §6.1.3).
/// RCODE 16 is split between header and OPT, which hickory does on encode only
/// if an OPT is present; the OPT's version 0 advertises the highest we support.
fn build_badvers_response(query: &Message) -> Result<Vec<u8>, HandlerError> {
    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.response_code = ResponseCode::BADVERS;
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    for q in &query.queries {
        response.add_query(q.clone());
    }
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_max_payload(MIN_UDP_SIZE as u16);
    response.set_edns(edns);
    Ok(response.to_vec()?)
}

/// Fit a response to the client's UDP limit, truncating with TC set so it
/// retries over TCP (RFC 1035 §4.2.1 / RFC 6891).
///
/// Needed because upstream answers can exceed what the client asked for (with
/// DNSSEC on, `noadd` forces DO and a 1232-byte payload upstream). The limit is
/// [`client_udp_payload`]. [`Message::truncate`] keeps header, question and OPT
/// and drops the record sections. On a parse failure the original bytes are
/// returned — an oversized datagram beats a dropped query. UDP only.
pub fn truncate_for_udp(query_bytes: &[u8], response_bytes: Vec<u8>) -> Vec<u8> {
    // Every client's limit is at least 512, so skip the query parse.
    if response_bytes.len() <= MIN_UDP_SIZE {
        return response_bytes;
    }
    let max_size = client_udp_payload(query_bytes);
    if response_bytes.len() <= max_size {
        return response_bytes;
    }
    match Message::from_bytes(&response_bytes) {
        Ok(msg) => msg.truncate().to_vec().unwrap_or(response_bytes),
        Err(_) => response_bytes,
    }
}

/// The UDP payload size the client is willing to receive: its EDNS OPT
/// advertised size floored at [`MIN_UDP_SIZE`] (RFC 6891 §6.2.3), or
/// [`MIN_UDP_SIZE`] when the client sent no OPT (RFC 1035 §2.3.4).
fn client_udp_payload(query_bytes: &[u8]) -> usize {
    let advertised = Message::from_bytes(query_bytes)
        .ok()
        .and_then(|m| m.edns.map(|e| e.max_payload()))
        .unwrap_or(0) as usize;
    advertised.max(MIN_UDP_SIZE)
}

/// Remaining TTL of a cached entry in seconds, floored at 0; the `DoH` max-age.
fn remaining_ttl_secs(cached: &crate::cache::CacheValue) -> u32 {
    cached
        .ttl()
        .saturating_sub(cached.elapsed())
        .as_secs()
        .min(u32::MAX as u64) as u32
}

/// Produce a cache-hit response: age the TTLs and patch in the client's ID.
/// Both are writes at known offsets — one copy, no parse or re-encode.
fn prepare_cached_response(cached: &crate::cache::CacheValue, query_id: u16) -> Vec<u8> {
    let mut bytes = cached.bytes().to_vec();
    let elapsed = cached.elapsed().as_secs() as u32;
    ttl::apply_elapsed(&mut bytes, cached.ttl_offsets(), elapsed);
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
        let mut msg = Message::response(1, OpCode::Query);
        msg.metadata.response_code = rcode;
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
            msg.add_authority(rec);
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
        let key = CacheKey::new(
            "example.com".to_string(),
            1,
            ClientResponseProfile::default(),
        );
        set.insert(key.clone(), ());
        {
            let _g = RefreshGuard {
                set: set.clone(),
                key: key.clone(),
            };
        }
        assert!(!set.contains_key(&key));
    }

    use crate::dns::block::{BlockConfig, BlockMode};
    use hickory_proto::op::{Edns, MessageType, Query};

    fn plain_query() -> Vec<u8> {
        let mut msg = Message::new(42, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        msg.to_vec().unwrap()
    }

    fn edns_query(payload: u16) -> Vec<u8> {
        let mut msg = Message::new(42, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(payload);
        msg.set_edns(edns);
        msg.to_vec().unwrap()
    }

    /// A NOERROR response echoing the question with `n` A answer records.
    fn response_with_n_a_records(n: usize) -> Vec<u8> {
        let name = Name::from_str("example.com.").unwrap();
        let mut msg = Message::response(42, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.add_query(Query::query(name.clone(), RecordType::A));
        for i in 0..n {
            let addr = Ipv4Addr::new(10, 0, (i >> 8) as u8, (i & 0xff) as u8);
            msg.add_answer(Record::from_rdata(name.clone(), 300, RData::A(A(addr))));
        }
        msg.to_vec().unwrap()
    }

    #[test]
    fn small_response_passes_through_untouched() {
        let resp = response_with_n_a_records(1);
        assert!(resp.len() <= MIN_UDP_SIZE, "precondition: {}", resp.len());
        let out = truncate_for_udp(&plain_query(), resp.clone());
        assert_eq!(out, resp);
        assert!(!Message::from_bytes(&out).unwrap().metadata.truncation);
    }

    #[test]
    fn oversized_response_to_plain_client_sets_tc_and_fits_512() {
        let resp = response_with_n_a_records(120);
        assert!(resp.len() > MIN_UDP_SIZE, "precondition: {}", resp.len());
        let out = truncate_for_udp(&plain_query(), resp);
        assert!(out.len() <= MIN_UDP_SIZE, "must fit 512, got {}", out.len());
        let parsed = Message::from_bytes(&out).unwrap();
        assert!(parsed.metadata.truncation, "TC bit must be set");
        assert!(parsed.answers.is_empty(), "answers must be dropped");
        assert_eq!(parsed.queries.len(), 1, "question must be preserved");
        assert_eq!(parsed.metadata.id, 42, "id must be preserved");
    }

    #[test]
    fn response_within_advertised_edns_size_not_truncated() {
        let resp = response_with_n_a_records(120);
        assert!(resp.len() < 4096, "precondition: {}", resp.len());
        let out = truncate_for_udp(&edns_query(4096), resp.clone());
        assert_eq!(out, resp);
        assert!(!Message::from_bytes(&out).unwrap().metadata.truncation);
    }

    #[test]
    fn oversized_response_to_edns_client_truncated_to_advertised() {
        // Responses served to an EDNS client carry an OPT (added by
        // `prepare_response_for_client`); it must survive truncation.
        let mut msg = Message::from_bytes(&response_with_n_a_records(120)).unwrap();
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        msg.set_edns(edns);
        let resp = msg.to_vec().unwrap();
        assert!(resp.len() > 1232, "precondition: {}", resp.len());
        let out = truncate_for_udp(&edns_query(1232), resp);
        assert!(
            out.len() <= 1232,
            "must fit advertised 1232, got {}",
            out.len()
        );
        let parsed = Message::from_bytes(&out).unwrap();
        assert!(parsed.metadata.truncation, "TC bit must be set");
        assert!(
            parsed.edns.is_some(),
            "OPT must be preserved for an EDNS client"
        );
    }

    #[test]
    fn edns_advertised_below_512_is_floored_to_512() {
        let resp = response_with_n_a_records(20);
        assert!(
            resp.len() > MIN_UDP_SIZE / 2 && resp.len() <= MIN_UDP_SIZE,
            "precondition: {}",
            resp.len()
        );
        // Advertised 200 must be floored to 512, so this response fits untouched.
        let out = truncate_for_udp(&edns_query(200), resp.clone());
        assert_eq!(out, resp);
    }

    #[test]
    fn unparseable_oversized_response_returned_unchanged() {
        let garbage = vec![0xffu8; 600];
        let out = truncate_for_udp(&plain_query(), garbage.clone());
        assert_eq!(out, garbage);
    }

    /// A `Query`-opcode message for `example.com`/A with an explicit RD bit.
    fn query_with_rd(rd: bool) -> Message {
        let mut msg = Message::new(7, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = rd;
        msg.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        msg
    }

    #[test]
    fn refused_response_echoes_query_rd() {
        for rd in [true, false] {
            let bytes = build_refused_response(&query_with_rd(rd)).unwrap();
            let resp = Message::from_bytes(&bytes).unwrap();
            assert_eq!(resp.metadata.recursion_desired, rd, "RD must be copied");
            assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
            assert!(resp.metadata.recursion_available, "RA stays advertised");
        }
    }

    #[test]
    fn blocked_response_echoes_query_rd() {
        let modes = [
            BlockConfig::default(), // null_ip
            BlockConfig {
                mode: BlockMode::Nxdomain,
                ..BlockConfig::default()
            },
            BlockConfig {
                mode: BlockMode::Refused,
                ..BlockConfig::default()
            },
        ];
        for cfg in modes {
            for rd in [true, false] {
                let bytes =
                    build_blocked_response(&query_with_rd(rd), RecordType::A, &cfg).unwrap();
                let resp = Message::from_bytes(&bytes).unwrap();
                assert_eq!(resp.metadata.recursion_desired, rd, "RD must be copied");
            }
        }
    }

    #[test]
    fn servfail_echoes_query_rd() {
        for rd in [true, false] {
            let bytes = build_servfail(&query_with_rd(rd).to_vec().unwrap());
            let resp = Message::from_bytes(&bytes).unwrap();
            assert_eq!(resp.metadata.recursion_desired, rd, "RD must be copied");
            assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        }
    }

    #[test]
    fn notimp_response_echoes_opcode_question_and_rd() {
        let mut q = Message::new(11, MessageType::Query, OpCode::Status);
        q.metadata.recursion_desired = false;
        q.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let resp = Message::from_bytes(&build_notimp_response(&q).unwrap()).unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NotImp);
        assert_eq!(
            resp.metadata.op_code,
            OpCode::Status,
            "opcode must be echoed"
        );
        assert_eq!(resp.metadata.message_type, MessageType::Response);
        assert!(!resp.metadata.recursion_desired, "RD must be copied");
        assert_eq!(resp.metadata.id, 11);
        assert_eq!(resp.queries.len(), 1, "question must be echoed");
    }

    #[test]
    fn badvers_response_sets_extended_rcode_and_opt() {
        let resp =
            Message::from_bytes(&build_badvers_response(&query_with_rd(true)).unwrap()).unwrap();
        // Extended RCODE 16. On the wire BADVERS and BADSIG are indistinguishable
        // (both encode 16), so assert the numeric code rather than the variant.
        assert_eq!(
            u16::from(resp.metadata.response_code),
            16,
            "extended RCODE must be 16"
        );
        let edns = resp
            .edns
            .as_ref()
            .expect("BADVERS response must carry an OPT");
        assert_eq!(
            edns.version(),
            0,
            "must advertise the highest supported version"
        );
        assert!(resp.metadata.recursion_desired, "RD must be copied");
        assert_eq!(resp.queries.len(), 1, "question must be echoed");
    }

    fn make_query(domain: &str, rtype: RecordType) -> Message {
        let mut msg = Message::new(42, MessageType::Query, OpCode::Query);
        let name = Name::from_ascii(domain).expect("valid domain name");
        msg.add_query(Query::query(name, rtype));
        msg
    }

    fn blocked(msg: &Message, rtype: RecordType, cfg: &BlockConfig) -> Message {
        let bytes = build_blocked_response(msg, rtype, cfg).unwrap();
        Message::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn null_ip_mode_returns_unspecified_addresses() {
        let cfg = BlockConfig::default();
        let a = blocked(
            &make_query("ads.example.com.", RecordType::A),
            RecordType::A,
            &cfg,
        );
        assert_eq!(a.metadata.response_code, ResponseCode::NoError);
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

        let aaaa = blocked(
            &make_query("ads.example.com.", RecordType::AAAA),
            RecordType::AAAA,
            &cfg,
        );
        assert_eq!(
            aaaa.answers[0].data,
            RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))
        );

        let txt = blocked(
            &make_query("ads.example.com.", RecordType::TXT),
            RecordType::TXT,
            &cfg,
        );
        assert_eq!(txt.metadata.response_code, ResponseCode::NoError);
        assert!(txt.answers.is_empty());
    }

    #[test]
    fn nxdomain_mode_returns_nxdomain_for_all_types() {
        let cfg = BlockConfig {
            mode: BlockMode::Nxdomain,
            ..BlockConfig::default()
        };
        for rt in [RecordType::A, RecordType::AAAA, RecordType::TXT] {
            let m = blocked(&make_query("ads.example.com.", rt), rt, &cfg);
            assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
            assert!(m.answers.is_empty());
        }
    }

    #[test]
    fn refused_mode_returns_refused_for_all_types() {
        let cfg = BlockConfig {
            mode: BlockMode::Refused,
            ..BlockConfig::default()
        };
        for rt in [RecordType::A, RecordType::AAAA, RecordType::TXT] {
            let m = blocked(&make_query("ads.example.com.", rt), rt, &cfg);
            assert_eq!(m.metadata.response_code, ResponseCode::Refused);
            assert!(m.answers.is_empty());
        }
    }

    #[test]
    fn custom_ip_mode_uses_configured_addresses() {
        let cfg = BlockConfig {
            mode: BlockMode::CustomIp,
            custom_v4: Some(Ipv4Addr::new(192, 0, 2, 1)),
            custom_v6: Some("100::1".parse().unwrap()),
        };
        let a = blocked(
            &make_query("ads.example.com.", RecordType::A),
            RecordType::A,
            &cfg,
        );
        assert_eq!(a.answers[0].data, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))));
        let aaaa = blocked(
            &make_query("ads.example.com.", RecordType::AAAA),
            RecordType::AAAA,
            &cfg,
        );
        assert_eq!(
            aaaa.answers[0].data,
            RData::AAAA(AAAA("100::1".parse().unwrap()))
        );
    }

    #[test]
    fn custom_ip_mode_unset_address_gives_empty_noerror() {
        let cfg = BlockConfig {
            mode: BlockMode::CustomIp,
            custom_v4: None,
            custom_v6: None,
        };
        let a = blocked(
            &make_query("ads.example.com.", RecordType::A),
            RecordType::A,
            &cfg,
        );
        assert_eq!(a.metadata.response_code, ResponseCode::NoError);
        assert!(a.answers.is_empty());
    }
}
