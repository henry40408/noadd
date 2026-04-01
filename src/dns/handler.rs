use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::warn;

use crate::cache::{CacheKey, DnsCache};
use crate::filter::engine::{FilterEngine, FilterResult};
use crate::upstream::forwarder::{ForwardError, UpstreamForwarder};

/// Default TTL (seconds) used when no answer records are present in the response.
const DEFAULT_TTL_SECS: u64 = 300;

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
}

impl DnsHandler {
    pub fn new(
        filter: Arc<ArcSwap<FilterEngine>>,
        cache: DnsCache,
        forwarder: Arc<UpstreamForwarder>,
        log_tx: mpsc::Sender<QueryContext>,
    ) -> Self {
        Self {
            filter,
            cache,
            forwarder,
            log_tx,
            refreshing: Arc::new(Mutex::new(HashSet::new())),
        }
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

        // 1. Parse query
        let message = Message::from_bytes(query_bytes)?;
        let query = message.queries().first().ok_or(HandlerError::NoQuery)?;
        let domain = query.name().to_ascii();
        // Strip trailing dot for filter matching
        let domain_clean = domain.trim_end_matches('.');
        let query_type = query.query_type();
        let query_id = message.id();

        // 2. Check filter
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
                    if let Some(mut cached) = self.cache.get(&cache_key).await {
                        // Patch DNS ID to match the query
                        let id_bytes = query_id.to_be_bytes();
                        if cached.bytes.len() >= 2 {
                            cached.bytes[0] = id_bytes[0];
                            cached.bytes[1] = id_bytes[1];
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
                                    let result = forwarder.forward(&query_owned).await;
                                    if let Ok((response, _)) = result {
                                        let ttl = extract_min_ttl(&response);
                                        cache.insert(key.clone(), response, ttl).await;
                                    }
                                    refreshing.lock().unwrap().remove(&key);
                                });
                            }
                        }

                        (cached.bytes, "allowed".to_string(), true, None, None, None)
                    } else {
                        // 4. Forward upstream
                        let (response, upstream_addr) = self.forwarder.forward(query_bytes).await?;
                        let ttl = extract_min_ttl(&response);
                        self.cache.insert(cache_key, response.clone(), ttl).await;
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
            warn!("failed to send log event: {e}");
        }

        Ok(response_bytes)
    }
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

/// Returns the current Unix timestamp in milliseconds.
///
/// Uses a simple approach without pulling in chrono.
fn chrono_timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
