use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Instant;

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
}

/// Core DNS query handler implementing the filter-cache-forward pipeline.
///
/// Shared across all listener tasks (UDP, TCP, DoH) behind `Arc<DnsHandler>`.
pub struct DnsHandler {
    filter: Arc<ArcSwap<FilterEngine>>,
    cache: DnsCache,
    forwarder: Arc<UpstreamForwarder>,
    log_tx: mpsc::Sender<QueryContext>,
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
                    (response, "blocked".to_string(), false, None, Some(rule), Some(list))
                }
                FilterResult::Allowed => {
                    let cache_key: CacheKey = (domain_clean.to_lowercase(), query_type.into());

                    // 3. Check cache
                    if let Some(mut cached) = self.cache.get(&cache_key).await {
                        // Patch DNS ID to match the query
                        let id_bytes = query_id.to_be_bytes();
                        if cached.len() >= 2 {
                            cached[0] = id_bytes[0];
                            cached[1] = id_bytes[1];
                        }
                        (cached, "allowed".to_string(), true, None, None, None)
                    } else {
                        // 4. Forward upstream
                        let (response, upstream_addr) =
                            self.forwarder.forward(query_bytes).await?;
                        self.cache.insert(cache_key, response.clone()).await;
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
                let record = Record::from_rdata(
                    name,
                    300,
                    RData::A(A(Ipv4Addr::UNSPECIFIED)),
                );
                response.add_answer(record);
            }
            RecordType::AAAA => {
                let record = Record::from_rdata(
                    name,
                    300,
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

/// Returns the current Unix timestamp in milliseconds.
///
/// Uses a simple approach without pulling in chrono.
fn chrono_timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
