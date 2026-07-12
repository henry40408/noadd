use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::sync::mpsc;

use noadd::cache::DnsCache;
use noadd::dns::handler::{self, DnsHandler, QueryAction, QueryContext};
use noadd::dns::ratelimit::IpRateLimiter;
use noadd::filter::engine::FilterEngine;
use noadd::filter::parser::{ParsedRule, RuleAction};
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

fn make_query_bytes(domain: &str, record_type: RecordType) -> Vec<u8> {
    let mut msg = Message::new(1234, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut query = hickory_proto::op::Query::new();
    query.set_name(Name::from_str(domain).unwrap());
    query.set_query_type(record_type);
    msg.add_query(query);
    msg.to_vec().unwrap()
}

async fn make_handler(
    block_rules: Vec<(ParsedRule, String)>,
    allow_rules: Vec<ParsedRule>,
) -> (DnsHandler, mpsc::Receiver<QueryContext>) {
    let engine = FilterEngine::from_named_rules(block_rules, allow_rules);
    let filter = Arc::new(ArcSwap::from_pointee(engine));
    let cache = DnsCache::new(100);
    let config = UpstreamConfig::default();
    let forwarder = Arc::new(UpstreamForwarder::new(config).await);
    let (tx, rx) = mpsc::channel(64);
    let handler = DnsHandler::new(filter, cache, forwarder, tx);
    (handler, rx)
}

#[tokio::test]
async fn test_handler_blocks_domain() {
    let block_rules = vec![(
        ParsedRule {
            domain: "ads.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        },
        "test-list".to_string(),
    )];

    let (handler, _rx) = make_handler(block_rules, vec![]).await;
    let query = make_query_bytes("ads.example.com", RecordType::A);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let result = handler.handle(&query, client_ip, None).await.unwrap();
    let response = Message::from_bytes(&result.bytes).unwrap();

    assert!(response.metadata.message_type == MessageType::Response);
    assert_eq!(response.metadata.id, 1234);
    assert!(!response.answers.is_empty(), "should have an answer");

    let answer = &response.answers[0];
    match &answer.data {
        RData::A(a) => {
            assert_eq!(a.0, Ipv4Addr::UNSPECIFIED, "blocked A should be 0.0.0.0");
        }
        other => panic!("expected A record, got {other:?}"),
    }
}

#[tokio::test]
async fn test_handler_blocks_aaaa_domain() {
    let block_rules = vec![(
        ParsedRule {
            domain: "ads.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        },
        "test-list".to_string(),
    )];

    let (handler, _rx) = make_handler(block_rules, vec![]).await;
    let query = make_query_bytes("ads.example.com", RecordType::AAAA);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let result = handler.handle(&query, client_ip, None).await.unwrap();
    let response = Message::from_bytes(&result.bytes).unwrap();

    assert!(!response.answers.is_empty(), "should have an answer");
    let answer = &response.answers[0];
    match &answer.data {
        RData::AAAA(aaaa) => {
            assert_eq!(
                aaaa.0,
                std::net::Ipv6Addr::UNSPECIFIED,
                "blocked AAAA should be ::"
            );
        }
        other => panic!("expected AAAA record, got {other:?}"),
    }
}

#[tokio::test]
async fn test_handler_forwards_allowed_domain() {
    let (handler, _rx) = make_handler(vec![], vec![]).await;
    let query = make_query_bytes("example.com", RecordType::A);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let result = handler.handle(&query, client_ip, None).await.unwrap();
    assert!(!result.bytes.is_empty(), "response should be non-empty");

    let response = Message::from_bytes(&result.bytes).unwrap();
    assert!(response.metadata.message_type == MessageType::Response);
}

#[tokio::test]
async fn test_handler_sends_log_event() {
    let block_rules = vec![(
        ParsedRule {
            domain: "ads.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        },
        "test-list".to_string(),
    )];

    let (handler, mut rx) = make_handler(block_rules, vec![]).await;
    let query = make_query_bytes("ads.example.com", RecordType::A);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    handler.handle(&query, client_ip, None).await.unwrap();

    let ctx = rx.try_recv().expect("should receive a log event");
    assert_eq!(ctx.action, QueryAction::Blocked);
    assert_eq!(ctx.domain, "ads.example.com");
    assert_eq!(ctx.client_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert!(ctx.matched_rule.is_some());
    assert!(ctx.matched_list.is_some());
}

/// Build a fake DNS response with a single A record at the given TTL.
fn build_response_with_ttl(id: u16, domain: &str, ttl: u32) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
    msg.metadata.response_code = ResponseCode::NoError;
    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;

    let name = Name::from_str(domain).unwrap();
    let record = Record::from_rdata(name, ttl, RData::A(A(Ipv4Addr::new(93, 184, 216, 34))));
    msg.add_answer(record);
    msg.to_vec().unwrap()
}

#[test]
fn test_decrement_ttl_reduces_answer_ttl() {
    let original = build_response_with_ttl(0xABCD, "example.com.", 300);
    let patched = handler::decrement_ttl(&original, 120);

    let msg = Message::from_bytes(&patched).unwrap();
    let answer_ttl = msg.answers[0].ttl;
    assert_eq!(
        answer_ttl, 180,
        "TTL should be decremented from 300 by 120 to 180"
    );
}

#[test]
fn test_decrement_ttl_clamps_to_minimum_1() {
    let original = build_response_with_ttl(0x1234, "example.com.", 60);
    let patched = handler::decrement_ttl(&original, 9999);

    let msg = Message::from_bytes(&patched).unwrap();
    let answer_ttl = msg.answers[0].ttl;
    assert_eq!(answer_ttl, 1, "TTL should be clamped to minimum of 1");
}

#[tokio::test]
async fn test_handler_returns_refused_when_rate_limit_exhausted() {
    // Block rule keeps the test local (no upstream calls). Rate limiter
    // configured with 1 token capacity, 0 qps refill — one query allowed,
    // the second must be refused.
    let block_rules = vec![(
        ParsedRule {
            domain: "ads.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        },
        "test-list".to_string(),
    )];
    let engine = FilterEngine::from_named_rules(block_rules, vec![]);
    let filter = Arc::new(ArcSwap::from_pointee(engine));
    let cache = DnsCache::new(100);
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);
    let (tx, mut rx) = mpsc::channel(16);
    // qps=1, burst=1 — back-to-back queries happen in microseconds, far
    // below the 1s needed to refill one token, so the second query from
    // the same IP is guaranteed to be refused.
    let limiter = Arc::new(IpRateLimiter::new(1, 1));
    let handler = DnsHandler::new(filter, cache, forwarder, tx).with_rate_limiter(limiter);

    let query = make_query_bytes("ads.example.com", RecordType::A);
    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Check that the first allowed query still returns the blocked answer
    // (NoError with 0.0.0.0), not REFUSED — so we know we're not
    // over-filtering.
    let first = handler.handle(&query, ip1, None).await.unwrap();
    let first_msg = Message::from_bytes(&first.bytes).unwrap();
    assert_eq!(first_msg.metadata.response_code, ResponseCode::NoError);

    let second = handler.handle(&query, ip1, None).await.unwrap();
    let second_msg = Message::from_bytes(&second.bytes).unwrap();
    assert_eq!(
        second_msg.metadata.response_code,
        ResponseCode::Refused,
        "2nd query from ip1 should be REFUSED after bucket drained"
    );

    // ip2 has its own bucket — must still be served.
    let from_ip2 = handler.handle(&query, ip2, None).await.unwrap();
    let from_ip2_msg = Message::from_bytes(&from_ip2.bytes).unwrap();
    assert_eq!(
        from_ip2_msg.metadata.response_code,
        ResponseCode::NoError,
        "ip2 should not be affected by ip1's exhaustion"
    );

    // A rate-limited query must emit a log entry tagged QueryAction::RateLimited.
    let mut saw_rate_limited = false;
    while let Ok(ctx) = rx.try_recv() {
        if ctx.action == QueryAction::RateLimited {
            assert_eq!(ctx.client_ip, ip1);
            saw_rate_limited = true;
        }
    }
    assert!(
        saw_rate_limited,
        "expected a log event with action=rate_limited"
    );
}

#[tokio::test]
async fn test_handler_counts_dropped_log_events() {
    // Tiny channel (capacity 1, no receiver consuming) saturates immediately,
    // so try_send fails on every query past the first. Queries still succeed
    // (logging is non-blocking), but the drop counter should increment.
    let block_rules = vec![(
        ParsedRule {
            domain: "ads.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        },
        "test-list".to_string(),
    )];
    let engine = FilterEngine::from_named_rules(block_rules, vec![]);
    let filter = Arc::new(ArcSwap::from_pointee(engine));
    let cache = DnsCache::new(100);
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);
    let (tx, _rx) = mpsc::channel(1);
    let handler = DnsHandler::new(filter, cache, forwarder, tx);

    let query = make_query_bytes("ads.example.com", RecordType::A);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    for _ in 0..20 {
        let _ = handler.handle(&query, client_ip, None).await.unwrap();
    }

    assert!(
        handler.log_drop_count() > 0,
        "at least one log event should have been dropped (got {})",
        handler.log_drop_count()
    );
}

#[tokio::test]
async fn test_handler_inflight_limit_serves_all_queries() {
    // With a low concurrency limit, queries must still complete (permits are
    // released once each call returns). Uses a block rule so queries stay
    // local and fast — no upstream dependency.
    let block_rules = vec![(
        ParsedRule {
            domain: "ads.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        },
        "test-list".to_string(),
    )];
    let engine = FilterEngine::from_named_rules(block_rules, vec![]);
    let filter = Arc::new(ArcSwap::from_pointee(engine));
    let cache = DnsCache::new(100);
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);
    let (tx, _rx) = mpsc::channel(256);
    let handler = Arc::new(DnsHandler::with_max_inflight(
        filter, cache, forwarder, tx, 2,
    ));

    let query = make_query_bytes("ads.example.com", RecordType::A);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let mut joins = Vec::new();
    for _ in 0..50 {
        let h = handler.clone();
        let q = query.clone();
        joins.push(tokio::spawn(
            async move { h.handle(&q, client_ip, None).await },
        ));
    }

    for j in joins {
        let outcome = j.await.unwrap().expect("query should succeed");
        let response = Message::from_bytes(&outcome.bytes).unwrap();
        assert!(!response.answers.is_empty());
    }
}

#[tokio::test]
async fn test_non_query_opcode_returns_notimp() {
    // A blocked domain keeps this local (no upstream) and proves the opcode
    // check fires before the filter: a STATUS query for a blocked name must
    // still come back NOTIMP, not a synthesized block answer.
    let block_rules = vec![(
        ParsedRule {
            domain: "ads.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        },
        "test-list".to_string(),
    )];
    let (handler, _rx) = make_handler(block_rules, vec![]).await;

    let mut msg = Message::new(7, MessageType::Query, OpCode::Status);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_str("ads.example.com").unwrap(),
        RecordType::A,
    ));
    let query = msg.to_vec().unwrap();

    let result = handler
        .handle(&query, IpAddr::V4(Ipv4Addr::LOCALHOST), None)
        .await
        .unwrap();
    let resp = Message::from_bytes(&result.bytes).unwrap();

    assert_eq!(resp.metadata.response_code, ResponseCode::NotImp);
    assert_eq!(
        resp.metadata.op_code,
        OpCode::Status,
        "opcode must be echoed"
    );
    assert_eq!(resp.metadata.id, 7);
    assert_eq!(resp.metadata.message_type, MessageType::Response);
}

#[tokio::test]
async fn test_unsupported_edns_version_returns_badvers() {
    let block_rules = vec![(
        ParsedRule {
            domain: "ads.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        },
        "test-list".to_string(),
    )];
    let (handler, _rx) = make_handler(block_rules, vec![]).await;

    let mut msg = Message::new(9, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_str("ads.example.com").unwrap(),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    edns.set_version(1); // unsupported EDNS version
    edns.set_max_payload(1232);
    msg.set_edns(edns);
    let query = msg.to_vec().unwrap();

    let result = handler
        .handle(&query, IpAddr::V4(Ipv4Addr::LOCALHOST), None)
        .await
        .unwrap();
    let resp = Message::from_bytes(&result.bytes).unwrap();

    // Extended RCODE 16 (BADVERS); indistinguishable from BADSIG on the wire.
    assert_eq!(u16::from(resp.metadata.response_code), 16);
    assert!(resp.edns.is_some(), "BADVERS response must carry an OPT");
}

#[test]
fn test_decrement_ttl_zero_elapsed_unchanged() {
    let original = build_response_with_ttl(0x5678, "example.com.", 300);
    let patched = handler::decrement_ttl(&original, 0);

    let msg = Message::from_bytes(&patched).unwrap();
    let answer_ttl = msg.answers[0].ttl;
    assert_eq!(
        answer_ttl, 300,
        "TTL should remain unchanged when elapsed is 0"
    );
}
