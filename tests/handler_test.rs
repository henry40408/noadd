use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::sync::mpsc;

use noadd::cache::DnsCache;
use noadd::dns::handler::{self, DnsHandler, QueryContext};
use noadd::dns::ratelimit::IpRateLimiter;
use noadd::filter::engine::FilterEngine;
use noadd::filter::parser::{ParsedRule, RuleAction};
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

fn make_query_bytes(domain: &str, record_type: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
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
    let engine = FilterEngine::new(block_rules, allow_rules);
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
    let response = Message::from_bytes(&result).unwrap();

    assert!(response.message_type() == MessageType::Response);
    assert_eq!(response.id(), 1234);
    assert!(!response.answers().is_empty(), "should have an answer");

    let answer = &response.answers()[0];
    match answer.data() {
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
    let response = Message::from_bytes(&result).unwrap();

    assert!(!response.answers().is_empty(), "should have an answer");
    let answer = &response.answers()[0];
    match answer.data() {
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
    assert!(!result.is_empty(), "response should be non-empty");

    let response = Message::from_bytes(&result).unwrap();
    assert!(response.message_type() == MessageType::Response);
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
    assert_eq!(ctx.action, "blocked");
    assert_eq!(ctx.domain, "ads.example.com");
    assert_eq!(ctx.client_ip, "127.0.0.1");
    assert!(ctx.matched_rule.is_some());
    assert!(ctx.matched_list.is_some());
}

/// Build a fake DNS response with a single A record at the given TTL.
fn build_response_with_ttl(id: u16, domain: &str, ttl: u32) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Response);
    msg.set_op_code(OpCode::Query);
    msg.set_response_code(ResponseCode::NoError);
    msg.set_recursion_desired(true);
    msg.set_recursion_available(true);

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
    let answer_ttl = msg.answers()[0].ttl();
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
    let answer_ttl = msg.answers()[0].ttl();
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
    let engine = FilterEngine::new(block_rules, vec![]);
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
    let first_msg = Message::from_bytes(&first).unwrap();
    assert_eq!(first_msg.response_code(), ResponseCode::NoError);

    let second = handler.handle(&query, ip1, None).await.unwrap();
    let second_msg = Message::from_bytes(&second).unwrap();
    assert_eq!(
        second_msg.response_code(),
        ResponseCode::Refused,
        "2nd query from ip1 should be REFUSED after bucket drained"
    );

    // ip2 has its own bucket — must still be served.
    let from_ip2 = handler.handle(&query, ip2, None).await.unwrap();
    let from_ip2_msg = Message::from_bytes(&from_ip2).unwrap();
    assert_eq!(
        from_ip2_msg.response_code(),
        ResponseCode::NoError,
        "ip2 should not be affected by ip1's exhaustion"
    );

    // A rate-limited query must emit a log entry tagged "rate_limited".
    let mut saw_rate_limited = false;
    while let Ok(ctx) = rx.try_recv() {
        if ctx.action == "rate_limited" {
            assert_eq!(ctx.client_ip, ip1.to_string());
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
    let engine = FilterEngine::new(block_rules, vec![]);
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
    let engine = FilterEngine::new(block_rules, vec![]);
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
        let bytes = j.await.unwrap().expect("query should succeed");
        let response = Message::from_bytes(&bytes).unwrap();
        assert!(!response.answers().is_empty());
    }
}

#[test]
fn test_decrement_ttl_zero_elapsed_unchanged() {
    let original = build_response_with_ttl(0x5678, "example.com.", 300);
    let patched = handler::decrement_ttl(&original, 0);

    let msg = Message::from_bytes(&patched).unwrap();
    let answer_ttl = msg.answers()[0].ttl();
    assert_eq!(
        answer_ttl, 300,
        "TTL should remain unchanged when elapsed is 0"
    );
}
