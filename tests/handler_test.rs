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

fn make_handler(
    block_rules: Vec<(ParsedRule, String)>,
    allow_rules: Vec<ParsedRule>,
) -> (DnsHandler, mpsc::Receiver<QueryContext>) {
    let engine = FilterEngine::new(block_rules, allow_rules);
    let filter = Arc::new(ArcSwap::from_pointee(engine));
    let cache = DnsCache::new(100);
    let config = UpstreamConfig::default();
    let forwarder = Arc::new(UpstreamForwarder::new(config));
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

    let (handler, _rx) = make_handler(block_rules, vec![]);
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

    let (handler, _rx) = make_handler(block_rules, vec![]);
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
    let (handler, _rx) = make_handler(vec![], vec![]);
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

    let (handler, mut rx) = make_handler(block_rules, vec![]);
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
