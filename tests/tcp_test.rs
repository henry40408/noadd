//! End-to-end coverage for the TCP DNS listener's wire behavior:
//! length-prefixed framing (RFC 1035 §4.2.2) and connection reuse (RFC 7766).
//!
//! These drive `serve_tcp` over a real loopback socket rather than exercising
//! the handler in isolation, so the 2-byte framing and the accept/read loop
//! are verified the way a real DNS client sees them.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use noadd::cache::DnsCache;
use noadd::dns::handler::{DnsHandler, QueryContext};
use noadd::dns::tcp::serve_tcp;
use noadd::filter::engine::FilterEngine;
use noadd::filter::parser::{ParsedRule, RuleAction};
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

const BLOCKED_DOMAIN: &str = "ads.example.com";

fn make_query_bytes(id: u16, domain: &str, record_type: RecordType) -> Vec<u8> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let mut query = hickory_proto::op::Query::new();
    query.set_name(Name::from_str(domain).unwrap());
    query.set_query_type(record_type);
    msg.add_query(query);
    msg.to_vec().unwrap()
}

/// A handler that blocks `ads.example.com`, so queries resolve locally to a
/// synthesized `0.0.0.0` and never touch a real upstream.
async fn build_blocking_handler() -> (Arc<DnsHandler>, mpsc::Receiver<QueryContext>) {
    let block_rules = vec![(
        ParsedRule {
            domain: BLOCKED_DOMAIN.to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        },
        "test-list".to_string(),
    )];
    let engine = FilterEngine::from_named_rules(block_rules, vec![]);
    let filter = Arc::new(ArcSwap::from_pointee(engine));
    let cache = DnsCache::new(100);
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);
    let (tx, rx) = mpsc::channel(64);
    (Arc::new(DnsHandler::new(filter, cache, forwarder, tx)), rx)
}

/// Bind an ephemeral loopback port and spawn `serve_tcp` on it, returning a
/// connected client stream. Binding here (not inside `serve_tcp`) lets the test
/// learn the port without a bind-drop-rebind race.
async fn connect_to_listener(handler: Arc<DnsHandler>) -> TcpStream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_tcp(listener, handler).await;
    });
    TcpStream::connect(addr).await.unwrap()
}

/// Send one length-prefixed query and read one length-prefixed response,
/// asserting the declared 2-byte length matches the bytes that follow.
async fn query_over_tcp(stream: &mut TcpStream, query: &[u8]) -> Message {
    stream
        .write_u16(u16::try_from(query.len()).unwrap())
        .await
        .unwrap();
    stream.write_all(query).await.unwrap();
    stream.flush().await.unwrap();

    let len = stream.read_u16().await.unwrap() as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(
        buf.len(),
        len,
        "response body must be exactly the length declared by the 2-byte prefix"
    );
    Message::from_bytes(&buf).unwrap()
}

/// RFC 1035 §4.2.2: a TCP query is a 2-byte length prefix followed by the
/// message, and the response is framed the same way.
#[tokio::test]
async fn tcp_length_prefixed_framing() {
    let (handler, _rx) = build_blocking_handler().await;
    let mut stream = connect_to_listener(handler).await;

    let query = make_query_bytes(0xABCD, BLOCKED_DOMAIN, RecordType::A);
    let resp = query_over_tcp(&mut stream, &query).await;

    assert_eq!(resp.metadata.message_type, MessageType::Response);
    assert_eq!(resp.metadata.id, 0xABCD, "response must echo the query id");
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    let answer = resp
        .answers
        .first()
        .expect("blocked query yields an answer");
    match &answer.data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::UNSPECIFIED, "blocked A must be 0.0.0.0"),
        other => panic!("expected A record, got {other:?}"),
    }
}

/// RFC 7766: multiple queries may be sent over a single reused connection; the
/// server must answer each without closing the stream between them.
#[tokio::test]
async fn tcp_connection_reuse_serves_multiple_queries() {
    let (handler, _rx) = build_blocking_handler().await;
    let mut stream = connect_to_listener(handler).await;

    // Two sequential queries with distinct ids over the same TcpStream.
    let first = query_over_tcp(
        &mut stream,
        &make_query_bytes(0x0001, BLOCKED_DOMAIN, RecordType::A),
    )
    .await;
    assert_eq!(first.metadata.id, 0x0001);
    assert!(!first.answers.is_empty(), "first query must be answered");

    let second = query_over_tcp(
        &mut stream,
        &make_query_bytes(0x0002, BLOCKED_DOMAIN, RecordType::A),
    )
    .await;
    assert_eq!(
        second.metadata.id, 0x0002,
        "second query on the reused connection must get its own response"
    );
    assert!(!second.answers.is_empty(), "second query must be answered");

    // The connection stays usable — a third query still succeeds.
    let third = query_over_tcp(
        &mut stream,
        &make_query_bytes(0x0003, BLOCKED_DOMAIN, RecordType::A),
    )
    .await;
    assert_eq!(third.metadata.id, 0x0003);
    assert!(!third.answers.is_empty(), "third query must be answered");
}
