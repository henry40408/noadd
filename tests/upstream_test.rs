use std::net::Ipv4Addr;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};

/// Build a minimal DNS wire-format query for the given domain and record type.
fn build_query(domain: &str, record_type: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(0x1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let name = Name::from_ascii(domain).expect("valid domain name");
    let query = Query::query(name, record_type);
    msg.add_query(query);

    msg.to_bytes().expect("failed to serialize DNS query")
}

#[tokio::test]
async fn test_forward_resolves_known_domain() {
    let config = UpstreamConfig::default();
    let forwarder = UpstreamForwarder::new(config);

    let query = build_query("example.com.", RecordType::A);
    let (response, upstream) = forwarder
        .forward(&query)
        .await
        .expect("forward should succeed");

    // Response should be non-empty and contain at least a DNS header (12 bytes).
    assert!(
        response.len() >= 12,
        "response too short: {} bytes",
        response.len()
    );

    // The upstream address should be one of the configured servers.
    assert!(!upstream.is_empty(), "upstream address should not be empty");
}

#[tokio::test]
async fn test_forward_failover_on_bad_primary() {
    let config = UpstreamConfig {
        servers: vec![
            // 192.0.2.0/24 is TEST-NET-1 (RFC 5737), should be unreachable.
            "192.0.2.1:53".into(),
            "1.1.1.1:53".into(),
        ],
        // Short timeout so the test doesn't take too long waiting for the bad server.
        timeout_ms: 1000,
    };
    let forwarder = UpstreamForwarder::new(config);

    let query = build_query("example.com.", RecordType::A);
    let (response, upstream) = forwarder
        .forward(&query)
        .await
        .expect("forward should succeed after failover");

    assert!(
        response.len() >= 12,
        "response too short: {} bytes",
        response.len()
    );
    assert_eq!(
        upstream, "1.1.1.1:53",
        "should have failed over to the second server"
    );
}

/// Build a DNS response with the TC (truncation) bit set.
fn build_tc_response(query_id: u16) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(query_id);
    msg.set_message_type(MessageType::Response);
    msg.set_truncated(true);
    msg.set_response_code(ResponseCode::NoError);
    msg.to_bytes().expect("serialize TC response")
}

/// Build a full DNS response (not truncated) with one A record.
fn build_full_response(query_id: u16, domain: &str) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(query_id);
    msg.set_message_type(MessageType::Response);
    msg.set_response_code(ResponseCode::NoError);
    msg.set_recursion_desired(true);
    msg.set_recursion_available(true);
    let name = Name::from_ascii(domain).unwrap();
    let record = Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(93, 184, 216, 34))));
    msg.add_answer(record);
    msg.to_bytes().expect("serialize full response")
}

#[tokio::test]
async fn test_forward_retries_tcp_on_truncation() {
    // Start a mock server that returns TC=1 on UDP, full response on TCP.
    let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp_listener = TcpListener::bind(udp_sock.local_addr().unwrap())
        .await
        .unwrap();
    let addr = udp_sock.local_addr().unwrap();

    // UDP handler: reply with TC=1
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, src) = udp_sock.recv_from(&mut buf).await.unwrap();
        let query = Message::from_bytes(&buf[..len]).unwrap();
        let tc_resp = build_tc_response(query.id());
        udp_sock.send_to(&tc_resp, src).await.unwrap();
    });

    // TCP handler: reply with full response
    tokio::spawn(async move {
        let (mut stream, _) = tcp_listener.accept().await.unwrap();
        let mut buf = [0u8; 514]; // 2-byte length prefix + message
        let mut total = 0;
        loop {
            use tokio::io::AsyncReadExt;
            let n = stream.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
            if total >= 2 {
                let msg_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                if total >= 2 + msg_len {
                    break;
                }
            }
        }
        let query = Message::from_bytes(&buf[2..total]).unwrap();
        let domain = query.queries()[0].name().to_ascii();
        let full_resp = build_full_response(query.id(), &domain);
        let len_prefix = (full_resp.len() as u16).to_be_bytes();
        stream.write_all(&len_prefix).await.unwrap();
        stream.write_all(&full_resp).await.unwrap();
    });

    let config = UpstreamConfig {
        servers: vec![addr.to_string()],
        timeout_ms: 5000,
    };
    let forwarder = UpstreamForwarder::new(config);

    let query = build_query("example.com.", RecordType::A);
    let (response, _upstream) = forwarder
        .forward(&query)
        .await
        .expect("forward should succeed via TCP fallback");

    let msg = Message::from_bytes(&response).unwrap();
    assert!(!msg.truncated(), "final response should not be truncated");
    assert!(
        !msg.answers().is_empty(),
        "TCP fallback response should contain answers"
    );
    assert_eq!(msg.answers()[0].ttl(), 300);
}
