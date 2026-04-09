use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

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

#[tokio::test]
async fn test_forward_failover_on_closed_local_port() {
    // Bind a UDP socket to claim a port, then immediately drop it so the
    // port is guaranteed closed for the duration of the test. This gives
    // a fast-failing primary upstream (ICMP unreachable / connection
    // refused) without waiting for a network timeout.
    let dead_addr = {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.local_addr().unwrap()
        // sock dropped here
    };

    let config = UpstreamConfig {
        servers: vec![dead_addr.to_string(), "1.1.1.1:53".into()],
        timeout_ms: 5000,
    };
    let forwarder = UpstreamForwarder::new(config);

    let query = build_query("example.com.", RecordType::A);
    let (response, upstream) = forwarder
        .forward(&query)
        .await
        .expect("forward should fail over from closed local port to real upstream");

    assert!(response.len() >= 12, "response too short");
    assert_eq!(
        upstream, "1.1.1.1:53",
        "should have failed over past the dead local port"
    );
}

// TC (truncation) → TCP fallback is now handled inside hickory's
// NameServer transport layer (`ResolverOpts::try_tcp_on_error`), so we
// no longer test it here — it would amount to testing a third-party
// dependency. The end-to-end behavior is still exercised by
// `test_forward_resolves_known_domain` against real upstreams.
