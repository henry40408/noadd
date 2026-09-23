use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

/// Build a minimal DNS wire-format query for the given domain and record type.
fn build_query(domain: &str, record_type: RecordType) -> Vec<u8> {
    let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;

    let name = Name::from_ascii(domain).expect("valid domain name");
    let query = Query::query(name, record_type);
    msg.add_query(query);

    msg.to_bytes().expect("failed to serialize DNS query")
}

#[tokio::test]
async fn test_forward_resolves_known_domain() {
    let config = UpstreamConfig::default();
    let forwarder = UpstreamForwarder::new(config).await;

    let query = build_query("example.com.", RecordType::A);
    let (response, upstream, _ad) = forwarder
        .forward(&query)
        .await
        .expect("forward should succeed");

    // 12 bytes is the DNS header alone.
    assert!(
        response.len() >= 12,
        "response too short: {} bytes",
        response.len()
    );

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
        // Short timeout (the forwarder clamps it up to MIN_TIMEOUT_MS anyway).
        timeout_ms: 1000,
    };
    let forwarder = UpstreamForwarder::new(config).await;

    let query = build_query("example.com.", RecordType::A);
    let (response, upstream, _ad) = forwarder
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
    // Claim then drop a UDP port: a closed port fails fast (ICMP unreachable)
    // instead of waiting out a timeout.
    let dead_addr = {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.local_addr().unwrap()
        // sock dropped here
    };

    let config = UpstreamConfig {
        servers: vec![dead_addr.to_string(), "1.1.1.1:53".into()],
        timeout_ms: 5000,
    };
    let forwarder = UpstreamForwarder::new(config).await;

    let query = build_query("example.com.", RecordType::A);
    let (response, upstream, _ad) = forwarder
        .forward(&query)
        .await
        .expect("forward should fail over from closed local port to real upstream");

    assert!(response.len() >= 12, "response too short");
    assert_eq!(
        upstream, "1.1.1.1:53",
        "should have failed over past the dead local port"
    );
}

// TC (truncation) → TCP fallback happens inside hickory's `NameServerPool`,
// so it is not tested here.

#[tokio::test]
async fn test_health_check_reports_live_upstream_as_ok() {
    // Regression: probing "." with A instead of NS got an empty NOERROR that
    // hickory turns into NoRecordsFound, so every probe looked failed.
    let config = UpstreamConfig {
        servers: vec!["1.1.1.1:53".into()],
        timeout_ms: 5000,
    };
    let forwarder = UpstreamForwarder::new(config).await;
    let results = forwarder.health_check().await;

    assert_eq!(results.len(), 1);
    let (server, ok, _ms) = &results[0];
    assert_eq!(server, "1.1.1.1:53");
    assert!(*ok, "expected live upstream 1.1.1.1:53 to report ok=true");
}

#[tokio::test]
async fn test_health_check_mullvad_dot_succeeds() {
    // Mullvad's plain UDP:53 REFUSEs recursion from arbitrary networks, but
    // its DoT endpoint (dns.mullvad.net:853) recurses and must probe healthy.
    let config = UpstreamConfig {
        servers: vec!["tls://dns.mullvad.net:853".into()],
        timeout_ms: 8000,
    };
    let forwarder = UpstreamForwarder::new(config).await;
    let results = forwarder.health_check().await;

    assert_eq!(results.len(), 1);
    let (server, ok, _ms) = &results[0];
    assert_eq!(server, "tls://dns.mullvad.net:853");
    assert!(*ok, "Mullvad DoT upstream should report ok=true");
}

#[tokio::test]
async fn test_forward_via_mullvad_dot_resolves_known_domain() {
    // End-to-end: a real query through Mullvad DoT.
    let config = UpstreamConfig {
        servers: vec!["tls://dns.mullvad.net:853".into()],
        timeout_ms: 8000,
    };
    let forwarder = UpstreamForwarder::new(config).await;

    let query = build_query("example.com.", RecordType::A);
    let (response, upstream, _ad) = forwarder
        .forward(&query)
        .await
        .expect("forward via Mullvad DoT should succeed");

    assert!(response.len() >= 12, "response too short");
    assert_eq!(upstream, "tls://dns.mullvad.net:853");
}

#[tokio::test]
async fn test_health_check_reports_dead_upstream_as_fail() {
    // A closed port probes as fail without affecting the live upstream.
    let dead_addr = {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.local_addr().unwrap()
    };
    let config = UpstreamConfig {
        servers: vec![dead_addr.to_string(), "1.1.1.1:53".into()],
        timeout_ms: 2000,
    };
    let forwarder = UpstreamForwarder::new(config).await;
    let results = forwarder.health_check().await;

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].0, dead_addr.to_string());
    assert!(!results[0].1, "dead upstream should report ok=false");
    assert_eq!(results[1].0, "1.1.1.1:53");
    assert!(results[1].1, "live upstream should report ok=true");
}

#[tokio::test]
async fn test_health_check_probe_retries_once_on_failure() {
    // The probe retries once so a stale DoT/DoH connection does not report a
    // live upstream down. A black-holed TEST-NET-1 address burns the full
    // timeout per attempt, so elapsed time shows the retry ran — and the dead
    // upstream must still report fail.
    //
    // `timeout_ms` is clamped up to MIN_TIMEOUT_MS (5000ms) in the forwarder:
    // one attempt ~5s, two ~10s, so a 7500ms floor proves the retry.
    const EFFECTIVE_TIMEOUT_MS: u64 = 5000;
    let config = UpstreamConfig {
        servers: vec!["192.0.2.1:53".into()],
        timeout_ms: 1000,
    };
    let forwarder = UpstreamForwarder::new(config).await;
    let results = forwarder.health_check().await;

    assert_eq!(results.len(), 1);
    let (server, ok, ms) = &results[0];
    assert_eq!(server, "192.0.2.1:53");
    assert!(!ok, "unreachable upstream must still report ok=false");
    let two_attempt_floor = EFFECTIVE_TIMEOUT_MS + EFFECTIVE_TIMEOUT_MS / 2; // 7500ms
    assert!(
        *ms >= two_attempt_floor,
        "probe should retry once: expected >= {two_attempt_floor}ms across two attempts, got {ms}ms",
    );
}

// Hickory's NoRecordsFound (NXDOMAIN / NODATA) must become a synthesized response
// carrying the upstream's rcode, not a ForwardError (which the client saw as
// SERVFAIL).

#[tokio::test]
async fn test_forward_nxdomain_returns_response_not_error() {
    // .invalid (RFC 6761) is guaranteed not to exist: expect Ok(NXDOMAIN).
    let config = UpstreamConfig::default();
    let forwarder = UpstreamForwarder::new(config).await;

    let query = build_query("nonexistent-noadd-probe.invalid.", RecordType::A);
    let (response_bytes, upstream, _ad) = forwarder
        .forward(&query)
        .await
        .expect("forward should return Ok for NXDOMAIN, not a forwarding error");

    let response =
        Message::from_vec(&response_bytes).expect("response must be valid DNS wire format");

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NXDomain,
        "NXDOMAIN name must produce NXDomain response code, got {:?}",
        response.metadata.response_code
    );
    assert_eq!(
        response.metadata.message_type,
        MessageType::Response,
        "message_type must be Response"
    );
    assert_eq!(
        response.metadata.id, 0x1234,
        "response id must echo the query id"
    );
    assert!(
        !response.queries.is_empty(),
        "question section must be present in the response"
    );
    assert!(
        !upstream.is_empty(),
        "upstream address must be reported even for NXDOMAIN"
    );
}

#[tokio::test]
async fn test_forward_nodata_returns_noerror() {
    // example.com (RFC 2606) has no MX records: NODATA, expect Ok(NoError).
    let config = UpstreamConfig::default();
    let forwarder = UpstreamForwarder::new(config).await;

    let query = build_query("example.com.", RecordType::MX);
    let (response_bytes, upstream, _ad) = forwarder
        .forward(&query)
        .await
        .expect("forward should return Ok for NODATA, not a forwarding error");

    let response =
        Message::from_vec(&response_bytes).expect("response must be valid DNS wire format");

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "NODATA response must carry NoError response code, got {:?}",
        response.metadata.response_code
    );
    assert_eq!(
        response.metadata.message_type,
        MessageType::Response,
        "message_type must be Response"
    );
    assert_eq!(
        response.metadata.id, 0x1234,
        "response id must echo the query id"
    );
    assert!(
        !upstream.is_empty(),
        "upstream address must be reported even for NODATA"
    );
}
