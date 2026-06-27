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
    let forwarder = UpstreamForwarder::new(config).await;

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
    let forwarder = UpstreamForwarder::new(config).await;

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

#[tokio::test]
async fn test_health_check_reports_live_upstream_as_ok() {
    // Regression test for the probe hitting the root "." with A instead
    // of NS: hickory translates the empty-answer NOERROR from "." A into
    // a NoRecordsFound error, making every probe look like a failure.
    // A live upstream must appear as ok=true.
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
    // Mullvad's plain UDP:53 endpoint returns REFUSED to recursive
    // queries from arbitrary networks (anti-amplification policy), so
    // 194.242.2.2:53 cannot be used as a real upstream. Their DoT
    // endpoint at dns.mullvad.net:853 fully recurses, so the forwarder
    // must report it as healthy.
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
    // End-to-end: forward a real query through Mullvad DoT and verify
    // we get a usable DNS response back.
    let config = UpstreamConfig {
        servers: vec!["tls://dns.mullvad.net:853".into()],
        timeout_ms: 8000,
    };
    let forwarder = UpstreamForwarder::new(config).await;

    let query = build_query("example.com.", RecordType::A);
    let (response, upstream) = forwarder
        .forward(&query)
        .await
        .expect("forward via Mullvad DoT should succeed");

    assert!(response.len() >= 12, "response too short");
    assert_eq!(upstream, "tls://dns.mullvad.net:853");
}

#[tokio::test]
async fn test_health_check_reports_dead_upstream_as_fail() {
    // A closed local port should probe as fail without affecting the
    // live upstream's result.
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
    // A persistent DoT/DoH connection can go stale between health checks;
    // the probe retries the same upstream once so a single stale-connection
    // failure doesn't report a live upstream as down. Use an unreachable
    // TEST-NET-1 address (RFC 5737) that black-holes packets so each attempt
    // burns the full timeout: two attempts must take noticeably longer than
    // one, which is how we observe that the retry actually ran. The upstream
    // is genuinely dead, so it must still report fail (the retry must not
    // turn a dead upstream into a false positive).
    //
    // The per-attempt timeout is clamped to a 5000ms floor (MIN_TIMEOUT_MS in
    // the forwarder), so `timeout_ms` below is effectively 5000ms/attempt
    // regardless of the small value requested. One attempt therefore takes
    // ~5s and two take ~10s; the 7500ms lower bound sits between them so it
    // can only be reached if the retry actually ran.
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

// Regression tests for the fix that converts hickory's ProtoErrorKind::NoRecordsFound
// (NXDOMAIN / NODATA) from a forwarding error into a synthesized DNS response with
// the real upstream response code, so callers receive Ok instead of an error.

#[tokio::test]
async fn test_forward_nxdomain_returns_response_not_error() {
    // Query a guaranteed-nonexistent name under the .invalid TLD (RFC 6761).
    // Before the fix, hickory's NoRecordsFound propagated as ForwardError,
    // producing SERVFAIL to the client. After the fix, forward() returns Ok
    // with a proper NXDOMAIN response message.
    let config = UpstreamConfig::default();
    let forwarder = UpstreamForwarder::new(config).await;

    let query = build_query("nonexistent-noadd-probe.invalid.", RecordType::A);
    let (response_bytes, upstream) = forwarder
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
    // Query example.com for MX records. example.com has no MX records
    // (it is a reserved example domain per RFC 2606), so the upstream
    // returns NoError with an empty answer section — NODATA. hickory
    // converts this to a NoRecordsFound error; before the fix that
    // propagated as ForwardError. After the fix, forward() returns Ok
    // with a NoError response.
    let config = UpstreamConfig::default();
    let forwarder = UpstreamForwarder::new(config).await;

    let query = build_query("example.com.", RecordType::MX);
    let (response_bytes, upstream) = forwarder
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
