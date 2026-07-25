use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;

use noadd::net::{TrustedProxies, extract_client_ip};

// --- Cidr / TrustedProxies parsing ---

#[test]
fn parse_empty_string_yields_empty_set() {
    let tp = TrustedProxies::parse("").expect("empty parses");
    assert!(tp.is_empty());
    assert!(!tp.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
}

#[test]
fn parse_whitespace_only_yields_empty_set() {
    let tp = TrustedProxies::parse("  ,  ,").expect("whitespace parses");
    assert!(tp.is_empty());
}

#[test]
fn parse_ipv4_cidr_matches_in_range() {
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    assert!(tp.contains(IpAddr::V4(Ipv4Addr::new(172, 18, 0, 19))));
    assert!(tp.contains(IpAddr::V4(Ipv4Addr::new(172, 18, 255, 255))));
    assert!(!tp.contains(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 1))));
    assert!(!tp.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
}

#[test]
fn parse_bare_ipv4_is_host_route() {
    let tp = TrustedProxies::parse("172.18.0.19").unwrap();
    assert!(tp.contains(IpAddr::V4(Ipv4Addr::new(172, 18, 0, 19))));
    assert!(!tp.contains(IpAddr::V4(Ipv4Addr::new(172, 18, 0, 20))));
}

#[test]
fn parse_ipv6_cidr_matches_in_range() {
    let tp = TrustedProxies::parse("fd00::/8").unwrap();
    assert!(tp.contains(IpAddr::V6(Ipv6Addr::from_str("fd12:3456::1").unwrap())));
    assert!(!tp.contains(IpAddr::V6(Ipv6Addr::from_str("fe00::1").unwrap())));
}

#[test]
fn parse_multiple_cidrs_comma_separated() {
    let tp = TrustedProxies::parse("10.0.0.0/8, 172.16.0.0/12 ,192.168.0.0/16").unwrap();
    assert!(tp.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1))));
    assert!(tp.contains(IpAddr::V4(Ipv4Addr::new(172, 20, 5, 6))));
    assert!(tp.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 50, 50))));
    assert!(!tp.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn parse_zero_prefix_matches_all() {
    let tp = TrustedProxies::parse("0.0.0.0/0").unwrap();
    assert!(tp.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    assert!(tp.contains(IpAddr::V4(Ipv4Addr::BROADCAST)));
}

#[test]
fn parse_invalid_address_is_error() {
    assert!(TrustedProxies::parse("not.an.ip/24").is_err());
}

#[test]
fn parse_invalid_prefix_is_error() {
    assert!(TrustedProxies::parse("10.0.0.0/33").is_err());
    assert!(TrustedProxies::parse("::/129").is_err());
    assert!(TrustedProxies::parse("10.0.0.0/abc").is_err());
}

#[test]
fn parse_mixed_family_does_not_cross_match() {
    let tp = TrustedProxies::parse("10.0.0.0/8").unwrap();
    assert!(!tp.contains(IpAddr::V6(Ipv6Addr::from_str("::ffff:10.0.0.1").unwrap())));
}

// --- extract_client_ip helper ---

#[allow(
    clippy::unnecessary_wraps,
    reason = "returns Option to match the `extract_client_ip` connect-info argument shape"
)]
fn ci(addr: &str) -> Option<ConnectInfo<SocketAddr>> {
    Some(ConnectInfo(addr.parse().unwrap()))
}

fn headers_xff(value: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-forwarded-for", value.parse().unwrap());
    h
}

fn headers_xri(value: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-real-ip", value.parse().unwrap());
    h
}

#[test]
fn loopback_peer_always_trusts_headers() {
    let tp = TrustedProxies::parse("").unwrap();
    let connect = ci("127.0.0.1:50000");
    let headers = headers_xff("203.0.113.7");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn ipv6_loopback_peer_trusts_headers() {
    let tp = TrustedProxies::parse("").unwrap();
    let connect = ci("[::1]:50000");
    let headers = headers_xri("203.0.113.7");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn untrusted_peer_ignores_headers() {
    let tp = TrustedProxies::parse("").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("203.0.113.7");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(172, 18, 0, 19)));
}

#[test]
fn trusted_proxy_peer_honours_x_forwarded_for() {
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("203.0.113.7");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn trusted_proxy_peer_honours_x_real_ip() {
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xri("203.0.113.99");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99)));
}

#[test]
fn x_forwarded_for_rightmost_non_proxy_hop_is_used() {
    // 198.51.100.2 is not a configured proxy, so the chain is only vouched for
    // up to that point — everything left of it is hearsay.
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("203.0.113.7, 10.0.0.1, 198.51.100.2");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)));
}

#[test]
fn configured_proxy_hops_are_skipped_to_reach_the_client() {
    // The realistic shape: proxy appends its own peer, so the client sits to
    // the left of the proxy hops and every proxy is in --trusted-proxies.
    let tp = TrustedProxies::parse("172.18.0.0/16,10.0.0.0/8").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("203.0.113.7, 10.0.0.1, 172.18.0.19");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn client_supplied_x_forwarded_for_prefix_cannot_forge_the_client_ip() {
    // Regression: nginx's `$proxy_add_x_forwarded_for` and Cloudflare both
    // append, so a client-sent XFF survives as the leftmost entry. Honouring it
    // would hand an attacker a fresh rate-limit bucket per request.
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("1.2.3.4, 203.0.113.7, 172.18.0.19");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn forged_prefix_of_many_hops_does_not_shift_the_result() {
    // Padding the head is the cheapest evasion attempt; the walk starts at the
    // tail so it changes nothing (and MAX_XFF_HOPS bounds the parse cost).
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let forged = std::iter::repeat_n("1.2.3.4", 200)
        .collect::<Vec<_>>()
        .join(", ");
    let headers = headers_xff(&format!("{forged}, 203.0.113.7, 172.18.0.19"));
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn same_host_proxy_hop_is_skipped() {
    // Loopback entries are proxy hops for the same reason loopback peers are
    // trusted: a reverse proxy sharing the host.
    let tp = TrustedProxies::parse("").unwrap();
    let connect = ci("127.0.0.1:50000");
    let headers = headers_xff("203.0.113.7, 127.0.0.1");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn all_proxy_hops_attributes_the_outermost_proxy() {
    // Degenerate chain with no client entry. Over-attributing to the outermost
    // proxy is the safe failure: it cannot be steered by a forged header.
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("172.18.0.4, 172.18.0.19");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(172, 18, 0, 4)));
}

#[test]
fn unreadable_hop_ends_the_walk_instead_of_being_stepped_over() {
    // Skipping the unreadable entry would carry the walk into `1.2.3.4`, which
    // no proxy vouched for. Stopping attributes the last proxy actually read.
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("1.2.3.4, not-an-ip, 172.18.0.19");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(172, 18, 0, 19)));
}

#[test]
fn unreadable_innermost_hop_falls_back_to_the_peer() {
    // Nothing in the header was readable, so there is no hop to attribute and
    // the peer — the one address the client cannot choose — stands in.
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("1.2.3.4, not-an-ip");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(172, 18, 0, 19)));
}

#[test]
fn hop_carrying_a_port_is_read_as_its_address() {
    // Azure's gateways and IIS ARR append `ip:port`. Failing to read that would
    // end the walk one hop early and hand `1.2.3.4` the result.
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("1.2.3.4, 203.0.113.7:53821, 172.18.0.19");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn bracketed_ipv6_hop_is_read_as_its_address() {
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("1.2.3.4, [2001:db8::5]:443, 172.18.0.19");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(
        ip,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5))
    );
}

#[test]
fn rfc7239_for_parameter_leaking_into_the_header_is_read() {
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("1.2.3.4, for=\"203.0.113.7\", 172.18.0.19");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn walk_reaches_the_client_at_the_hop_limit_but_not_past_it() {
    // Pins MAX_XFF_HOPS at 32: a client 32 hops in is still found, one hop
    // further is not, and the walk falls back to the outermost proxy read.
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let proxies = |n: usize| {
        std::iter::repeat_n("172.18.0.19", n)
            .collect::<Vec<_>>()
            .join(", ")
    };

    let headers = headers_xff(&format!("203.0.113.7, {}", proxies(31)));
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));

    let headers = headers_xff(&format!("203.0.113.7, {}", proxies(32)));
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(172, 18, 0, 19)));
}

#[test]
fn client_inside_a_trusted_range_is_skipped_as_a_proxy_hop() {
    // Documented failure mode, pinned so it cannot change silently: the walk
    // skips every hop the list covers, so a range wide enough to hold clients
    // steps over the real one. `--trusted-proxies` must name proxies only.
    let tp = TrustedProxies::parse("192.168.1.0/24").unwrap();
    let connect = ci("192.168.1.5:50000");
    let headers = headers_xff("6.6.6.6, 192.168.1.77");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6)));
}

#[test]
fn x_forwarded_for_preferred_over_x_real_ip() {
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
    headers.insert("x-real-ip", "198.51.100.2".parse().unwrap());
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn malformed_header_falls_back_to_peer() {
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("not-an-ip");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(172, 18, 0, 19)));
}

#[test]
fn no_connect_info_treated_as_test_loopback() {
    let tp = TrustedProxies::parse("").unwrap();
    let headers = headers_xff("203.0.113.7");
    let ip = extract_client_ip(None, &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
}

#[test]
fn no_connect_info_no_headers_yields_loopback() {
    let tp = TrustedProxies::parse("").unwrap();
    let headers = HeaderMap::new();
    let ip = extract_client_ip(None, &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
}
