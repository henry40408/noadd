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
    assert!(tp.contains(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
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
fn x_forwarded_for_first_hop_is_used() {
    let tp = TrustedProxies::parse("172.18.0.0/16").unwrap();
    let connect = ci("172.18.0.19:50000");
    let headers = headers_xff("203.0.113.7, 10.0.0.1, 198.51.100.2");
    let ip = extract_client_ip(connect.as_ref(), &headers, &tp);
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
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
