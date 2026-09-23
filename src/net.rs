//! Network helpers shared by the `DoH` and admin HTTP layers.
//!
//! `TrustedProxies` (`--trusted-proxies`) decides which TCP peers may set the
//! client IP via `X-Forwarded-For` / `X-Real-IP`: loopback always, plus any
//! configured CIDR. From anyone else the headers are ignored — a spoofed source
//! IP would defeat per-IP rate limiting and pollute the query log.
//!
//! A trusted peer is not enough: nginx's `$proxy_add_x_forwarded_for` and
//! Cloudflare *append*, so the leftmost XFF entry is attacker-controlled.
//! `extract_client_ip` therefore walks from the right to the first hop that is
//! not a proxy. A proxy missing from the list is taken as the client (safe);
//! a range too wide — one covering clients too — lets the walk step over the
//! real client and honour its forged value (unsafe).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;

/// A single IPv4/IPv6 CIDR block.
#[derive(Debug, Clone, Copy)]
pub struct Cidr {
    base: IpAddr,
    prefix_len: u8,
}

/// Parse error for a single CIDR or the comma-separated list.
#[derive(Debug, thiserror::Error)]
pub enum CidrParseError {
    #[error("invalid IP address in CIDR `{0}`")]
    InvalidAddress(String),
    #[error("invalid prefix length in CIDR `{0}`")]
    InvalidPrefix(String),
    #[error("prefix length {prefix} out of range for {family} in `{input}`")]
    PrefixOutOfRange {
        input: String,
        family: &'static str,
        prefix: u8,
    },
}

impl Cidr {
    /// Parse `addr` or `addr/prefix`. A bare address is treated as a host
    /// route (/32 for IPv4, /128 for IPv6).
    pub fn parse(s: &str) -> Result<Self, CidrParseError> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };

        let base: IpAddr = addr_part
            .parse()
            .map_err(|_err| CidrParseError::InvalidAddress(s.to_string()))?;

        let max_prefix = match base {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };

        let prefix_len = match prefix_part {
            None => max_prefix,
            Some(p) => p
                .trim()
                .parse::<u8>()
                .map_err(|_err| CidrParseError::InvalidPrefix(s.to_string()))?,
        };

        if prefix_len > max_prefix {
            return Err(CidrParseError::PrefixOutOfRange {
                input: s.to_string(),
                family: if max_prefix == 32 { "IPv4" } else { "IPv6" },
                prefix: prefix_len,
            });
        }

        Ok(Cidr { base, prefix_len })
    }

    /// Whether `ip` is in this CIDR. Cross-family checks (e.g. `::ffff:a.b.c.d`
    /// against an IPv4 block) deliberately return false.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(b), IpAddr::V4(i)) => {
                let mask: u32 = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (u32::from(b) & mask) == (u32::from(i) & mask)
            }
            (IpAddr::V6(b), IpAddr::V6(i)) => {
                let mask: u128 = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (u128::from(b) & mask) == (u128::from(i) & mask)
            }
            _ => false,
        }
    }
}

impl FromStr for Cidr {
    type Err = CidrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Cidr::parse(s)
    }
}

/// A configured set of CIDRs whose peers are allowed to set client-IP headers.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies {
    cidrs: Vec<Cidr>,
}

impl TrustedProxies {
    /// Parse a comma-separated CIDR list, ignoring empty entries so a stray
    /// comma does not break startup.
    pub fn parse(input: &str) -> Result<Self, CidrParseError> {
        let mut cidrs = Vec::new();
        for chunk in input.split(',') {
            let trimmed = chunk.trim();
            if trimmed.is_empty() {
                continue;
            }
            cidrs.push(Cidr::parse(trimmed)?);
        }
        Ok(TrustedProxies { cidrs })
    }

    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.cidrs.len()
    }

    /// Return true if `ip` belongs to any configured CIDR.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }

    /// Whether `ip` is a proxy hop: loopback or a configured CIDR.
    fn is_proxy_hop(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.contains(ip)
    }
}

/// How many `X-Forwarded-For` hops are inspected, counting from the right.
///
/// Proxies append, so what matters is at the tail; the cap stops a client
/// padding the head into many parses per `DoH` query.
const MAX_XFF_HOPS: usize = 32;

/// Parse one `X-Forwarded-For` entry, tolerating the forms proxies actually emit.
///
/// Besides bare addresses: `1.2.3.4:53821` (Azure, IIS ARR), bracketed IPv6
/// with or without a port, and RFC 7239 `for=` syntax. An unreadable entry
/// stops the caller's walk.
fn parse_forwarded_hop(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim();
    let hop = match hop.get(..4) {
        Some(p) if p.eq_ignore_ascii_case("for=") => &hop[4..],
        _ => hop,
    };
    let hop = hop.trim_matches('"').trim();

    // `[2001:db8::1]` or `[2001:db8::1]:443`.
    if let Some(rest) = hop.strip_prefix('[') {
        let (addr, _port) = rest.split_once(']')?;
        return addr.parse().ok();
    }
    if let Ok(ip) = hop.parse::<IpAddr>() {
        return Some(ip);
    }
    // A bare IPv6 parsed above, so a colon here means `1.2.3.4:443`.
    let (addr, _port) = hop.rsplit_once(':')?;
    addr.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// Resolve the originating client IP for logging and rate limiting.
///
/// `connect` is the TCP peer (None in tests that bypass axum, and then headers
/// are trusted). `X-Forwarded-For` is walked right-to-left and the first
/// non-proxy hop wins; see the module docs.
pub fn extract_client_ip(
    connect: Option<&ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    trusted: &TrustedProxies,
) -> IpAddr {
    let peer = connect.map(|ci| ci.0.ip());

    let trust_headers = match peer {
        None => true,
        Some(ip) if ip.is_loopback() => true,
        Some(ip) => trusted.contains(ip),
    };

    if trust_headers
        && let Some(hv) = headers.get("x-forwarded-for")
        && let Ok(s) = hv.to_str()
    {
        let mut outermost_proxy = None;
        for hop in s.rsplit(',').take(MAX_XFF_HOPS) {
            // Skipping an unreadable hop would walk into unvouched entries.
            let Some(ip) = parse_forwarded_hop(hop) else {
                break;
            };
            if !trusted.is_proxy_hop(ip) {
                return ip;
            }
            outermost_proxy = Some(ip);
        }
        // All hops read were proxies: use the outermost. If the innermost entry
        // was unreadable, fall through to `X-Real-IP` / the peer.
        if let Some(ip) = outermost_proxy {
            return ip;
        }
    }
    if trust_headers
        && let Some(hv) = headers.get("x-real-ip")
        && let Ok(s) = hv.to_str()
        && let Ok(ip) = s.trim().parse::<IpAddr>()
    {
        return ip;
    }

    peer.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}
