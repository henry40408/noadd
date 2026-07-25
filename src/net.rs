//! Network helpers shared by the `DoH` and admin HTTP layers.
//!
//! `TrustedProxies` parses a comma-separated CIDR list (typically supplied via
//! `--trusted-proxies` / `NOADD_TRUSTED_PROXIES`) and decides which TCP peers
//! are allowed to forge the originating client IP via `X-Forwarded-For` or
//! `X-Real-IP`. Everything else falls back to the TCP peer address.
//!
//! Trust policy:
//! 1. Loopback peers (127.0.0.0/8, `::1`) are *always* trusted — this keeps the
//!    "reverse proxy on the same host" path working with no config.
//! 2. Peers whose address matches a configured CIDR are trusted (e.g. a Docker
//!    bridge `172.18.0.0/16` when noadd sits behind SWAG/nginx in another
//!    container).
//! 3. Otherwise headers are client-controlled and must NOT be honoured —
//!    spoofing the source IP would defeat per-IP rate limiting and pollute the
//!    query log.
//!
//! Trusting the *peer* is only half the job: `X-Forwarded-For` is a list, and
//! a trusted proxy may well have appended to a list the client started. nginx's
//! ubiquitous `$proxy_add_x_forwarded_for` and Cloudflare both *append* rather
//! than overwrite, so `XFF: <attacker value>, <real client>` reaches noadd with
//! a perfectly trustworthy peer in front of it. The leftmost entry is therefore
//! attacker-controlled in exactly the deployments noadd documents, which is why
//! `extract_client_ip` walks the list from the right and returns the first hop
//! that is *not* a configured proxy. Every proxy in the chain consequently has
//! to appear in `--trusted-proxies` (for Cloudflare, its published ranges);
//! a hop that is missing is attributed as the client, which over-attributes to
//! a proxy — the safe direction — instead of honouring a forged value.

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

    /// Return true if `ip` belongs to this CIDR. Cross-family checks (e.g.
    /// IPv6 `::ffff:a.b.c.d` against an IPv4 block) deliberately return false
    /// — operators should list both families explicitly if both are in use.
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
    /// Parse a comma-separated CIDR list. Empty entries (consecutive commas,
    /// trailing comma, all-whitespace) are ignored so operators can drop a
    /// stray comma without breaking startup.
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

    /// Return true if `ip` is a proxy hop rather than a client: loopback (a
    /// same-host proxy, trusted implicitly as peers are) or a configured CIDR.
    fn is_proxy_hop(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.contains(ip)
    }
}

/// How many `X-Forwarded-For` hops are inspected, counting from the right.
///
/// Proxies append, so the entries that matter are always at the tail; a client
/// can only pad the head. Capping the walk keeps a padded header from costing
/// the `DoH` hot path a thousand `IpAddr` parses per query.
const MAX_XFF_HOPS: usize = 32;

/// Resolve the originating client IP for logging and rate limiting.
///
/// `connect` is the TCP peer (None during unit tests that bypass the axum
/// service stack); `headers` carries any proxy-supplied client-IP hints.
/// `trusted` decides which non-loopback peers are allowed to set those hints.
///
/// `X-Forwarded-For` is walked right-to-left and the first non-proxy hop wins;
/// see the module docs for why the leftmost entry must not be used.
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
        // Innermost (appended last, nearest noadd) first, so the walk starts at
        // the hop the adjacent proxy vouched for and moves outwards.
        let hops_inward_out: Vec<IpAddr> = s
            .rsplit(',')
            .take(MAX_XFF_HOPS)
            .filter_map(|hop| hop.trim().parse::<IpAddr>().ok())
            .collect();

        // The first entry no configured proxy accounts for is where the vouched
        // chain ends — everything beyond it is the client's own claim.
        if let Some(&client) = hops_inward_out
            .iter()
            .find(|&&ip| !trusted.is_proxy_hop(ip))
        {
            return client;
        }
        // Every hop is a known proxy (or the header held only garbage). With no
        // client to attribute, fall back to the outermost hop — the last of an
        // inward-out list. An all-garbage header leaves the list empty and drops
        // through to `X-Real-IP` / the peer.
        if let Some(&outermost) = hops_inward_out.last() {
            return outermost;
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
