//! Reverse-proxy forward auth: trust a username injected by a fronting proxy
//! (Authelia, Authentik, oauth2-proxy, tinyauth, ...) via a configurable
//! request header.
//!
//! Trust policy is deliberately **stricter** than [`crate::net`]'s client-IP
//! handling. There, a forged `X-Forwarded-For` only pollutes logs and rate
//! limits, so loopback is trusted implicitly as a convenience. Here, a forged
//! header hands the caller a fully authenticated operator session — so
//! forward auth has its own, separate CIDR allow-list
//! (`--forward-auth-trusted-proxies`) and loopback gets **no** special case:
//! the proxy's peer address must be listed explicitly, every time.

use std::net::IpAddr;

use axum::http::{HeaderMap, HeaderName};

use crate::net::{CidrParseError, TrustedProxies};

/// Maximum accepted username length, mirroring `create_user_handler`'s limit
/// on operator usernames created through the regular signup path.
pub const MAX_USERNAME_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum ForwardAuthConfigError {
    #[error("invalid header name `{0}` for --forward-auth-header")]
    InvalidHeader(String),
    #[error("invalid CIDR in --forward-auth-trusted-proxies: {0}")]
    InvalidCidr(#[from] CidrParseError),
    #[error(
        "--forward-auth-header requires a non-empty --forward-auth-trusted-proxies; \
         an unrestricted header would let any client forge an operator identity"
    )]
    MissingTrustedProxies,
    #[error("--forward-auth-trusted-proxies was set without --forward-auth-header")]
    MissingHeader,
}

/// Validated forward-auth configuration: the header to read the username
/// from, and the CIDRs whose peers are allowed to set it.
pub struct ForwardAuthConfig {
    header: HeaderName,
    trusted: TrustedProxies,
}

impl ForwardAuthConfig {
    /// Build a config from the raw `--forward-auth-header` /
    /// `--forward-auth-trusted-proxies` values, or `Ok(None)` if the feature
    /// is left off (both empty). Either flag set without the other is a
    /// startup error — a header with no allow-list would trust any client,
    /// and an allow-list with no header does nothing.
    pub fn from_args(header: &str, cidrs: &str) -> Result<Option<Self>, ForwardAuthConfigError> {
        let header = header.trim();
        let cidrs = cidrs.trim();

        if header.is_empty() && cidrs.is_empty() {
            return Ok(None);
        }
        if header.is_empty() {
            return Err(ForwardAuthConfigError::MissingHeader);
        }
        if cidrs.is_empty() {
            return Err(ForwardAuthConfigError::MissingTrustedProxies);
        }

        let header_name = HeaderName::from_bytes(header.as_bytes())
            .map_err(|_err| ForwardAuthConfigError::InvalidHeader(header.to_string()))?;

        let trusted = TrustedProxies::parse(cidrs)?;
        // A list that parsed but yielded no CIDRs (e.g. ",,") must not leave
        // forward auth "on" while trusting nothing — that's the same footgun
        // as an empty allow-list, just reached via a different input.
        if trusted.is_empty() {
            return Err(ForwardAuthConfigError::MissingTrustedProxies);
        }

        Ok(Some(ForwardAuthConfig {
            header: header_name,
            trusted,
        }))
    }

    /// The header name the config was built with, for startup logging.
    pub fn header(&self) -> &HeaderName {
        &self.header
    }

    /// Number of configured trusted CIDRs, for startup logging.
    pub fn trusted_len(&self) -> usize {
        self.trusted.len()
    }

    /// Resolve the operator username asserted by the proxy, or `None` if the
    /// request cannot be trusted. `peer` is the TCP peer address (`None` when
    /// there is no `ConnectInfo`, e.g. a raw `tower::Service` call in tests —
    /// treated as untrusted, never as loopback).
    pub fn resolve_username(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<String> {
        let peer = peer?;
        if !self.trusted.contains(peer) {
            return None;
        }

        // A repeated header (e.g. a client-supplied value the proxy failed to
        // strip, plus the proxy's own appended value) arrives as two header
        // values. Picking either — first or last — is a spoofing hazard, so
        // any request with more than one value for the header is rejected
        // outright rather than guessing which one is trustworthy.
        let mut values = headers.get_all(&self.header).iter();
        let first = values.next()?;
        if values.next().is_some() {
            return None;
        }

        normalize_username(first.to_str().ok()?)
    }
}

/// Trim and validate a raw header value as a username: non-empty, within
/// [`MAX_USERNAME_LEN`] characters, and free of control characters (which
/// have no legitimate place in a username and could otherwise smuggle
/// terminal escapes or similar into logs).
fn normalize_username(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_USERNAME_LEN {
        return None;
    }
    if trimmed.chars().any(char::is_control) {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        headers
    }

    #[test]
    fn both_empty_disables_forward_auth() {
        assert!(ForwardAuthConfig::from_args("", "").unwrap().is_none());
    }

    #[test]
    fn header_without_cidrs_is_an_error() {
        assert!(matches!(
            ForwardAuthConfig::from_args("Remote-User", ""),
            Err(ForwardAuthConfigError::MissingTrustedProxies)
        ));
    }

    #[test]
    fn cidrs_without_header_is_an_error() {
        assert!(matches!(
            ForwardAuthConfig::from_args("", "127.0.0.1/32"),
            Err(ForwardAuthConfigError::MissingHeader)
        ));
    }

    #[test]
    fn cidrs_that_parse_to_nothing_is_an_error() {
        assert!(matches!(
            ForwardAuthConfig::from_args("Remote-User", ",,"),
            Err(ForwardAuthConfigError::MissingTrustedProxies)
        ));
    }

    #[test]
    fn bad_header_name_is_an_error() {
        assert!(matches!(
            ForwardAuthConfig::from_args("bad header\n", "127.0.0.1/32"),
            Err(ForwardAuthConfigError::InvalidHeader(_))
        ));
    }

    #[test]
    fn bad_cidr_is_an_error() {
        assert!(matches!(
            ForwardAuthConfig::from_args("Remote-User", "not-a-cidr"),
            Err(ForwardAuthConfigError::InvalidCidr(_))
        ));
    }

    #[test]
    fn resolve_username_none_without_peer() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8")
            .unwrap()
            .unwrap();
        let headers = headers_with("Remote-User", "alice");
        assert!(cfg.resolve_username(None, &headers).is_none());
    }

    #[test]
    fn resolve_username_none_for_untrusted_loopback_peer() {
        // Loopback is NOT implicitly trusted here, unlike extract_client_ip.
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8")
            .unwrap()
            .unwrap();
        let headers = headers_with("Remote-User", "alice");
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(cfg.resolve_username(Some(peer), &headers).is_none());
    }

    #[test]
    fn resolve_username_none_without_header() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8")
            .unwrap()
            .unwrap();
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(
            cfg.resolve_username(Some(peer), &HeaderMap::new())
                .is_none()
        );
    }

    #[test]
    fn resolve_username_none_for_empty_username() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8")
            .unwrap()
            .unwrap();
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let headers = headers_with("Remote-User", "   ");
        assert!(cfg.resolve_username(Some(peer), &headers).is_none());
    }

    #[test]
    fn resolve_username_none_for_oversized_username() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8")
            .unwrap()
            .unwrap();
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let long = "a".repeat(MAX_USERNAME_LEN + 1);
        let headers = headers_with("Remote-User", &long);
        assert!(cfg.resolve_username(Some(peer), &headers).is_none());
    }

    #[test]
    fn resolve_username_none_for_control_char_username() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8")
            .unwrap()
            .unwrap();
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        // A raw `\n` cannot survive `HeaderValue` construction at all (the
        // HTTP layer itself rejects it); a tab is a control char that HTTP
        // does permit in header values, so it's the one that must be caught
        // by `normalize_username` itself.
        let headers = headers_with("Remote-User", "ali\tce");
        assert!(cfg.resolve_username(Some(peer), &headers).is_none());
    }

    #[test]
    fn resolve_username_none_for_duplicated_header() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8")
            .unwrap()
            .unwrap();
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.append("Remote-User", "alice".parse().unwrap());
        headers.append("Remote-User", "bob".parse().unwrap());
        assert!(cfg.resolve_username(Some(peer), &headers).is_none());
    }

    #[test]
    fn resolve_username_trims_and_returns_trusted_peer() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8")
            .unwrap()
            .unwrap();
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let headers = headers_with("Remote-User", "alice ");
        assert_eq!(
            cfg.resolve_username(Some(peer), &headers),
            Some("alice".to_string())
        );
    }

    #[test]
    fn header_matching_is_case_insensitive() {
        // Configured with mixed case; sent all-lowercase, as HTTP header names
        // require case-insensitive matching.
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8")
            .unwrap()
            .unwrap();
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let headers = headers_with("remote-user", "alice");
        assert_eq!(
            cfg.resolve_username(Some(peer), &headers),
            Some("alice".to_string())
        );
    }
}
