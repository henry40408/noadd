//! Reverse-proxy forward auth: trust a username injected by a fronting proxy
//! (Authelia, Authentik, oauth2-proxy, tinyauth, ...) via a configurable
//! request header.
//!
//! Trust is deliberately **stricter** than [`crate::net`]'s client-IP handling:
//! a forged `X-Forwarded-For` only pollutes logs and rate limits, but a forged
//! header here is a full operator session. So forward auth has its own CIDR
//! allow-list (`--forward-auth-trusted-proxies`) and loopback gets **no**
//! implicit trust.

use std::net::IpAddr;

use axum::http::{HeaderMap, HeaderName};

use crate::net::{CidrParseError, TrustedProxies};

/// Maximum username length, matching `create_user_handler`'s limit.
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
    logout_url: Option<String>,
}

impl ForwardAuthConfig {
    /// Build a config from `--forward-auth-header` /
    /// `--forward-auth-trusted-proxies`, or `Ok(None)` if both are empty. Either
    /// without the other is an error: a header with no allow-list trusts any
    /// client, and an allow-list with no header does nothing.
    pub fn from_args(
        header: &str,
        cidrs: &str,
        logout_url: &str,
    ) -> Result<Option<Self>, ForwardAuthConfigError> {
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
        // A list that parsed to no CIDRs (e.g. ",,") is the same footgun as an
        // empty one.
        if trusted.is_empty() {
            return Err(ForwardAuthConfigError::MissingTrustedProxies);
        }

        let logout_url = {
            let t = logout_url.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        };

        Ok(Some(ForwardAuthConfig {
            header: header_name,
            trusted,
            logout_url,
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

    /// The configured proxy/SSO logout URL, if any.
    pub fn logout_url(&self) -> Option<&str> {
        self.logout_url.as_deref()
    }

    /// Resolve the username asserted by the proxy, or `None` if the request
    /// cannot be trusted. A `None` `peer` (no `ConnectInfo`) is untrusted.
    pub fn resolve_username(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<String> {
        let peer = peer?;
        if !self.trusted.contains(peer) {
            return None;
        }

        // A repeated header (a client value the proxy failed to strip plus its
        // own) is rejected: picking either one is a spoofing hazard.
        let mut values = headers.get_all(&self.header).iter();
        let first = values.next()?;
        if values.next().is_some() {
            return None;
        }

        normalize_username(first.to_str().ok()?)
    }
}

/// Trim and validate a header value as a username: non-empty, at most
/// [`MAX_USERNAME_LEN`] characters, and free of control characters (which could
/// smuggle terminal escapes into logs).
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
        assert!(ForwardAuthConfig::from_args("", "", "").unwrap().is_none());
    }

    #[test]
    fn header_without_cidrs_is_an_error() {
        assert!(matches!(
            ForwardAuthConfig::from_args("Remote-User", "", ""),
            Err(ForwardAuthConfigError::MissingTrustedProxies)
        ));
    }

    #[test]
    fn cidrs_without_header_is_an_error() {
        assert!(matches!(
            ForwardAuthConfig::from_args("", "127.0.0.1/32", ""),
            Err(ForwardAuthConfigError::MissingHeader)
        ));
    }

    #[test]
    fn cidrs_that_parse_to_nothing_is_an_error() {
        assert!(matches!(
            ForwardAuthConfig::from_args("Remote-User", ",,", ""),
            Err(ForwardAuthConfigError::MissingTrustedProxies)
        ));
    }

    #[test]
    fn bad_header_name_is_an_error() {
        assert!(matches!(
            ForwardAuthConfig::from_args("bad header\n", "127.0.0.1/32", ""),
            Err(ForwardAuthConfigError::InvalidHeader(_))
        ));
    }

    #[test]
    fn bad_cidr_is_an_error() {
        assert!(matches!(
            ForwardAuthConfig::from_args("Remote-User", "not-a-cidr", ""),
            Err(ForwardAuthConfigError::InvalidCidr(_))
        ));
    }

    #[test]
    fn resolve_username_none_without_peer() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8", "")
            .unwrap()
            .unwrap();
        let headers = headers_with("Remote-User", "alice");
        assert!(cfg.resolve_username(None, &headers).is_none());
    }

    #[test]
    fn resolve_username_none_for_untrusted_loopback_peer() {
        // Loopback is NOT implicitly trusted here, unlike extract_client_ip.
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8", "")
            .unwrap()
            .unwrap();
        let headers = headers_with("Remote-User", "alice");
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(cfg.resolve_username(Some(peer), &headers).is_none());
    }

    #[test]
    fn resolve_username_none_without_header() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8", "")
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
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8", "")
            .unwrap()
            .unwrap();
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let headers = headers_with("Remote-User", "   ");
        assert!(cfg.resolve_username(Some(peer), &headers).is_none());
    }

    #[test]
    fn resolve_username_none_for_oversized_username() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8", "")
            .unwrap()
            .unwrap();
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let long = "a".repeat(MAX_USERNAME_LEN + 1);
        let headers = headers_with("Remote-User", &long);
        assert!(cfg.resolve_username(Some(peer), &headers).is_none());
    }

    #[test]
    fn resolve_username_none_for_control_char_username() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8", "")
            .unwrap()
            .unwrap();
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        // `HeaderValue` already rejects `\n` but permits a tab, so the tab is
        // what `normalize_username` itself must catch.
        let headers = headers_with("Remote-User", "ali\tce");
        assert!(cfg.resolve_username(Some(peer), &headers).is_none());
    }

    #[test]
    fn resolve_username_none_for_duplicated_header() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8", "")
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
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8", "")
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
        // Configured mixed-case, sent lowercase: header names are case-insensitive.
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8", "")
            .unwrap()
            .unwrap();
        let peer: IpAddr = "10.0.0.5".parse().unwrap();
        let headers = headers_with("remote-user", "alice");
        assert_eq!(
            cfg.resolve_username(Some(peer), &headers),
            Some("alice".to_string())
        );
    }

    #[test]
    fn from_args_trims_and_returns_logout_url() {
        let cfg = ForwardAuthConfig::from_args(
            "Remote-User",
            "10.0.0.0/8",
            "  https://sso.example/logout  ",
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.logout_url(), Some("https://sso.example/logout"));
    }

    #[test]
    fn from_args_empty_logout_url_is_none() {
        let cfg = ForwardAuthConfig::from_args("Remote-User", "10.0.0.0/8", "   ")
            .unwrap()
            .unwrap();
        assert!(cfg.logout_url().is_none());
    }
}
