//! Block-response configuration: how the DNS handler answers a query that the
//! filter engine blocks. Selected at runtime via the `block_mode` /
//! `block_custom_ipv4` / `block_custom_ipv6` settings.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// How a filter-blocked query is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockMode {
    /// `0.0.0.0` for A, `::` for AAAA, empty `NoError` for other types.
    NullIp,
    /// `NXDOMAIN` for every query type.
    Nxdomain,
    /// `REFUSED` for every query type.
    Refused,
    /// Operator-supplied IPv4 (A) / IPv6 (AAAA); empty `NoError` when the
    /// relevant address is unset or the query is another type.
    CustomIp,
}

impl BlockMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockMode::NullIp => "null_ip",
            BlockMode::Nxdomain => "nxdomain",
            BlockMode::Refused => "refused",
            BlockMode::CustomIp => "custom_ip",
        }
    }
}

impl FromStr for BlockMode {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "null_ip" => Ok(BlockMode::NullIp),
            "nxdomain" => Ok(BlockMode::Nxdomain),
            "refused" => Ok(BlockMode::Refused),
            "custom_ip" => Ok(BlockMode::CustomIp),
            _ => Err(()),
        }
    }
}

/// Runtime block-response configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockConfig {
    pub mode: BlockMode,
    pub custom_v4: Option<Ipv4Addr>,
    pub custom_v6: Option<Ipv6Addr>,
}

impl Default for BlockConfig {
    fn default() -> Self {
        BlockConfig {
            mode: BlockMode::NullIp,
            custom_v4: None,
            custom_v6: None,
        }
    }
}

/// Build a `BlockConfig` from raw setting strings. An absent or unrecognised
/// mode falls back to `NullIp`; an empty or unparseable IP becomes `None`.
pub fn from_settings(mode: Option<&str>, v4: Option<&str>, v6: Option<&str>) -> BlockConfig {
    let mode = mode
        .and_then(|s| BlockMode::from_str(s.trim()).ok())
        .unwrap_or(BlockMode::NullIp);
    let custom_v4 = v4.and_then(|s| s.trim().parse::<Ipv4Addr>().ok());
    let custom_v6 = v6.and_then(|s| s.trim().parse::<Ipv6Addr>().ok());
    BlockConfig {
        mode,
        custom_v4,
        custom_v6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_roundtrips_through_str() {
        for (s, m) in [
            ("null_ip", BlockMode::NullIp),
            ("nxdomain", BlockMode::Nxdomain),
            ("refused", BlockMode::Refused),
            ("custom_ip", BlockMode::CustomIp),
        ] {
            assert_eq!(BlockMode::from_str(s).unwrap(), m);
            assert_eq!(m.as_str(), s);
        }
    }

    #[test]
    fn unknown_mode_string_is_err() {
        assert!(BlockMode::from_str("bogus").is_err());
    }

    #[test]
    fn from_settings_defaults_to_null_ip() {
        let cfg = from_settings(None, None, None);
        assert_eq!(cfg, BlockConfig::default());
        assert_eq!(cfg.mode, BlockMode::NullIp);
    }

    #[test]
    fn from_settings_unknown_mode_falls_back_to_null_ip() {
        assert_eq!(
            from_settings(Some("bogus"), None, None).mode,
            BlockMode::NullIp
        );
    }

    #[test]
    fn from_settings_parses_custom_ips() {
        let cfg = from_settings(Some("custom_ip"), Some("192.0.2.1"), Some("100::1"));
        assert_eq!(cfg.mode, BlockMode::CustomIp);
        assert_eq!(cfg.custom_v4, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(cfg.custom_v6, Some("100::1".parse::<Ipv6Addr>().unwrap()));
    }

    #[test]
    fn from_settings_empty_or_bad_ip_is_none() {
        let cfg = from_settings(Some("custom_ip"), Some(""), Some("not-an-ip"));
        assert_eq!(cfg.custom_v4, None);
        assert_eq!(cfg.custom_v6, None);
    }
}
