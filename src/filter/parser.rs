/// Adblock/hosts rule parser.
///
/// Supports AdGuard/ABP, hosts-file, and plain-domain formats.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Block,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRule {
    pub domain: String,
    pub action: RuleAction,
    /// If true, also matches all subdomains
    pub is_subdomain: bool,
}

/// Localhost-like entries that should be skipped when encountered as the domain
/// in a hosts-file line or as a plain domain.
const LOCALHOST_ENTRIES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// Returns true if the domain is a localhost-like entry that should be skipped.
fn is_localhost_entry(domain: &str) -> bool {
    LOCALHOST_ENTRIES.contains(&domain)
}

/// Returns true if the string looks like an IP address (starts with a digit or colon).
fn looks_like_ip(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_digit() || c == ':')
}

/// Parse a single rule line. Returns `None` for comments, empty lines, and
/// unparseable rules.
pub fn parse_rule(line: &str) -> Option<ParsedRule> {
    let trimmed = line.trim();

    // Empty or whitespace-only
    if trimmed.is_empty() {
        return None;
    }

    // Comments
    if trimmed.starts_with('#') || trimmed.starts_with('!') {
        return None;
    }

    // AdGuard/ABP allow: @@||domain.com^
    if let Some(rest) = trimmed.strip_prefix("@@||") {
        let domain = rest.strip_suffix('^').unwrap_or(rest).to_lowercase();
        if domain.is_empty() || is_localhost_entry(&domain) {
            return None;
        }
        return Some(ParsedRule {
            domain,
            action: RuleAction::Allow,
            is_subdomain: true,
        });
    }

    // AdGuard/ABP block: ||domain.com^
    if let Some(rest) = trimmed.strip_prefix("||") {
        let domain = rest.strip_suffix('^').unwrap_or(rest).to_lowercase();
        if domain.is_empty() || is_localhost_entry(&domain) {
            return None;
        }
        return Some(ParsedRule {
            domain,
            action: RuleAction::Block,
            is_subdomain: true,
        });
    }

    // Hosts format: 0.0.0.0/127.0.0.1/::1/etc followed by domain
    if looks_like_ip(trimmed) {
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            // Take the second token as the domain, ignore inline comments
            let domain = parts[1].to_lowercase();
            if is_localhost_entry(&domain) || !domain.contains('.') {
                return None;
            }
            return Some(ParsedRule {
                domain,
                action: RuleAction::Block,
                is_subdomain: false,
            });
        }
        // Bare IP or unparseable
        return None;
    }

    // Plain domain: must contain a dot, no spaces
    if !trimmed.contains(' ') && trimmed.contains('.') {
        let domain = trimmed.to_lowercase();
        if is_localhost_entry(&domain) {
            return None;
        }
        return Some(ParsedRule {
            domain,
            action: RuleAction::Block,
            is_subdomain: false,
        });
    }

    None
}

/// Parse a multi-line list of rules.
pub fn parse_list(content: &str) -> Vec<ParsedRule> {
    content.lines().filter_map(parse_rule).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_caret_optional_for_adblock() {
        // Without trailing ^
        let result = parse_rule("||example.com").unwrap();
        assert_eq!(result.domain, "example.com");
        assert_eq!(result.action, RuleAction::Block);
        assert!(result.is_subdomain);
    }
}
