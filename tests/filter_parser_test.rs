use noadd::filter::parser::{parse_list, parse_rule, ParsedRule, RuleAction};

#[test]
fn test_parse_adblock_block_rule() {
    let result = parse_rule("||example.com^").unwrap();
    assert_eq!(
        result,
        ParsedRule {
            domain: "example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        }
    );
}

#[test]
fn test_parse_adblock_allow_rule() {
    let result = parse_rule("@@||example.com^").unwrap();
    assert_eq!(
        result,
        ParsedRule {
            domain: "example.com".to_string(),
            action: RuleAction::Allow,
            is_subdomain: true,
        }
    );
}

#[test]
fn test_parse_hosts_format_zero() {
    let result = parse_rule("0.0.0.0 ads.example.com").unwrap();
    assert_eq!(
        result,
        ParsedRule {
            domain: "ads.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: false,
        }
    );
}

#[test]
fn test_parse_hosts_format_localhost() {
    let result = parse_rule("127.0.0.1 tracker.example.com").unwrap();
    assert_eq!(
        result,
        ParsedRule {
            domain: "tracker.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: false,
        }
    );
}

#[test]
fn test_parse_plain_domain() {
    let result = parse_rule("malware.example.com").unwrap();
    assert_eq!(
        result,
        ParsedRule {
            domain: "malware.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: false,
        }
    );
}

#[test]
fn test_parse_comment_hash() {
    assert!(parse_rule("# This is a comment").is_none());
}

#[test]
fn test_parse_comment_bang() {
    assert!(parse_rule("! Another comment").is_none());
}

#[test]
fn test_parse_empty_line() {
    assert!(parse_rule("").is_none());
    assert!(parse_rule("   ").is_none());
    assert!(parse_rule("\t").is_none());
}

#[test]
fn test_parse_hosts_localhost_entry_skipped() {
    assert!(parse_rule("127.0.0.1 localhost").is_none());
    assert!(parse_rule("0.0.0.0 local").is_none());
    assert!(parse_rule("127.0.0.1 broadcasthost").is_none());
    assert!(parse_rule("::1 ip6-localhost").is_none());
    assert!(parse_rule("localhost").is_none());
}

#[test]
fn test_parse_list_multiple_rules() {
    let content = r#"
# Comment line
! Another comment
||ads.example.com^
@@||safe.example.com^
0.0.0.0 tracker.example.com
127.0.0.1 localhost
malware.bad.com

"#;
    let rules = parse_list(content);
    assert_eq!(rules.len(), 4);
    assert_eq!(rules[0].domain, "ads.example.com");
    assert_eq!(rules[0].action, RuleAction::Block);
    assert!(rules[0].is_subdomain);
    assert_eq!(rules[1].domain, "safe.example.com");
    assert_eq!(rules[1].action, RuleAction::Allow);
    assert!(rules[1].is_subdomain);
    assert_eq!(rules[2].domain, "tracker.example.com");
    assert_eq!(rules[2].action, RuleAction::Block);
    assert!(!rules[2].is_subdomain);
    assert_eq!(rules[3].domain, "malware.bad.com");
    assert_eq!(rules[3].action, RuleAction::Block);
    assert!(!rules[3].is_subdomain);
}

#[test]
fn test_parse_domain_lowercased() {
    let result = parse_rule("||EXAMPLE.COM^").unwrap();
    assert_eq!(result.domain, "example.com");

    let result = parse_rule("0.0.0.0 ADS.Example.COM").unwrap();
    assert_eq!(result.domain, "ads.example.com");
}
