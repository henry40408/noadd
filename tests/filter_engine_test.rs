use noadd::filter::engine::{FilterEngine, FilterResult};
use noadd::filter::parser::{ParsedRule, RuleAction};

fn block_rule(domain: &str, is_subdomain: bool) -> ParsedRule {
    ParsedRule {
        domain: domain.to_owned(),
        action: RuleAction::Block,
        is_subdomain,
    }
}

fn allow_rule(domain: &str, is_subdomain: bool) -> ParsedRule {
    ParsedRule {
        domain: domain.to_owned(),
        action: RuleAction::Allow,
        is_subdomain,
    }
}

#[test]
fn test_exact_block() {
    let engine = FilterEngine::new(
        vec![(block_rule("ads.example.com", false), "list1".into())],
        vec![],
    );

    assert!(matches!(
        engine.check("ads.example.com"),
        FilterResult::Blocked { .. }
    ));
    // Exact-only rule must NOT match subdomains
    assert_eq!(engine.check("sub.ads.example.com"), FilterResult::Allowed);
    // Unrelated domain
    assert_eq!(engine.check("example.com"), FilterResult::Allowed);
}

#[test]
fn test_subdomain_block() {
    let engine = FilterEngine::new(
        vec![(block_rule("ads.example.com", true), "list1".into())],
        vec![],
    );

    // Exact domain itself
    assert!(matches!(
        engine.check("ads.example.com"),
        FilterResult::Blocked { .. }
    ));
    // Subdomain of the blocked domain
    assert!(matches!(
        engine.check("sub.ads.example.com"),
        FilterResult::Blocked { .. }
    ));
    // Parent domain must NOT be blocked
    assert_eq!(engine.check("example.com"), FilterResult::Allowed);
}

#[test]
fn test_allowed_domain() {
    let engine = FilterEngine::new(vec![], vec![]);
    assert_eq!(engine.check("anything.com"), FilterResult::Allowed);
    assert_eq!(engine.check("safe.example.com"), FilterResult::Allowed);
}

#[test]
fn test_allowlist_overrides_blocklist() {
    let engine = FilterEngine::new(
        vec![(block_rule("ads.example.com", true), "blocklist".into())],
        vec![allow_rule("ads.example.com", true)],
    );

    // The allowlist should take priority
    assert_eq!(engine.check("ads.example.com"), FilterResult::Allowed);
    assert_eq!(engine.check("sub.ads.example.com"), FilterResult::Allowed);
}

#[test]
fn test_provenance_tracking() {
    let engine = FilterEngine::new(
        vec![
            (block_rule("tracker.net", false), "easylist".into()),
            (block_rule("ads.example.com", true), "adguard".into()),
        ],
        vec![],
    );

    // Exact match provenance
    match engine.check("tracker.net") {
        FilterResult::Blocked { rule, list } => {
            assert_eq!(rule, "tracker.net");
            assert_eq!(list, "easylist");
        }
        other => panic!("expected Blocked, got {other:?}"),
    }

    // Trie match provenance
    match engine.check("sub.ads.example.com") {
        FilterResult::Blocked { rule, list } => {
            assert_eq!(rule, "ads.example.com");
            assert_eq!(list, "adguard");
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

#[test]
fn test_empty_engine_allows_everything() {
    let engine = FilterEngine::new(vec![], vec![]);
    assert_eq!(engine.check("anything.example.com"), FilterResult::Allowed);
    assert_eq!(engine.check("a.b.c.d.e.f.g"), FilterResult::Allowed);
    assert_eq!(engine.blocked_domain_count(), 0);
}
