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
    let engine = FilterEngine::from_named_rules(
        vec![(block_rule("ads.example.com", false), "list1".into())],
        vec![],
    );

    assert!(matches!(
        engine.check("ads.example.com"),
        FilterResult::Blocked { .. }
    ));
    // Exact-only rule must NOT match subdomains
    assert!(matches!(
        engine.check("sub.ads.example.com"),
        FilterResult::Allowed { .. }
    ));
    // Unrelated domain
    assert!(matches!(
        engine.check("example.com"),
        FilterResult::Allowed { .. }
    ));
}

#[test]
fn test_subdomain_block() {
    let engine = FilterEngine::from_named_rules(
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
    assert!(matches!(
        engine.check("example.com"),
        FilterResult::Allowed { .. }
    ));
}

#[test]
fn test_allowed_domain() {
    let engine = FilterEngine::new(vec![], vec![], vec![]);
    assert!(matches!(
        engine.check("anything.com"),
        FilterResult::Allowed { .. }
    ));
    assert!(matches!(
        engine.check("safe.example.com"),
        FilterResult::Allowed { .. }
    ));
}

#[test]
fn test_allowlist_overrides_blocklist() {
    let engine = FilterEngine::from_named_rules(
        vec![(block_rule("ads.example.com", true), "blocklist".into())],
        vec![allow_rule("ads.example.com", true)],
    );

    // The allowlist should take priority
    assert!(matches!(
        engine.check("ads.example.com"),
        FilterResult::Allowed { .. }
    ));
    assert!(matches!(
        engine.check("sub.ads.example.com"),
        FilterResult::Allowed { .. }
    ));
}

#[test]
fn test_provenance_tracking() {
    let engine = FilterEngine::from_named_rules(
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
    let engine = FilterEngine::new(vec![], vec![], vec![]);
    assert!(matches!(
        engine.check("anything.example.com"),
        FilterResult::Allowed { .. }
    ));
    assert!(matches!(
        engine.check("a.b.c.d.e.f.g"),
        FilterResult::Allowed { .. }
    ));
    assert_eq!(engine.blocked_domain_count(), 0);
}

// --- Build-path optimization (HashMap children + pre-interned names) ---

#[test]
fn new_with_pre_interned_list_names_resolves_provenance() {
    // Production path: caller hands FilterEngine an already-deduplicated list
    // name table plus (rule, list_idx) pairs. This is what `rebuild_filter`
    // does so it can avoid cloning the same list name once per rule.
    let list_names: Vec<Box<str>> = vec!["easylist".into(), "adguard".into()];
    let block_rules = vec![
        (block_rule("tracker.net", false), 0u16),
        (block_rule("ads.example.com", true), 1u16),
    ];
    let engine = FilterEngine::new(list_names, block_rules, vec![]);

    match engine.check("tracker.net") {
        FilterResult::Blocked { rule, list } => {
            assert_eq!(rule, "tracker.net");
            assert_eq!(list, "easylist");
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
    match engine.check("sub.ads.example.com") {
        FilterResult::Blocked { rule, list } => {
            assert_eq!(rule, "ads.example.com");
            assert_eq!(list, "adguard");
        }
        other => panic!("expected Blocked, got {other:?}"),
    }
}

#[test]
fn build_is_insertion_order_independent() {
    // The flat trie is built from a HashMap whose iteration order is
    // non-deterministic. Two builds from the same rules in different orders
    // must still produce identical lookup results — sorting at flatten time
    // is what makes that true.
    let mut rules_a = vec![
        (block_rule("a.example.com", true), 0u16),
        (block_rule("b.example.com", true), 0u16),
        (block_rule("ads.example.com", true), 0u16),
        (block_rule("tracker.net", false), 0u16),
        (block_rule("zzz.example.com", true), 0u16),
    ];
    let mut rules_b = rules_a.clone();
    rules_b.reverse();
    rules_a.swap(0, 3);

    let list_names: Vec<Box<str>> = vec!["L".into()];
    let engine_a = FilterEngine::new(list_names.clone(), rules_a, vec![]);
    let engine_b = FilterEngine::new(list_names, rules_b, vec![]);

    for q in [
        "a.example.com",
        "deep.b.example.com",
        "ads.example.com",
        "tracker.net",
        "unrelated.org",
        "zzz.example.com",
    ] {
        assert_eq!(
            engine_a.check(q),
            engine_b.check(q),
            "order independence broken for query `{q}`"
        );
    }
}

#[test]
fn lowercases_uppercase_query_against_lowercased_rules() {
    // Parser already lowercases rule.domain. The engine must trust that and
    // still match queries that arrive in mixed case — i.e. the lookup path
    // is the only place case folding happens.
    let engine = FilterEngine::from_named_rules(
        vec![(block_rule("ads.example.com", true), "L".into())],
        vec![],
    );
    assert!(matches!(
        engine.check("ADS.Example.COM"),
        FilterResult::Blocked { .. }
    ));
    assert!(matches!(
        engine.check("Sub.ADS.example.com"),
        FilterResult::Blocked { .. }
    ));
}
