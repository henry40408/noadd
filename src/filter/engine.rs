/// Domain filter engine using HashMap for exact matches and a reverse-domain
/// trie for subdomain matching.
///
/// Designed for concurrent read access behind `ArcSwap<FilterEngine>`.
use std::collections::HashMap;

use crate::filter::parser::{ParsedRule, RuleAction};

/// Result of checking a domain against the filter engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterResult {
    Allowed { rule: Option<String> },
    Blocked { rule: String, list: String },
}

/// A node in the reverse-domain trie.
///
/// Domains are stored with labels reversed so that walking from the root
/// follows TLD → second-level → third-level etc.  When any node along the
/// walk is marked as a terminal the lookup short-circuits (subdomain match).
#[derive(Debug, Default)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    /// If `Some`, this node marks the end of a blocking/allowing rule.
    /// For block tries the value is `(original_rule, list_name)`.
    /// For allow tries the value is `()` (we only need the boolean).
    is_terminal: bool,
    /// Provenance stored only in block trie nodes.
    rule: Option<String>,
    list: Option<String>,
}

impl TrieNode {
    fn insert(&mut self, labels: &[&str], rule: Option<String>, list: Option<String>) {
        let mut node = self;
        for &label in labels {
            node = node.children.entry(label.to_owned()).or_default();
        }
        node.is_terminal = true;
        node.rule = rule;
        node.list = list;
    }

    /// Walk the trie for the given reversed labels. Returns the first terminal
    /// node encountered (closest ancestor match).
    fn lookup(&self, labels: &[&str]) -> Option<(&TrieNode, usize)> {
        let mut node = self;
        for (i, &label) in labels.iter().enumerate() {
            match node.children.get(label) {
                Some(child) => {
                    node = child;
                    if node.is_terminal {
                        return Some((node, i));
                    }
                }
                None => return None,
            }
        }
        None
    }

    /// Approximate count of terminal nodes in the trie.
    fn terminal_count(&self) -> usize {
        let mut count = if self.is_terminal { 1 } else { 0 };
        for child in self.children.values() {
            count += child.terminal_count();
        }
        count
    }
}

/// Split a domain into reversed labels for trie operations.
fn reversed_labels(domain: &str) -> Vec<&str> {
    domain.split('.').rev().collect()
}

/// The filter engine.  Immutable after construction — rebuild to update rules.
pub struct FilterEngine {
    /// Exact-match blocklist: domain → (rule, list_name).
    exact_block: HashMap<String, (String, String)>,
    /// Subdomain blocklist trie (reversed labels).
    block_trie: TrieNode,
    /// Exact-match allowlist: domain → original rule text.
    exact_allow: HashMap<String, String>,
    /// Subdomain allowlist trie (reversed labels).
    allow_trie: TrieNode,
}

// SAFETY: all fields are plain data with no interior mutability.
unsafe impl Send for FilterEngine {}
unsafe impl Sync for FilterEngine {}

impl FilterEngine {
    /// Build a new engine from parsed rules.
    ///
    /// * `block_rules` — each entry pairs a parsed rule with the name of the
    ///   list it came from (provenance tracking).
    /// * `allow_rules` — allowlist rules (provenance is not tracked).
    pub fn new(block_rules: Vec<(ParsedRule, String)>, allow_rules: Vec<ParsedRule>) -> Self {
        let mut exact_block = HashMap::new();
        let mut block_trie = TrieNode::default();
        let mut exact_allow = HashMap::new();
        let mut allow_trie = TrieNode::default();

        for (rule, list_name) in block_rules {
            debug_assert_eq!(rule.action, RuleAction::Block);
            let domain = rule.domain.to_lowercase();
            if rule.is_subdomain {
                let labels = reversed_labels(&domain);
                block_trie.insert(&labels, Some(domain.clone()), Some(list_name));
            } else {
                exact_block.insert(domain.clone(), (domain, list_name));
            }
        }

        for rule in allow_rules {
            debug_assert_eq!(rule.action, RuleAction::Allow);
            let domain = rule.domain.to_lowercase();
            if rule.is_subdomain {
                let labels = reversed_labels(&domain);
                allow_trie.insert(&labels, Some(domain.clone()), None);
            } else {
                exact_allow.insert(domain.clone(), domain);
            }
        }

        Self {
            exact_block,
            block_trie,
            exact_allow,
            allow_trie,
        }
    }

    /// Check whether `domain` should be blocked.
    ///
    /// Priority order:
    /// 1. Allowlist exact match → Allowed
    /// 2. Allowlist subdomain match → Allowed
    /// 3. Blocklist exact match → Blocked
    /// 4. Blocklist subdomain match → Blocked
    /// 5. Default → Allowed
    pub fn check(&self, domain: &str) -> FilterResult {
        let lower = domain.to_lowercase();

        // 1. Exact allow
        if let Some(rule) = self.exact_allow.get(&lower) {
            return FilterResult::Allowed {
                rule: Some(rule.clone()),
            };
        }

        // 2. Subdomain allow (trie)
        let labels = reversed_labels(&lower);
        if let Some((node, _)) = self.allow_trie.lookup(&labels) {
            return FilterResult::Allowed {
                rule: node.rule.clone(),
            };
        }

        // 3. Exact block
        if let Some((rule, list)) = self.exact_block.get(&lower) {
            return FilterResult::Blocked {
                rule: rule.clone(),
                list: list.clone(),
            };
        }

        // 4. Subdomain block (trie)
        if let Some((node, _)) = self.block_trie.lookup(&labels) {
            return FilterResult::Blocked {
                rule: node.rule.clone().unwrap_or_default(),
                list: node.list.clone().unwrap_or_default(),
            };
        }

        // 5. Default
        FilterResult::Allowed { rule: None }
    }

    /// Approximate count of blocked domains (exact entries + trie terminals).
    pub fn blocked_domain_count(&self) -> usize {
        self.exact_block.len() + self.block_trie.terminal_count()
    }
}
