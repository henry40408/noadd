/// Domain filter engine using HashMap for exact matches and a flat-serialized
/// reverse-domain trie for subdomain matching.
///
/// Designed for concurrent read access behind `ArcSwap<FilterEngine>`.
///
/// ## Memory layout
///
/// The trie is serialized into two contiguous byte buffers (`nodes` + `labels`)
/// instead of a tree of heap-allocated structs.  This eliminates:
/// - Per-`Vec` header overhead (24 bytes each)
/// - Per-`Box<str>` pointer+len (16 bytes each)
/// - Allocator bookkeeping (~16 bytes per allocation)
/// - Alignment padding
///
/// A typical node in the old tree cost ~114 bytes; the same node in the flat
/// trie costs ~15 bytes (7.5× more compact).
use std::cmp::Ordering;
use std::collections::HashMap;

use fst::Map as FstMap;
use fst::Set as FstSet;

use crate::filter::parser::{ParsedRule, RuleAction};

/// Result of checking a domain against the filter engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterResult {
    Allowed { rule: Option<String> },
    Blocked { rule: String, list: String },
}

/// Sentinel: this trie node is not a terminal.
const NOT_TERMINAL: u16 = u16::MAX;

/// Size of one child-index entry in the flat trie `nodes` buffer.
/// Layout: label_offset(u32) + label_len(u8) + child_node_offset(u32) = 9.
const CHILD_ENTRY: usize = 9;

// ── Flat trie ───────────────────────────────────────────────────────────

/// Compact trie serialized into two contiguous byte buffers.
///
/// ### Node layout (`nodes` buffer)
///
/// ```text
/// +0  u16  terminal_value   (NOT_TERMINAL if non-terminal)
/// +2  u16  child_count (N)
/// +4  N × ChildEntry
/// ```
///
/// ### ChildEntry (9 bytes, sorted by label)
///
/// ```text
/// +0  u32  label_offset     (into `labels`)
/// +4  u8   label_len
/// +5  u32  child_node_offset (into `nodes`)
/// ```
struct FlatTrie {
    nodes: Vec<u8>,
    labels: Vec<u8>,
    terminal_count: usize,
}

impl FlatTrie {
    /// Look up reversed `labels` in the trie.  Returns `(terminal_value, depth)`
    /// of the first terminal node hit, where *depth* is the index of the last
    /// label consumed (inclusive).
    fn lookup(&self, labels: &[&str]) -> Option<(u16, usize)> {
        if self.nodes.is_empty() {
            return None;
        }
        let mut off = 0usize;
        for (depth, &label) in labels.iter().enumerate() {
            let child_count = read_u16(&self.nodes, off + 2) as usize;
            let entries = off + 4;

            // Binary search children by label.
            let target = label.as_bytes();
            let mut lo = 0usize;
            let mut hi = child_count;
            let mut found_off = None;
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                let e = entries + mid * CHILD_ENTRY;
                let lbl = self.label_at(e);
                match lbl.cmp(target) {
                    Ordering::Equal => {
                        found_off = Some(read_u32(&self.nodes, e + 5) as usize);
                        break;
                    }
                    Ordering::Less => lo = mid + 1,
                    Ordering::Greater => hi = mid,
                }
            }
            let child_off = found_off?;
            off = child_off;
            let tv = read_u16(&self.nodes, off);
            if tv != NOT_TERMINAL {
                return Some((tv, depth));
            }
        }
        None
    }

    /// Read the label bytes for the child entry starting at `entry_off`.
    #[inline]
    fn label_at(&self, entry_off: usize) -> &[u8] {
        let lo = read_u32(&self.nodes, entry_off) as usize;
        let len = self.nodes[entry_off + 4] as usize;
        &self.labels[lo..lo + len]
    }
}

// ── Flat trie builder ───────────────────────────────────────────────────

/// Temporary tree node used only during construction, then serialized into
/// a `FlatTrie` and dropped.
///
/// Children live in a `HashMap` so insertion is O(1) — large blocklists
/// concentrate tens of thousands of second-level domains under a single TLD
/// node, and a sorted `Vec` made that the dominant cost of `rebuild_filter`
/// (every `Vec::insert` shifted later siblings). Sorting happens once per
/// node at serialize time instead.
struct BuildNode {
    children: HashMap<Box<str>, BuildNode>,
    terminal: u16,
}

impl BuildNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            terminal: NOT_TERMINAL,
        }
    }

    fn insert(&mut self, labels: &[&str], terminal: u16) {
        let mut node = self;
        for &label in labels {
            node = node
                .children
                .entry(Box::from(label))
                .or_insert_with(BuildNode::new);
        }
        node.terminal = terminal;
    }

    /// Serialize this tree into a `FlatTrie`.
    fn flatten(&self) -> FlatTrie {
        let mut nodes = Vec::new();
        let mut labels = Vec::new();
        let mut terminal_count = 0usize;
        Self::serialize(self, &mut nodes, &mut labels, &mut terminal_count);
        nodes.shrink_to_fit();
        labels.shrink_to_fit();
        FlatTrie {
            nodes,
            labels,
            terminal_count,
        }
    }

    fn serialize(
        node: &BuildNode,
        nodes: &mut Vec<u8>,
        labels: &mut Vec<u8>,
        tc: &mut usize,
    ) -> u32 {
        let offset = nodes.len() as u32;

        if node.terminal != NOT_TERMINAL {
            *tc += 1;
        }

        // Sort children by label — required for the binary-search lookup in
        // FlatTrie. HashMap iteration order is otherwise nondeterministic.
        let mut sorted: Vec<(&Box<str>, &BuildNode)> = node.children.iter().collect();
        sorted.sort_unstable_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));

        // Header: terminal_value + child_count
        nodes.extend_from_slice(&node.terminal.to_le_bytes());
        nodes.extend_from_slice(&(sorted.len() as u16).to_le_bytes());

        // Reserve space for child entries (filled after recursive serialization).
        let entries_start = nodes.len();
        nodes.resize(entries_start + CHILD_ENTRY * sorted.len(), 0);

        for (i, (label, child)) in sorted.iter().enumerate() {
            let label_offset = labels.len() as u32;
            let label_len = label.len() as u8;
            labels.extend_from_slice(label.as_bytes());

            let child_offset = Self::serialize(child, nodes, labels, tc);

            let e = entries_start + i * CHILD_ENTRY;
            nodes[e..e + 4].copy_from_slice(&label_offset.to_le_bytes());
            nodes[e + 4] = label_len;
            nodes[e + 5..e + 9].copy_from_slice(&child_offset.to_le_bytes());
        }

        offset
    }
}

// ── Byte helpers ────────────────────────────────────────────────────────

#[inline]
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Reconstruct the domain from reversed labels up to (and including) `depth`.
fn reconstruct_domain(labels: &[&str], depth: usize) -> String {
    let mut parts = labels[..=depth].to_vec();
    parts.reverse();
    parts.join(".")
}

/// Split a domain into reversed labels for trie operations.
fn reversed_labels(domain: &str) -> Vec<&str> {
    domain.split('.').rev().collect()
}

// ── Filter engine ───────────────────────────────────────────────────────

/// The filter engine.  Immutable after construction — rebuild to update rules.
pub struct FilterEngine {
    /// Interned list names.  Block rules store only a `u16` index into this.
    list_names: Vec<Box<str>>,
    /// Exact-match blocklist: domain → list index (FST map).
    exact_block: FstMap<Vec<u8>>,
    /// Subdomain blocklist (flat trie, reversed labels).
    block_trie: FlatTrie,
    /// Exact-match allowlist (FST set).
    exact_allow: FstSet<Vec<u8>>,
    /// Subdomain allowlist (flat trie, reversed labels).
    allow_trie: FlatTrie,
}

/// Marker value stored in allow-trie terminals (any value != NOT_TERMINAL).
const ALLOW_MARKER: u16 = 0;

impl FilterEngine {
    /// Build a new engine from rules with caller-interned list names.
    ///
    /// `block_rules` is `(ParsedRule, list_idx)` where `list_idx` indexes into
    /// `list_names`. This is what `rebuild_filter` calls so the same list
    /// name is interned once at the rebuild site instead of being cloned per
    /// rule (a 500k× allocation cut on large blocklists).
    ///
    /// `ParsedRule.domain` is trusted to already be lowercase — `parser.rs`
    /// guarantees this on every code path. The engine does not re-lowercase
    /// rule domains; only the query passed to [`check`] is folded.
    pub fn new(
        list_names: Vec<Box<str>>,
        block_rules: Vec<(ParsedRule, u16)>,
        allow_rules: Vec<ParsedRule>,
    ) -> Self {
        let mut exact_block_entries: Vec<(String, u16)> = Vec::with_capacity(block_rules.len() / 4);
        let mut block_build = BuildNode::new();
        let mut exact_allow_entries: Vec<String> = Vec::with_capacity(allow_rules.len() / 4);
        let mut allow_build = BuildNode::new();

        for (rule, list_idx) in block_rules {
            debug_assert_eq!(rule.action, RuleAction::Block);
            debug_assert!(
                !rule.domain.bytes().any(|b| b.is_ascii_uppercase()),
                "parser must lowercase rule domains; got `{}`",
                rule.domain
            );
            if rule.is_subdomain {
                let labels = reversed_labels(&rule.domain);
                block_build.insert(&labels, list_idx);
            } else {
                exact_block_entries.push((rule.domain, list_idx));
            }
        }

        for rule in allow_rules {
            debug_assert_eq!(rule.action, RuleAction::Allow);
            debug_assert!(
                !rule.domain.bytes().any(|b| b.is_ascii_uppercase()),
                "parser must lowercase rule domains; got `{}`",
                rule.domain
            );
            if rule.is_subdomain {
                let labels = reversed_labels(&rule.domain);
                allow_build.insert(&labels, ALLOW_MARKER);
            } else {
                exact_allow_entries.push(rule.domain);
            }
        }

        // Serialize trees into flat byte buffers and drop the build trees.
        let block_trie = block_build.flatten();
        let allow_trie = allow_build.flatten();

        // Build FST map for exact block (requires sorted, deduplicated input).
        exact_block_entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        exact_block_entries.dedup_by(|(a, _), (b, _)| a == b);
        let exact_block = FstMap::from_iter(
            exact_block_entries
                .iter()
                .map(|(d, idx)| (d.as_str(), *idx as u64)),
        )
        .expect("sorted exact_block");

        // Build FST set for exact allow.
        exact_allow_entries.sort();
        exact_allow_entries.dedup();
        let exact_allow = FstSet::from_iter(exact_allow_entries.iter().map(|d| d.as_str()))
            .expect("sorted exact_allow");

        Self {
            list_names,
            exact_block,
            block_trie,
            exact_allow,
            allow_trie,
        }
    }

    /// Convenience constructor for tests and ad-hoc callers that don't want
    /// to intern list names themselves. Production code on the rebuild path
    /// should call [`FilterEngine::new`] directly to avoid cloning the same
    /// list name once per rule.
    pub fn from_named_rules(
        block_rules: Vec<(ParsedRule, String)>,
        allow_rules: Vec<ParsedRule>,
    ) -> Self {
        let mut list_names: Vec<Box<str>> = Vec::new();
        let mut list_intern: HashMap<String, u16> = HashMap::new();
        let mut indexed = Vec::with_capacity(block_rules.len());
        for (rule, name) in block_rules {
            let idx = *list_intern.entry(name).or_insert_with_key(|k| {
                let i = list_names.len() as u16;
                list_names.push(Box::from(k.as_str()));
                i
            });
            indexed.push((rule, idx));
        }
        Self::new(list_names, indexed, allow_rules)
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
        // Skip the `to_lowercase` allocation when the input is already
        // lowercase — the common case for DNS queries, which normalize
        // case during wire decoding.
        let lower_storage: Option<String> = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            Some(domain.to_lowercase())
        } else {
            None
        };
        let lower: &str = lower_storage.as_deref().unwrap_or(domain);

        // 1. Exact allow
        if self.exact_allow.contains(lower.as_bytes()) {
            return FilterResult::Allowed {
                rule: Some(lower.to_string()),
            };
        }

        // 2. Subdomain allow (trie)
        let labels = reversed_labels(lower);
        if let Some((_marker, depth)) = self.allow_trie.lookup(&labels) {
            return FilterResult::Allowed {
                rule: Some(reconstruct_domain(&labels, depth)),
            };
        }

        // 3. Exact block
        if let Some(list_idx) = self.exact_block.get(lower.as_bytes()) {
            return FilterResult::Blocked {
                rule: lower.to_string(),
                list: self.list_names[list_idx as usize].to_string(),
            };
        }

        // 4. Subdomain block (trie)
        if let Some((list_idx, depth)) = self.block_trie.lookup(&labels) {
            return FilterResult::Blocked {
                rule: reconstruct_domain(&labels, depth),
                list: self.list_names[list_idx as usize].to_string(),
            };
        }

        // 5. Default
        FilterResult::Allowed { rule: None }
    }

    /// Approximate count of blocked domains (exact entries + trie terminals).
    pub fn blocked_domain_count(&self) -> usize {
        self.exact_block.len() + self.block_trie.terminal_count
    }

    /// Estimated heap bytes used by this engine (for diagnostics).
    pub fn heap_bytes(&self) -> usize {
        let block_trie = self.block_trie.nodes.capacity() + self.block_trie.labels.capacity();
        let allow_trie = self.allow_trie.nodes.capacity() + self.allow_trie.labels.capacity();
        let exact_block = self.exact_block.as_fst().as_bytes().len();
        let exact_allow = self.exact_allow.as_fst().as_bytes().len();
        block_trie + allow_trie + exact_block + exact_allow
    }
}
