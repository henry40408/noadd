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
struct BuildNode {
    children: Vec<(Box<str>, BuildNode)>,
    terminal: u16,
}

impl BuildNode {
    fn new() -> Self {
        Self {
            children: Vec::new(),
            terminal: NOT_TERMINAL,
        }
    }

    fn insert(&mut self, labels: &[&str], terminal: u16) {
        let mut node = self;
        for &label in labels {
            let idx = match node
                .children
                .binary_search_by(|(k, _)| k.as_ref().cmp(label))
            {
                Ok(i) => i,
                Err(i) => {
                    node.children
                        .insert(i, (Box::from(label), BuildNode::new()));
                    i
                }
            };
            node = &mut node.children[idx].1;
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

        // Header: terminal_value + child_count
        nodes.extend_from_slice(&node.terminal.to_le_bytes());
        nodes.extend_from_slice(&(node.children.len() as u16).to_le_bytes());

        // Reserve space for child entries (filled after recursive serialization).
        let entries_start = nodes.len();
        nodes.resize(entries_start + CHILD_ENTRY * node.children.len(), 0);

        for (i, (label, child)) in node.children.iter().enumerate() {
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

// SAFETY: all fields are plain data with no interior mutability.
unsafe impl Send for FilterEngine {}
unsafe impl Sync for FilterEngine {}

/// Marker value stored in allow-trie terminals (any value != NOT_TERMINAL).
const ALLOW_MARKER: u16 = 0;

impl FilterEngine {
    /// Build a new engine from parsed rules.
    pub fn new(block_rules: Vec<(ParsedRule, String)>, allow_rules: Vec<ParsedRule>) -> Self {
        // Intern list names: name → index.
        let mut list_names: Vec<Box<str>> = Vec::new();
        let mut list_intern: HashMap<String, u16> = HashMap::new();

        let mut exact_block_entries: Vec<(String, u16)> = Vec::new();
        let mut block_build = BuildNode::new();
        let mut exact_allow_entries: Vec<String> = Vec::new();
        let mut allow_build = BuildNode::new();

        for (rule, list_name) in block_rules {
            debug_assert_eq!(rule.action, RuleAction::Block);
            let domain = rule.domain.to_lowercase();
            let list_idx = *list_intern.entry(list_name).or_insert_with_key(|k| {
                let idx = list_names.len() as u16;
                list_names.push(Box::from(k.as_str()));
                idx
            });
            if rule.is_subdomain {
                let labels = reversed_labels(&domain);
                block_build.insert(&labels, list_idx);
            } else {
                exact_block_entries.push((domain, list_idx));
            }
        }

        for rule in allow_rules {
            debug_assert_eq!(rule.action, RuleAction::Allow);
            let domain = rule.domain.to_lowercase();
            if rule.is_subdomain {
                let labels = reversed_labels(&domain);
                allow_build.insert(&labels, ALLOW_MARKER);
            } else {
                exact_allow_entries.push(domain);
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
        if self.exact_allow.contains(lower.as_bytes()) {
            return FilterResult::Allowed { rule: Some(lower) };
        }

        // 2. Subdomain allow (trie)
        let labels = reversed_labels(&lower);
        if let Some((_marker, depth)) = self.allow_trie.lookup(&labels) {
            return FilterResult::Allowed {
                rule: Some(reconstruct_domain(&labels, depth)),
            };
        }

        // 3. Exact block
        if let Some(list_idx) = self.exact_block.get(lower.as_bytes()) {
            return FilterResult::Blocked {
                rule: lower,
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
