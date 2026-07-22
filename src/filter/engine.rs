/// Domain filter engine using `HashMap` for exact matches and a flat-serialized
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
/// Layout: `label_offset(u32)` + `label_len(u16)` + `child_node_offset(u32)` = 10.
const CHILD_ENTRY: usize = 10;

// ── Flat trie ───────────────────────────────────────────────────────────

/// Compact trie serialized into two contiguous byte buffers.
///
/// ### Node layout (`nodes` buffer)
///
/// ```text
/// +0  u16  terminal_value   (NOT_TERMINAL if non-terminal)
/// +2  u32  child_count (N)
/// +6  N × ChildEntry
/// ```
///
/// ### `ChildEntry` (10 bytes, sorted by label)
///
/// ```text
/// +0  u32  label_offset     (into `labels`)
/// +4  u16  label_len
/// +6  u32  child_node_offset (into `nodes`)
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
            let child_count = read_u32(&self.nodes, off + 2) as usize;
            let entries = off + 6;

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
                        found_off = Some(read_u32(&self.nodes, e + 6) as usize);
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
        let len = read_u16(&self.nodes, entry_off + 4) as usize;
        &self.labels[lo..lo + len]
    }
}

// ── Flat trie builder ───────────────────────────────────────────────────

/// `FxHash` — the hash rustc uses internally. `SipHash` (the `std` default) is
/// DoS-resistant, which the trie build does not need: keys are DNS labels
/// coming from operator-configured blocklists, never from query traffic, and
/// the map is discarded before any query touches the engine. Over a million
/// label hashes per rebuild, the cheaper mixer is worth the swap.
#[derive(Default)]
struct FxHasher {
    hash: u64,
}

/// Fractional part of the golden ratio, scaled to 64 bits — `FxHash`'s mixer.
const FX_SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

impl FxHasher {
    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(FX_SEED);
    }
}

impl std::hash::Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            self.add(u64::from_le_bytes(
                chunk.try_into().expect("chunks_exact(8) yields 8 bytes"),
            ));
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut buf = [0u8; 8];
            buf[..rem.len()].copy_from_slice(rem);
            self.add(u64::from_le_bytes(buf));
        }
        // Mix the length so trailing zero bytes cannot alias a shorter label.
        self.add(bytes.len() as u64);
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

#[derive(Default, Clone)]
struct FxBuildHasher;

impl std::hash::BuildHasher for FxBuildHasher {
    type Hasher = FxHasher;

    #[inline]
    fn build_hasher(&self) -> FxHasher {
        FxHasher::default()
    }
}

/// Temporary tree node used only during construction, then serialized into
/// a `FlatTrie` and dropped.
///
/// Children live in a `HashMap` so insertion is O(1) — large blocklists
/// concentrate tens of thousands of second-level domains under a single TLD
/// node, and a sorted `Vec` made that the dominant cost of `rebuild_filter`
/// (every `Vec::insert` shifted later siblings). Sorting happens once per
/// node at serialize time instead.
struct BuildNode {
    children: HashMap<Box<str>, BuildNode, FxBuildHasher>,
    terminal: u16,
}

impl BuildNode {
    fn new() -> Self {
        Self {
            children: HashMap::default(),
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

        // Header: terminal_value (u16) + child_count (u32). child_count is u32
        // because a single TLD node can hold well over 65 535 second-level
        // domains on large blocklists; a u16 here silently truncated the count
        // and made `lookup`'s binary search miss children (domains stopped
        // being blocked).
        nodes.extend_from_slice(&node.terminal.to_le_bytes());
        let child_count = u32::try_from(sorted.len()).expect("child count exceeds u32");
        nodes.extend_from_slice(&child_count.to_le_bytes());

        // Reserve space for child entries (filled after recursive serialization).
        let entries_start = nodes.len();
        nodes.resize(entries_start + CHILD_ENTRY * sorted.len(), 0);

        for (i, (label, child)) in sorted.iter().enumerate() {
            let label_offset = labels.len() as u32;
            // u16 (not u8): the rule parser does not bound label length, so an
            // over-long label would otherwise truncate and corrupt lookups.
            let label_len = u16::try_from(label.len()).expect("label length exceeds u16");
            labels.extend_from_slice(label.as_bytes());

            let child_offset = Self::serialize(child, nodes, labels, tc);

            let e = entries_start + i * CHILD_ENTRY;
            nodes[e..e + 4].copy_from_slice(&label_offset.to_le_bytes());
            nodes[e + 4..e + 6].copy_from_slice(&label_len.to_le_bytes());
            nodes[e + 6..e + 10].copy_from_slice(&child_offset.to_le_bytes());
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

/// Marker value stored in allow-trie terminals (any value != `NOT_TERMINAL`).
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
        // Partition first, build second. Splitting exact from subdomain rules
        // is cheap (a move per rule), and it leaves two wholly independent
        // build jobs — the reverse-domain trie and the FST — that can then run
        // on separate threads instead of one after the other.
        let mut exact_block_entries: Vec<(String, u16)> = Vec::with_capacity(block_rules.len() / 4);
        let mut sub_block_rules: Vec<(String, u16)> = Vec::with_capacity(block_rules.len());
        let mut exact_allow_entries: Vec<String> = Vec::with_capacity(allow_rules.len() / 4);
        let mut sub_allow_rules: Vec<String> = Vec::with_capacity(allow_rules.len());

        for (rule, list_idx) in block_rules {
            debug_assert_eq!(rule.action, RuleAction::Block);
            debug_assert!(
                !rule.domain.bytes().any(|b| b.is_ascii_uppercase()),
                "parser must lowercase rule domains; got `{}`",
                rule.domain
            );
            if rule.is_subdomain {
                sub_block_rules.push((rule.domain, list_idx));
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
                sub_allow_rules.push(rule.domain);
            } else {
                exact_allow_entries.push(rule.domain);
            }
        }

        // The trie build and the FST build touch disjoint data, and on a large
        // blocklist they cost roughly the same (tens of ms each). Running them
        // concurrently makes the rebuild cost the slower of the two rather than
        // their sum. `thread::scope` keeps the borrows here and needs no
        // runtime — `new` is already called from a blocking worker.
        let (block_trie, allow_trie, exact_block, exact_allow) = std::thread::scope(|scope| {
            let block_trie_job = scope.spawn(|| {
                let mut build = BuildNode::new();
                for (domain, list_idx) in &sub_block_rules {
                    build.insert(&reversed_labels(domain), *list_idx);
                }
                build.flatten()
            });
            let allow_trie_job = scope.spawn(|| {
                let mut build = BuildNode::new();
                for domain in &sub_allow_rules {
                    build.insert(&reversed_labels(domain), ALLOW_MARKER);
                }
                build.flatten()
            });
            let exact_block_job = scope.spawn(|| {
                // FST construction requires sorted, deduplicated input.
                exact_block_entries.sort_by(|(a, _), (b, _)| a.cmp(b));
                exact_block_entries.dedup_by(|(a, _), (b, _)| a == b);
                FstMap::from_iter(
                    exact_block_entries
                        .iter()
                        .map(|(d, idx)| (d.as_str(), *idx as u64)),
                )
                .expect("sorted exact_block")
            });

            // Smallest job by far (allow lists are orders of magnitude shorter
            // than block lists), so the caller's thread takes it rather than
            // paying to spawn a fourth.
            exact_allow_entries.sort();
            exact_allow_entries.dedup();
            let exact_allow =
                FstSet::from_iter(exact_allow_entries.iter().map(std::string::String::as_str))
                    .expect("sorted exact_allow");

            (
                block_trie_job.join().expect("block trie build panicked"),
                allow_trie_job.join().expect("allow trie build panicked"),
                exact_block_job.join().expect("exact block build panicked"),
                exact_allow,
            )
        });

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

#[cfg(test)]
mod tests {
    use super::*;

    fn block_subdomain(domain: &str) -> ParsedRule {
        ParsedRule {
            domain: domain.to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        }
    }

    /// A single trie node can hold more than `u16::MAX` children on large
    /// blocklists (tens of thousands of second-level domains under one TLD).
    /// Regression: the child count was serialized as `u16`, so it truncated
    /// past 65 535 and `lookup`'s binary search missed children — silently
    /// unblocking domains on exactly the large-list workload the engine targets.
    #[test]
    fn trie_lookup_survives_more_than_u16_children_under_one_node() {
        let n: u32 = 70_000; // > u16::MAX (65 535)
        // Zero-padded so lexicographic (sorted) order matches numeric order;
        // every `d#####` label lands under the shared `com` node.
        let block_rules: Vec<(ParsedRule, String)> = (0..n)
            .map(|i| {
                (
                    block_subdomain(&format!("d{i:05}.com")),
                    "test-list".to_string(),
                )
            })
            .collect();
        let engine = FilterEngine::from_named_rules(block_rules, Vec::new());

        // Domains whose sorted position sits past the old u16 truncation point.
        assert!(
            matches!(engine.check("d69999.com"), FilterResult::Blocked { .. }),
            "child beyond the u16 boundary must still be blocked"
        );
        assert!(matches!(
            engine.check("d65535.com"),
            FilterResult::Blocked { .. }
        ));
        assert!(matches!(
            engine.check("d00000.com"),
            FilterResult::Blocked { .. }
        ));
        // A domain that was never inserted stays allowed.
        assert!(matches!(
            engine.check("d70000.com"),
            FilterResult::Allowed { .. }
        ));
    }

    /// The rule parser does not bound label length, so a label longer than 255
    /// bytes must round-trip. Regression: label length was serialized as `u8`
    /// and truncated (e.g. 300 → 44), corrupting the stored label and breaking
    /// lookup.
    #[test]
    fn trie_lookup_survives_label_longer_than_u8() {
        let long_label = "a".repeat(300);
        let domain = format!("{long_label}.com");
        let engine = FilterEngine::from_named_rules(
            vec![(block_subdomain(&domain), "test-list".to_string())],
            Vec::new(),
        );
        assert!(
            matches!(engine.check(&domain), FilterResult::Blocked { .. }),
            "a >255-byte label must round-trip and still block"
        );
    }
}
