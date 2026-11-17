package filter

import (
	"cmp"
	"encoding/binary"
	"slices"
	"strings"
)

// notTerminal marks a trie node that ends no rule.
const notTerminal = 0xFFFF

// childEntrySize is the size of one child entry in trie.nodes:
// label offset (u32) + label length (u16) + child node offset (u32).
const childEntrySize = 10

// maxTrieDomainLen keeps every label length inside a u16.
const maxTrieDomainLen = 0xFFFF

// trie is a reverse-domain trie flattened into two byte buffers, so the
// garbage collector scans two pointers however many rules there are.
//
// Node layout in nodes, all little endian:
//
//	+0 u16 terminal value (notTerminal if the node ends no rule)
//	+2 u32 child count
//	+6 child entries sorted by label, childEntrySize bytes each
//
// The root is at offset 0 and its labels live in the labels buffer.
type trie struct {
	nodes     []byte
	labels    []byte
	terminals int
}

// lookup walks the labels of domain from the right and returns the value of
// the first terminal on the way, which is the shortest matching rule. start is
// the index in domain where that rule begins.
func (t *trie) lookup(domain string) (value uint16, start int, found bool) {
	var node uint32
	end := len(domain)
	for {
		start = strings.LastIndexByte(domain[:end], '.') + 1
		child, ok := t.child(node, domain[start:end])
		if !ok {
			return 0, 0, false
		}
		node = child
		if value = t.terminal(node); value != notTerminal {
			return value, start, true
		}
		if start == 0 {
			return 0, 0, false
		}
		end = start - 1
	}
}

func (t *trie) terminal(node uint32) uint16 {
	return binary.LittleEndian.Uint16(t.nodes[node:])
}

// child binary-searches the children of node for label.
func (t *trie) child(node uint32, label string) (uint32, bool) {
	count := int(binary.LittleEndian.Uint32(t.nodes[node+2:]))
	entries := t.nodes[node+6:]
	low, high := 0, count
	for low < high {
		mid := int(uint(low+high) >> 1)
		entry := entries[mid*childEntrySize:]
		labelStart := binary.LittleEndian.Uint32(entry)
		labelEnd := labelStart + uint32(binary.LittleEndian.Uint16(entry[4:]))
		stored := t.labels[labelStart:labelEnd]
		switch {
		case string(stored) == label:
			return binary.LittleEndian.Uint32(entry[6:]), true
		case string(stored) < label:
			low = mid + 1
		default:
			high = mid
		}
	}
	return 0, false
}

func (t *trie) heapBytes() int { return cap(t.nodes) + cap(t.labels) }

// trieRule is one rule to insert. end is the length of the part of domain that
// the builder has not consumed yet.
type trieRule struct {
	domain string
	value  uint16
	seq    uint32
	end    int32
}

func newTrieRule(domain string, value uint16, seq uint32) trieRule {
	return trieRule{domain: domain, value: value, seq: seq, end: int32(len(domain))}
}

// compareFromRight orders domains label by label starting at the right, with
// an ancestor before its subdomains. That is the order of a pre-order walk
// over the trie, so each node's rules form one contiguous run.
func compareFromRight(a, b string) int {
	endA, endB := len(a), len(b)
	for endA >= 0 && endB >= 0 {
		startA := strings.LastIndexByte(a[:endA], '.') + 1
		startB := strings.LastIndexByte(b[:endB], '.') + 1
		if c := strings.Compare(a[startA:endA], b[startB:endB]); c != 0 {
			return c
		}
		endA, endB = startA-1, startB-1
	}
	return cmp.Compare(endA, endB)
}

func sortTrieRules(rules []trieRule) {
	slices.SortFunc(rules, func(a, b trieRule) int {
		if c := compareFromRight(a.domain, b.domain); c != 0 {
			return c
		}
		return cmp.Compare(a.seq, b.seq)
	})
}

// terminalOwners records which lists hold a rule at one terminal node. The
// builder visits nodes in offset order, so a slice of these is sorted.
type terminalOwners struct {
	node uint32
	mask uint64
}

// labelGroup is a run of rules that share the next label.
type labelGroup struct {
	label  string
	lo, hi int
}

// trieBuilder writes the flat layout straight from rules sorted by
// sortTrieRules, without building a tree of maps first.
type trieBuilder struct {
	trie   trie
	groups []labelGroup
	// owners is filled only when trackOwners is set.
	trackOwners bool
	owners      []terminalOwners
	// unique, when not nil, counts per list the rules no other list covers.
	unique []uint32
}

func buildTrie(sortedRules []trieRule, builder *trieBuilder) {
	builder.writeNode(sortedRules, 0)
	builder.trie.nodes = slices.Clip(builder.trie.nodes)
	builder.trie.labels = slices.Clip(builder.trie.labels)
}

// writeNode writes the node for rules (all rules whose consumed labels match)
// and returns its offset. ancestors is the owner mask of the terminals above.
func (b *trieBuilder) writeNode(rules []trieRule, ancestors uint64) uint32 {
	offset := uint32(len(b.trie.nodes))

	terminal := uint16(notTerminal)
	var own uint64
	consumed := 0
	for consumed < len(rules) && rules[consumed].end < 0 {
		terminal = rules[consumed].value
		own |= listBit(terminal)
		consumed++
	}
	if consumed > 0 {
		b.trie.terminals++
		b.recordTerminal(offset, rules[:consumed], ancestors|own)
	}

	base := len(b.groups)
	b.groupByNextLabel(rules[consumed:], consumed, base)
	groups := b.groups[base:len(b.groups)]

	b.trie.nodes = binary.LittleEndian.AppendUint16(b.trie.nodes, terminal)
	b.trie.nodes = binary.LittleEndian.AppendUint32(b.trie.nodes, uint32(len(groups)))
	entriesStart := len(b.trie.nodes)
	b.trie.nodes = append(b.trie.nodes, make([]byte, childEntrySize*len(groups))...)

	for i, group := range groups {
		labelOffset := uint32(len(b.trie.labels))
		b.trie.labels = append(b.trie.labels, group.label...)
		child := b.writeNode(rules[group.lo:group.hi], ancestors|own)
		entry := b.trie.nodes[entriesStart+i*childEntrySize:]
		binary.LittleEndian.PutUint32(entry, labelOffset)
		binary.LittleEndian.PutUint16(entry[4:], uint16(len(group.label)))
		binary.LittleEndian.PutUint32(entry[6:], child)
	}
	b.groups = b.groups[:base]
	return offset
}

// groupByNextLabel consumes the last label of each rule and appends one group
// per distinct label. lo and hi are relative to the first rule of the node, so
// offset is how many rules the caller skipped. Groups before base belong to
// the callers up the stack.
func (b *trieBuilder) groupByNextLabel(rules []trieRule, offset, base int) {
	for i := range rules {
		rule := &rules[i]
		start := int32(strings.LastIndexByte(rule.domain[:rule.end], '.') + 1)
		label := rule.domain[start:rule.end]
		rule.end = start - 1
		last := len(b.groups) - 1
		if last >= base && b.groups[last].label == label {
			b.groups[last].hi++
			continue
		}
		b.groups = append(b.groups, labelGroup{label: label, lo: offset + i, hi: offset + i + 1})
	}
}

// recordTerminal feeds the unique-rule count and the owner index.
func (b *trieBuilder) recordTerminal(node uint32, terminalRules []trieRule, covering uint64) {
	if b.trackOwners {
		var own uint64
		for _, rule := range terminalRules {
			own |= listBit(rule.value)
		}
		b.owners = append(b.owners, terminalOwners{node: node, mask: own})
	}
	if b.unique == nil {
		return
	}
	for _, rule := range terminalRules {
		if covering&^listBit(rule.value) == 0 {
			b.unique[rule.value]++
		}
	}
}

// coveringOwners returns the lists holding a rule at domain or at any parent
// of it. owners must come from the builder that produced t.
func (t *trie) coveringOwners(domain string, owners []terminalOwners) uint64 {
	var mask uint64
	var node uint32
	end := len(domain)
	for {
		start := strings.LastIndexByte(domain[:end], '.') + 1
		child, ok := t.child(node, domain[start:end])
		if !ok {
			return mask
		}
		node = child
		if t.terminal(node) != notTerminal {
			mask |= ownersAt(owners, node)
		}
		if start == 0 {
			return mask
		}
		end = start - 1
	}
}

func ownersAt(owners []terminalOwners, node uint32) uint64 {
	index, found := slices.BinarySearchFunc(owners, node, func(entry terminalOwners, target uint32) int {
		return cmp.Compare(entry.node, target)
	})
	if !found {
		return 0
	}
	return owners[index].mask
}

// listBit identifies a list inside a coverage mask. Indexes past 63 share the
// top bit, so a rule shared only among such lists reads as unique, which
// over-reports impact (the safe direction).
func listBit(index uint16) uint64 {
	return 1 << min(index, 63)
}
