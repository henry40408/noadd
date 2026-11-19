package filter

import (
	"slices"
	"strings"
	"sync"
)

// CustomListID is the list id of custom rules, which have no filter_lists
// row. Real ids start at 1, so zero cannot collide.
const CustomListID int64 = 0

// ListMeta is a list's name and row id. Block rules refer to it by index.
type ListMeta struct {
	Name string
	ID   int64
}

// BlockRule is a block rule together with the index of its list in
// EngineInput.Lists.
type BlockRule struct {
	Rule    ParsedRule
	ListIdx uint16
}

// EngineInput is everything New needs. Rule domains must already be lower
// case, which ParseLine guarantees; only the query given to Check is folded.
type EngineInput struct {
	Lists []ListMeta
	Block []BlockRule
	Allow []ParsedRule
}

// Verdict is the result of Check. A blocked verdict carries the matching rule
// and the list it came from. An allowed one carries the allow rule, if any.
type Verdict struct {
	Blocked bool
	Rule    string
	List    string
}

// Engine answers filter queries. It is immutable once built; rebuild to change
// the rules.
type Engine struct {
	lists       []ListMeta
	exactBlock  exactSet
	blockTrie   trie
	exactAllow  exactSet
	allowTrie   trie
	uniqueRules []uint32
}

// allowMarker is the value stored in allow-trie terminals.
const allowMarker = 0

// ruleBuckets are the rules split by how they match.
type ruleBuckets struct {
	exactBlock []exactEntry
	subBlock   []trieRule
	exactAllow []exactEntry
	subAllow   []trieRule
}

func splitRules(input EngineInput) ruleBuckets {
	var buckets ruleBuckets
	for _, block := range input.Block {
		rule := block.Rule
		if rule.IsSubdomain {
			if len(rule.Domain) <= maxTrieDomainLen {
				buckets.subBlock = append(buckets.subBlock, newTrieRule(rule.Domain, block.ListIdx, uint32(len(buckets.subBlock))))
			}
			continue
		}
		buckets.exactBlock = append(buckets.exactBlock, exactEntry{domain: rule.Domain, list: block.ListIdx, seq: uint32(len(buckets.exactBlock))})
	}
	for _, rule := range input.Allow {
		if rule.IsSubdomain {
			if len(rule.Domain) <= maxTrieDomainLen {
				buckets.subAllow = append(buckets.subAllow, newTrieRule(rule.Domain, allowMarker, uint32(len(buckets.subAllow))))
			}
			continue
		}
		buckets.exactAllow = append(buckets.exactAllow, exactEntry{domain: rule.Domain, seq: uint32(len(buckets.exactAllow))})
	}
	return buckets
}

// New builds an engine. The four structures touch disjoint data, so they are
// built in parallel and a rebuild costs the slowest one, not the sum.
func New(input EngineInput) *Engine {
	buckets := splitRules(input)
	engine := &Engine{lists: input.Lists, uniqueRules: make([]uint32, len(input.Lists))}

	var wg sync.WaitGroup
	var blockOwners []terminalOwners
	wg.Go(func() {
		builder := &trieBuilder{trackOwners: true, unique: engine.uniqueRules}
		sortTrieRules(buckets.subBlock)
		buildTrie(buckets.subBlock, builder)
		engine.blockTrie, blockOwners = builder.trie, builder.owners
	})
	wg.Go(func() {
		sortTrieRules(buckets.subAllow)
		builder := &trieBuilder{}
		buildTrie(buckets.subAllow, builder)
		engine.allowTrie = builder.trie
	})
	wg.Go(func() {
		sortExactEntries(buckets.exactBlock)
		engine.exactBlock = packExactSet(buckets.exactBlock, true)
	})
	sortExactEntries(buckets.exactAllow)
	engine.exactAllow = packExactSet(buckets.exactAllow, false)
	wg.Wait()

	countUniqueExactRules(engine, buckets.exactBlock, blockOwners)
	return engine
}

// countUniqueExactRules adds the exact rules no other list covers. An exact
// rule is covered by the same domain as an exact rule of another list, or by a
// subdomain rule at or above it. A subdomain rule is never covered by an exact
// one, which is why the two kinds are counted separately.
func countUniqueExactRules(engine *Engine, sortedExact []exactEntry, blockOwners []terminalOwners) {
	for start := 0; start < len(sortedExact); {
		end := start
		var exactOwners uint64
		for end < len(sortedExact) && sortedExact[end].domain == sortedExact[start].domain {
			exactOwners |= listBit(sortedExact[end].list)
			end++
		}
		covering := exactOwners | engine.blockTrie.coveringOwners(sortedExact[start].domain, blockOwners)
		for _, entry := range sortedExact[start:end] {
			if covering&^listBit(entry.list) == 0 {
				engine.uniqueRules[entry.list]++
			}
		}
		start = end
	}
}

// Check decides whether domain is blocked. Priority: allow exact, allow
// subdomain, block exact, block subdomain, else allowed.
func (e *Engine) Check(domain string) Verdict {
	lower := domain
	if hasASCIIUpper(domain) {
		lower = strings.ToLower(domain)
	}
	if _, found := e.exactAllow.find(lower); found {
		return Verdict{Rule: lower}
	}
	if _, start, found := e.allowTrie.lookup(lower); found {
		return Verdict{Rule: lower[start:]}
	}
	if index, found := e.exactBlock.find(lower); found {
		return Verdict{Blocked: true, Rule: lower, List: e.lists[e.exactBlock.lists[index]].Name}
	}
	if list, start, found := e.blockTrie.lookup(lower); found {
		return Verdict{Blocked: true, Rule: lower[start:], List: e.lists[list].Name}
	}
	return Verdict{}
}

func hasASCIIUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

// UniqueRulesByList counts, per filter_lists.id (CustomListID for custom
// rules), the block rules no other list provides. A list missing from the map
// contributed no block rules. Zero means removing that list alone changes
// nothing; two identical lists both report zero.
func (e *Engine) UniqueRulesByList() map[int64]uint32 {
	counts := make(map[int64]uint32, len(e.lists))
	for i, list := range e.lists {
		counts[list.ID] = e.uniqueRules[i]
	}
	return counts
}

// NewFromNamed interns list names in order of first use, for callers that have
// no filter_lists rows. List ids are positional, starting at 1.
func NewFromNamed(block []NamedBlockRule, allow []ParsedRule) *Engine {
	var input EngineInput
	for _, named := range block {
		index := slices.IndexFunc(input.Lists, func(list ListMeta) bool { return list.Name == named.List })
		if index < 0 {
			index = len(input.Lists)
			input.Lists = append(input.Lists, ListMeta{Name: named.List, ID: int64(index) + 1})
		}
		input.Block = append(input.Block, BlockRule{Rule: named.Rule, ListIdx: uint16(index)})
	}
	input.Allow = allow
	return New(input)
}

// NamedBlockRule is a block rule that names its list instead of indexing it.
type NamedBlockRule struct {
	Rule ParsedRule
	List string
}
