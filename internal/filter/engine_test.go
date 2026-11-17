package filter

import (
	"fmt"
	"maps"
	"strings"
	"testing"
)

func blockRule(domain string, isSubdomain bool) ParsedRule {
	return ParsedRule{Domain: domain, Action: ActionBlock, IsSubdomain: isSubdomain}
}

func allowRule(domain string, isSubdomain bool) ParsedRule {
	return ParsedRule{Domain: domain, Action: ActionAllow, IsSubdomain: isSubdomain}
}

func named(rule ParsedRule, list string) NamedBlockRule {
	return NamedBlockRule{Rule: rule, List: list}
}

func wantBlocked(t *testing.T, engine *Engine, domain string) {
	t.Helper()
	if verdict := engine.Check(domain); !verdict.Blocked {
		t.Errorf("Check(%q) = %+v, want blocked", domain, verdict)
	}
}

func wantAllowed(t *testing.T, engine *Engine, domain string) {
	t.Helper()
	if verdict := engine.Check(domain); verdict.Blocked {
		t.Errorf("Check(%q) = %+v, want allowed", domain, verdict)
	}
}

func wantVerdict(t *testing.T, engine *Engine, domain string, want Verdict) {
	t.Helper()
	if got := engine.Check(domain); got != want {
		t.Errorf("Check(%q) = %+v, want %+v", domain, got, want)
	}
}

// Rust: test_exact_block
func TestExactBlock(t *testing.T) {
	engine := NewFromNamed([]NamedBlockRule{named(blockRule("ads.example.com", false), "list1")}, nil)
	wantBlocked(t, engine, "ads.example.com")
	// An exact-only rule must not match subdomains.
	wantAllowed(t, engine, "sub.ads.example.com")
	wantAllowed(t, engine, "example.com")
}

// Rust: test_subdomain_block
func TestSubdomainBlock(t *testing.T) {
	engine := NewFromNamed([]NamedBlockRule{named(blockRule("ads.example.com", true), "list1")}, nil)
	wantBlocked(t, engine, "ads.example.com")
	wantBlocked(t, engine, "sub.ads.example.com")
	// The parent must not be blocked.
	wantAllowed(t, engine, "example.com")
}

// Rust: test_allowed_domain
func TestAllowedDomain(t *testing.T) {
	engine := New(EngineInput{})
	wantAllowed(t, engine, "anything.com")
	wantAllowed(t, engine, "safe.example.com")
}

// Rust: test_allowlist_overrides_blocklist
func TestAllowlistOverridesBlocklist(t *testing.T) {
	engine := NewFromNamed(
		[]NamedBlockRule{named(blockRule("ads.example.com", true), "blocklist")},
		[]ParsedRule{allowRule("ads.example.com", true)},
	)
	wantAllowed(t, engine, "ads.example.com")
	wantAllowed(t, engine, "sub.ads.example.com")
}

// Rust: test_provenance_tracking
func TestProvenanceTracking(t *testing.T) {
	engine := NewFromNamed([]NamedBlockRule{
		named(blockRule("tracker.net", false), "easylist"),
		named(blockRule("ads.example.com", true), "adguard"),
	}, nil)
	wantVerdict(t, engine, "tracker.net", Verdict{Blocked: true, Rule: "tracker.net", List: "easylist"})
	wantVerdict(t, engine, "sub.ads.example.com", Verdict{Blocked: true, Rule: "ads.example.com", List: "adguard"})
}

// Rust: test_empty_engine_allows_everything
func TestEmptyEngineAllowsEverything(t *testing.T) {
	engine := New(EngineInput{})
	wantAllowed(t, engine, "anything.example.com")
	wantAllowed(t, engine, "a.b.c.d.e.f.g")
	if got := engine.BlockedDomainCount(); got != 0 {
		t.Errorf("BlockedDomainCount = %d, want 0", got)
	}
}

// Rust: new_with_pre_interned_list_names_resolves_provenance
func TestNewWithPreInternedListNamesResolvesProvenance(t *testing.T) {
	engine := New(EngineInput{
		Lists: []ListMeta{{Name: "easylist", ID: 1}, {Name: "adguard", ID: 2}},
		Block: []BlockRule{
			{Rule: blockRule("tracker.net", false), ListIdx: 0},
			{Rule: blockRule("ads.example.com", true), ListIdx: 1},
		},
	})
	wantVerdict(t, engine, "tracker.net", Verdict{Blocked: true, Rule: "tracker.net", List: "easylist"})
	wantVerdict(t, engine, "sub.ads.example.com", Verdict{Blocked: true, Rule: "ads.example.com", List: "adguard"})
}

// Rust: build_is_insertion_order_independent
func TestBuildIsInsertionOrderIndependent(t *testing.T) {
	rulesA := []BlockRule{
		{Rule: blockRule("tracker.net", false)},
		{Rule: blockRule("b.example.com", true)},
		{Rule: blockRule("ads.example.com", true)},
		{Rule: blockRule("a.example.com", true)},
		{Rule: blockRule("zzz.example.com", true)},
	}
	rulesB := make([]BlockRule, len(rulesA))
	for i, rule := range rulesA {
		rulesB[len(rulesA)-1-i] = rule
	}
	lists := []ListMeta{{Name: "L", ID: 1}}
	engineA := New(EngineInput{Lists: lists, Block: rulesA})
	engineB := New(EngineInput{Lists: lists, Block: rulesB})
	for _, query := range []string{
		"a.example.com", "deep.b.example.com", "ads.example.com",
		"tracker.net", "unrelated.org", "zzz.example.com",
	} {
		if a, b := engineA.Check(query), engineB.Check(query); a != b {
			t.Errorf("order independence broken for %q: %+v vs %+v", query, a, b)
		}
	}
}

// Rust: lowercases_uppercase_query_against_lowercased_rules
func TestLowercasesUppercaseQuery(t *testing.T) {
	engine := NewFromNamed([]NamedBlockRule{named(blockRule("ads.example.com", true), "L")}, nil)
	wantBlocked(t, engine, "ADS.Example.COM")
	wantBlocked(t, engine, "Sub.ADS.example.com")
}

func uniqueEngine(rules ...struct {
	rule ParsedRule
	id   int64
}) map[int64]uint32 {
	var input EngineInput
	for _, entry := range rules {
		index := -1
		for i, list := range input.Lists {
			if list.ID == entry.id {
				index = i
			}
		}
		if index < 0 {
			index = len(input.Lists)
			input.Lists = append(input.Lists, ListMeta{Name: fmt.Sprintf("list-%d", entry.id), ID: entry.id})
		}
		input.Block = append(input.Block, BlockRule{Rule: entry.rule, ListIdx: uint16(index)})
	}
	return New(input).UniqueRulesByList()
}

type idRule = struct {
	rule ParsedRule
	id   int64
}

func wantUnique(t *testing.T, got, want map[int64]uint32) {
	t.Helper()
	if !maps.Equal(got, want) {
		t.Errorf("UniqueRulesByList = %v, want %v", got, want)
	}
}

// Rust: a_lists_own_rules_are_all_unique_when_it_is_the_only_list
func TestOwnRulesAreUniqueWhenOnlyList(t *testing.T) {
	got := uniqueEngine(idRule{blockRule("ads.example", true), 1}, idRule{blockRule("tracker.example", false), 1})
	wantUnique(t, got, map[int64]uint32{1: 2})
}

// Rust: a_rule_two_lists_both_hold_is_unique_to_neither
func TestSharedRuleIsUniqueToNeither(t *testing.T) {
	got := uniqueEngine(idRule{blockRule("ads.example", true), 1}, idRule{blockRule("ads.example", true), 2})
	wantUnique(t, got, map[int64]uint32{1: 0, 2: 0})
}

// Rust: a_broader_subdomain_rule_covers_a_narrower_rule_in_another_list
func TestBroaderSubdomainRuleCoversNarrowerRule(t *testing.T) {
	got := uniqueEngine(
		idRule{blockRule("example", true), 1},
		idRule{blockRule("ads.example", true), 2},
		idRule{blockRule("deep.ads.example", false), 2},
	)
	wantUnique(t, got, map[int64]uint32{1: 1, 2: 0})
}

// Rust: an_exact_rule_elsewhere_does_not_cover_a_subdomain_rule
func TestExactRuleElsewhereDoesNotCoverSubdomainRule(t *testing.T) {
	got := uniqueEngine(idRule{blockRule("ads.example", false), 1}, idRule{blockRule("ads.example", true), 2})
	wantUnique(t, got, map[int64]uint32{1: 0, 2: 1})
}

// Rust: a_parent_subdomain_rule_covers_an_exact_rule_in_another_list
func TestParentSubdomainRuleCoversExactRule(t *testing.T) {
	got := uniqueEngine(idRule{blockRule("example", true), 1}, idRule{blockRule("ads.example", false), 2})
	wantUnique(t, got, map[int64]uint32{1: 1, 2: 0})
}

// Rust: a_sibling_domain_does_not_cover_anything
func TestSiblingDomainDoesNotCoverAnything(t *testing.T) {
	got := uniqueEngine(
		idRule{blockRule("ads.example", true), 1},
		idRule{blockRule("cdn.example", true), 2},
		// Ends with "ads.example" but is not under it.
		idRule{blockRule("notads.example", true), 2},
	)
	wantUnique(t, got, map[int64]uint32{1: 1, 2: 2})
}

// Rust: custom_rules_take_part_in_the_comparison
func TestCustomRulesTakePartInTheComparison(t *testing.T) {
	got := uniqueEngine(idRule{blockRule("ads.example", true), CustomListID}, idRule{blockRule("ads.example", true), 3})
	wantUnique(t, got, map[int64]uint32{CustomListID: 0, 3: 0})
}

// Rust: trie_lookup_survives_more_than_u16_children_under_one_node
func TestTrieLookupSurvivesMoreThanU16Children(t *testing.T) {
	const count = 70_000 // above 65 535
	block := make([]NamedBlockRule, count)
	for i := range block {
		block[i] = named(blockRule(fmt.Sprintf("d%05d.com", i), true), "test-list")
	}
	engine := NewFromNamed(block, nil)
	wantBlocked(t, engine, "d69999.com")
	wantBlocked(t, engine, "d65535.com")
	wantBlocked(t, engine, "d00000.com")
	wantAllowed(t, engine, "d70000.com")
}

// Rust: trie_lookup_survives_label_longer_than_u8
func TestTrieLookupSurvivesLabelLongerThanU8(t *testing.T) {
	domain := strings.Repeat("a", 300) + ".com"
	engine := NewFromNamed([]NamedBlockRule{named(blockRule(domain, true), "test-list")}, nil)
	wantBlocked(t, engine, domain)
}

// Not in Rust: pin the duplicate and priority rules the Opus review asks about.
func TestDuplicateRulesResolveLikeRust(t *testing.T) {
	engine := NewFromNamed([]NamedBlockRule{
		named(blockRule("exact.example", false), "first"),
		named(blockRule("exact.example", false), "second"),
		named(blockRule("sub.example", true), "first"),
		named(blockRule("sub.example", true), "second"),
		named(blockRule("example", true), "parent"),
	}, nil)
	// The exact set is checked before the trie, so it wins even over a parent rule.
	wantVerdict(t, engine, "exact.example", Verdict{Blocked: true, Rule: "exact.example", List: "first"})
	// In the trie the shortest matching rule wins.
	wantVerdict(t, engine, "x.sub.example", Verdict{Blocked: true, Rule: "example", List: "parent"})

	engine = NewFromNamed([]NamedBlockRule{
		named(blockRule("exact.example", false), "first"),
		named(blockRule("exact.example", false), "second"),
		named(blockRule("sub.example", true), "first"),
		named(blockRule("sub.example", true), "second"),
	}, nil)
	wantVerdict(t, engine, "exact.example", Verdict{Blocked: true, Rule: "exact.example", List: "first"})
	wantVerdict(t, engine, "x.sub.example", Verdict{Blocked: true, Rule: "sub.example", List: "second"})
	if got := engine.BlockedDomainCount(); got != 2 {
		t.Errorf("BlockedDomainCount = %d, want 2", got)
	}
}

func TestMoreThan64ListsShareTheTopBit(t *testing.T) {
	var input EngineInput
	for i := range 70 {
		input.Lists = append(input.Lists, ListMeta{Name: fmt.Sprintf("l%d", i), ID: int64(i + 1)})
	}
	input.Block = []BlockRule{
		{Rule: blockRule("a.example", true), ListIdx: 65},
		{Rule: blockRule("a.example", true), ListIdx: 66},
		{Rule: blockRule("b.example", true), ListIdx: 2},
		{Rule: blockRule("b.example", true), ListIdx: 3},
	}
	unique := New(input).UniqueRulesByList()
	// Lists past 63 read as unique to each other; lists below keep exact bits.
	if unique[66] != 1 || unique[67] != 1 || unique[3] != 0 || unique[4] != 0 {
		t.Errorf("unique = %v", unique)
	}
}
