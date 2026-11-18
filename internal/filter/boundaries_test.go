package filter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEngineKeepsARuleAtTheLongestTrieDomainAndDropsOneByteMore(t *testing.T) {
	t.Parallel()
	atLimit := strings.Repeat("a", maxTrieDomainLen)
	overLimit := strings.Repeat("b", maxTrieDomainLen+1)
	engine := NewFromNamed(
		[]NamedBlockRule{
			named(blockRule(atLimit, true), "list"),
			named(blockRule(overLimit, true), "list"),
		},
		nil,
	)
	wantBlocked(t, engine, atLimit)
	wantAllowed(t, engine, overLimit)

	allowed := NewFromNamed(
		[]NamedBlockRule{named(blockRule(atLimit, true), "list"), named(blockRule(overLimit, true), "list")},
		[]ParsedRule{allowRule(atLimit, true), allowRule(overLimit, true)},
	)
	// The allow rule at the limit is kept, so it overrides the block rule.
	if verdict := allowed.Check(atLimit); verdict.Blocked || verdict.Rule != atLimit {
		t.Fatalf("allow rule at the limit lost: blocked=%v rule length %d", verdict.Blocked, len(verdict.Rule))
	}
	if verdict := allowed.Check(overLimit); verdict.Rule != "" {
		t.Fatalf("an allow rule one byte over the limit was kept: rule length %d", len(verdict.Rule))
	}
}

func TestCheckFoldsAnyASCIIUppercaseLetter(t *testing.T) {
	t.Parallel()
	engine := NewFromNamed([]NamedBlockRule{
		named(blockRule("ads", true), "list"),
		named(blockRule("examplez.com", true), "list"),
		named(blockRule("alpha.com", true), "list"),
	}, nil)
	for _, domain := range []string{"ADS", "Ads", "ads", "exampleZ.com", "EXAMPLEZ.COM", "Alpha.com", "A.alpha.com"} {
		wantBlocked(t, engine, domain)
	}
}

func TestHeapBytesSumsEveryStructure(t *testing.T) {
	t.Parallel()
	engine := NewFromNamed(
		[]NamedBlockRule{
			named(blockRule("sub.example.com", true), "list"),
			named(blockRule("exact.example.com", false), "list"),
		},
		[]ParsedRule{allowRule("allowed.example.com", true), allowRule("allowed-exact.example.com", false)},
	)
	want := engine.blockTrie.heapBytes() + engine.allowTrie.heapBytes() +
		engine.exactBlock.heapBytes() + engine.exactAllow.heapBytes()
	if got := engine.HeapBytes(); got != want || got <= 0 {
		t.Fatalf("HeapBytes = %d, want %d", got, want)
	}
	for name, part := range map[string]int{
		"block trie": engine.blockTrie.heapBytes(), "allow trie": engine.allowTrie.heapBytes(),
		"exact block": engine.exactBlock.heapBytes(), "exact allow": engine.exactAllow.heapBytes(),
	} {
		if part <= 0 {
			t.Errorf("%s reports %d heap bytes", name, part)
		}
	}
}

func TestTrieHeapBytesCountsNodesAndLabels(t *testing.T) {
	t.Parallel()
	engine := NewFromNamed([]NamedBlockRule{named(blockRule("example.com", true), "list")}, nil)
	trie := engine.blockTrie
	if len(trie.nodes) == 0 || len(trie.labels) == 0 {
		t.Fatal("trie is empty")
	}
	if got, want := trie.heapBytes(), cap(trie.nodes)+cap(trie.labels); got != want {
		t.Fatalf("heapBytes = %d, want %d", got, want)
	}
}

func TestPackExactSetKeepsTheFirstOfDuplicatesAndSizesExactly(t *testing.T) {
	t.Parallel()
	entries := []exactEntry{
		{domain: "a.example", list: 1},
		{domain: "a.example", list: 2},
		{domain: "b.example", list: 3},
	}
	set := packExactSet(entries, true)
	if set.len() != 2 {
		t.Fatalf("len = %d, want 2 distinct domains", set.len())
	}
	if index, found := set.find("a.example"); !found || set.lists[index] != 1 {
		t.Fatalf("a.example: index %d, found %v, lists %v", index, found, set.lists)
	}
	const dataBytes = len("a.example") + len("b.example")
	if got, want := set.heapBytes(), dataBytes+4*(2+1)+2*2; got != want {
		t.Fatalf("heapBytes = %d, want %d (capacities are sized from the distinct domains)", got, want)
	}
	withoutLists := packExactSet(entries, false)
	if got, want := withoutLists.heapBytes(), dataBytes+4*(2+1); got != want {
		t.Fatalf("heapBytes without lists = %d, want %d", got, want)
	}
}

func TestNewFromNamedNumbersListsFromOne(t *testing.T) {
	t.Parallel()
	engine := NewFromNamed([]NamedBlockRule{
		named(blockRule("a.example", false), "first"),
		named(blockRule("b.example", false), "second"),
	}, nil)
	counts := engine.UniqueRulesByList()
	if len(counts) != 2 || counts[1] != 1 || counts[2] != 1 {
		t.Fatalf("UniqueRulesByList = %v, want ids 1 and 2", counts)
	}
}

// Enough siblings that the binary search must go left and right of the middle.
func TestTrieFindsEverySiblingLabelAndRejectsGaps(t *testing.T) {
	t.Parallel()
	var rules []NamedBlockRule
	for i := 0; i < 16; i++ {
		rules = append(rules, named(blockRule(fmt.Sprintf("s%02d.example.com", i*2), true), "list"))
	}
	engine := NewFromNamed(rules, nil)
	for i := 0; i < 16; i++ {
		wantBlocked(t, engine, fmt.Sprintf("www.s%02d.example.com", i*2))
		wantAllowed(t, engine, fmt.Sprintf("www.s%02d.example.com", i*2+1))
	}
	wantAllowed(t, engine, "a.example.com")
	wantAllowed(t, engine, "zzz.example.com")
}

func TestCompareFromRightOrdersAncestorsFirst(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want int
	}{
		{"com", "x.com", -1},
		{"x.com", "com", 1},
		{"a.com", "b.com", -1},
		{"b.com", "a.com", 1},
		{"x.a.com", "y.b.com", -1},
		{"a.com", "a.com", 0},
	}
	for _, c := range cases {
		if got := compareFromRight(c.a, c.b); got != c.want {
			t.Errorf("compareFromRight(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// A rule with an empty label ("||.example.com^") is odd input; it must not
// widen into a rule for example.com itself.
func TestARuleWithAnEmptyLabelDoesNotMatchTheDomainBelowIt(t *testing.T) {
	t.Parallel()
	engine := NewFromNamed([]NamedBlockRule{named(blockRule(".example.com", true), "list")}, nil)
	wantAllowed(t, engine, "example.com")
	wantAllowed(t, engine, "www.example.com")
}

func TestAssembleInputGroupsAllCustomRulesIntoOneList(t *testing.T) {
	t.Parallel()
	input, blockCount, allowCount := assembleInput(nil, []string{"||a.example^", "||b.example^"}, []string{"@@||c.example^"})
	if len(input.Lists) != 1 || input.Lists[0].ID != CustomListID {
		t.Fatalf("lists = %+v, want one custom list", input.Lists)
	}
	if blockCount != 2 || allowCount != 1 {
		t.Fatalf("counts = %d block, %d allow", blockCount, allowCount)
	}
	for _, rule := range input.Block {
		if rule.ListIdx != 0 {
			t.Fatalf("custom rule landed on list %d", rule.ListIdx)
		}
	}
}

func TestParseLineAcceptsAHostsLineStartingWithNine(t *testing.T) {
	t.Parallel()
	for _, line := range []string{"9.9.9.9 ads.example.com", "0.0.0.0 ads.example.com", ":: ads.example.com"} {
		rule, ok := ParseLine(line)
		if !ok || rule.Domain != "ads.example.com" || rule.IsSubdomain {
			t.Errorf("ParseLine(%q) = %+v, %v", line, rule, ok)
		}
	}
}

func TestFetchCheckedFailsOnStatus400ButNotOnTheLastSuccessCode(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bad":
			w.WriteHeader(http.StatusBadRequest)
		case "/redirect-target":
			w.WriteHeader(http.StatusAlreadyReported)
		}
		_, _ = w.Write([]byte("body"))
	}))
	t.Cleanup(server.Close)
	downloader := NewDownloader("noadd-test")
	if _, err := downloader.FetchChecked(context.Background(), server.URL+"/bad"); err == nil {
		t.Fatal("status 400 must fail FetchChecked")
	}
	if body, err := downloader.FetchChecked(context.Background(), server.URL+"/redirect-target"); err != nil || body != "body" {
		t.Fatalf("status 208 = %q, %v", body, err)
	}
}

func TestUpdateAllListsNoRebuildReportsWhetherAnyListChanged(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, manager := newManager(t)
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("||ads.example.com^\n"))
	}))
	t.Cleanup(good.Close)
	broken := httptest.NewServer(http.NotFoundHandler())
	brokenURL := broken.URL
	broken.Close()
	for name, url := range map[string]string{"good": good.URL, "broken": brokenURL} {
		if _, err := database.AddFilterList(ctx, name, url, true); err != nil {
			t.Fatal(err)
		}
	}

	changed, err := manager.UpdateAllListsNoRebuild(ctx)
	if err != nil || !changed {
		t.Fatalf("first update: changed=%v err=%v, want a change from the good list", changed, err)
	}
	changed, err = manager.UpdateAllListsNoRebuild(ctx)
	if err != nil || changed {
		t.Fatalf("second update: changed=%v err=%v, want no change", changed, err)
	}
}
