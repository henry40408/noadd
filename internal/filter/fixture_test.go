package filter

import (
	"sync"
	"sync/atomic"
	"testing"
)

// rustFixtureLists and rustFixtureVerdicts (fixture_data_test.go) were
// produced by the released Rust image ghcr.io/henry40408/noadd:0.41.1 (see
// PORTING.txt).
func TestEngineMatchesRustOnFixture(t *testing.T) {
	var input EngineInput
	for i, content := range rustFixtureLists {
		listIdx := uint16(len(input.Lists))
		input.Lists = append(input.Lists, ListMeta{Name: "fx" + string(rune('1'+i)), ID: int64(i + 1)})
		for _, rule := range ParseList(content) {
			if rule.Action == ActionAllow {
				input.Allow = append(input.Allow, rule)
				continue
			}
			input.Block = append(input.Block, BlockRule{Rule: rule, ListIdx: listIdx})
		}
	}
	engine := New(input)

	var blocked, allowedByRule, allowedWithoutRule int
	for _, rust := range rustFixtureVerdicts {
		want := Verdict{Blocked: rust.blocked, Rule: rust.rule, List: rust.list}
		if got := engine.Check(rust.domain); got != want {
			t.Errorf("Check(%q) = %+v, Rust said %+v", rust.domain, got, want)
		}
		switch {
		case want.Blocked:
			blocked++
		case want.Rule != "":
			allowedByRule++
		default:
			allowedWithoutRule++
		}
	}
	if len(rustFixtureVerdicts) < 280 || blocked < 180 || allowedByRule < 90 || allowedWithoutRule < 6 {
		t.Fatalf("fixture too small: %d checked, %d blocked, %d allowed by a rule, %d allowed without",
			len(rustFixtureVerdicts), blocked, allowedByRule, allowedWithoutRule)
	}
}

// Run with -race: readers must never see a half-built engine.
func TestHolderSwapUnderLoad(t *testing.T) {
	blocking := NewFromNamed([]NamedBlockRule{named(blockRule("ads.example.com", true), "L")}, nil)
	allowing := New(EngineInput{})
	holder := NewHolder(blocking)

	var stop atomic.Bool
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !stop.Load() {
				verdict := holder.Load().Check("sub.ads.example.com")
				if verdict.Blocked && verdict.List != "L" {
					t.Errorf("torn verdict %+v", verdict)
					return
				}
			}
		}()
	}
	for i := range 2000 {
		if i%2 == 0 {
			holder.Swap(allowing)
		} else {
			holder.Swap(blocking)
		}
	}
	stop.Store(true)
	readers.Wait()
	if holder.Swap(blocking) == nil {
		t.Fatal("Swap returned no previous engine")
	}
}
