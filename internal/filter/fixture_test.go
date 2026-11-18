package filter

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The lists and verdicts in testdata were produced by the released Rust
// image ghcr.io/henry40408/noadd:0.41.1 (see PORTING.txt).
func TestEngineMatchesRustOnFixture(t *testing.T) {
	var input EngineInput
	for i := 1; i <= 3; i++ {
		content, err := os.ReadFile(filepath.Join("testdata", "fixture-list"+string(rune('0'+i))+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		listIdx := uint16(len(input.Lists))
		input.Lists = append(input.Lists, ListMeta{Name: "fx" + string(rune('0'+i)), ID: int64(i)})
		for _, rule := range ParseList(string(content)) {
			if rule.Action == ActionAllow {
				input.Allow = append(input.Allow, rule)
				continue
			}
			input.Block = append(input.Block, BlockRule{Rule: rule, ListIdx: listIdx})
		}
	}
	engine := New(input)

	verdicts, err := os.ReadFile(filepath.Join("testdata", "verdicts.txt"))
	if err != nil {
		t.Fatal(err)
	}
	checked, blocked := 0, 0
	for _, line := range strings.Split(strings.TrimSuffix(string(verdicts), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		domain, action, list, rule := fields[0], fields[1], fields[2], fields[3]
		want := Verdict{Blocked: action == "blocked", Rule: rule, List: list}
		if got := engine.Check(domain); got != want {
			t.Errorf("Check(%q) = %+v, Rust said %+v", domain, got, want)
		}
		checked++
		if want.Blocked {
			blocked++
		}
	}
	if checked < 3000 || blocked < 1000 {
		t.Fatalf("fixture too small: %d checked, %d blocked", checked, blocked)
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
