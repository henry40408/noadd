package filter

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// benchListSHA256 pins the generated list to the one the Rust baseline in
// PORTING.txt was measured with.
const benchListSHA256 = "65b6e790a07311c45529a6ee6ba835322c59f5b0aae0b6e08dd36ebb738ec735"

func benchListLine(i int) string {
	switch i % 4 {
	case 0:
		return fmt.Sprintf("0.0.0.0 host%d.bench%d.example", i, i%977)
	case 1:
		return fmt.Sprintf("||ads%d.cdn%d.test^", i, i%503)
	case 2:
		return fmt.Sprintf("tracker%d.example.org", i)
	}
	if i%40 == 3 {
		return fmt.Sprintf("@@||ok%d.bench.test^", i)
	}
	return fmt.Sprintf("||beacon%d.bench.test^", i)
}

func benchListText(tb testing.TB) string {
	var text strings.Builder
	for i := range 1_200_000 {
		text.WriteString(benchListLine(i))
		text.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(text.String()))
	if got := hex.EncodeToString(sum[:]); got != benchListSHA256 {
		tb.Fatalf("bench list sha256 = %s, want %s", got, benchListSHA256)
	}
	return text.String()
}

// buildFromListText is the rebuild path: parse one list, then build.
func buildFromListText(text string) *Engine {
	input := EngineInput{Lists: []ListMeta{{Name: "bench", ID: 1}}}
	for _, rule := range ParseList(text) {
		if rule.Action == ActionAllow {
			input.Allow = append(input.Allow, rule)
			continue
		}
		input.Block = append(input.Block, BlockRule{Rule: rule})
	}
	return New(input)
}

func BenchmarkEngineBuild1M2(b *testing.B) {
	text := benchListText(b)
	b.ResetTimer()
	for range b.N {
		buildFromListText(text)
	}
}

func BenchmarkEngineCheck(b *testing.B) {
	engine := buildFromListText(benchListText(b))
	queries := map[string][]string{
		"exact-block":  {"host4.bench4.example", "tracker10.example.org", "host1000.bench23.example"},
		"subdomain":    {"x.ads1.cdn1.test", "deep.a.b.beacon7.bench.test", "www.beacon99999.bench.test"},
		"allow":        {"ok3.bench.test", "sub.ok43.bench.test", "ok83.bench.test"},
		"miss":         {"clean1.example.net", "unlisted.example.com", "www.google.com"},
		"deep-miss":    {"a.b.c.d.e.f.g.h.example.net", "a.b.c.d.e.f.g.h.bench.test"},
		"upper-subdom": {"X.ADS1.CDN1.TEST", "Host4.Bench4.Example"},
	}
	for name, domains := range queries {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := range b.N {
				engine.Check(domains[i%len(domains)])
			}
		})
	}
}

// BenchmarkHeap reports the heap the engine keeps once the list text and the
// parsed rules are garbage. The Rust baseline's "+75 MiB" also counts the
// list text its process still held, so this is the lower bound of that.
func BenchmarkHeap(b *testing.B) {
	for range b.N {
		before := heapInUse()
		engine := buildFromListText(benchListText(b))
		after := heapInUse()
		b.ReportMetric(float64(int64(after)-int64(before))/(1<<20), "MiB-retained")
		b.ReportMetric(float64(engine.HeapBytes())/(1<<20), "MiB-engine")
		runtime.KeepAlive(engine)
	}
}

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}
