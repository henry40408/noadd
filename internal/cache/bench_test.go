package cache

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/dns"
)

// threeAnswerResponse mirrors the mock of cache_hit_bench.rs: three A answers,
// so a hit has several TTLs to rewrite.
func threeAnswerResponse(domain string) []byte {
	msg := []byte{0xBE, 0xEF, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0}
	for _, label := range splitLabels(domain) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, 0, 1, 0, 1)
	for _, octet := range []byte{10, 20, 30} {
		msg = append(msg, 0xC0, 0x0C, 0, 1, 0, 1)
		msg = binary.BigEndian.AppendUint32(msg, 300)
		msg = append(msg, 0, 4, 203, 0, 113, octet)
	}
	return msg
}

func splitLabels(domain string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			labels = append(labels, domain[start:i])
			start = i + 1
		}
	}
	return labels
}

// BenchmarkCacheHit is the cache part of the hit path of cache_hit_bench.rs:
// Get, copy and rewrite the TTLs, from many goroutines over 64 keys.
func BenchmarkCacheHit(b *testing.B) {
	cache := New(Config{CapacityBytes: bigCapacity})
	keys := make([]Key, 64)
	for i := range keys {
		domain := fmt.Sprintf("hit-%d.bench.example.com", i)
		keys[i] = Key{Domain: domain, QueryType: 1}
		cache.Put(keys[i], threeAnswerResponse(domain), 300*time.Second, false)
	}

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			entry, state := cache.Get(keys[i%len(keys)])
			if state != Fresh {
				b.Error("a primed key must be fresh")
				return
			}
			served := append([]byte(nil), entry.Bytes...)
			dns.ApplyElapsed(served, entry.TTLOffsets, uint32(entry.Elapsed.Seconds()))
			i++
		}
	})
}

// BenchmarkCacheMemory fills a 5 MiB cache and compares the live heap per entry
// with the Rust weigher's estimate (365 bytes + domain + wire). The Rust bench
// could not be re-run (no cargo); that formula is the value the Rust code was
// calibrated to, and the plan allows 1.5 times it.
func BenchmarkCacheMemory(b *testing.B) {
	const entries = 10_000
	const capacity = 5 << 20

	for range b.N {
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		cache := New(Config{CapacityBytes: capacity})
		stored := 0
		estimate := 0
		for i := range entries {
			domain := fmt.Sprintf("entry-%d.bench.example.com", i)
			response := threeAnswerResponse(domain)
			cache.Put(Key{Domain: domain, QueryType: 1}, response, 300*time.Second, false)
			if i == 0 {
				estimate = int(Weight(Key{Domain: domain}, Entry{Bytes: response, TTLOffsets: dns.TTLOffsets(response)}))
			}
		}
		stored = cache.Len()

		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		perEntry := float64(int64(after.HeapInuse)-int64(before.HeapInuse)) / float64(stored)
		b.ReportMetric(perEntry, "heap-bytes/entry")
		b.ReportMetric(float64(estimate), "rust-weight/entry")
		if perEntry > 1.5*float64(estimate) {
			b.Fatalf("%.0f heap bytes per entry, over 1.5 times the Rust weight %d", perEntry, estimate)
		}
		runtime.KeepAlive(cache)
	}
}
