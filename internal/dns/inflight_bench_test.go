package dns

import (
	"fmt"
	"sync/atomic"
	"testing"
)

// BenchmarkInflightContention mirrors inflight_contention_test.rs: many workers
// each begin and finish distinct keys, so only the Group's lock is measured.
func BenchmarkInflightContention(b *testing.B) {
	group := NewGroup[string](0)
	var worker atomic.Int32

	b.RunParallel(func(pb *testing.PB) {
		id := worker.Add(1)
		for i := 0; pb.Next(); i++ {
			fetch, _ := group.Begin(fmt.Sprintf("w%d-q%d.bench.example.com", id, i))
			fetch.Finish()
		}
	})
}
