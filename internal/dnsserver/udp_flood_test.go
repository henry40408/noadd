package dnsserver

import (
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

// Behind a slow upstream, a datagram flood must not grow the
// goroutine count past the permits plus the backlog.
func TestUDPFloodBehindASlowUpstreamKeepsGoroutinesBounded(t *testing.T) {
	slow := startUpstream(t, 1500*time.Millisecond)
	const maxInflight = 8
	handler := newTestHandler(t, handlerOptions{upstreamAddr: slow.addr, maxInflight: maxInflight})
	addr, _ := startUDP(t, handler.Handler)
	client, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	before := runtime.NumGoroutine()
	peak := 0
	for i := range 3000 {
		if _, err := client.Write(queryBytes(t, uint16(i), fmt.Sprintf("flood-%d.example.com.", i), 1)); err != nil {
			t.Fatal(err)
		}
		if i%100 == 0 {
			peak = max(peak, runtime.NumGoroutine()-before)
		}
	}
	time.Sleep(200 * time.Millisecond)
	peak = max(peak, runtime.NumGoroutine()-before)
	// Each admitted datagram costs a handler goroutine, plus a bounded few for
	// its upstream attempt.
	if limit := maxInflight*datagramBacklogFactor*4 + 50; peak > limit {
		t.Fatalf("goroutines grew by %d, limit %d", peak, limit)
	}
}
