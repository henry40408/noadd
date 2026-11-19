package upstream

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type deadlineResolver struct{ remaining time.Duration }

func (r *deadlineResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	deadline, ok := ctx.Deadline()
	if ok {
		r.remaining = time.Until(deadline)
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}

func TestFirstAddressBoundsTheLookupToTenSeconds(t *testing.T) {
	t.Parallel()
	resolver := &deadlineResolver{}
	forwarder := New(context.Background(), Config{Servers: []string{"127.0.0.1:1"}, Resolver: resolver})
	if _, ok := forwarder.firstAddress(context.Background(), "dns.example:53", "dns.example"); !ok {
		t.Fatal("lookup failed")
	}
	if resolver.remaining < 5*time.Second || resolver.remaining > 10*time.Second {
		t.Fatalf("lookup deadline is %v away, want about 10s", resolver.remaining)
	}
}

func TestWithDefaultsKeepsExplicitTimeouts(t *testing.T) {
	t.Parallel()
	kept := Config{Timeout: 7 * time.Second, MinTimeout: 3 * time.Second}.withDefaults()
	if kept.Timeout != 7*time.Second || kept.MinTimeout != 3*time.Second {
		t.Fatalf("explicit timeouts were replaced: %+v", kept)
	}
	defaulted := Config{}.withDefaults()
	if defaulted.Timeout != DefaultMinTimeout || defaulted.MinTimeout != DefaultMinTimeout {
		t.Fatalf("zero timeouts did not take the defaults: %+v", defaulted)
	}
}

func idleConn(t *testing.T) *dns.Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	return &dns.Conn{Conn: client}
}

func TestTakeIdleExpiresAStreamAtExactlyTheIdleLimit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	exchanger := &tlsExchanger{now: func() time.Time { return now }}
	exchanger.idle = []idleStream{{conn: idleConn(t), since: now.Add(-streamIdleLimit + time.Nanosecond)}}
	if exchanger.takeIdle() == nil {
		t.Fatal("a stream idle for just under the limit must be reused")
	}
	exchanger.idle = []idleStream{{conn: idleConn(t), since: now.Add(-streamIdleLimit)}}
	if exchanger.takeIdle() != nil {
		t.Fatal("a stream idle for exactly the limit must be dropped")
	}
}

func TestPutIdleClosesAStreamBeyondThePoolSize(t *testing.T) {
	t.Parallel()
	exchanger := &tlsExchanger{now: time.Now}
	for range maxIdleStreams {
		exchanger.putIdle(idleConn(t))
	}
	if len(exchanger.idle) != maxIdleStreams {
		t.Fatalf("pool holds %d streams, want %d", len(exchanger.idle), maxIdleStreams)
	}
	extra := idleConn(t)
	exchanger.putIdle(extra)
	if len(exchanger.idle) != maxIdleStreams {
		t.Fatalf("pool grew to %d streams", len(exchanger.idle))
	}
	_ = extra.SetDeadline(time.Now().Add(time.Second))
	if _, err := extra.Write([]byte{0}); err == nil {
		t.Fatal("the surplus stream must be closed")
	}
}

func TestReconfigureClosesTheIdleStreamsOfTheOldSet(t *testing.T) {
	t.Parallel()
	addr, _, trust := fakeDoT(t, okReply("192.0.2.8"))
	_, port, _ := net.SplitHostPort(addr)
	forwarder := newTestForwarder(t, Config{
		Servers:   []string{"tls://example.com:" + port},
		TLSConfig: trust,
		Resolver:  staticResolver{addr: netip.MustParseAddr("127.0.0.1")},
	})
	if _, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	old := forwarder.set.Load().entries[0].exchanger.(*tlsExchanger)
	if len(old.idle) != 1 {
		t.Fatalf("expected one pooled stream, got %d", len(old.idle))
	}
	// An unusable entry leaves a nil slot, which Reconfigure must skip.
	forwarder.Reconfigure(context.Background(), []string{"not an address"})
	if len(old.idle) != 0 {
		t.Fatal("Reconfigure must close the old set's pooled streams")
	}
}

func TestUpdateLatencyIgnoresAnIndexJustPastTheEnd(t *testing.T) {
	t.Parallel()
	forwarder := threeServers(t)
	forwarder.UpdateLatency(3, 5)
	if len(forwarder.Latencies()) != 0 {
		t.Fatal("an out-of-range index must not record anything")
	}
}

func TestForwardAdvancesTheRoundRobinCounterOnlyInThatStrategy(t *testing.T) {
	t.Parallel()
	addr, _ := fakeUDP(t, okReply("192.0.2.1"))
	forwarder := newTestForwarder(t, Config{Servers: []string{addr}})
	query := queryFor("a.example.com.", dns.TypeA)
	if _, err := forwarder.Forward(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if got := forwarder.rrCounter.Load(); got != 0 {
		t.Fatalf("sequential Forward advanced the counter to %d", got)
	}
	forwarder.SetStrategy(RoundRobin)
	if _, err := forwarder.Forward(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if got := forwarder.rrCounter.Load(); got != 1 {
		t.Fatalf("round-robin Forward left the counter at %d, want 1", got)
	}
}

func rootNSReply(request *dns.Msg) *dns.Msg {
	response := rcodeReply(request, dns.RcodeSuccess)
	response.Answer = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "a.root-servers.net."}}
	return response
}

func TestLatencyIsRecordedInMilliseconds(t *testing.T) {
	t.Parallel()
	addr, _ := fakeUDP(t, func(request *dns.Msg) *dns.Msg {
		if request.Question[0].Qtype == dns.TypeNS {
			return rootNSReply(request)
		}
		return answerA(request, "192.0.2.1", 60)
	})
	forwarder := newTestForwarder(t, Config{Servers: []string{addr}})
	if _, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	assertMilliseconds := func(step string) {
		t.Helper()
		got, ok := forwarder.Latencies()[addr]
		if !ok || got < 0 || got > 1000 {
			t.Fatalf("%s: latency = %v (observed %v), want 0..1000 ms", step, got, ok)
		}
	}
	assertMilliseconds("after Forward")
	forwarder.Reconfigure(context.Background(), []string{addr})
	forwarder.ProbeAll(context.Background())
	assertMilliseconds("after ProbeAll")
}

func TestProbeRetriesOnceAfterAFailedAttempt(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	addr, _ := fakeUDP(t, func(request *dns.Msg) *dns.Msg {
		if attempts.Add(1) == 1 {
			return rcodeReply(request, dns.RcodeServerFailure)
		}
		return rootNSReply(request)
	})
	forwarder := newTestForwarder(t, Config{Servers: []string{addr}})
	if results := forwarder.HealthCheck(context.Background()); !results[0].OK {
		t.Fatal("a probe must retry once, so a stale first attempt does not mark the upstream down")
	}
}

func TestProbeStopsAfterTheConfiguredAttempts(t *testing.T) {
	t.Parallel()
	addr, received := fakeUDP(t, func(request *dns.Msg) *dns.Msg { return rcodeReply(request, dns.RcodeServerFailure) })
	forwarder := newTestForwarder(t, Config{Servers: []string{addr}})
	if results := forwarder.HealthCheck(context.Background()); results[0].OK {
		t.Fatal("a failing upstream must not be healthy")
	}
	if got := received.Load(); got != probeAttempts {
		t.Fatalf("probe sent %d queries, want %d", got, probeAttempts)
	}
}

func TestParseSpecRejectsADoHURLWithoutAHost(t *testing.T) {
	t.Parallel()
	if parsed, err := parseSpec("https:///dns-query"); err == nil {
		t.Fatalf("parseSpec = %+v, want an error", parsed)
	}
}

func TestParseSpecBracketedIPv6Hosts(t *testing.T) {
	t.Parallel()
	if got := mustParse(t, "tls://[2001:db8::1]:8853"); got.host != "2001:db8::1" || got.port != 8853 {
		t.Fatalf("with port: %+v", got)
	}
	if got := mustParse(t, "tls://[2001:db8::1]"); got.host != "2001:db8::1" || got.port != defaultTLSPort {
		t.Fatalf("default port: %+v", got)
	}
}
