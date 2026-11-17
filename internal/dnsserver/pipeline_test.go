package dnsserver

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/henry40408/noadd/internal/cache"
)

// plainKey is the cache key of a bare query: no EDNS, DO or CD, and upstream
// DNSSEC on by the forwarder's default. A zero Profile would key an entry the
// handler never looks up.
func plainKey(domain string, qtype uint16) cache.Key {
	return cache.Key{Domain: domain, QueryType: qtype, Profile: cache.Profile{UpstreamDNSSECEnabled: true}}
}

func askConcurrently(t *testing.T, handler *testHandler, callers int, names func(i int) string) {
	t.Helper()
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := handler.ask(t, 0xBEEF, names(i), mdns.TypeA)
			if len(unpack(t, response.Bytes).Answer) == 0 {
				t.Errorf("caller %d got no answer", i)
			}
		}()
	}
	wg.Wait()
}

// Rust: coalescing_test.rs test_cold_miss_coalesces_concurrent_queries
func TestColdMissCoalescesConcurrentQueries(t *testing.T) {
	fake := startUpstream(t, 200*time.Millisecond)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})

	askConcurrently(t, handler, 50, func(int) string { return "coalesce-me.example.com." })

	if hits := fake.received.Load(); hits != 1 {
		t.Fatalf("upstream requests = %d, want exactly 1 for 50 concurrent cold misses", hits)
	}
	if pending := handler.inflight.Len(); pending != 0 {
		t.Fatalf("%d keys still in flight", pending)
	}
}

// Rust: test_different_keys_do_not_coalesce
func TestDifferentKeysDoNotCoalesce(t *testing.T) {
	fake := startUpstream(t, 200*time.Millisecond)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	domains := []string{"one.example.com.", "two.example.com.", "three.example.com."}

	askConcurrently(t, handler, len(domains), func(i int) string { return domains[i] })

	if hits := fake.received.Load(); hits != int64(len(domains)) {
		t.Fatalf("upstream requests = %d, want %d", hits, len(domains))
	}
}

// Rust: test_slot_released_after_fetcher_completes
func TestSlotReleasedAfterFetcherCompletes(t *testing.T) {
	fake := startUpstream(t, 50*time.Millisecond)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	handler.ask(t, 1, "slot-release.example.com.", mdns.TypeA)
	if fake.received.Load() != 1 {
		t.Fatalf("upstream requests = %d, want 1", fake.received.Load())
	}

	other := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	other.ask(t, 1, "slot-release.example.com.", mdns.TypeA)
	if fake.received.Load() != 2 {
		t.Fatalf("a fresh handler with an empty cache must still fetch; upstream requests = %d", fake.received.Load())
	}
}

func TestSecondQueryIsServedFromCacheWithItsOwnIDAndAgedTTL(t *testing.T) {
	fake := startUpstream(t, 0)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	first := handler.ask(t, 0x1111, "cached.example.com.", mdns.TypeA)
	second := handler.ask(t, 0x2222, "CACHED.example.com.", mdns.TypeA)

	if fake.received.Load() != 1 {
		t.Fatalf("upstream requests = %d, want 1: the second query is a hit", fake.received.Load())
	}
	if unpack(t, first.Bytes).Id != 0x1111 || unpack(t, second.Bytes).Id != 0x2222 {
		t.Fatal("each client must get its own query ID")
	}
	if first.MinTTL != 60 || second.MinTTL > 60 || second.MinTTL < 59 {
		t.Fatalf("MinTTL first %d (stored TTL), second %d (remaining)", first.MinTTL, second.MinTTL)
	}
	entries := handler.logger.snapshot()
	if len(entries) != 2 || entries[0].Cached || !entries[1].Cached || entries[1].Upstream != nil {
		t.Fatalf("log entries: %+v", entries)
	}
	if entries[0].Upstream == nil || *entries[0].Upstream != fake.addr {
		t.Fatalf("first entry upstream = %v, want %s", entries[0].Upstream, fake.addr)
	}
}

func TestProfilesDoNotShareACacheEntry(t *testing.T) {
	fake := startUpstream(t, 0)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	handler.ask(t, 1, "profiles.example.com.", mdns.TypeA)

	withEDNS := new(mdns.Msg)
	withEDNS.SetQuestion("profiles.example.com.", mdns.TypeA)
	withEDNS.SetEdns0(1232, true)
	wire, _ := withEDNS.Pack()
	if _, err := handler.Handle(context.Background(), Request{Bytes: wire, ClientIP: localhost}); err != nil {
		t.Fatal(err)
	}
	if fake.received.Load() != 2 {
		t.Fatalf("upstream requests = %d, want 2: a DO client must not read a plain client's entry", fake.received.Load())
	}
}

func TestFailedUpstreamIsNotCachedAndWaitersRetryThemselves(t *testing.T) {
	fake := startUpstream(t, 0, answering(func(request *mdns.Msg) *mdns.Msg {
		response := new(mdns.Msg)
		response.SetRcode(request, mdns.RcodeServerFailure)
		return response
	}))
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})

	if _, err := handler.Handle(context.Background(), Request{Bytes: queryBytes(t, 1, "down.example.com.", mdns.TypeA), ClientIP: localhost}); err == nil {
		t.Fatal("an upstream that only answers SERVFAIL should fail the query")
	}
	if handler.cache.Len() != 0 {
		t.Fatal("a failure must not be cached")
	}
	if handler.inflight.Len() != 0 {
		t.Fatal("a failed fetcher left its key in flight")
	}
}

// Rust: stale_stampede_test.rs test_stale_refresh_is_deduplicated
func TestStaleRefreshIsDeduplicated(t *testing.T) {
	fake := startUpstream(t, 200*time.Millisecond)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	domain := "stampede-test.example.com"

	prime := handler.ask(t, 1, domain+".", mdns.TypeA)
	if fake.received.Load() != 1 {
		t.Fatalf("priming made %d upstream requests, want 1", fake.received.Load())
	}
	handler.cache.Put(plainKey(domain, mdns.TypeA), prime.Bytes, time.Millisecond, false)
	time.Sleep(10 * time.Millisecond)
	fake.received.Store(0)

	askConcurrently(t, handler, 50, func(int) string { return domain + "." })
	waitFor(t, "the refresh to reach the upstream", func() bool { return fake.received.Load() > 0 })
	time.Sleep(400 * time.Millisecond)

	if refreshes := fake.received.Load(); refreshes != 1 {
		t.Fatalf("upstream refreshes = %d, want exactly 1 for 50 stale hits", refreshes)
	}
}

// Rust: test_refresh_lock_released_after_completion
func TestRefreshLockReleasedAfterCompletion(t *testing.T) {
	fake := startUpstream(t, 100*time.Millisecond)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	domain := "relock-test.example.com"
	prime := handler.ask(t, 1, domain+".", mdns.TypeA)

	for round := 1; round <= 2; round++ {
		handler.cache.Put(plainKey(domain, mdns.TypeA), prime.Bytes, time.Millisecond, false)
		time.Sleep(10 * time.Millisecond)
		fake.received.Store(0)
		handler.ask(t, 1, domain+".", mdns.TypeA)
		waitFor(t, "the refresh to start", func() bool { return fake.received.Load() == 1 })
		waitFor(t, "the refresh lock to be released", func() bool {
			released := handler.refreshing.TryStart(plainKey(domain, mdns.TypeA))
			if released {
				handler.refreshing.End(plainKey(domain, mdns.TypeA))
			}
			return released
		})
		if refreshes := fake.received.Load(); refreshes != 1 {
			t.Fatalf("round %d: refreshes = %d, want 1", round, refreshes)
		}
	}
}

// Rust: test_different_domains_refresh_independently
func TestDifferentDomainsRefreshIndependently(t *testing.T) {
	fake := startUpstream(t, 300*time.Millisecond)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	domains := []string{"alpha.example.com", "beta.example.com"}
	for _, domain := range domains {
		prime := handler.ask(t, 1, domain+".", mdns.TypeA)
		handler.cache.Put(plainKey(domain, mdns.TypeA), prime.Bytes, time.Millisecond, false)
	}
	time.Sleep(10 * time.Millisecond)
	fake.received.Store(0)

	askConcurrently(t, handler, len(domains), func(i int) string { return domains[i] + "." })
	waitFor(t, "both refreshes", func() bool { return fake.received.Load() == 2 })
}

func TestStaleEntryIsServedWithoutWaitingForTheRefresh(t *testing.T) {
	fake := startUpstream(t, 300*time.Millisecond)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	prime := handler.ask(t, 1, "slow.example.com.", mdns.TypeA)
	handler.cache.Put(plainKey("slow.example.com", mdns.TypeA), prime.Bytes, time.Millisecond, false)
	time.Sleep(10 * time.Millisecond)

	started := time.Now()
	response := handler.ask(t, 2, "slow.example.com.", mdns.TypeA)
	if took := time.Since(started); took > 150*time.Millisecond {
		t.Fatalf("a stale hit took %v: it waited for the refresh", took)
	}
	if response.MinTTL != 0 {
		t.Fatalf("stale MinTTL = %d, want 0", response.MinTTL)
	}
}

func TestCloseEndsABackgroundRefresh(t *testing.T) {
	fake := startUpstream(t, 0, answering(func(*mdns.Msg) *mdns.Msg { return nil })) // never answers
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	handler.cache.Put(plainKey("hang.example.com", mdns.TypeA), unpackable(t, "hang.example.com."), time.Millisecond, false)
	time.Sleep(10 * time.Millisecond)
	handler.ask(t, 1, "hang.example.com.", mdns.TypeA)

	closed := make(chan struct{})
	go func() { handler.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not stop the hung refresh")
	}
}

func unpackable(t *testing.T, name string) []byte {
	t.Helper()
	response := new(mdns.Msg)
	response.SetReply(queryMsg(name))
	response.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60}, A: net.IPv4(1, 2, 3, 4)}}
	wire, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func queryMsg(name string) *mdns.Msg {
	query := new(mdns.Msg)
	query.SetQuestion(name, mdns.TypeA)
	return query
}

// Rust: stale_stampede_test.rs test_non_dnssec_client_gets_ad_stripped_but_log_keeps_verdict
func TestNonDNSSECClientGetsADStrippedButLogKeepsVerdict(t *testing.T) {
	fake := startUpstream(t, time.Millisecond, authenticating)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})

	response := handler.ask(t, 1, "ad-transparency.example.com.", mdns.TypeA)

	if response.Bytes[3]&0x20 != 0 {
		t.Fatal("a client without DO must not receive the AD bit")
	}
	entries := handler.logger.snapshot()
	if len(entries) != 1 || !entries[0].AuthenticatedData {
		t.Fatalf("the query log must keep the upstream's AD verdict: %+v", entries)
	}
}

func TestADIsKeptInTheLogOfACacheHit(t *testing.T) {
	fake := startUpstream(t, 0, authenticating)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	handler.ask(t, 1, "ad-hit.example.com.", mdns.TypeA)
	handler.ask(t, 2, "ad-hit.example.com.", mdns.TypeA)
	entries := handler.logger.snapshot()
	if len(entries) != 2 || !entries[1].Cached || !entries[1].AuthenticatedData {
		t.Fatalf("a cache hit must log the stored AD verdict: %+v", entries)
	}
}

func TestDOClientKeepsADAndOPT(t *testing.T) {
	fake := startUpstream(t, 0, answering(func(request *mdns.Msg) *mdns.Msg {
		response := plainAnswer(request, true)
		response.SetEdns0(1232, true)
		return response
	}))
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	query := new(mdns.Msg)
	query.SetQuestion("do.example.com.", mdns.TypeA)
	query.SetEdns0(1232, true)
	wire, _ := query.Pack()
	response, err := handler.Handle(context.Background(), Request{Bytes: wire, ClientIP: localhost})
	if err != nil {
		t.Fatal(err)
	}
	message := unpack(t, response.Bytes)
	if !message.AuthenticatedData || message.IsEdns0() == nil || !message.IsEdns0().Do() {
		t.Fatalf("a DO client should keep AD and OPT: %+v", message.MsgHdr)
	}
}

// Step 9 pin, seen from the handler: the upstream's OPT never reaches a client
// that sent none.
func TestPlainClientGetsNoOPT(t *testing.T) {
	fake := startUpstream(t, 0, answering(func(request *mdns.Msg) *mdns.Msg {
		response := plainAnswer(request, false)
		response.SetEdns0(1232, true)
		return response
	}))
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	response := handler.ask(t, 1, "plain.example.com.", mdns.TypeA)
	if unpack(t, response.Bytes).IsEdns0() != nil {
		t.Fatal("a client that sent no OPT must not receive one")
	}
	if cached := handler.ask(t, 2, "plain.example.com.", mdns.TypeA); unpack(t, cached.Bytes).IsEdns0() != nil {
		t.Fatal("the cached copy must not carry an OPT either")
	}
}

// Step 9 pin, seen from the handler: UDP TC=1 from upstream is a failure, so
// the client gets SERVFAIL and nothing is cached.
func TestTruncatedUpstreamAnswerBecomesServfailAndIsNotCached(t *testing.T) {
	fake := startUpstream(t, 0, answering(func(request *mdns.Msg) *mdns.Msg {
		response := plainAnswer(request, false)
		response.Truncated = true
		return response
	}))
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	wire := queryBytes(t, 0x4242, "tc.example.com.", mdns.TypeA)

	servfail := handler.respond(context.Background(), Request{Bytes: wire, ClientIP: localhost}, "udp", netipAddrPort())
	message := unpack(t, servfail)
	if message.Rcode != mdns.RcodeServerFailure || message.Id != 0x4242 || message.Truncated {
		t.Fatalf("response = %+v, want SERVFAIL with the client's ID", message.MsgHdr)
	}
	if handler.cache.Len() != 0 {
		t.Fatal("a truncated answer must not be cached")
	}
}

func TestResultSummaryIsOnlyLoggedWhenEnabled(t *testing.T) {
	fake := startUpstream(t, 0)
	for _, enabled := range []bool{false, true} {
		handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr, logResults: enabled})
		handler.ask(t, 1, "result.example.com.", mdns.TypeA)
		result := handler.logger.snapshot()[0].Result
		if !enabled && result != nil {
			t.Fatalf("result = %q with logging off", *result)
		}
		if enabled && (result == nil || *result != "203.0.113.10") {
			t.Fatalf("result = %v, want 203.0.113.10", result)
		}
	}
}

func TestResultSummary(t *testing.T) {
	response := new(mdns.Msg)
	response.SetQuestion("example.com.", mdns.TypeMX)
	response.Response = true
	header := func(rrtype uint16) mdns.RR_Header {
		return mdns.RR_Header{Name: "example.com.", Rrtype: rrtype, Class: mdns.ClassINET, Ttl: 60}
	}
	response.Answer = []mdns.RR{
		&mdns.MX{Hdr: header(mdns.TypeMX), Preference: 10, Mx: "mail.example.com."},
		&mdns.TXT{Hdr: header(mdns.TypeTXT), Txt: []string{"a", "b"}},
		&mdns.SRV{Hdr: header(mdns.TypeSRV), Priority: 1, Weight: 2, Port: 443, Target: "s.example.com."},
		&mdns.A{Hdr: header(mdns.TypeA), A: net.IPv4(1, 1, 1, 1)},
	}
	wire, _ := response.Pack()
	want := "10 mail.example.com., ab, s.example.com.:443 p=1 w=2"
	if got := resultSummary(wire); got != want {
		t.Fatalf("summary = %q, want %q (first three answers only)", got, want)
	}
	empty := new(mdns.Msg)
	emptyWire, _ := empty.Pack()
	if got := resultSummary(emptyWire); got != "" {
		t.Fatalf("empty answer summary = %q", got)
	}
	if got := queryTypeName(65280); got != "Unknown" || queryTypeName(mdns.TypeHTTPS) != "HTTPS" || !strings.HasPrefix(queryTypeName(1), "A") {
		t.Fatal("query type names")
	}
}
