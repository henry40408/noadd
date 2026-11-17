package dnsserver

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	mdns "github.com/miekg/dns"
)

const blockedDomain = "ads.example.com"

func blockingHandler(t testing.TB) *testHandler {
	return newTestHandler(t, handlerOptions{blocked: []string{blockedDomain}})
}

// Rust: handler_test.rs test_handler_blocks_domain
func TestHandlerBlocksDomain(t *testing.T) {
	response := unpack(t, blockingHandler(t).ask(t, 1234, blockedDomain+".", mdns.TypeA).Bytes)
	if !response.Response || response.Id != 1234 {
		t.Fatalf("response flag/id = %v/%d", response.Response, response.Id)
	}
	if len(response.Answer) == 0 {
		t.Fatal("blocked A should have an answer")
	}
	if got := response.Answer[0].(*mdns.A).A.String(); got != "0.0.0.0" {
		t.Fatalf("blocked A = %s, want 0.0.0.0", got)
	}
}

// Rust: test_handler_blocks_aaaa_domain
func TestHandlerBlocksAAAADomain(t *testing.T) {
	response := unpack(t, blockingHandler(t).ask(t, 1, blockedDomain+".", mdns.TypeAAAA).Bytes)
	if len(response.Answer) == 0 {
		t.Fatal("blocked AAAA should have an answer")
	}
	if got := response.Answer[0].(*mdns.AAAA).AAAA.String(); got != "::" {
		t.Fatalf("blocked AAAA = %s, want ::", got)
	}
}

// Rust: test_handler_forwards_allowed_domain (a local upstream replaces the network)
func TestHandlerForwardsAllowedDomain(t *testing.T) {
	handler := newTestHandler(t, handlerOptions{upstreamAddr: startUpstream(t, 0).addr})
	response := unpack(t, handler.ask(t, 1, "example.com.", mdns.TypeA).Bytes)
	if !response.Response || len(response.Answer) == 0 {
		t.Fatalf("forwarded response = %+v", response)
	}
}

// Rust: test_handler_sends_log_event
func TestHandlerSendsLogEvent(t *testing.T) {
	handler := blockingHandler(t)
	handler.ask(t, 1, blockedDomain+".", mdns.TypeA)

	entries := handler.logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("log entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if !entry.Blocked || entry.Domain != blockedDomain || entry.ClientIP != "127.0.0.1" || entry.QueryType != "A" {
		t.Fatalf("entry = %+v", entry)
	}
	if entry.Cached || entry.Upstream != nil || entry.DohToken != nil || entry.AuthenticatedData {
		t.Fatalf("a blocked entry has no upstream, cache or token: %+v", entry)
	}
}

// Rust: test_handler_returns_refused_when_rate_limit_exhausted
func TestHandlerReturnsRefusedWhenRateLimitExhausted(t *testing.T) {
	// qps=1 burst=1: back-to-back queries are far inside the 1 s refill.
	handler := newTestHandler(t, handlerOptions{blocked: []string{blockedDomain}, limiter: NewLimiter(1, 1)})
	query := queryBytes(t, 1, blockedDomain+".", mdns.TypeA)
	ask := func(ip string) *mdns.Msg {
		response, err := handler.Handle(context.Background(), Request{Bytes: query, ClientIP: netip.MustParseAddr(ip)})
		if err != nil {
			t.Fatal(err)
		}
		return unpack(t, response.Bytes)
	}

	if rcode := ask("10.0.0.1").Rcode; rcode != mdns.RcodeSuccess {
		t.Fatalf("first query rcode = %d, want the block answer", rcode)
	}
	if rcode := ask("10.0.0.1").Rcode; rcode != mdns.RcodeRefused {
		t.Fatalf("second query rcode = %d, want REFUSED", rcode)
	}
	if rcode := ask("10.0.0.2").Rcode; rcode != mdns.RcodeSuccess {
		t.Fatalf("other IP rcode = %d, want its own bucket", rcode)
	}

	var refused int
	for _, entry := range handler.logger.snapshot() {
		if entry.ClientIP == "10.0.0.1" && !entry.Blocked {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("rate-limited log entries = %d, want 1 (not blocked, client 10.0.0.1)", refused)
	}
}

func TestRateLimitedQueryReturnsRefusedWithMinTTLZero(t *testing.T) {
	handler := newTestHandler(t, handlerOptions{blocked: []string{blockedDomain}, limiter: NewLimiter(1, 1)})
	handler.ask(t, 1, blockedDomain+".", mdns.TypeA)
	if ttl := handler.ask(t, 2, blockedDomain+".", mdns.TypeA).MinTTL; ttl != 0 {
		t.Fatalf("REFUSED MinTTL = %d, want 0", ttl)
	}
}

func TestMappedIPv4ClientsShareOneBucket(t *testing.T) {
	handler := newTestHandler(t, handlerOptions{blocked: []string{blockedDomain}, limiter: NewLimiter(1, 1)})
	query := queryBytes(t, 1, blockedDomain+".", mdns.TypeA)
	for _, ip := range []string{"10.0.0.1", "::ffff:10.0.0.1"} {
		if _, err := handler.Handle(context.Background(), Request{Bytes: query, ClientIP: netip.MustParseAddr(ip)}); err != nil {
			t.Fatal(err)
		}
	}
	if tracked := handler.cfg.Limiter.TrackedIPs(); tracked != 1 {
		t.Fatalf("tracked IPs = %d, want 1", tracked)
	}
}

// Rust: test_handler_serves_queries_while_log_channel_is_saturated
func TestHandlerServesQueriesWhileTheLogIsSaturated(t *testing.T) {
	handler := newTestHandler(t, handlerOptions{blocked: []string{blockedDomain}, logCapacity: 1})
	for i := range 20 {
		response := unpack(t, handler.ask(t, uint16(i), blockedDomain+".", mdns.TypeA).Bytes)
		if response.Rcode != mdns.RcodeSuccess {
			t.Fatalf("query %d rcode = %d with a saturated logger", i, response.Rcode)
		}
	}
}

// Rust: test_handler_inflight_limit_serves_all_queries
func TestInflightLimitServesAllQueries(t *testing.T) {
	handler := newTestHandler(t, handlerOptions{blocked: []string{blockedDomain}, maxInflight: 2})
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if response := handler.ask(t, uint16(i), blockedDomain+".", mdns.TypeA); len(unpack(t, response.Bytes).Answer) == 0 {
				t.Errorf("query %d has no answer", i)
			}
		}()
	}
	wg.Wait()
	if len(handler.permits) != 0 {
		t.Fatalf("%d permits still held", len(handler.permits))
	}
}

func TestWaitingForAPermitEndsWithTheContext(t *testing.T) {
	handler := newTestHandler(t, handlerOptions{blocked: []string{blockedDomain}, maxInflight: 1})
	handler.permits <- struct{}{} // the only permit is taken
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := handler.Handle(ctx, Request{Bytes: queryBytes(t, 1, blockedDomain+".", mdns.TypeA), ClientIP: localhost})
	if err == nil {
		t.Fatal("Handle returned no error while waiting for a permit with a cancelled context")
	}
}

// Rust: test_non_query_opcode_returns_notimp (the opcode check fires before the filter)
func TestNonQueryOpcodeReturnsNotimp(t *testing.T) {
	query := new(mdns.Msg)
	query.SetQuestion(blockedDomain+".", mdns.TypeA)
	query.Id = 7
	query.Opcode = mdns.OpcodeStatus
	wire, _ := query.Pack()

	response, err := blockingHandler(t).Handle(context.Background(), Request{Bytes: wire, ClientIP: localhost})
	if err != nil {
		t.Fatal(err)
	}
	message := unpack(t, response.Bytes)
	if message.Rcode != mdns.RcodeNotImplemented || message.Opcode != mdns.OpcodeStatus || message.Id != 7 || !message.Response {
		t.Fatalf("response = %+v", message.MsgHdr)
	}
}

// Rust: test_unsupported_edns_version_returns_badvers
func TestUnsupportedEDNSVersionReturnsBadvers(t *testing.T) {
	query := new(mdns.Msg)
	query.SetQuestion(blockedDomain+".", mdns.TypeA)
	query.Id = 9
	opt := &mdns.OPT{Hdr: mdns.RR_Header{Name: ".", Rrtype: mdns.TypeOPT}}
	opt.SetVersion(1)
	opt.SetUDPSize(1232)
	query.Extra = append(query.Extra, opt)
	wire, _ := query.Pack()

	handler := blockingHandler(t)
	response, err := handler.Handle(context.Background(), Request{Bytes: wire, ClientIP: localhost})
	if err != nil {
		t.Fatal(err)
	}
	message := unpack(t, response.Bytes)
	if message.Rcode != mdns.RcodeBadVers || message.IsEdns0() == nil {
		t.Fatalf("BADVERS response: rcode %d, OPT %v", message.Rcode, message.IsEdns0())
	}
	if len(handler.logger.snapshot()) != 0 {
		t.Fatal("NOTIMP and BADVERS are not logged")
	}
}

func TestQueryWithNoQuestionIsAnError(t *testing.T) {
	wire, _ := new(mdns.Msg).Pack()
	if _, err := blockingHandler(t).Handle(context.Background(), Request{Bytes: wire, ClientIP: localhost}); err != ErrNoQuery {
		t.Fatalf("error = %v, want ErrNoQuery", err)
	}
}

func TestGarbageIsAParseError(t *testing.T) {
	if _, err := blockingHandler(t).Handle(context.Background(), Request{Bytes: []byte{1, 2, 3}, ClientIP: localhost}); err == nil {
		t.Fatal("garbage should not parse")
	}
}

func TestBlockConfigChangeAppliesToTheNextQuery(t *testing.T) {
	handler := blockingHandler(t)
	nx := handler.BlockConfig()
	nx.Mode = "nxdomain"
	handler.SetBlockConfig(nx)
	if rcode := unpack(t, handler.ask(t, 1, blockedDomain+".", mdns.TypeA).Bytes).Rcode; rcode != mdns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN after SetBlockConfig", rcode)
	}
}

func TestBlockedMinTTLMatchesTheWrittenTTL(t *testing.T) {
	response := blockingHandler(t).ask(t, 1, blockedDomain+".", mdns.TypeA)
	if got := unpack(t, response.Bytes).Answer[0].Header().Ttl; got != response.MinTTL {
		t.Fatalf("answer TTL %d != MinTTL %d", got, response.MinTTL)
	}
}

func TestSubdomainOfBlockedDomainIsBlockedWhateverTheCase(t *testing.T) {
	handler := blockingHandler(t)
	if len(unpack(t, handler.ask(t, 1, "WWW.Ads.EXAMPLE.com.", mdns.TypeA).Bytes).Answer) == 0 {
		t.Fatal("mixed-case subdomain was not blocked")
	}
	if entry := handler.logger.snapshot()[0]; entry.Domain != "WWW.Ads.EXAMPLE.com" {
		t.Fatalf("logged domain = %q, want the query's own spelling", entry.Domain)
	}
}
