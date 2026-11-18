package upstream

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func okReply(ip string) reply {
	return func(request *dns.Msg) *dns.Msg { return answerA(request, ip, 300) }
}

func unpack(t *testing.T, wire []byte) *dns.Msg {
	t.Helper()
	response := new(dns.Msg)
	if err := response.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	return response
}

func firstA(t *testing.T, response *dns.Msg) string {
	t.Helper()
	if len(response.Answer) == 0 {
		t.Fatalf("no answer: %v", response)
	}
	a, ok := response.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("not an A record: %v", response.Answer[0])
	}
	return a.A.String()
}

func TestForwardUDPRestoresClientID(t *testing.T) {
	addr, _ := fakeUDP(t, okReply("192.0.2.1"))
	forwarder := newTestForwarder(t, Config{Servers: []string{addr}})

	result, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	response := unpack(t, result.Bytes)
	if response.Id != 0x1234 || firstA(t, response) != "192.0.2.1" || result.Upstream != addr {
		t.Fatalf("id %#x, result %+v", response.Id, result)
	}
}

func TestForwardRejectsMalformedQuery(t *testing.T) {
	forwarder := newTestForwarder(t, Config{Servers: []string{closedUDPAddr(t)}})
	if _, err := forwarder.Forward(context.Background(), []byte{1, 2, 3}); !errors.Is(err, ErrBadQuery) {
		t.Fatalf("err = %v", err)
	}
}

// Wire fixtures 062-065: an upstream SERVFAIL or REFUSED is a failure, so the
// next upstream gets the query.
func TestForwardFailsOverOnServfailAndRefused(t *testing.T) {
	for name, rcode := range map[string]int{"servfail": dns.RcodeServerFailure, "refused": dns.RcodeRefused} {
		t.Run(name, func(t *testing.T) {
			bad, badCount := fakeUDP(t, func(r *dns.Msg) *dns.Msg { return rcodeReply(r, rcode) })
			good, _ := fakeUDP(t, okReply("192.0.2.2"))
			forwarder := newTestForwarder(t, Config{Servers: []string{bad, good}})

			result, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA))
			if err != nil {
				t.Fatal(err)
			}
			if result.Upstream != good || badCount.Load() == 0 || firstA(t, unpack(t, result.Bytes)) != "192.0.2.2" {
				t.Fatalf("result %+v, bad upstream hits %d", result, badCount.Load())
			}
		})
	}
}

// Wire fixture 084: UDP TC=1 is a failure (the Rust pool had no TCP retry), so
// with no other upstream the caller gets ErrAllFailed, which the handler turns
// into SERVFAIL.
func TestForwardTruncatedUDPIsAFailure(t *testing.T) {
	truncated, hits := fakeUDP(t, func(r *dns.Msg) *dns.Msg {
		response := answerA(r, "192.0.2.3", 300)
		response.Truncated = true
		return response
	})
	forwarder := newTestForwarder(t, Config{Servers: []string{truncated}})

	_, err := forwarder.Forward(context.Background(), queryFor("big.example.com.", dns.TypeA))

	if !errors.Is(err, ErrAllFailed) {
		t.Fatalf("err = %v, want ErrAllFailed", err)
	}
	if hits.Load() == 0 {
		t.Fatal("the upstream was never asked")
	}
}

func TestForwardTruncatedUDPFallsOverToNextUpstream(t *testing.T) {
	truncated, _ := fakeUDP(t, func(r *dns.Msg) *dns.Msg {
		response := answerA(r, "192.0.2.3", 300)
		response.Truncated = true
		return response
	})
	good, _ := fakeUDP(t, okReply("192.0.2.4"))
	forwarder := newTestForwarder(t, Config{Servers: []string{truncated, good}})

	result, err := forwarder.Forward(context.Background(), queryFor("big.example.com.", dns.TypeA))
	if err != nil || result.Upstream != good {
		t.Fatalf("result %+v, err %v", result, err)
	}
}

// Wire fixture 092: nobody answers.
func TestForwardUnreachableUpstreamFails(t *testing.T) {
	forwarder := newTestForwarder(t, Config{Servers: []string{closedUDPAddr(t)}})
	if _, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA)); !errors.Is(err, ErrAllFailed) {
		t.Fatalf("err = %v", err)
	}
}

func TestForwardIgnoresResponseForAnotherQuestion(t *testing.T) {
	liar, _ := fakeUDP(t, func(r *dns.Msg) *dns.Msg {
		other := r.Copy()
		other.Question[0].Name = "other.example.com."
		return answerA(other, "192.0.2.5", 300)
	})
	forwarder := newTestForwarder(t, Config{Servers: []string{liar}})
	if _, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA)); !errors.Is(err, ErrAllFailed) {
		t.Fatalf("a mismatched question must not be accepted: %v", err)
	}
}

func TestForwardCancelledContextReturnsPromptly(t *testing.T) {
	silent, _ := fakeUDP(t, func(*dns.Msg) *dns.Msg { return nil })
	forwarder := newTestForwarder(t, Config{Servers: []string{silent}, MinTimeout: 5 * time.Second, Timeout: 5 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := forwarder.Forward(ctx, queryFor("a.example.com.", dns.TypeA))

	if err == nil || time.Since(started) > 2*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(started))
	}
}

func TestForwardRetransmitsLostDatagram(t *testing.T) {
	drop := make(chan struct{}, 1)
	drop <- struct{}{}
	addr, count := fakeUDP(t, func(r *dns.Msg) *dns.Msg {
		select {
		case <-drop:
			return nil
		default:
			return answerA(r, "192.0.2.6", 300)
		}
	})
	forwarder := newTestForwarder(t, Config{
		Servers: []string{addr}, MinTimeout: 3 * time.Second, Timeout: 3 * time.Second,
		RetransmitInterval: 50 * time.Millisecond,
	})

	result, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA))
	if err != nil || firstA(t, unpack(t, result.Bytes)) != "192.0.2.6" || count.Load() < 2 {
		t.Fatalf("result %+v, err %v, datagrams %d", result, err, count.Load())
	}
}

func TestForwardNegativeResponseIsRebuiltWithAuthority(t *testing.T) {
	addr, _ := fakeUDP(t, func(r *dns.Msg) *dns.Msg {
		response := rcodeReply(r, dns.RcodeNameError)
		response.Ns = []dns.RR{exampleSOA()}
		return response
	})
	forwarder := newTestForwarder(t, Config{Servers: []string{addr}})

	result, err := forwarder.Forward(context.Background(), queryFor("nx.example.com.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	response := unpack(t, result.Bytes)
	if response.Rcode != dns.RcodeNameError || len(response.Ns) != 1 || response.IsEdns0() != nil {
		t.Fatalf("response = %v", response)
	}
}

// The upstream always gets DO when DNSSEC is on, and a plain client still gets
// no OPT back (the wire fixtures strip OPT in prepare).
func TestForwardStripsOPTForPlainClient(t *testing.T) {
	var sawDO atomic.Bool
	addr, _ := fakeUDP(t, func(r *dns.Msg) *dns.Msg {
		if opt := r.IsEdns0(); opt != nil {
			sawDO.Store(opt.Do())
		}
		response := answerA(r, "192.0.2.7", 300)
		response.AuthenticatedData = true
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(1232)
		opt.SetDo()
		response.Extra = append(response.Extra, opt)
		return response
	})
	forwarder := newTestForwarder(t, Config{Servers: []string{addr}})
	forwarder.SetDNSSECEnabled(true)

	result, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	response := unpack(t, result.Bytes)
	if !sawDO.Load() || response.IsEdns0() != nil || response.AuthenticatedData || !result.AuthenticatedData {
		t.Fatalf("sawDO %v, response %v, result AD %v", sawDO.Load(), response, result.AuthenticatedData)
	}
}

func TestDNSSECToggle(t *testing.T) {
	forwarder := newTestForwarder(t, Config{Servers: []string{closedUDPAddr(t)}})
	if !forwarder.DNSSECEnabled() {
		t.Fatal("DNSSEC transparency starts on, as in Rust")
	}
	forwarder.SetDNSSECEnabled(false)
	if forwarder.DNSSECEnabled() {
		t.Fatal("toggle did not stick")
	}
}

func threeServers(t *testing.T) *Forwarder {
	t.Helper()
	return newTestForwarder(t, Config{Servers: []string{"127.0.0.1:1", "127.0.0.2:1", "127.0.0.3:1"}})
}

// Rust: sequential_order_is_configured_order and round-robin tests
func TestStrategyOrders(t *testing.T) {
	forwarder := threeServers(t)
	if got := forwarder.ServerOrder(); !equalInts(got, []int{0, 1, 2}) {
		t.Fatalf("sequential: %v", got)
	}
	forwarder.SetStrategy(RoundRobin)
	next := func() []int {
		order := forwarder.ServerOrder()
		forwarder.rrCounter.Add(1) // Forward advances it once per query
		return order
	}
	first, second, third, fourth := next(), next(), next(), next()
	if !equalInts(first, []int{0, 1, 2}) || !equalInts(second, []int{1, 2, 0}) ||
		!equalInts(third, []int{2, 0, 1}) || !equalInts(fourth, []int{0, 1, 2}) {
		t.Fatalf("round-robin: %v %v %v %v", first, second, third, fourth)
	}
}

func TestLowestLatencyOrdersByEMAWithStableTies(t *testing.T) {
	forwarder := threeServers(t)
	forwarder.SetStrategy(LowestLatency)
	if got := forwarder.ServerOrder(); !equalInts(got, []int{0, 1, 2}) {
		t.Fatalf("unobserved servers keep configured order: %v", got)
	}
	forwarder.UpdateLatency(2, 10)
	forwarder.UpdateLatency(0, 50)
	if got := forwarder.ServerOrder(); !equalInts(got, []int{2, 0, 1}) {
		t.Fatalf("observed first, fastest first: %v", got)
	}
}

func TestEMAAlpha(t *testing.T) {
	forwarder := threeServers(t)
	forwarder.UpdateLatency(0, 100)
	forwarder.UpdateLatency(0, 200)
	if got := forwarder.Latencies()["127.0.0.1:1"]; got < 129.99 || got > 130.01 {
		t.Fatalf("EMA = %v, want 0.3*200+0.7*100 = 130", got)
	}
	if len(forwarder.Latencies()) != 1 {
		t.Fatal("unobserved servers are omitted")
	}
	forwarder.UpdateLatency(99, 5)
	forwarder.UpdateLatency(-1, 5)
}

func TestSetStrategyRoundTrip(t *testing.T) {
	forwarder := threeServers(t)
	for _, strategy := range []Strategy{RoundRobin, LowestLatency, Sequential} {
		forwarder.SetStrategy(strategy)
		if forwarder.Strategy() != strategy {
			t.Fatalf("strategy %v", strategy)
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Rust: reconfigure tests
func TestReconfigureSwapsServersAndResetsLatencies(t *testing.T) {
	forwarder := threeServers(t)
	forwarder.UpdateLatency(0, 10)

	forwarder.Reconfigure(context.Background(), []string{"127.0.0.9:53"})

	if got := forwarder.Servers(); len(got) != 1 || got[0] != "127.0.0.9:53" {
		t.Fatalf("servers = %v", got)
	}
	if len(forwarder.Latencies()) != 0 {
		t.Fatal("a new server list starts with no observations")
	}
}

func TestReconfigureSkipsUnparseableEntries(t *testing.T) {
	forwarder := newTestForwarder(t, Config{Servers: []string{"1.1.1.1:53", "not an address"}})
	if _, err := forwarder.Forward(context.Background(), []byte{0}); !errors.Is(err, ErrBadQuery) {
		t.Fatal(err)
	}
	if len(forwarder.ServerOrder()) != 2 {
		t.Fatal("an unusable entry keeps its slot so indices stay aligned")
	}
}

func TestNoServersFailsCleanly(t *testing.T) {
	forwarder := newTestForwarder(t, Config{Servers: []string{"not an address"}})
	if _, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA)); !errors.Is(err, ErrAllFailed) {
		t.Fatalf("err = %v", err)
	}
}

func TestHealthCheckReportsEachUpstream(t *testing.T) {
	good, _ := fakeUDP(t, func(r *dns.Msg) *dns.Msg {
		response := rcodeReply(r, dns.RcodeSuccess)
		response.Answer = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "a.root-servers.net."}}
		return response
	})
	empty, _ := fakeUDP(t, func(r *dns.Msg) *dns.Msg { return rcodeReply(r, dns.RcodeSuccess) })
	forwarder := newTestForwarder(t, Config{Servers: []string{good, empty, closedUDPAddr(t)}})

	results := forwarder.HealthCheck(context.Background())

	if len(results) != 3 || !results[0].OK || results[1].OK || results[2].OK {
		t.Fatalf("results = %+v: only a positive answer to the root NS probe is healthy", results)
	}
	forwarder.ProbeAll(context.Background())
	if _, ok := forwarder.Latencies()[good]; !ok {
		t.Fatal("ProbeAll must record latency for a healthy upstream")
	}
}

// Rust tests/upstream_test.rs, against local fakes instead of the internet.
func TestForwardOverDoTReusesConnection(t *testing.T) {
	addr, connections, trust := fakeDoT(t, okReply("192.0.2.8"))
	port := addr[strings.LastIndex(addr, ":")+1:]
	forwarder := newTestForwarder(t, Config{
		Servers:   []string{"tls://example.com:" + port},
		TLSConfig: trust,
		Resolver:  staticResolver{addr: netip.MustParseAddr("127.0.0.1")},
	})

	for range 3 {
		result, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA))
		if err != nil || firstA(t, unpack(t, result.Bytes)) != "192.0.2.8" {
			t.Fatalf("result %+v, err %v", result, err)
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("%d connections for 3 sequential queries, want 1", connections.Load())
	}
}

func TestForwardOverDoTRecoversFromClosedConnection(t *testing.T) {
	addr, connections, trust := fakeDoT(t, okReply("192.0.2.9"))
	port := addr[strings.LastIndex(addr, ":")+1:]
	forwarder := newTestForwarder(t, Config{
		Servers:   []string{"tls://example.com:" + port},
		TLSConfig: trust,
		Resolver:  staticResolver{addr: netip.MustParseAddr("127.0.0.1")},
	})
	query := queryFor("a.example.com.", dns.TypeA)
	if _, err := forwarder.Forward(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	forwarder.set.Load().entries[0].exchanger.closeIdle()
	if _, err := forwarder.Forward(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if connections.Load() != 2 {
		t.Fatalf("connections = %d", connections.Load())
	}
}

func TestForwardOverDoH(t *testing.T) {
	addr, requests, trust := fakeDoH(t, func(r *dns.Msg) *dns.Msg {
		if r.Id != 0 {
			return rcodeReply(r, dns.RcodeFormatError)
		}
		return answerA(r, "192.0.2.10", 300)
	})
	port := addr[strings.LastIndex(addr, ":")+1:]
	forwarder := newTestForwarder(t, Config{
		Servers:   []string{"https://example.com:" + port + "/dns-query"},
		TLSConfig: trust,
		Resolver:  staticResolver{addr: netip.MustParseAddr("127.0.0.1")},
	})

	result, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	response := unpack(t, result.Bytes)
	if response.Id != 0x1234 || firstA(t, response) != "192.0.2.10" || requests.Load() != 1 {
		t.Fatalf("id %#x, requests %d: DoH must send ID 0 and the client ID must come back", response.Id, requests.Load())
	}
}

func TestForwardOverDoHFailsOnHTTPError(t *testing.T) {
	addr, _, trust := fakeDoH(t, func(*dns.Msg) *dns.Msg { return nil })
	port := addr[strings.LastIndex(addr, ":")+1:]
	forwarder := newTestForwarder(t, Config{
		Servers:   []string{"https://example.com:" + port + "/dns-query"},
		TLSConfig: trust,
		Resolver:  staticResolver{addr: netip.MustParseAddr("127.0.0.1")},
	})
	if _, err := forwarder.Forward(context.Background(), queryFor("a.example.com.", dns.TypeA)); !errors.Is(err, ErrAllFailed) {
		t.Fatalf("err = %v", err)
	}
}

func TestFailureReasonNamesTheRealCause(t *testing.T) {
	cases := []struct {
		name      string
		truncated bool
		rcode     int
		want      string
	}{
		{"truncated empty NOERROR", true, dns.RcodeSuccess, "truncated response (TC=1)"},
		{"servfail", false, dns.RcodeServerFailure, "response code SERVFAIL"},
		{"extended rcode is not NOERROR", false, dns.RcodeBadCookie, "response code BADCOOKIE"},
		{"unnamed rcode", false, 99, "response code 99"},
	}
	for _, c := range cases {
		response := new(dns.Msg)
		response.Truncated, response.Rcode = c.truncated, c.rcode
		if got := failureReason(response); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func classifyReply(rcode int, qtype uint16, mutate func(*dns.Msg)) verdict {
	reply := new(dns.Msg)
	reply.SetQuestion("example.com.", qtype)
	reply.Response = true
	reply.Rcode = rcode
	mutate(reply)
	return classify(reply)
}

func TestClassifyAnswerSectionDecidesPositiveOrNegative(t *testing.T) {
	record := func(name string, rrtype uint16) dns.RR {
		return &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET}}
	}
	cases := []struct {
		name  string
		qtype uint16
		build func(*dns.Msg)
		want  verdict
	}{
		{"A with answer", dns.TypeA, func(m *dns.Msg) { m.Answer = []dns.RR{record("other.", dns.TypeA)} }, verdictPositive},
		{"A with only authority", dns.TypeA, func(m *dns.Msg) { m.Ns = []dns.RR{record("example.com.", dns.TypeSOA)} }, verdictNegative},
		{"A with matching record in extra", dns.TypeA, func(m *dns.Msg) { m.Extra = []dns.RR{record("EXAMPLE.com", dns.TypeA)} }, verdictPositive},
		{"ANY with record about the name", dns.TypeANY, func(m *dns.Msg) { m.Answer = []dns.RR{record("example.com", dns.TypeTXT)} }, verdictPositive},
		{"ANY with record about another name", dns.TypeANY, func(m *dns.Msg) { m.Answer = []dns.RR{record("other.com.", dns.TypeTXT)} }, verdictNegative},
		{"SOA covering the name", dns.TypeSOA, func(m *dns.Msg) { m.Ns = []dns.RR{record("com.", dns.TypeSOA)} }, verdictPositive},
		{"SOA of an unrelated zone", dns.TypeSOA, func(m *dns.Msg) { m.Ns = []dns.RR{record("org.", dns.TypeSOA)} }, verdictNegative},
	}
	for _, tc := range cases {
		if got := classifyReply(dns.RcodeSuccess, tc.qtype, tc.build); got != tc.want {
			t.Errorf("%s: verdict %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestClassifyWithoutQuestionIsNegative(t *testing.T) {
	if got := classify(&dns.Msg{}); got != verdictNegative {
		t.Fatalf("verdict = %d, want negative", got)
	}
}

func TestClassifyFailureRcodesAndTruncation(t *testing.T) {
	for _, rcode := range []int{dns.RcodeServerFailure, dns.RcodeRefused, 16} {
		if got := classifyReply(rcode, dns.TypeA, func(*dns.Msg) {}); got != verdictFailure {
			t.Errorf("rcode %d: verdict %d, want failure", rcode, got)
		}
	}
	if got := classifyReply(dns.RcodeSuccess, dns.TypeA, func(m *dns.Msg) { m.Truncated = true }); got != verdictFailure {
		t.Errorf("truncated: verdict %d, want failure", got)
	}
}
