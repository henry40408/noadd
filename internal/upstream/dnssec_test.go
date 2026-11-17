package upstream

import (
	"testing"

	"github.com/miekg/dns"
)

func clientRequest(edns *bool) *dns.Msg {
	request := new(dns.Msg)
	request.SetQuestion("api.example.com.", dns.TypeA)
	if edns != nil {
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(4096)
		if *edns {
			opt.SetDo()
		}
		request.Extra = append(request.Extra, opt)
	}
	return request
}

func withDO(do bool) *bool { return &do }

func responseWithDNSSECRecords() *dns.Msg {
	response := new(dns.Msg)
	response.Id = 0x1234
	response.Response = true
	response.AuthenticatedData = true
	response.SetQuestion("api.example.com.", dns.TypeA)
	response.Answer = []dns.RR{&dns.RRSIG{Hdr: dns.RR_Header{Name: "api.example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}}}
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(4096)
	opt.SetDo()
	response.Extra = []dns.RR{opt}
	return response
}

// Rust: ensure_dnssec_ok_adds_opt_when_absent
func TestEnsureDNSSECOKAddsOPTWhenAbsent(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion(".", dns.TypeA)

	forced := prepareUpstreamRequest(request, true)

	opt := forced.IsEdns0()
	if opt == nil || !opt.Do() || opt.UDPSize() != 1232 {
		t.Fatalf("OPT = %+v", opt)
	}
	if request.IsEdns0() != nil {
		t.Fatal("the client's request must not be modified")
	}
}

// Rust: ensure_dnssec_ok_upserts_existing_opt_without_duplicating
func TestEnsureDNSSECOKUpsertsExistingOPTWithoutDuplicating(t *testing.T) {
	request := clientRequest(withDO(false))

	forced := prepareUpstreamRequest(request, true)

	opts := 0
	for _, rr := range forced.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			opts++
		}
	}
	opt := forced.IsEdns0()
	if opts != 1 || !opt.Do() || opt.UDPSize() != 4096 {
		t.Fatalf("OPT count %d, %+v: an existing larger payload must be kept", opts, opt)
	}
}

func TestWithoutForcedDOTheQueryIsSentAsIs(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion(".", dns.TypeA)
	if prepareUpstreamRequest(request, false).IsEdns0() != nil {
		t.Fatal("no OPT must be added when DO forcing is off")
	}
}

// Rust: response_for_plain_client_omits_opt_and_dnssec_records
func TestResponseForPlainClientOmitsOPTAndDNSSECRecords(t *testing.T) {
	response := responseWithDNSSECRecords()

	prepareResponseForClient(response, clientRequest(nil))

	if response.IsEdns0() != nil || len(response.Answer) != 0 || response.AuthenticatedData {
		t.Fatalf("response = %v", response)
	}
}

// Rust: response_for_edns_client_without_do_has_opt_but_no_dnssec_records
func TestResponseForEDNSClientWithoutDOHasOPTButNoDNSSECRecords(t *testing.T) {
	response := responseWithDNSSECRecords()

	prepareResponseForClient(response, clientRequest(withDO(false)))

	opt := response.IsEdns0()
	if opt == nil || opt.Do() || opt.UDPSize() != dnssecUDPPayload {
		t.Fatalf("OPT = %+v", opt)
	}
	if len(response.Answer) != 0 || response.AuthenticatedData {
		t.Fatalf("response = %v", response)
	}
}

// Rust: response_for_do_client_keeps_opt_and_dnssec_records
func TestResponseForDOClientKeepsOPTAndDNSSECRecords(t *testing.T) {
	response := responseWithDNSSECRecords()

	prepareResponseForClient(response, clientRequest(withDO(true)))

	if opt := response.IsEdns0(); opt == nil || !opt.Do() {
		t.Fatal("a DO client must get OPT with DO")
	}
	if len(response.Answer) != 1 || response.Answer[0].Header().Rrtype != dns.TypeRRSIG || !response.AuthenticatedData {
		t.Fatalf("response = %v", response)
	}
}

// Every type hickory treats as DNSSEC goes for a non-DO client, from all three
// sections, unless it is the type asked for.
func TestStripCoversEveryDNSSECTypeInEverySection(t *testing.T) {
	for recordType := range dnssecTypes {
		response := new(dns.Msg)
		response.SetQuestion("a.example.com.", dns.TypeA)
		record := &dns.RFC3597{Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: recordType, Class: dns.ClassINET}}
		keep := &dns.A{Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}}
		response.Answer = []dns.RR{record, keep}
		response.Ns = []dns.RR{record}
		response.Extra = []dns.RR{record}

		prepareResponseForClient(response, clientRequest(nil))

		if len(response.Answer) != 1 || len(response.Ns) != 0 || len(response.Extra) != 0 {
			t.Errorf("type %s: answer %d, authority %d, additional %d",
				dns.TypeToString[recordType], len(response.Answer), len(response.Ns), len(response.Extra))
		}
	}
}

func TestStripKeepsTheTypeTheClientAskedFor(t *testing.T) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeDNSKEY)
	response.Answer = []dns.RR{&dns.RFC3597{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}}}

	prepareResponseForClient(response, clientRequest(nil))

	if len(response.Answer) != 1 {
		t.Fatal("a DNSKEY answer to a DNSKEY query must be kept")
	}
}

func exampleSOA() dns.RR {
	soa, err := dns.NewRR("example.com. 7200 IN SOA ns1.example.com. hostmaster.example.com. 2026042954 1200 144 1814400 7200")
	if err != nil {
		panic(err)
	}
	return soa
}

func negativeInput(rcode int, authority ...dns.RR) *dns.Msg {
	upstream := new(dns.Msg)
	upstream.Rcode = rcode
	upstream.Response = true
	upstream.Authoritative = true
	upstream.Ns = authority
	upstream.Extra = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "x.", Rrtype: dns.TypeA, Class: dns.ClassINET}}}
	return upstream
}

// Rust: negative_response_echoes_query_rd
func TestNegativeResponseEchoesQueryRD(t *testing.T) {
	for _, rd := range []bool{true, false} {
		request := new(dns.Msg)
		request.SetQuestion("api.example.com.", dns.TypeAAAA)
		request.RecursionDesired = rd
		response := buildNegativeResponse(negativeInput(dns.RcodeNameError, exampleSOA()), request)
		if response.RecursionDesired != rd || !response.RecursionAvailable || response.Rcode != dns.RcodeNameError {
			t.Errorf("rd=%v: response = %v", rd, response)
		}
	}
}

// Rust: negative_response_uses_full_authority_section_without_duplicating_soa
func TestNegativeResponseUsesFullAuthoritySectionWithoutDuplicatingSOA(t *testing.T) {
	request := clientRequest(withDO(true))
	nsec := &dns.RFC3597{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET}}

	response := buildNegativeResponse(negativeInput(dns.RcodeSuccess, exampleSOA(), nsec), request)

	if len(response.Ns) != 2 || response.Ns[0].Header().Rrtype != dns.TypeSOA || response.Ns[1].Header().Rrtype != dns.TypeNSEC {
		t.Fatalf("authority = %v", response.Ns)
	}
	if len(response.Answer) != 0 || response.AuthenticatedData || response.Authoritative {
		t.Fatalf("only the authority section, and no AD or AA, may carry over: %v", response)
	}
}

// Rust: negative_response_echoes_opt_when_client_used_edns
func TestNegativeResponseEchoesOPTWhenClientUsedEDNS(t *testing.T) {
	response := buildNegativeResponse(negativeInput(dns.RcodeSuccess, exampleSOA()), clientRequest(withDO(false)))

	if opt := response.IsEdns0(); opt == nil || opt.Do() {
		t.Fatalf("OPT = %+v", opt)
	}
}

// Rust: negative_response_omits_opt_when_client_sent_none
func TestNegativeResponseOmitsOPTWhenClientSentNone(t *testing.T) {
	response := buildNegativeResponse(negativeInput(dns.RcodeNameError, exampleSOA()), clientRequest(nil))

	if response.IsEdns0() != nil {
		t.Fatal("a client without OPT must get none")
	}
}

// The UDP TC=1 case of the wire fixtures: the Rust pool had no TCP connection,
// so truncation was a failure. NXDOMAIN with TC also fails, not a negative answer.
func TestClassifyMirrorsHickory(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion("a.example.com.", dns.TypeA)
	answer := func(rcode int, truncated bool, records ...dns.RR) *dns.Msg {
		response := request.Copy()
		response.Response, response.Rcode, response.Truncated, response.Answer = true, rcode, truncated, records
		return response
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}}

	cases := []struct {
		name     string
		response *dns.Msg
		want     verdict
	}{
		{"answer", answer(dns.RcodeSuccess, false, a), verdictPositive},
		{"nodata", answer(dns.RcodeSuccess, false), verdictNegative},
		{"nxdomain", answer(dns.RcodeNameError, false), verdictNegative},
		{"nxdomain with a CNAME is relayed", answer(dns.RcodeNameError, false, &dns.CNAME{Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}}), verdictPositive},
		{"servfail", answer(dns.RcodeServerFailure, false), verdictFailure},
		{"refused", answer(dns.RcodeRefused, false), verdictFailure},
		{"formerr", answer(dns.RcodeFormatError, false), verdictFailure},
		{"notimp", answer(dns.RcodeNotImplemented, false), verdictFailure},
		{"badvers", answer(16, false), verdictFailure},
		{"truncated answer", answer(dns.RcodeSuccess, true, a), verdictFailure},
		{"truncated empty", answer(dns.RcodeSuccess, true), verdictFailure},
		{"truncated nxdomain", answer(dns.RcodeNameError, true), verdictFailure},
		{"unknown rcode is relayed", answer(12, false), verdictPositive},
	}
	for _, c := range cases {
		if got := classify(c.response); got != c.want {
			t.Errorf("%s: classify = %d, want %d", c.name, got, c.want)
		}
	}
}
