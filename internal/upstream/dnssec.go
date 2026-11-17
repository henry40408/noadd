package upstream

import (
	"github.com/miekg/dns"
)

// dnssecUDPPayload is the EDNS UDP payload when forcing DO: the DNS flag day
// value, which avoids IP fragmentation of signed responses.
const dnssecUDPPayload = 1232

// dnssecTypes are the record types hickory strips for a client that did not set
// DO (RecordType::is_dnssec), unless the client asked for that very type.
var dnssecTypes = map[uint16]bool{
	dns.TypeDNSKEY: true, dns.TypeCDNSKEY: true, dns.TypeCDS: true, dns.TypeDS: true,
	dns.TypeKEY: true, dns.TypeNSEC: true, dns.TypeNSEC3: true, dns.TypeNSEC3PARAM: true,
	dns.TypeRRSIG: true, dns.TypeSIG: true, dns.TypeTSIG: true,
}

// prepareUpstreamRequest returns a copy of the client's query for the upstream.
// With forceDO it carries one OPT with DO set and a payload of at least 1232;
// a second OPT is never added.
func prepareUpstreamRequest(clientRequest *dns.Msg, forceDO bool) *dns.Msg {
	request := clientRequest.Copy()
	if !forceDO {
		return request
	}
	opt := request.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(dnssecUDPPayload)
		request.Extra = append(request.Extra, opt)
	}
	opt.SetDo()
	if opt.UDPSize() < dnssecUDPPayload {
		opt.SetUDPSize(dnssecUDPPayload)
	}
	return request
}

// prepareResponseForClient fits an upstream response to what the client's
// request advertised. DO may have been forced upstream: RFC 3225 requires
// stripping DNSSEC records for a non-DO client, and RFC 6891 ties OPT presence
// to the client's request. A fresh minimal OPT also keeps upstream EDNS options
// out of the shared cache.
func prepareResponseForClient(response, clientRequest *dns.Msg) {
	clientOpt := clientRequest.IsEdns0()
	clientDO := clientOpt != nil && clientOpt.Do()

	if !clientDO {
		stripDNSSECRecords(response)
	}
	response.CheckingDisabled = clientRequest.CheckingDisabled
	// RFC 6840 section 5.7: no AD for a client that did not request DNSSEC.
	if !clientDO {
		response.AuthenticatedData = false
	}

	response.Extra = withoutOPT(response.Extra)
	if clientOpt == nil {
		// The extended RCODE lives in the OPT, which this client cannot receive.
		response.Rcode &= 0xF
		return
	}
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(dnssecUDPPayload)
	if clientDO {
		opt.SetDo()
	}
	response.Extra = append(response.Extra, opt)
}

func stripDNSSECRecords(response *dns.Msg) {
	if len(response.Question) == 0 {
		return
	}
	queryType := response.Question[0].Qtype
	keep := func(records []dns.RR) []dns.RR {
		kept := records[:0]
		for _, record := range records {
			recordType := record.Header().Rrtype
			if recordType == queryType || !dnssecTypes[recordType] {
				kept = append(kept, record)
			}
		}
		return kept
	}
	response.Answer = keep(response.Answer)
	response.Ns = keep(response.Ns)
	response.Extra = keep(response.Extra)
}

func withoutOPT(records []dns.RR) []dns.RR {
	kept := records[:0]
	for _, record := range records {
		if record.Header().Rrtype != dns.TypeOPT {
			kept = append(kept, record)
		}
	}
	return kept
}

// buildNegativeResponse rebuilds an NXDOMAIN or NODATA answer from the
// upstream's, as the Rust forwarder does for hickory's NoRecordsFound. It keeps
// the authority section (SOA, NSEC and RRSIG) so clients can negative-cache per
// RFC 2308; without the SOA, iOS re-queries always-NODATA names on nearly every
// connection. The rest of the upstream message is dropped, and AD stays unset.
func buildNegativeResponse(upstream, clientRequest *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.Id = clientRequest.Id
	response.Response = true
	response.Opcode = dns.OpcodeQuery
	response.Rcode = upstream.Rcode & 0xF
	// RFC 1035 section 4.1.1: RD is set by the client and copied.
	response.RecursionDesired = clientRequest.RecursionDesired
	response.RecursionAvailable = true
	response.Question = append(response.Question, clientRequest.Question...)
	response.Ns = append(response.Ns, upstream.Ns...)
	prepareResponseForClient(response, clientRequest)
	return response
}
