package dns

import (
	mdns "github.com/miekg/dns"
)

// advertisedUDPSize is the payload size of the OPT record in a BADVERS reply.
const advertisedUDPSize = minUDPSize

// newResponse starts a response that echoes the query's ID, question and RD
// bit. RA is always set, as the Rust handler does.
func newResponse(query *mdns.Msg, opcode int) *mdns.Msg {
	response := new(mdns.Msg)
	response.Id = query.Id
	response.Response = true
	response.Compress = true
	response.Opcode = opcode
	response.RecursionDesired = query.RecursionDesired
	response.RecursionAvailable = true
	response.Question = append(response.Question, query.Question...)
	return response
}

// BuildRefused builds a REFUSED response for a query.
func BuildRefused(query *mdns.Msg) ([]byte, error) {
	response := newResponse(query, mdns.OpcodeQuery)
	response.Rcode = mdns.RcodeRefused
	return response.Pack()
}

// BuildServfail builds a SERVFAIL from raw query bytes. When the query does
// not parse, it returns a bare header that carries only the raw ID.
func BuildServfail(queryBytes []byte) []byte {
	query := new(mdns.Msg)
	if query.Unpack(queryBytes) == nil {
		response := newResponse(query, mdns.OpcodeQuery)
		response.Rcode = mdns.RcodeServerFailure
		if packed, err := response.Pack(); err == nil {
			return packed
		}
	}
	return bareServfail(queryBytes)
}

// bareServfail is QR+RD+RA+SERVFAIL with empty sections; it is what Rust
// answers when it cannot parse the query at all.
func bareServfail(queryBytes []byte) []byte {
	var id [2]byte
	copy(id[:], queryBytes)
	return []byte{id[0], id[1], 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0}
}

// BuildNotimp builds a NOTIMP response for a non-QUERY opcode, echoing the
// opcode, ID, question and RD bit.
func BuildNotimp(query *mdns.Msg) ([]byte, error) {
	response := newResponse(query, query.Opcode)
	response.Rcode = mdns.RcodeNotImplemented
	return response.Pack()
}

// BuildBadvers builds the BADVERS response for an unsupported EDNS version
// (RFC 6891 section 6.1.3). Packing splits the extended RCODE 16 between the
// header and the OPT record.
func BuildBadvers(query *mdns.Msg) ([]byte, error) {
	response := newResponse(query, mdns.OpcodeQuery)
	response.SetEdns0(advertisedUDPSize, false)
	response.Rcode = mdns.RcodeBadVers
	return response.Pack()
}
