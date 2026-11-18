package dns

import (
	mdns "github.com/miekg/dns"
)

// minUDPSize is the smallest payload any client accepts (RFC 1035 section 2.3.4).
const minUDPSize = 512

// TruncateForUDP fits a response to the client's UDP limit. An oversized
// response becomes header, question and OPT with TC set, so the client retries
// over TCP. Unparseable responses come back unchanged: an oversized datagram
// beats a dropped query. UDP only.
func TruncateForUDP(queryBytes, responseBytes []byte) []byte {
	// Every client's limit is at least 512, so skip the query parse.
	if len(responseBytes) <= minUDPSize {
		return responseBytes
	}
	if len(responseBytes) <= clientUDPPayload(queryBytes) {
		return responseBytes
	}
	response := new(mdns.Msg)
	if response.Unpack(responseBytes) != nil {
		return responseBytes
	}
	truncated := keepHeaderQuestionAndOPT(response)
	packed, err := truncated.Pack()
	if err != nil {
		return responseBytes
	}
	return packed
}

func keepHeaderQuestionAndOPT(response *mdns.Msg) *mdns.Msg {
	truncated := new(mdns.Msg)
	truncated.MsgHdr = response.MsgHdr
	truncated.Truncated = true
	truncated.Compress = response.Compress
	truncated.Question = response.Question
	if opt := response.IsEdns0(); opt != nil {
		truncated.Extra = []mdns.RR{opt}
	}
	return truncated
}

// clientUDPPayload is the client's advertised EDNS size floored at 512, or 512
// when the client sent no OPT (RFC 6891 section 6.2.3).
func clientUDPPayload(queryBytes []byte) int {
	query := new(mdns.Msg)
	if query.Unpack(queryBytes) != nil {
		return minUDPSize
	}
	opt := query.IsEdns0()
	if opt == nil {
		return minUDPSize
	}
	return max(int(opt.UDPSize()), minUDPSize)
}
