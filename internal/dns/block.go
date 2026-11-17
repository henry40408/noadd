// Package dns holds the DNS wire-level helpers and, later, the query handler.
package dns

import (
	"net/netip"
	"strings"

	mdns "github.com/miekg/dns"
)

// blockedResponseTTLSeconds is the TTL of the synthesized A/AAAA answer.
const blockedResponseTTLSeconds = 300

// BlockMode selects how a filter-blocked query is answered.
type BlockMode string

const (
	// BlockNullIP answers 0.0.0.0 for A, :: for AAAA and an empty NOERROR otherwise.
	BlockNullIP BlockMode = "null_ip"
	// BlockNXDomain answers NXDOMAIN for every query type.
	BlockNXDomain BlockMode = "nxdomain"
	// BlockRefused answers REFUSED for every query type.
	BlockRefused BlockMode = "refused"
	// BlockCustomIP answers the operator's addresses; empty NOERROR when the
	// address for the query type is unset.
	BlockCustomIP BlockMode = "custom_ip"
)

// BlockConfig is the runtime block-response configuration. An invalid
// netip.Addr means "unset".
type BlockConfig struct {
	Mode     BlockMode
	CustomV4 netip.Addr
	CustomV6 netip.Addr
}

// BlockConfigFromSettings builds a BlockConfig from raw setting strings. An
// unrecognised mode falls back to null_ip; an empty or unparseable address
// becomes unset.
func BlockConfigFromSettings(mode, v4, v6 string) BlockConfig {
	return BlockConfig{
		Mode:     parseBlockMode(mode),
		CustomV4: parseIPv4(v4),
		CustomV6: parseIPv6(v6),
	}
}

func parseBlockMode(raw string) BlockMode {
	switch mode := BlockMode(strings.TrimSpace(raw)); mode {
	case BlockNullIP, BlockNXDomain, BlockRefused, BlockCustomIP:
		return mode
	}
	return BlockNullIP
}

func parseIPv4(raw string) netip.Addr {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is4() {
		return netip.Addr{}
	}
	return addr
}

// parseIPv6 accepts IPv4-mapped addresses, as Rust's Ipv6Addr does, but not zones.
func parseIPv6(raw string) netip.Addr {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is6() || addr.Zone() != "" {
		return netip.Addr{}
	}
	return addr
}

// BuildBlocked builds the wire response for a blocked query. Like the Rust
// handler, it never echoes the query's OPT record.
func BuildBlocked(query *mdns.Msg, config BlockConfig) ([]byte, error) {
	response := newResponse(query, mdns.OpcodeQuery)
	switch config.Mode {
	case BlockRefused:
		response.Rcode = mdns.RcodeRefused
	case BlockNXDomain:
		response.Rcode = mdns.RcodeNameError
	default:
		response.Answer = blockedAnswers(query, config)
	}
	return response.Pack()
}

func blockedAnswers(query *mdns.Msg, config BlockConfig) []mdns.RR {
	if len(query.Question) == 0 {
		return nil
	}
	question := query.Question[0]
	v4, v6 := netip.IPv4Unspecified(), netip.IPv6Unspecified()
	if config.Mode == BlockCustomIP {
		v4, v6 = config.CustomV4, config.CustomV6
	}
	header := mdns.RR_Header{Name: question.Name, Class: mdns.ClassINET, Ttl: blockedResponseTTLSeconds}

	switch question.Qtype {
	case mdns.TypeA:
		if !v4.IsValid() {
			return nil
		}
		header.Rrtype = mdns.TypeA
		return []mdns.RR{&mdns.A{Hdr: header, A: v4.AsSlice()}}
	case mdns.TypeAAAA:
		if !v6.IsValid() {
			return nil
		}
		header.Rrtype = mdns.TypeAAAA
		return []mdns.RR{&mdns.AAAA{Hdr: header, AAAA: v6.AsSlice()}}
	}
	return nil
}
