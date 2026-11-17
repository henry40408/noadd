package dns

import (
	"net"
	"testing"

	mdns "github.com/miekg/dns"
)

func mustPack(t *testing.T, msg *mdns.Msg) []byte {
	t.Helper()
	msg.Compress = true
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return packed
}

func mustUnpack(t *testing.T, wire []byte) *mdns.Msg {
	t.Helper()
	msg := new(mdns.Msg)
	if err := msg.Unpack(wire); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return msg
}

func newQuery(id uint16, name string, qtype uint16) *mdns.Msg {
	query := new(mdns.Msg)
	query.SetQuestion(name, qtype)
	query.Id = id
	return query
}

func newResponseMsg(id uint16, name string, qtype uint16) *mdns.Msg {
	response := newQuery(id, name, qtype)
	response.Response = true
	response.RecursionAvailable = true
	return response
}

func aRecord(name string, ttl uint32, last byte) mdns.RR {
	return &mdns.A{
		Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: ttl},
		A:   net.IPv4(203, 0, 113, last),
	}
}

func queryWithRD(recursionDesired bool) *mdns.Msg {
	query := newQuery(7, "example.com.", mdns.TypeA)
	query.RecursionDesired = recursionDesired
	return query
}
