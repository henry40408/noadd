package dns

import (
	"bytes"
	"testing"

	mdns "github.com/miekg/dns"
)

func plainQuery(t *testing.T) []byte {
	t.Helper()
	return mustPack(t, newQuery(42, "example.com.", mdns.TypeA))
}

func ednsQuery(t *testing.T, payload uint16) []byte {
	t.Helper()
	query := newQuery(42, "example.com.", mdns.TypeA)
	query.SetEdns0(payload, false)
	return mustPack(t, query)
}

func responseWithARecords(t *testing.T, count int, withOPT uint16) []byte {
	t.Helper()
	msg := newResponseMsg(42, "example.com.", mdns.TypeA)
	for i := range count {
		msg.Answer = append(msg.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300},
			A:   []byte{10, 0, byte(i >> 8), byte(i)},
		})
	}
	if withOPT != 0 {
		msg.SetEdns0(withOPT, false)
	}
	return mustPack(t, msg)
}

func TestSmallResponsePassesThroughUntouched(t *testing.T) {
	response := responseWithARecords(t, 1, 0)
	if got := TruncateForUDP(plainQuery(t), response); !bytes.Equal(got, response) {
		t.Fatal("small response was modified")
	}
}

func TestOversizedResponseToPlainClientSetsTCAndFits512(t *testing.T) {
	response := responseWithARecords(t, 120, 0)
	if len(response) <= minUDPSize {
		t.Fatalf("precondition: %d bytes", len(response))
	}
	out := TruncateForUDP(plainQuery(t), response)
	got := mustUnpack(t, out)
	if len(out) > minUDPSize || !got.Truncated || len(got.Answer) != 0 || len(got.Question) != 1 || got.Id != 42 {
		t.Fatalf("len %d, %+v", len(out), got)
	}
}

func TestResponseWithinAdvertisedEDNSSizeIsNotTruncated(t *testing.T) {
	response := responseWithARecords(t, 120, 0)
	out := TruncateForUDP(ednsQuery(t, 4096), response)
	if !bytes.Equal(out, response) || mustUnpack(t, out).Truncated {
		t.Fatal("response within the advertised size was truncated")
	}
}

func TestOversizedResponseToEDNSClientKeepsItsOPT(t *testing.T) {
	response := responseWithARecords(t, 120, 1232)
	if len(response) <= 1232 {
		t.Fatalf("precondition: %d bytes", len(response))
	}
	out := TruncateForUDP(ednsQuery(t, 1232), response)
	got := mustUnpack(t, out)
	if len(out) > 1232 || !got.Truncated || got.IsEdns0() == nil {
		t.Fatalf("len %d, truncated %v, opt %v", len(out), got.Truncated, got.IsEdns0())
	}
}

func TestAdvertisedSizeBelow512IsFlooredTo512(t *testing.T) {
	response := responseWithARecords(t, 20, 0)
	if len(response) <= minUDPSize/2 || len(response) > minUDPSize {
		t.Fatalf("precondition: %d bytes", len(response))
	}
	if got := TruncateForUDP(ednsQuery(t, 200), response); !bytes.Equal(got, response) {
		t.Fatal("advertised 200 must be floored to 512")
	}
}

func TestUnparseableOversizedResponseIsReturnedUnchanged(t *testing.T) {
	garbage := bytes.Repeat([]byte{0xff}, 600)
	if got := TruncateForUDP(plainQuery(t), garbage); !bytes.Equal(got, garbage) {
		t.Fatal("garbage was modified")
	}
}

func TestUnparseableQueryUsesTheDefaultLimit(t *testing.T) {
	response := responseWithARecords(t, 120, 0)
	got := TruncateForUDP([]byte{1, 2, 3}, response)
	if !mustUnpack(t, got).Truncated {
		t.Fatal("expected TC with the 512 default")
	}
}
