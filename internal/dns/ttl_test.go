package dns

import (
	"bytes"
	"encoding/binary"
	"net"
	"slices"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// recordTTLs lists every TTL a parser sees, in section order. OPT is not a record.
func recordTTLs(t *testing.T, wire []byte) []uint32 {
	t.Helper()
	msg := mustUnpack(t, wire)
	var ttls []uint32
	for _, section := range [][]mdns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, record := range section {
			if record.Header().Rrtype != mdns.TypeOPT {
				ttls = append(ttls, record.Header().Ttl)
			}
		}
	}
	return ttls
}

func ttlAt(wire []byte, offset int) uint32 {
	return binary.BigEndian.Uint32(wire[offset : offset+4])
}

func assertTTLs(t *testing.T, wire []byte, want ...uint32) {
	t.Helper()
	if got := recordTTLs(t, wire); !slices.Equal(got, want) {
		t.Fatalf("TTLs = %v, want %v", got, want)
	}
}

func TestEverySectionIsDecremented(t *testing.T) {
	msg := newResponseMsg(1, "example.com.", mdns.TypeA)
	msg.Answer = []mdns.RR{aRecord("example.com.", 300, 1)}
	msg.Ns = []mdns.RR{&mdns.NS{
		Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: 600},
		Ns:  "ns1.example.com.",
	}}
	msg.Extra = []mdns.RR{aRecord("ns1.example.com.", 900, 2)}
	wire := mustPack(t, msg)

	assertTTLs(t, wire, 300, 600, 900)
	assertTTLs(t, PatchTTL(wire, 100), 200, 500, 800)
}

func TestCompressedOwnerNameIsWalkedPast(t *testing.T) {
	msg := newResponseMsg(2, "example.com.", mdns.TypeA)
	for _, last := range []byte{1, 2, 3} {
		msg.Answer = append(msg.Answer, aRecord("example.com.", 300, last))
	}
	wire := mustPack(t, msg)

	if !bytes.Contains(wire, []byte{0xC0, 0x0C}) {
		t.Fatal("fixture has no compression pointer, so the pointer branch is untested")
	}
	assertTTLs(t, PatchTTL(wire, 60), 240, 240, 240)
}

func TestCNAMEChainIsWalkedPast(t *testing.T) {
	msg := newResponseMsg(3, "www.example.com.", mdns.TypeA)
	msg.Answer = []mdns.RR{
		&mdns.CNAME{
			Hdr:    mdns.RR_Header{Name: "www.example.com.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 3600},
			Target: "target.example.net.",
		},
		aRecord("target.example.net.", 120, 7),
	}
	assertTTLs(t, PatchTTL(mustPack(t, msg), 60), 3540, 60)
}

func TestNegativeAnswerDecrementsItsSOA(t *testing.T) {
	msg := newResponseMsg(4, "nope.example.com.", mdns.TypeA)
	msg.Rcode = mdns.RcodeNameError
	msg.Ns = []mdns.RR{soaRecord(3600, 300)}
	assertTTLs(t, PatchTTL(mustPack(t, msg), 600), 3000)
}

func TestLongTXTRecordIsWalkedPast(t *testing.T) {
	msg := newResponseMsg(5, "example.com.", mdns.TypeTXT)
	msg.Answer = []mdns.RR{
		&mdns.TXT{
			Hdr: mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 300},
			Txt: []string{"v=spf1 include:_spf.example.com include:_spf2.example.com ~all", string(bytes.Repeat([]byte("x"), 255))},
		},
		&mdns.AAAA{
			Hdr:  mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2001:db8::1"),
		},
	}
	assertTTLs(t, PatchTTL(mustPack(t, msg), 1), 299, 299)
}

// An OPT "TTL" is not a TTL: decrementing it would silently flip the DO bit.
func TestOPTPseudoTTLIsLeftAlone(t *testing.T) {
	msg := newResponseMsg(6, "example.com.", mdns.TypeA)
	msg.Answer = []mdns.RR{aRecord("example.com.", 300, 1)}
	msg.SetEdns0(1232, true)
	wire := mustPack(t, msg)

	patched := PatchTTL(wire, 250)

	assertTTLs(t, patched, 50)
	before, after := mustUnpack(t, wire).IsEdns0(), mustUnpack(t, patched).IsEdns0()
	if after == nil || !after.Do() || after.Version() != before.Version() || after.ExtendedRcode() != before.ExtendedRcode() {
		t.Fatalf("OPT changed: before %v after %v", before, after)
	}
	if got := len(TTLOffsets(wire)); got != 1 {
		t.Fatalf("offsets = %d, want only the A record", got)
	}
}

// TSIG's TTL is sent as 0; clamping it up to 1 would break the signature.
func TestTSIGPseudoTTLIsLeftAlone(t *testing.T) {
	msg := newResponseMsg(7, "example.com.", mdns.TypeA)
	msg.Answer = []mdns.RR{aRecord("example.com.", 300, 1)}
	wire := mustPack(t, msg)

	tsigTTLAt := len(wire) + 5
	wire = append(wire, 0x00, 0x00, 250, 0x00, 255)
	wire = binary.BigEndian.AppendUint32(wire, 0)
	wire = binary.BigEndian.AppendUint16(wire, 0)
	wire[11] = 1 // ARCOUNT

	offsets := TTLOffsets(wire)
	if len(offsets) != 1 || int(offsets[0]) == tsigTTLAt {
		t.Fatalf("offsets = %v, TSIG at %d must be excluded", offsets, tsigTTLAt)
	}
	if got := ttlAt(PatchTTL(wire, 500), tsigTTLAt); got != 0 {
		t.Fatalf("TSIG TTL = %d, want 0", got)
	}
}

func TestOffsetsPointAtTheTTLTheParserReads(t *testing.T) {
	msg := newResponseMsg(8, "example.com.", mdns.TypeA)
	msg.Answer = []mdns.RR{aRecord("example.com.", 300, 1), aRecord("example.com.", 600, 2)}
	wire := mustPack(t, msg)

	var read []uint32
	for _, offset := range TTLOffsets(wire) {
		read = append(read, ttlAt(wire, int(offset)))
	}
	if want := recordTTLs(t, wire); !slices.Equal(read, want) {
		t.Fatalf("TTLs at offsets = %v, parser reads %v", read, want)
	}
}

func TestPatchingRewritesOnlyTheTTLBytes(t *testing.T) {
	msg := newResponseMsg(9, "example.com.", mdns.TypeA)
	msg.Answer = []mdns.RR{aRecord("example.com.", 300, 1)}
	msg.Authoritative = true
	original := mustPack(t, msg)

	patched := PatchTTL(original, 100)

	if len(patched) != len(original) {
		t.Fatalf("length changed: %d -> %d", len(original), len(patched))
	}
	inTTL := map[int]bool{}
	for _, offset := range TTLOffsets(original) {
		for i := range 4 {
			inTTL[int(offset)+i] = true
		}
	}
	for i := range original {
		if original[i] != patched[i] && !inTTL[i] {
			t.Fatalf("byte %d outside the TTL fields changed", i)
		}
	}
}

// The walk reads only TYPE and RDLENGTH, so an unknown type must not stop it.
func TestUnknownRecordTypeIsWalkedPast(t *testing.T) {
	msg := newResponseMsg(10, "example.com.", mdns.TypeA)
	msg.Answer = []mdns.RR{aRecord("example.com.", 300, 1)}
	wire := mustPack(t, msg)

	unknownTTLAt := len(wire) + 6
	wire = append(wire, 0xC0, 0x0C, 0x00, 65, 0x00, 0x01)
	wire = binary.BigEndian.AppendUint32(wire, 600)
	wire = binary.BigEndian.AppendUint16(wire, 40)
	wire = append(wire, bytes.Repeat([]byte{0xDE}, 40)...)

	trailingTTLAt := len(wire) + 6
	wire = append(wire, 0xC0, 0x0C, 0x00, 1, 0x00, 0x01)
	wire = binary.BigEndian.AppendUint32(wire, 450)
	wire = binary.BigEndian.AppendUint16(wire, 4)
	wire = append(wire, 203, 0, 113, 9)
	wire[7] = 3 // ANCOUNT

	offsets := TTLOffsets(wire)
	if len(offsets) != 3 || int(offsets[1]) != unknownTTLAt || int(offsets[2]) != trailingTTLAt {
		t.Fatalf("offsets = %v, want unknown at %d and trailing at %d", offsets, unknownTTLAt, trailingTTLAt)
	}
	patched := PatchTTL(wire, 50)
	got := []uint32{ttlAt(patched, int(offsets[0])), ttlAt(patched, unknownTTLAt), ttlAt(patched, trailingTTLAt)}
	if want := []uint32{250, 550, 400}; !slices.Equal(got, want) {
		t.Fatalf("patched TTLs = %v, want %v", got, want)
	}
}

func TestUnwalkableMessageIsServedUnchanged(t *testing.T) {
	msg := newResponseMsg(11, "example.com.", mdns.TypeA)
	msg.Answer = []mdns.RR{aRecord("example.com.", 300, 1)}
	good := mustPack(t, msg)

	mutated := func(change func([]byte)) []byte {
		wire := slices.Clone(good)
		change(wire)
		return wire
	}
	cases := map[string][]byte{
		"empty":                                {},
		"header only, truncated":               good[:8],
		"record cut short":                     good[:len(good)-3],
		"rdlength past the end":                mutated(func(b []byte) { b[len(b)-5] = 0xFF }),
		"reserved label type":                  mutated(func(b []byte) { b[12] = 0x80 }),
		"answer count larger than the message": mutated(func(b []byte) { b[7] = 0xFF }),
	}
	for name, wire := range cases {
		if offsets := TTLOffsets(wire); len(offsets) != 0 {
			t.Errorf("%s: offsets = %v, want none", name, offsets)
		}
		if patched := PatchTTL(wire, 100); !bytes.Equal(patched, wire) {
			t.Errorf("%s: message was modified", name)
		}
	}
}

func TestBogusOffsetDoesNotPanic(t *testing.T) {
	wire := make([]byte, 20)
	patched := slices.Clone(wire)
	ApplyElapsed(patched, []uint32{18, 4096, 1<<32 - 1}, 10)
	if !bytes.Equal(patched, wire) {
		t.Fatal("offsets that do not fit a four-byte field must be skipped")
	}
}

func soaRecord(ttl, minimum uint32) mdns.RR {
	return &mdns.SOA{
		Hdr:     mdns.RR_Header{Name: "example.com.", Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: ttl},
		Ns:      "ns1.example.com.",
		Mbox:    "hostmaster.example.com.",
		Serial:  20260101,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  minimum,
	}
}

func cacheResponse(t *testing.T, rcode int, answers []mdns.RR, soaMinimum *uint32) []byte {
	t.Helper()
	msg := newResponseMsg(1, "example.com.", mdns.TypeA)
	msg.Rcode = rcode
	msg.Answer = answers
	if soaMinimum != nil {
		msg.Ns = []mdns.RR{soaRecord(3600, *soaMinimum)}
	}
	return mustPack(t, msg)
}

func TestCacheTTL(t *testing.T) {
	soa := func(v uint32) *uint32 { return &v }
	cases := []struct {
		name   string
		wire   []byte
		want   time.Duration
		cached bool
	}{
		{"servfail is not cached", cacheResponse(t, mdns.RcodeServerFailure, nil, nil), 0, false},
		{"refused is not cached", cacheResponse(t, mdns.RcodeRefused, nil, nil), 0, false},
		{"positive uses the minimum answer TTL", cacheResponse(t, mdns.RcodeSuccess,
			[]mdns.RR{aRecord("example.com.", 120, 1), aRecord("example.com.", 60, 2), aRecord("example.com.", 900, 3)}, nil), 60 * time.Second, true},
		{"nxdomain with a huge SOA minimum is capped", cacheResponse(t, mdns.RcodeNameError, nil, soa(3600)), 60 * time.Second, true},
		{"nxdomain with a small SOA minimum is used as is", cacheResponse(t, mdns.RcodeNameError, nil, soa(15)), 15 * time.Second, true},
		{"empty noerror uses the negative TTL", cacheResponse(t, mdns.RcodeSuccess, nil, soa(86400)), 60 * time.Second, true},
		{"empty noerror without SOA falls back to the cap", cacheResponse(t, mdns.RcodeSuccess, nil, nil), 60 * time.Second, true},
		{"unparseable is not cached", []byte{0xff, 0xff}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, cached := CacheTTL(tc.wire)
			if got != tc.want || cached != tc.cached {
				t.Fatalf("CacheTTL = %v, %v; want %v, %v", got, cached, tc.want, tc.cached)
			}
		})
	}
}

func TestFieldEndingAtTheBufferEndIsPatched(t *testing.T) {
	buf := []byte{0, 0, 0, 0, 0, 0, 1, 0}

	ApplyElapsed(buf, []uint32{4}, 100)

	if got := ttlAt(buf, 4); got != 156 {
		t.Fatalf("TTL = %d, want 156", got)
	}
}

func TestSkipNameNeedsBothBytesOfAPointer(t *testing.T) {
	if _, ok := skipName([]byte{0xC0}, 0); ok {
		t.Fatal("a pointer cut after its first byte must be rejected")
	}
	next, ok := skipName([]byte{0xC0, 0x00}, 0)
	if !ok || next != 2 {
		t.Fatalf("complete pointer: next %d, ok %v", next, ok)
	}
}

func TestHeaderOnlyMessageIsWalkable(t *testing.T) {
	offsets, ok := scanTTLOffsets(make([]byte, headerLen))
	if !ok || len(offsets) != 0 {
		t.Fatalf("offsets %v, ok %v", offsets, ok)
	}
	if _, ok := scanTTLOffsets(make([]byte, headerLen-1)); ok {
		t.Fatal("a buffer shorter than the header must be rejected")
	}
}

func TestRecordWithEmptyRDataEndsExactlyAtTheBufferEnd(t *testing.T) {
	msg := newResponseMsg(12, "example.com.", mdns.TypeA)
	msg.Answer = []mdns.RR{&mdns.ANY{Hdr: mdns.RR_Header{
		Name: "example.com.", Rrtype: mdns.TypeNULL, Class: mdns.ClassINET, Ttl: 300,
	}}}
	wire := mustPack(t, msg)

	if offsets := TTLOffsets(wire); len(offsets) != 1 {
		t.Fatalf("offsets = %v, want one", offsets)
	}
}

// Every proper prefix of a message is unwalkable and must neither panic nor
// yield offsets.
func TestEveryTruncationIsRejectedWithoutPanicking(t *testing.T) {
	msg := newResponseMsg(13, "example.com.", mdns.TypeA)
	msg.Answer = []mdns.RR{aRecord("example.com.", 300, 1)}
	wire := mustPack(t, msg)

	for length := range wire {
		if offsets := TTLOffsets(wire[:length]); len(offsets) != 0 {
			t.Errorf("cut to %d bytes: offsets = %v, want none", length, offsets)
		}
	}
}
