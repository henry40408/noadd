package dns

import (
	"bytes"
	"testing"

	mdns "github.com/miekg/dns"
)

func TestRefusedResponseEchoesQueryRD(t *testing.T) {
	for _, rd := range []bool{true, false} {
		wire, err := BuildRefused(queryWithRD(rd))
		if err != nil {
			t.Fatal(err)
		}
		got := mustUnpack(t, wire)
		if got.RecursionDesired != rd || got.Rcode != mdns.RcodeRefused || !got.RecursionAvailable {
			t.Errorf("rd=%v: %+v", rd, got.MsgHdr)
		}
	}
}

func TestServfailEchoesQueryRD(t *testing.T) {
	for _, rd := range []bool{true, false} {
		got := mustUnpack(t, BuildServfail(mustPack(t, queryWithRD(rd))))
		if got.RecursionDesired != rd || got.Rcode != mdns.RcodeServerFailure || len(got.Question) != 1 {
			t.Errorf("rd=%v: %+v", rd, got)
		}
	}
}

func TestServfailForUnparseableQueryIsABareHeader(t *testing.T) {
	cases := map[string]struct{ query, want []byte }{
		"two bytes of ID": {[]byte{0xAB, 0xCD}, []byte{0xAB, 0xCD, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0}},
		"one byte":        {[]byte{0xAB}, []byte{0xAB, 0, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0}},
		"empty":           {nil, []byte{0, 0, 0x81, 0x82, 0, 0, 0, 0, 0, 0, 0, 0}},
	}
	for name, tc := range cases {
		if got := BuildServfail(tc.query); !bytes.Equal(got, tc.want) {
			t.Errorf("%s: %x, want %x", name, got, tc.want)
		}
	}
}

func TestNotimpEchoesOpcodeQuestionAndRD(t *testing.T) {
	query := newQuery(11, "example.com.", mdns.TypeA)
	query.Opcode = mdns.OpcodeStatus
	query.RecursionDesired = false

	wire, err := BuildNotimp(query)
	if err != nil {
		t.Fatal(err)
	}
	got := mustUnpack(t, wire)
	if got.Rcode != mdns.RcodeNotImplemented || got.Opcode != mdns.OpcodeStatus || !got.Response ||
		got.RecursionDesired || got.Id != 11 || len(got.Question) != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestBadversSetsExtendedRcodeAndOPT(t *testing.T) {
	query := queryWithRD(true)
	query.SetEdns0(1232, false)
	query.IsEdns0().SetVersion(1)

	wire, err := BuildBadvers(query)
	if err != nil {
		t.Fatal(err)
	}
	got := mustUnpack(t, wire)
	opt := got.IsEdns0()
	if opt == nil {
		t.Fatal("BADVERS response must carry an OPT")
	}
	if got.Rcode != mdns.RcodeBadVers || opt.ExtendedRcode() != 16 || wire[3]&0x0F != 0 {
		t.Fatalf("rcode %d, extended %d, header nibble %d", got.Rcode, opt.ExtendedRcode(), wire[3]&0x0F)
	}
	if opt.Version() != 0 || opt.UDPSize() != 512 || opt.Do() {
		t.Fatalf("OPT version %d size %d do %v", opt.Version(), opt.UDPSize(), opt.Do())
	}
	if !got.RecursionDesired || len(got.Question) != 1 {
		t.Fatalf("RD/question not echoed: %+v", got)
	}
}
