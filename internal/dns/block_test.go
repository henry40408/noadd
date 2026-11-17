package dns

import (
	"net/netip"
	"testing"

	mdns "github.com/miekg/dns"
)

func buildBlocked(t *testing.T, query *mdns.Msg, config BlockConfig) *mdns.Msg {
	t.Helper()
	wire, err := BuildBlocked(query, config)
	if err != nil {
		t.Fatalf("BuildBlocked: %v", err)
	}
	return mustUnpack(t, wire)
}

func TestBlockConfigFromSettings(t *testing.T) {
	t.Run("defaults to null_ip", func(t *testing.T) {
		if got := BlockConfigFromSettings("", "", ""); got != (BlockConfig{Mode: BlockNullIP}) {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("unknown mode falls back to null_ip", func(t *testing.T) {
		if got := BlockConfigFromSettings("bogus", "", "").Mode; got != BlockNullIP {
			t.Fatalf("mode = %q", got)
		}
	})
	t.Run("every mode round-trips", func(t *testing.T) {
		for _, mode := range []BlockMode{BlockNullIP, BlockNXDomain, BlockRefused, BlockCustomIP} {
			if got := BlockConfigFromSettings(string(mode), "", "").Mode; got != mode {
				t.Errorf("%q -> %q", mode, got)
			}
		}
	})
	t.Run("parses custom addresses", func(t *testing.T) {
		got := BlockConfigFromSettings("custom_ip", " 192.0.2.1 ", "100::1")
		if got.CustomV4 != netip.MustParseAddr("192.0.2.1") || got.CustomV6 != netip.MustParseAddr("100::1") {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("empty or wrong-family address is unset", func(t *testing.T) {
		for _, tc := range [][2]string{{"", "not-an-ip"}, {"100::1", "192.0.2.1"}, {"", "fe80::1%eth0"}} {
			got := BlockConfigFromSettings("custom_ip", tc[0], tc[1])
			if got.CustomV4.IsValid() || got.CustomV6.IsValid() {
				t.Errorf("%v: got %+v, want both unset", tc, got)
			}
		}
	})
}

func TestNullIPReturnsUnspecifiedAddresses(t *testing.T) {
	config := BlockConfig{Mode: BlockNullIP}

	a := buildBlocked(t, newQuery(42, "ads.example.com.", mdns.TypeA), config)
	if a.Rcode != mdns.RcodeSuccess || len(a.Answer) != 1 || a.Answer[0].(*mdns.A).A.String() != "0.0.0.0" {
		t.Fatalf("A answer: %v", a)
	}
	aaaa := buildBlocked(t, newQuery(42, "ads.example.com.", mdns.TypeAAAA), config)
	if len(aaaa.Answer) != 1 || aaaa.Answer[0].(*mdns.AAAA).AAAA.String() != "::" {
		t.Fatalf("AAAA answer: %v", aaaa)
	}
	if ttl := a.Answer[0].Header().Ttl; ttl != 300 {
		t.Fatalf("TTL = %d, want 300", ttl)
	}
	txt := buildBlocked(t, newQuery(42, "ads.example.com.", mdns.TypeTXT), config)
	if txt.Rcode != mdns.RcodeSuccess || len(txt.Answer) != 0 {
		t.Fatalf("TXT answer: %v", txt)
	}
}

func TestNXDomainAndRefusedApplyToEveryType(t *testing.T) {
	modes := map[BlockMode]int{BlockNXDomain: mdns.RcodeNameError, BlockRefused: mdns.RcodeRefused}
	for mode, rcode := range modes {
		for _, qtype := range []uint16{mdns.TypeA, mdns.TypeAAAA, mdns.TypeTXT} {
			got := buildBlocked(t, newQuery(42, "ads.example.com.", qtype), BlockConfig{Mode: mode})
			if got.Rcode != rcode || len(got.Answer) != 0 {
				t.Errorf("%s/%d: rcode %d answers %d", mode, qtype, got.Rcode, len(got.Answer))
			}
		}
	}
}

func TestCustomIPUsesConfiguredAddresses(t *testing.T) {
	config := BlockConfig{Mode: BlockCustomIP, CustomV4: netip.MustParseAddr("192.0.2.1"), CustomV6: netip.MustParseAddr("100::1")}
	a := buildBlocked(t, newQuery(42, "ads.example.com.", mdns.TypeA), config)
	aaaa := buildBlocked(t, newQuery(42, "ads.example.com.", mdns.TypeAAAA), config)
	if a.Answer[0].(*mdns.A).A.String() != "192.0.2.1" || aaaa.Answer[0].(*mdns.AAAA).AAAA.String() != "100::1" {
		t.Fatalf("got %v / %v", a.Answer, aaaa.Answer)
	}
}

func TestCustomIPUnsetAddressGivesEmptyNoError(t *testing.T) {
	for _, qtype := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
		got := buildBlocked(t, newQuery(42, "ads.example.com.", qtype), BlockConfig{Mode: BlockCustomIP})
		if got.Rcode != mdns.RcodeSuccess || len(got.Answer) != 0 {
			t.Errorf("type %d: %v", qtype, got)
		}
	}
}

func TestBlockedResponseEchoesQueryRD(t *testing.T) {
	configs := []BlockConfig{{Mode: BlockNullIP}, {Mode: BlockNXDomain}, {Mode: BlockRefused}}
	for _, config := range configs {
		for _, rd := range []bool{true, false} {
			got := buildBlocked(t, queryWithRD(rd), config)
			if got.RecursionDesired != rd || !got.RecursionAvailable || !got.Response {
				t.Errorf("%s rd=%v: %+v", config.Mode, rd, got.MsgHdr)
			}
		}
	}
}
