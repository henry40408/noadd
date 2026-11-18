package netx

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func mustTrusted(t *testing.T, list string) TrustedProxies {
	t.Helper()
	set, err := ParseTrustedProxies(list)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%q): %v", list, err)
	}
	return set
}

func addr(text string) netip.Addr { return netip.MustParseAddr(text) }

func TestParseTrustedProxies(t *testing.T) {
	empty := mustTrusted(t, "")
	if !empty.IsEmpty() || empty.Contains(addr("10.0.0.1")) {
		t.Fatal("empty list must be empty and match nothing")
	}
	if !mustTrusted(t, "  ,  ,").IsEmpty() {
		t.Fatal("whitespace-only list must be empty")
	}

	cases := []struct {
		list    string
		ip      string
		matches bool
	}{
		{"172.18.0.0/16", "172.18.0.19", true},
		{"172.18.0.0/16", "172.18.255.255", true},
		{"172.18.0.0/16", "172.19.0.1", false},
		{"172.18.0.19", "172.18.0.19", true},
		{"172.18.0.19", "172.18.0.20", false},
		{"fd00::/8", "fd12:3456::1", true},
		{"fd00::/8", "fe00::1", false},
		{"10.0.0.0/8, 172.16.0.0/12 ,192.168.0.0/16", "172.20.5.6", true},
		{"10.0.0.0/8, 172.16.0.0/12 ,192.168.0.0/16", "192.168.50.50", true},
		{"10.0.0.0/8, 172.16.0.0/12 ,192.168.0.0/16", "8.8.8.8", false},
		{"0.0.0.0/0", "1.2.3.4", true},
		{"0.0.0.0/0", "255.255.255.255", true},
		{"10.0.0.0/8", "::ffff:10.0.0.1", false},
		{"::ffff:10.0.0.0/104", "10.0.0.5", false},
	}
	for _, c := range cases {
		if got := mustTrusted(t, c.list).Contains(addr(c.ip)); got != c.matches {
			t.Errorf("%q contains %s = %v, want %v", c.list, c.ip, got, c.matches)
		}
	}
}

func TestParseTrustedProxiesRejectsBadInput(t *testing.T) {
	for _, bad := range []string{"not.an.ip/24", "10.0.0.0/33", "::/129", "10.0.0.0/abc", "fe80::1%eth0", "10.0.0.0/+8"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

type clientIPCase struct {
	name    string
	trusted string
	peer    string // empty = no connection info
	xff     string
	xri     string
	want    string
}

func TestClientIP(t *testing.T) {
	forged := strings.TrimSuffix(strings.Repeat("1.2.3.4, ", 200), ", ")
	proxies := func(n int) string { return strings.TrimSuffix(strings.Repeat("172.18.0.19, ", n), ", ") }
	const net18 = "172.18.0.0/16"
	cases := []clientIPCase{
		{"loopback peer trusts headers", "", "127.0.0.1", "203.0.113.7", "", "203.0.113.7"},
		{"ipv6 loopback trusts headers", "", "::1", "", "203.0.113.7", "203.0.113.7"},
		{"untrusted peer ignores headers", "", "172.18.0.19", "203.0.113.7", "", "172.18.0.19"},
		{"trusted peer honours xff", net18, "172.18.0.19", "203.0.113.7", "", "203.0.113.7"},
		{"trusted peer honours x-real-ip", net18, "172.18.0.19", "", "203.0.113.99", "203.0.113.99"},
		{"rightmost non-proxy hop", net18, "172.18.0.19", "203.0.113.7, 10.0.0.1, 198.51.100.2", "", "198.51.100.2"},
		{"configured proxies skipped", "172.18.0.0/16,10.0.0.0/8", "172.18.0.19", "203.0.113.7, 10.0.0.1, 172.18.0.19", "", "203.0.113.7"},
		{"forged prefix", net18, "172.18.0.19", "1.2.3.4, 203.0.113.7, 172.18.0.19", "", "203.0.113.7"},
		{"forged prefix of many hops", net18, "172.18.0.19", forged + ", 203.0.113.7, 172.18.0.19", "", "203.0.113.7"},
		{"same host proxy hop", "", "127.0.0.1", "203.0.113.7, 127.0.0.1", "", "203.0.113.7"},
		{"all proxies: outermost", net18, "172.18.0.19", "172.18.0.4, 172.18.0.19", "", "172.18.0.4"},
		{"unreadable hop ends walk", net18, "172.18.0.19", "1.2.3.4, not-an-ip, 172.18.0.19", "", "172.18.0.19"},
		{"unreadable innermost falls back to peer", net18, "172.18.0.19", "1.2.3.4, not-an-ip", "", "172.18.0.19"},
		{"hop with port", net18, "172.18.0.19", "1.2.3.4, 203.0.113.7:53821, 172.18.0.19", "", "203.0.113.7"},
		{"bracketed ipv6 hop", net18, "172.18.0.19", "1.2.3.4, [2001:db8::5]:443, 172.18.0.19", "", "2001:db8::5"},
		{"rfc7239 for=", net18, "172.18.0.19", `1.2.3.4, for="203.0.113.7", 172.18.0.19`, "", "203.0.113.7"},
		{"hop limit reached", net18, "172.18.0.19", "203.0.113.7, " + proxies(31), "", "203.0.113.7"},
		{"hop limit exceeded", net18, "172.18.0.19", "203.0.113.7, " + proxies(32), "", "172.18.0.19"},
		{"client inside trusted range is skipped", "192.168.1.0/24", "192.168.1.5", "6.6.6.6, 192.168.1.77", "", "6.6.6.6"},
		{"xff preferred over x-real-ip", net18, "172.18.0.19", "203.0.113.7", "198.51.100.2", "203.0.113.7"},
		{"malformed header falls back to peer", net18, "172.18.0.19", "not-an-ip", "", "172.18.0.19"},
		{"no connect info trusts headers", "", "", "203.0.113.7", "", "203.0.113.7"},
		{"no connect info no headers", "", "", "", "", "127.0.0.1"},
		{"mapped peer matches ipv4 cidr", "10.0.0.0/8", "::ffff:10.0.0.5", "203.0.113.7", "", "203.0.113.7"},
		{"mapped loopback peer trusted", "", "::ffff:127.0.0.1", "203.0.113.7", "", "203.0.113.7"},
		{"mapped untrusted peer canonical", "", "::ffff:192.0.2.9", "203.0.113.7", "", "192.0.2.9"},
		{"mapped xff hops canonical", "10.0.0.0/8", "127.0.0.1", "[::ffff:203.0.113.7], ::ffff:10.0.0.5", "", "203.0.113.7"},
		{"pure ipv6 peer unaffected", "10.0.0.0/8", "2001:db8::1", "203.0.113.7", "", "2001:db8::1"},
		{"x-real-ip mapped canonical", "", "127.0.0.1", "", "::ffff:203.0.113.7", "203.0.113.7"},
		{"mapped form cidr does not match ipv4", "::ffff:10.0.0.0/104", "::ffff:10.0.0.5", "203.0.113.7", "", "10.0.0.5"},
		{"xff mapped loopback hop is proxy", "", "127.0.0.1", "203.0.113.7, ::ffff:127.0.0.1", "", "203.0.113.7"},
		{"ipv4-compatible loopback hop not trusted", "", "127.0.0.1", "203.0.113.7, ::127.0.0.1", "", "::127.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			header := http.Header{}
			if c.xff != "" {
				header.Set("X-Forwarded-For", c.xff)
			}
			if c.xri != "" {
				header.Set("X-Real-IP", c.xri)
			}
			var peer netip.Addr
			if c.peer != "" {
				peer = addr(c.peer)
			}
			got := ClientIP(peer, header, mustTrusted(t, c.trusted))
			if got != addr(c.want) {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestRequestClientIPFailsClosedOnUnparseablePeer(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "garbage"
	request.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := RequestClientIP(request, TrustedProxies{}); got != addr("127.0.0.1") {
		t.Fatalf("got %s, want loopback without trusting headers", got)
	}
	request.RemoteAddr = "127.0.0.1:50000"
	if got := RequestClientIP(request, TrustedProxies{}); got != addr("203.0.113.7") {
		t.Fatalf("got %s", got)
	}
}

func TestClientIPTrustsLinkLocalProxyWithZone(t *testing.T) {
	trusted := mustTrusted(t, "fe80::/10")
	header := http.Header{"X-Forwarded-For": []string{"203.0.113.9"}}
	got := ClientIP(addr("fe80::1%eth0"), header, trusted)
	if got != addr("203.0.113.9") {
		t.Fatalf("ClientIP = %v; the forwarded address must be honoured", got)
	}
	if peer := ClientIP(addr("fe80::1%eth0"), nil, trusted); peer.Zone() != "" {
		t.Fatalf("peer %v keeps its zone, so rate-limit keys would split per interface", peer)
	}
}

func TestTrustedProxiesLenCountsConfiguredCIDRs(t *testing.T) {
	if got := mustTrusted(t, "10.0.0.0/8, ,192.168.0.0/16").Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}
	if got := (TrustedProxies{}).Len(); got != 0 {
		t.Fatalf("zero value Len() = %d", got)
	}
}

func TestParseCIDRAcceptsTheLongestPrefix(t *testing.T) {
	for _, text := range []string{"10.0.0.1/32", "::1/128"} {
		if _, err := ParseCIDR(text); err != nil {
			t.Errorf("%q: %v", text, err)
		}
	}
}

func TestParseCIDRNamesTheAddressFamilyOfARangeError(t *testing.T) {
	for text, family := range map[string]string{"10.0.0.0/33": "IPv4", "::/129": "IPv6"} {
		_, err := ParseCIDR(text)
		if err == nil || !strings.Contains(err.Error(), "for "+family+" in") {
			t.Errorf("%q: err = %v, want a %s range error", text, err, family)
		}
	}
}
