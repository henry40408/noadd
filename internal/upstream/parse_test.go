package upstream

import (
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, input string) spec {
	t.Helper()
	parsed, err := parseSpec(input)
	if err != nil {
		t.Fatalf("parseSpec(%q): %v", input, err)
	}
	return parsed
}

// Rust: parse_plain_udp_v4
func TestParsePlainUDPV4(t *testing.T) {
	if got := mustParse(t, "1.1.1.1:53"); got != (spec{host: "1.1.1.1", port: 53}) {
		t.Fatalf("got %+v", got)
	}
}

// Rust: parse_plain_udp_v6
func TestParsePlainUDPV6(t *testing.T) {
	if got := mustParse(t, "[::1]:53"); got != (spec{host: "::1", port: 53}) {
		t.Fatalf("got %+v", got)
	}
}

// Rust: parse_dot_default_port
func TestParseDoTDefaultPort(t *testing.T) {
	want := spec{host: "dns.quad9.net", port: 853, transport: transportTLS}
	if got := mustParse(t, "tls://dns.quad9.net"); got != want {
		t.Fatalf("got %+v", got)
	}
}

// Rust: parse_dot_explicit_port
func TestParseDoTExplicitPort(t *testing.T) {
	if got := mustParse(t, "tls://dns.quad9.net:8853"); got.port != 8853 {
		t.Fatalf("port = %d", got.port)
	}
}

// Rust: parse_doh_default_path_and_port
func TestParseDoHDefaultPathAndPort(t *testing.T) {
	want := spec{host: "dns.quad9.net", port: 443, transport: transportHTTPS, path: "/dns-query"}
	if got := mustParse(t, "https://dns.quad9.net"); got != want {
		t.Fatalf("got %+v", got)
	}
}

// Rust: parse_doh_custom_path
func TestParseDoHCustomPath(t *testing.T) {
	want := spec{host: "dns.example.com", port: 443, transport: transportHTTPS, path: "/custom-dns"}
	if got := mustParse(t, "https://dns.example.com/custom-dns"); got != want {
		t.Fatalf("got %+v", got)
	}
}

// Rust: parse_doh_with_port_and_path
func TestParseDoHWithPortAndPath(t *testing.T) {
	want := spec{host: "dns.example.com", port: 8443, transport: transportHTTPS, path: "/dns-query"}
	if got := mustParse(t, "https://dns.example.com:8443/dns-query"); got != want {
		t.Fatalf("got %+v", got)
	}
}

// Rust: parse_invalid_udp_returns_error, parse_empty_returns_error,
// parse_dot_invalid_port, parse_dot_unclosed_ipv6, parse_bare_ip_rejects_inet_aton_shorthand,
// parse_bare_hostname_still_rejected
func TestParseRejectsInvalidEntries(t *testing.T) {
	for _, input := range []string{
		"not an address", "", "   ", "tls://dns.example.com:abc", "tls://[::1:853",
		"1.1", "010.1.1.1", "0x01010101", "dns.example.com", "localhost:53",
		"tls://", "tls://:853", "tls://dns.example.com:70000", "tls://[::1]x",
	} {
		if parsed, err := parseSpec(input); err == nil {
			t.Errorf("parseSpec(%q) = %+v, want an error", input, parsed)
		}
	}
}

// Rust: parse_bare_ipv4_takes_port_53
func TestParseBareIPv4TakesPort53(t *testing.T) {
	if got := mustParse(t, "1.1.1.1"); got != (spec{host: "1.1.1.1", port: 53}) {
		t.Fatalf("got %+v", got)
	}
}

// Rust: parse_bare_ipv6_takes_port_53 (a bare IPv6 literal has colons but no port)
func TestParseBareIPv6TakesPort53(t *testing.T) {
	got := mustParse(t, "2606:4700:4700::1111")
	if got != (spec{host: "2606:4700:4700::1111", port: 53}) {
		t.Fatalf("got %+v", got)
	}
	if got.canonical() != "[2606:4700:4700::1111]:53" {
		t.Fatalf("canonical = %q", got.canonical())
	}
}

// Rust: parse_upstreams_accepts_newlines_and_commas
func TestParseUpstreamsAcceptsNewlinesAndCommas(t *testing.T) {
	got, err := ParseUpstreams("1.1.1.1:53\ntls://dns.quad9.net:853, https://dns.quad9.net/dns-query")
	want := []string{"1.1.1.1:53", "tls://dns.quad9.net:853", "https://dns.quad9.net:443/dns-query"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, %v", got, err)
	}
}

// Rust: parse_upstreams_canonicalizes_every_scheme
func TestParseUpstreamsCanonicalizesEveryScheme(t *testing.T) {
	got, err := ParseUpstreams("1.1.1.1\n::1\ntls://dns.quad9.net\nhttps://dns.quad9.net")
	want := []string{"1.1.1.1:53", "[::1]:53", "tls://dns.quad9.net:853", "https://dns.quad9.net:443/dns-query"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, %v", got, err)
	}
}

// Rust: parse_upstreams_dedupes_equivalent_spellings
func TestParseUpstreamsDedupesEquivalentSpellings(t *testing.T) {
	got, err := ParseUpstreams("1.1.1.1, 1.1.1.1:53, [::1]:53, ::1")
	if want := []string{"1.1.1.1:53", "[::1]:53"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, %v", got, err)
	}
}

// Rust: parse_upstreams_rejects_empty
func TestParseUpstreamsRejectsEmpty(t *testing.T) {
	for _, input := range []string{"", "   \n  "} {
		if _, err := ParseUpstreams(input); err == nil {
			t.Errorf("ParseUpstreams(%q) succeeded", input)
		}
	}
}

// Rust: parse_upstreams_reports_bad_entry
func TestParseUpstreamsReportsBadEntry(t *testing.T) {
	_, err := ParseUpstreams("1.1.1.1:53\nnot an address")
	if err == nil || !strings.Contains(err.Error(), "not an address") {
		t.Fatalf("error should name the bad entry: %v", err)
	}
}

func TestParseStrategy(t *testing.T) {
	for _, name := range []string{"sequential", "round-robin", "lowest-latency"} {
		if got, err := ParseStrategy(name); err != nil || got.String() != name {
			t.Errorf("ParseStrategy(%q) = %v, %v", name, got, err)
		}
	}
	if _, err := ParseStrategy("fastest"); err == nil {
		t.Error("an unknown strategy must be rejected")
	}
}
