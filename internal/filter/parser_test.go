package filter

import (
	"slices"
	"testing"
)

func wantRule(t *testing.T, line string, want ParsedRule) {
	t.Helper()
	got, ok := ParseLine(line)
	if !ok {
		t.Fatalf("ParseLine(%q) = none, want %+v", line, want)
	}
	if got != want {
		t.Fatalf("ParseLine(%q) = %+v, want %+v", line, got, want)
	}
}

func wantNone(t *testing.T, line string) {
	t.Helper()
	if got, ok := ParseLine(line); ok {
		t.Fatalf("ParseLine(%q) = %+v, want none", line, got)
	}
}

// Rust: test_parse_adblock_block_rule
func TestParseAdblockBlockRule(t *testing.T) {
	wantRule(t, "||example.com^", ParsedRule{Domain: "example.com", Action: ActionBlock, IsSubdomain: true})
}

// Rust: test_parse_adblock_allow_rule
func TestParseAdblockAllowRule(t *testing.T) {
	wantRule(t, "@@||example.com^", ParsedRule{Domain: "example.com", Action: ActionAllow, IsSubdomain: true})
}

// Rust: test_parse_hosts_format_zero
func TestParseHostsFormatZero(t *testing.T) {
	wantRule(t, "0.0.0.0 ads.example.com", ParsedRule{Domain: "ads.example.com", Action: ActionBlock})
}

// Rust: test_parse_hosts_format_localhost
func TestParseHostsFormatLocalhost(t *testing.T) {
	wantRule(t, "127.0.0.1 tracker.example.com", ParsedRule{Domain: "tracker.example.com", Action: ActionBlock})
}

// Rust: test_parse_plain_domain
func TestParsePlainDomain(t *testing.T) {
	wantRule(t, "malware.example.com", ParsedRule{Domain: "malware.example.com", Action: ActionBlock})
}

// Rust: test_parse_comment_hash
func TestParseCommentHash(t *testing.T) { wantNone(t, "# This is a comment") }

// Rust: test_parse_comment_bang
func TestParseCommentBang(t *testing.T) { wantNone(t, "! Another comment") }

// Rust: test_parse_empty_line
func TestParseEmptyLine(t *testing.T) {
	for _, line := range []string{"", "   ", "\t"} {
		wantNone(t, line)
	}
}

// Rust: test_parse_hosts_localhost_entry_skipped
func TestParseHostsLocalhostEntrySkipped(t *testing.T) {
	for _, line := range []string{
		"127.0.0.1 localhost",
		"0.0.0.0 local",
		"127.0.0.1 broadcasthost",
		"::1 ip6-localhost",
		"localhost",
	} {
		wantNone(t, line)
	}
}

// Rust: test_parse_list_multiple_rules
func TestParseListMultipleRules(t *testing.T) {
	content := `
# Comment line
! Another comment
||ads.example.com^
@@||safe.example.com^
0.0.0.0 tracker.example.com
127.0.0.1 localhost
malware.bad.com

`
	want := []ParsedRule{
		{Domain: "ads.example.com", Action: ActionBlock, IsSubdomain: true},
		{Domain: "safe.example.com", Action: ActionAllow, IsSubdomain: true},
		{Domain: "tracker.example.com", Action: ActionBlock},
		{Domain: "malware.bad.com", Action: ActionBlock},
	}
	if got := ParseList(content); !slices.Equal(got, want) {
		t.Fatalf("ParseList = %+v, want %+v", got, want)
	}
}

// Rust: test_parse_domain_lowercased
func TestParseDomainLowercased(t *testing.T) {
	wantRule(t, "||EXAMPLE.COM^", ParsedRule{Domain: "example.com", Action: ActionBlock, IsSubdomain: true})
	wantRule(t, "0.0.0.0 ADS.Example.COM", ParsedRule{Domain: "ads.example.com", Action: ActionBlock})
}

// Rust unit test in src/filter/parser.rs: trailing_caret_optional_for_adblock
func TestTrailingCaretOptionalForAdblock(t *testing.T) {
	wantRule(t, "||example.com", ParsedRule{Domain: "example.com", Action: ActionBlock, IsSubdomain: true})
}

func TestParseListHandlesCRLF(t *testing.T) {
	got := ParseList("||a.com^\r\n0.0.0.0 b.com\r\n")
	if len(got) != 2 || got[0].Domain != "a.com" || got[1].Domain != "b.com" {
		t.Fatalf("ParseList = %+v", got)
	}
}
