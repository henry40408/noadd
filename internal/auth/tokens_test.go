package auth

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func isAlphanumeric(s string) bool {
	return strings.Trim(s, alphanumeric) == ""
}

func TestSessionTokenShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		token := NewSessionToken()
		if len(token) != 64 || !isAlphanumeric(token) {
			t.Fatalf("bad token %q", token)
		}
		seen[token] = true
	}
	if len(seen) != 50 {
		t.Fatal("tokens collided")
	}
}

// The alphabet draw must reach every symbol; a biased or truncated draw would
// shrink the entropy silently.
func TestRandomStringCoversTheAlphabet(t *testing.T) {
	seen := map[rune]bool{}
	for _, r := range randomString(alphanumeric, 5000) {
		seen[r] = true
	}
	if len(seen) != len(alphanumeric) {
		t.Fatalf("saw %d of %d symbols", len(seen), len(alphanumeric))
	}
}

// Rust: api_key_shape_and_prefix
func TestAPIKeyShapeAndPrefix(t *testing.T) {
	full, prefix, hash := NewAPIKey()
	if !strings.HasPrefix(full, "noadd_") || len(full) != len("noadd_")+40 || !isAlphanumeric(full[len("noadd_"):]) {
		t.Fatalf("bad key %q", full)
	}
	if !strings.HasPrefix(prefix, "noadd_") || len(prefix) != len("noadd_")+4 || !strings.HasPrefix(full, prefix) {
		t.Fatalf("bad prefix %q for %q", prefix, full)
	}
	if hash != HashToken(full) || len(hash) != 128 || strings.Trim(hash, "0123456789abcdef") != "" {
		t.Fatalf("bad hash %q", hash)
	}
}

// Rust: hash_is_stable_and_distinct
func TestHashTokenIsStableAndDistinct(t *testing.T) {
	first, again := HashToken("noadd_abc"), HashToken("noadd_abc")
	if first != again {
		t.Fatal("hash is not deterministic")
	}
	if HashToken("noadd_abc") == HashToken("noadd_abd") {
		t.Fatal("distinct tokens collided")
	}
}

// Rust: session_log_id_is_stable_and_distinct
func TestSidHashIsStableAndDistinct(t *testing.T) {
	var salt [SessionLogSaltLen]byte
	first, second := HashToken(NewSessionToken()), HashToken(NewSessionToken())
	id := SidHash(salt, first)
	if id != SidHash(salt, first) || id == SidHash(salt, second) {
		t.Fatal("not stable or not distinct")
	}
	if len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" {
		t.Fatalf("bad id %q", id)
	}
}

// Rust: session_log_id_with_actually_depends_on_the_salt. Only differing salts
// over the same token prove salting happens; an unsalted digest passes every
// other assertion.
func TestSidHashDependsOnTheSalt(t *testing.T) {
	var saltA, saltB [SessionLogSaltLen]byte
	for i := range saltA {
		saltA[i], saltB[i] = 0x11, 0x22
	}
	if SidHash(saltA, "same-token-both-times") == SidHash(saltB, "same-token-both-times") {
		t.Fatal("salt has no effect")
	}
}

func TestSessionCookieName(t *testing.T) {
	if SessionCookieName(true) != "__Host-session" || SessionCookieName(false) != "session" {
		t.Fatal("wrong cookie names")
	}
}

// Rust: setup_token_generates_two_groups_from_the_alphabet
func TestSetupTokenGeneratesTwoGroupsFromTheAlphabet(t *testing.T) {
	shown, ok := GenerateSetupToken(nil).Display()
	head, tail, found := strings.Cut(shown, "-")
	if !ok || !found || len(head) != 5 || len(tail) != 5 {
		t.Fatalf("bad display %q", shown)
	}
	if strings.Trim(head+tail, setupTokenAlphabet) != "" {
		t.Fatalf("symbol outside the alphabet in %q", shown)
	}
}

// Rust: setup_token_match_ignores_case_hyphens_and_whitespace
func TestSetupTokenMatchIgnoresCaseHyphensAndWhitespace(t *testing.T) {
	token := FixedSetupToken("ABCDE-FGHJK", nil)
	for submitted, want := range map[string]bool{
		"abcde-fghjk": true, " ABCDEFGHJK ": true, "ABCDE-FGHJM": false, "": false,
	} {
		if token.Matches(submitted) != want {
			t.Errorf("Matches(%q) != %v", submitted, want)
		}
	}
}

// Rust: a_cleared_or_absent_setup_token_matches_nothing
func TestClearedOrAbsentSetupTokenMatchesNothing(t *testing.T) {
	token := FixedSetupToken("ABCDE-FGHJK", nil)
	token.Clear()
	if token.Matches("ABCDE-FGHJK") {
		t.Fatal("cleared token matched")
	}
	if _, ok := token.Display(); ok {
		t.Fatal("cleared token displayed")
	}
	if NoSetupToken(nil).Matches("") {
		t.Fatal("absent token matched the empty string")
	}
}

func TestSetupAttemptsAreThrottledPerIP(t *testing.T) {
	clock := newFakeClock()
	token := FixedSetupToken("ABCDE-FGHJK", clock.Now)
	ip := netip.MustParseAddr("10.0.0.1")
	for i := 0; i < 5; i++ {
		if !token.AllowAttempt(ip) {
			t.Fatalf("attempt %d refused", i+1)
		}
	}
	if token.AllowAttempt(ip) {
		t.Fatal("sixth attempt allowed")
	}
	if !token.AllowAttempt(netip.MustParseAddr("10.0.0.2")) {
		t.Fatal("another IP shares the budget")
	}
	clock.Advance(61 * time.Second)
	if !token.AllowAttempt(ip) {
		t.Fatal("budget not restored after the window")
	}
	// The second IP's window elapsed; the first IP's was just restarted.
	if token.PruneAttempts() != 1 {
		t.Fatal("prune must drop only the elapsed entry")
	}
}
