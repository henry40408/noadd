package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNormalizeUsernameRejectsALeadingControlCharacter(t *testing.T) {
	t.Parallel()
	// TrimSpace keeps \x01, so only the IndexFunc result of 0 catches it.
	if user, ok := NormalizeUsername("\x01alice"); ok {
		t.Fatalf("a leading control character was accepted as %q", user)
	}
}

func TestNormalizeUsernameLengthBoundary(t *testing.T) {
	t.Parallel()
	if _, ok := NormalizeUsername(strings.Repeat("あ", MaxUsernameLen)); !ok {
		t.Fatal("a username of exactly MaxUsernameLen characters must be accepted")
	}
	if _, ok := NormalizeUsername(strings.Repeat("あ", MaxUsernameLen+1)); ok {
		t.Fatal("a username one character over MaxUsernameLen must be rejected")
	}
}

func TestIsVisibleASCIIBoundaries(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"\x1f": false,
		"\x20": true,
		"\t":   true,
		"\x7e": true,
		"\x7f": false,
		"\x00": false,
	}
	for value, want := range cases {
		if got := isVisibleASCII(value); got != want {
			t.Errorf("isVisibleASCII(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestIsHeaderNameBoundaries(t *testing.T) {
	t.Parallel()
	valid := []string{"a", "z", "A", "Z", "0", "9", "!", "~", "-", "`", "X-Remote-User"}
	for _, name := range valid {
		if !isHeaderName(name) {
			t.Errorf("isHeaderName(%q) = false, want true", name)
		}
	}
	// Each is the neighbour just outside a character range of the token rule.
	invalid := []string{"{", "@", "[", "/", ":", " ", "(", "\x7f", "é"}
	for _, name := range invalid {
		if isHeaderName(name) {
			t.Errorf("isHeaderName(%q) = true, want false", name)
		}
	}
}

func TestForwardAuthAcceptsSpaceInsideAHeaderValue(t *testing.T) {
	t.Parallel()
	forward := mustForwardAuth(t, "Remote-User", "10.0.0.0/8", "")
	request := requestFrom("10.1.2.3:4000", "Remote-User", "alice smith")
	if user, ok := forward.Identify(request); !ok || user != "alice smith" {
		t.Fatalf("Identify = %q, %v", user, ok)
	}
}

func TestLockoutSaturatesInsteadOfWrappingTheFailureCount(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	lockout := NewLockout(clock.Now)
	lockout.failures[1] = lockoutEntry{failures: math.MaxUint32, last: clock.Now()}
	if got := lockout.RecordFailure(1); got != LockoutMax {
		t.Fatalf("penalty at the saturated count = %v, want %v", got, LockoutMax)
	}
	if !lockout.IsLocked(1) {
		t.Fatal("a saturated account must stay locked")
	}
}

func phcWith(params string, saltLen, keyLen int) string {
	encode := base64.RawStdEncoding.EncodeToString
	return "$argon2id$v=19$" + params + "$" + encode(make([]byte, saltLen)) + "$" + encode(make([]byte, keyLen))
}

func TestParsePHCAcceptsAHashWithoutAVersionField(t *testing.T) {
	t.Parallel()
	hash := strings.Replace(phcWith("m=8,t=1,p=1", 8, minOutputLen), "$v=19", "", 1)
	if _, err := parsePHC(hash); err != nil {
		t.Fatalf("parsePHC without a version: %v", err)
	}
}

func TestParsePHCKeyLengthBoundary(t *testing.T) {
	t.Parallel()
	if _, err := parsePHC(phcWith("m=8,t=1,p=1", 8, minOutputLen)); err != nil {
		t.Fatalf("a key of exactly minOutputLen bytes: %v", err)
	}
	if _, err := parsePHC(phcWith("m=8,t=1,p=1", 8, minOutputLen-1)); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("a key one byte short: err = %v, want ErrInvalidHash", err)
	}
}

func TestParsePHCParameterBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		params string
		valid  bool
	}{
		{"threads at the uint8 limit", "m=2040,t=1,p=255", true},
		{"threads past the uint8 limit", "m=4096,t=1,p=256", false},
		{"memory exactly 8 KiB per lane", "m=16,t=1,p=2", true},
		{"memory one under 8 KiB per lane", "m=15,t=1,p=2", false},
		{"memory under 8 KiB per lane with several lanes", "m=8,t=1,p=2", false},
		{"memory at the verify cap", "m=1048576,t=1,p=1", true},
		{"memory over the verify cap", "m=1048577,t=1,p=1", false},
		{"zero passes", "m=16,t=0,p=1", false},
		{"zero lanes", "m=16,t=1,p=0", false},
	}
	for _, c := range cases {
		_, err := parsePHC(phcWith(c.params, 8, 32))
		if c.valid && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if !c.valid && !errors.Is(err, ErrInvalidHash) {
			t.Errorf("%s: err = %v, want ErrInvalidHash", c.name, err)
		}
	}
}

func TestNewPasswordWorkDefaultsToTheCPUCount(t *testing.T) {
	t.Parallel()
	for _, limit := range []int{0, -1} {
		if got := NewPasswordWork(limit).Limit(); got != runtime.NumCPU() {
			t.Errorf("NewPasswordWork(%d).Limit() = %d, want %d", limit, got, runtime.NumCPU())
		}
	}
}

func TestPasswordWorkAvailableCountsTheHeldSlots(t *testing.T) {
	t.Parallel()
	work := NewPasswordWork(3)
	work.slots <- struct{}{}
	if got := work.Available(); got != 2 {
		t.Fatalf("Available with one slot held = %d, want 2", got)
	}
	work.slots <- struct{}{}
	work.slots <- struct{}{}
	if got := work.Available(); got != 0 {
		t.Fatalf("Available with every slot held = %d, want 0", got)
	}
	// A full limiter must make a cancelled caller give up, not wait.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := work.SpendVerifyCost(ctx, "x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SpendVerifyCost on a full limiter: %v", err)
	}
}

func TestNormalizeSetupTokenUppercasesTheFirstLetterOfTheAlphabet(t *testing.T) {
	t.Parallel()
	if got := normalizeSetupToken("a-z A"); got != "AZA" {
		t.Fatalf("normalizeSetupToken = %q, want AZA", got)
	}
}

// The rejection limit keeps the draw uniform; a wrong limit skews some
// characters by a quarter, far outside this tolerance.
func TestRandomStringIsUniform(t *testing.T) {
	t.Parallel()
	const samples = 620000
	counts := map[rune]int{}
	for _, c := range randomString(alphanumeric, samples) {
		counts[c]++
	}
	mean := samples / len(alphanumeric)
	for _, c := range alphanumeric {
		if diff := counts[c] - mean; diff < -mean/20 || diff > mean/20 {
			t.Errorf("character %q drawn %d times, mean %d", c, counts[c], mean)
		}
	}
}
