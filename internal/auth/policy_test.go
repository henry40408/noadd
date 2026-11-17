package auth

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPolicyLengthMessages(t *testing.T) {
	cases := []struct{ password, want string }{
		{strings.Repeat("a", 11), "password must be at least 12 characters"},
		{strings.Repeat("a", 129), "password must be at most 128 characters"},
		// Characters, not bytes: 11 CJK characters are 33 bytes.
		{strings.Repeat("密", 11), "password must be at least 12 characters"},
	}
	for _, c := range cases {
		err := ValidatePolicy(c.password)
		var policy *PolicyError
		if !errors.As(err, &policy) || policy.Message != c.want {
			t.Errorf("%d bytes: err = %v, want %q", len(c.password), err, c.want)
		}
	}
}

func TestPolicyAcceptsAStrongPassphrase(t *testing.T) {
	if err := ValidatePolicy("zx-initial-Strong-passphrase-9143-lamp", "admin"); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRejectionWording(t *testing.T) {
	err := ValidatePolicy("password1234", "admin")
	want := "password rejected: it is too easy to guess. Use a longer passphrase of several unrelated words."
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v", err)
	}
}

// Parity with the Rust zxcvbn 3.1 verdicts captured from release 0.41.1 over
// POST /api/users/me/password (username "admin"). Only accept/reject is
// observable there, so only that is compared.
func TestPolicyParityWithRust(t *testing.T) {
	raw, err := os.ReadFile("testdata/zxcvbn_scores.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Password string `json:"password"`
			Accepted bool   `json:"accepted"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var mismatches []string
	for _, c := range fixture.Cases {
		if accepted := ValidatePolicy(c.Password, "admin") == nil; accepted != c.Accepted {
			mismatches = append(mismatches, c.Password)
		}
	}
	t.Logf("%d of %d verdicts differ from Rust", len(mismatches), len(fixture.Cases))
	if len(mismatches) > 0 {
		t.Logf("differing passwords: %q", mismatches)
	}
	// Plan section 7 decision 3 accepts the Go score where the libraries
	// disagree; this bound only catches a gross regression of the port.
	if limit := len(fixture.Cases) / 4; len(mismatches) > limit {
		t.Fatalf("%d mismatches exceed %d", len(mismatches), limit)
	}
}
