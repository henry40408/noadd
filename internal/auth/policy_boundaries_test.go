package auth

import (
	"math/rand"
	"strings"
	"testing"
)

// strongPassword is a fixed pseudo-random string, so zxcvbn rates it well at
// any length.
func strongPassword(length int) string {
	random := rand.New(rand.NewSource(1))
	out := make([]byte, length)
	for i := range out {
		out[i] = alphanumeric[random.Intn(len(alphanumeric))]
	}
	return string(out)
}

func TestValidatePolicyLengthBoundaries(t *testing.T) {
	t.Parallel()
	if err := ValidatePolicy(strongPassword(MaxPasswordLength)); err != nil {
		t.Fatalf("a password of exactly MaxPasswordLength characters: %v", err)
	}
	err := ValidatePolicy(strongPassword(MaxPasswordLength + 1))
	if err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("a password one character too long: %v", err)
	}
}

// "purple monkey dishwasher" scores exactly minPasswordScore with zxcvbn, so
// it separates ">= minimum" from "> minimum".
func TestValidatePolicyAcceptsTheMinimumScore(t *testing.T) {
	t.Parallel()
	if err := ValidatePolicy("purple monkey dishwasher"); err != nil {
		t.Fatalf("a password at the minimum score was rejected: %v", err)
	}
}
