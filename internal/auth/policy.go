package auth

import (
	"fmt"
	"unicode/utf8"

	zxcvbn "github.com/ccojocar/zxcvbn-go"
)

const (
	// MinPasswordLength and MaxPasswordLength bound a password being set. The
	// maximum bounds Argon2's work; an overlong password is rejected rather
	// than truncated, which would let two passwords open the same account.
	MinPasswordLength = 12
	MaxPasswordLength = 128
	// MaxLoginPasswordLength only bounds unauthenticated Argon2 work at
	// sign-in; it is far looser so passwords set before the limit still work.
	MaxLoginPasswordLength = 1024

	// minPasswordScore is the weakest zxcvbn score a new password may have.
	// Three is "moderate protection from an offline slow-hash scenario"; four
	// demands a long passphrase, and online guessing is already throttled.
	minPasswordScore = 3
)

// PolicyError is a rejected new password; Error is the message shown to the
// operator.
type PolicyError struct{ Message string }

func (e *PolicyError) Error() string { return e.Message }

// ValidatePolicy checks a to-be-set password. Length is checked before
// guessability, as the more actionable message. userInputs (the username)
// make zxcvbn penalise passwords built from them.
func ValidatePolicy(password string, userInputs ...string) error {
	length := utf8.RuneCountInString(password)
	if length < MinPasswordLength {
		return &PolicyError{fmt.Sprintf("password must be at least %d characters", MinPasswordLength)}
	}
	if length > MaxPasswordLength {
		return &PolicyError{fmt.Sprintf("password must be at most %d characters", MaxPasswordLength)}
	}
	if zxcvbn.PasswordStrength(password, userInputs).Score >= minPasswordScore {
		return nil
	}
	// The Go zxcvbn port has no feedback text, so the reason is always the
	// generic one the Rust code uses when zxcvbn offers no warning.
	return &PolicyError{"password rejected: it is too easy to guess. Use a longer passphrase of several unrelated words."}
}
