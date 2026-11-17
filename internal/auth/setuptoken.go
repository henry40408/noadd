package auth

import (
	"crypto/subtle"
	"net/netip"
	"sync"
	"time"
	"unicode"
)

const (
	setupAttempts = 5
	setupWindow   = 60 * time.Second
)

func isSpace(r rune) bool { return unicode.IsSpace(r) }

// SetupToken is the one-time first-run secret printed to the server's stderr.
// It proves the caller can read that output, so a stranger who reaches an
// unconfigured instance first cannot claim it. It lives in memory only.
//
// It also owns the per-IP throttle on setup attempts, a budget separate from
// sign-in so setting up does not spend the operator's login attempts.
type SetupToken struct {
	mu       sync.Mutex
	token    string
	attempts *Limiter
}

func newSetupToken(token string, now func() time.Time) *SetupToken {
	return &SetupToken{token: token, attempts: NewLimiter(setupAttempts, setupWindow, now)}
}

// GenerateSetupToken makes a SetupToken with a fresh random token.
func GenerateSetupToken(now func() time.Time) *SetupToken {
	return newSetupToken(NewSetupToken(), now)
}

// FixedSetupToken makes a SetupToken with a known token, for tests.
func FixedSetupToken(token string, now func() time.Time) *SetupToken {
	return newSetupToken(normalizeSetupToken(token), now)
}

// NoSetupToken refuses every attempt; used when setup is not available.
func NoSetupToken(now func() time.Time) *SetupToken {
	return newSetupToken("", now)
}

// AllowAttempt spends one setup attempt for ip and reports false when over
// budget. An attempt is never refunded.
func (s *SetupToken) AllowAttempt(ip netip.Addr) bool {
	if !s.attempts.Check(ip) {
		return false
	}
	s.attempts.Record(ip)
	return true
}

// Display is the token as shown to the operator (XXXXX-XXXXX), if still live.
func (s *SetupToken) Display() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == "" {
		return "", false
	}
	head := min(setupTokenGroupLen, len(s.token))
	return s.token[:head] + "-" + s.token[head:], true
}

// Matches compares a submitted token, ignoring case, hyphens and whitespace,
// in constant time.
func (s *SetupToken) Matches(submitted string) bool {
	s.mu.Lock()
	expected := s.token
	s.mu.Unlock()
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(normalizeSetupToken(submitted)), []byte(expected)) == 1
}

// PruneAttempts evicts throttle entries whose window elapsed.
func (s *SetupToken) PruneAttempts() int { return s.attempts.Prune() }

// Clear forgets the token once an operator exists.
func (s *SetupToken) Clear() {
	s.mu.Lock()
	s.token = ""
	s.mu.Unlock()
}
