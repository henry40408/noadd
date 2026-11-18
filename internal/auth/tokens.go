// Package auth holds the authentication primitives: password hashing and
// policy, token generation and hashing, the in-memory session store, account
// lockout, per-IP limiters and forward-auth identification.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/blake2b"
)

const (
	sessionTokenLen = 64
	apiKeyPrefix    = "noadd_"
	// 40 alphanumeric characters are about 238 bits of entropy.
	apiKeyBodyLen = 40
	// displayPrefixBodyLen is how many body characters join apiKeyPrefix in the
	// prefix shown next to a stored key.
	displayPrefixBodyLen = 4

	alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	// setupTokenAlphabet is Crockford base32: no I, L, O or U.
	setupTokenAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// setupTokenGroupLen is the length of each half of the displayed token.
	setupTokenGroupLen = 5

	// SessionLogSaltKey is the settings key holding the hex-encoded audit salt.
	SessionLogSaltKey = "session_log_salt"
	// SessionLogSaltLen is the salt length in bytes.
	SessionLogSaltLen = 16
)

// randomString draws n characters uniformly from alphabet. It rejects bytes
// that would bias the choice, so alphabets that do not divide 256 stay uniform.
func randomString(alphabet string, n int) string {
	limit := 256 - 256%len(alphabet)
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		rand.Read(buf)
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out = append(out, alphabet[int(b)%len(alphabet)])
			if len(out) == n {
				break
			}
		}
	}
	return string(out)
}

// NewSessionToken returns a fresh 64-character alphanumeric session token.
func NewSessionToken() string {
	return randomString(alphanumeric, sessionTokenLen)
}

// NewAPIKey mints an API key. The full token is shown to the user once; only
// the hash is stored.
func NewAPIKey() (full, displayPrefix, hash string) {
	body := randomString(alphanumeric, apiKeyBodyLen)
	full = apiKeyPrefix + body
	displayPrefix = apiKeyPrefix + body[:displayPrefixBodyLen]
	return full, displayPrefix, HashToken(full)
}

// NewSetupToken returns 10 Crockford base32 symbols (50 bits).
func NewSetupToken() string {
	return randomString(setupTokenAlphabet, setupTokenGroupLen*2)
}

// HashToken is BLAKE2b-512 of secret as lower hex. It is unsalted and fast on
// purpose: every input is high-entropy random, so there is no dictionary to
// defend against, and the digest must stay indexable for an equality lookup.
func HashToken(secret string) string {
	sum := blake2b.Sum512([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SidHash is the stable, salted identifier for correlating session events in
// logs: the first 8 bytes of BLAKE2b-512(salt || tokenHash). The salt keeps it
// from matching a stolen database row. Never log the token itself.
func SidHash(salt [SessionLogSaltLen]byte, tokenHash string) string {
	hasher, _ := blake2b.New512(nil)
	hasher.Write(salt[:])
	hasher.Write([]byte(tokenHash))
	return hex.EncodeToString(hasher.Sum(nil)[:8])
}

// SessionCookieName is the cookie name to emit. A browser silently drops a
// __Host- cookie that lacks Secure, so plain-HTTP deployments use "session".
func SessionCookieName(secure bool) string {
	if secure {
		return "__Host-session"
	}
	return "session"
}

func normalizeSetupToken(raw string) string {
	var out strings.Builder
	for _, r := range raw {
		if r == '-' || isSpace(r) {
			continue
		}
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		out.WriteRune(r)
	}
	return out.String()
}

func randomBytes(buf []byte) { rand.Read(buf) }
