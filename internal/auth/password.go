package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters for new hashes (the Rust defaults): 19 MiB, 2 passes,
// 1 lane, 32-byte output, 16-byte salt.
const (
	argonMemoryKiB = 19456
	argonTime      = 2
	argonThreads   = 1
	argonKeyLen    = 32
	argonSaltLen   = 16
	argonVersion   = 19

	// maxVerifyMemoryKiB bounds a stored hash's memory cost so a corrupt row
	// cannot make verification allocate without limit.
	maxVerifyMemoryKiB = 1 << 20
	minOutputLen       = 4

	// NoPasswordSentinel is stored in users.password_hash for operators
	// provisioned from a forward-auth header. "!" is not a valid PHC string, so
	// it never matches (the /etc/shadow convention).
	NoPasswordSentinel = "!"
)

// ErrInvalidHash is returned for a stored hash that is not a usable PHC
// string. Callers must check HasNoPassword first: the sentinel is an error
// here, while a passwordless account must get an ordinary 401, not a 500.
var ErrInvalidHash = errors.New("invalid password hash")

var phcEncoding = base64.RawStdEncoding

// HashPassword hashes password with Argon2id and a random salt, returning a
// PHC string.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVersion, argonMemoryKiB, argonTime, argonThreads,
		phcEncoding.EncodeToString(salt), phcEncoding.EncodeToString(key)), nil
}

// HasNoPassword reports whether the stored hash marks an account that cannot
// authenticate with a password.
func HasNoPassword(hash string) bool { return hash == NoPasswordSentinel }

type phcHash struct {
	id      string
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	key     []byte
}

// parsePHC reads "$argon2id$v=19$m=..,t=..,p=..$salt$hash". The parameters
// stored in the hash are used, so hashes made under older settings verify.
func parsePHC(encoded string) (phcHash, error) {
	parsed := phcHash{memory: argonMemoryKiB, time: argonTime, threads: argonThreads}
	fields := strings.Split(encoded, "$")
	if len(fields) < 5 || fields[0] != "" {
		return parsed, ErrInvalidHash
	}
	parsed.id = fields[1]
	if parsed.id != "argon2id" && parsed.id != "argon2i" {
		return parsed, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidHash, parsed.id)
	}
	rest := fields[2:]
	if version, found := strings.CutPrefix(rest[0], "v="); found {
		if version != strconv.Itoa(argonVersion) {
			return parsed, fmt.Errorf("%w: unsupported version %q", ErrInvalidHash, version)
		}
		rest = rest[1:]
	}
	if len(rest) != 3 {
		return parsed, ErrInvalidHash
	}
	if err := parsed.applyParams(rest[0]); err != nil {
		return parsed, err
	}
	var err error
	if parsed.salt, err = phcEncoding.DecodeString(rest[1]); err != nil {
		return parsed, fmt.Errorf("%w: salt: %v", ErrInvalidHash, err)
	}
	if parsed.key, err = phcEncoding.DecodeString(rest[2]); err != nil {
		return parsed, fmt.Errorf("%w: hash: %v", ErrInvalidHash, err)
	}
	if len(parsed.key) < minOutputLen || len(parsed.salt) == 0 {
		return parsed, ErrInvalidHash
	}
	return parsed, nil
}

func (p *phcHash) applyParams(text string) error {
	for _, pair := range strings.Split(text, ",") {
		name, value, found := strings.Cut(pair, "=")
		number, err := strconv.ParseUint(value, 10, 32)
		if !found || err != nil {
			return fmt.Errorf("%w: parameter %q", ErrInvalidHash, pair)
		}
		switch name {
		case "m":
			p.memory = uint32(number)
		case "t":
			p.time = uint32(number)
		case "p":
			if number > 255 {
				return fmt.Errorf("%w: parameter %q", ErrInvalidHash, pair)
			}
			p.threads = uint8(number)
		}
	}
	if p.time == 0 || p.threads == 0 || p.memory < 8*uint32(p.threads) || p.memory > maxVerifyMemoryKiB {
		return fmt.Errorf("%w: parameters out of range", ErrInvalidHash)
	}
	return nil
}

// VerifyPassword checks password against a PHC hash in constant time. A wrong
// password is (false, nil); an unparseable hash is an error.
func VerifyPassword(password, encoded string) (bool, error) {
	parsed, err := parsePHC(encoded)
	if err != nil {
		return false, err
	}
	derive := argon2.IDKey
	if parsed.id == "argon2i" {
		derive = argon2.Key
	}
	key := derive([]byte(password), parsed.salt, parsed.time, parsed.memory, parsed.threads, uint32(len(parsed.key)))
	return subtle.ConstantTimeCompare(key, parsed.key) == 1, nil
}
