package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/henry40408/noadd/internal/netx"
)

// MaxUsernameLen is the longest accepted username, in characters.
const MaxUsernameLen = 64

// Configuration errors of --forward-auth-*; the messages match the Rust ones.
var (
	ErrForwardAuthMissingTrustedProxies = errors.New(
		"--forward-auth-header requires a non-empty --forward-auth-trusted-proxies; " +
			"an unrestricted header would let any client forge an operator identity")
	ErrForwardAuthMissingHeader = errors.New("--forward-auth-trusted-proxies was set without --forward-auth-header")
)

// ForwardAuth trusts a username injected by a fronting proxy (Authelia,
// Authentik, oauth2-proxy, ...) via a configurable request header.
//
// Trust is deliberately stricter than netx.ClientIP: a forged X-Forwarded-For
// only pollutes logs and rate limits, but a forged header here is a full
// operator session. So it has its own CIDR allow-list and loopback gets no
// implicit trust.
type ForwardAuth struct {
	header    string
	trusted   netx.TrustedProxies
	logoutURL string
}

// NewForwardAuth validates --forward-auth-header, -trusted-proxies and
// -logout-url. It returns nil when header and CIDRs are both empty. Either
// without the other is an error: a header with no allow-list trusts any
// client, and an allow-list with no header does nothing.
func NewForwardAuth(header, cidrs, logoutURL string) (*ForwardAuth, error) {
	header = strings.TrimSpace(header)
	cidrs = strings.TrimSpace(cidrs)
	if header == "" && cidrs == "" {
		return nil, nil
	}
	if header == "" {
		return nil, ErrForwardAuthMissingHeader
	}
	if cidrs == "" {
		return nil, ErrForwardAuthMissingTrustedProxies
	}
	if !isHeaderName(header) {
		return nil, fmt.Errorf("invalid header name `%s` for --forward-auth-header", header)
	}
	trusted, err := netx.ParseTrustedProxies(cidrs)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR in --forward-auth-trusted-proxies: %w", err)
	}
	// A list that parsed to no CIDRs (",,") is the same footgun as an empty one.
	if trusted.IsEmpty() {
		return nil, ErrForwardAuthMissingTrustedProxies
	}
	return &ForwardAuth{
		header:    http.CanonicalHeaderKey(header),
		trusted:   trusted,
		logoutURL: strings.TrimSpace(logoutURL),
	}, nil
}

// Header is the configured header name, for startup logging.
func (f *ForwardAuth) Header() string { return f.header }

// TrustedLen is the number of trusted CIDRs, for startup logging.
func (f *ForwardAuth) TrustedLen() int { return f.trusted.Len() }

// LogoutURL is the configured proxy/SSO logout URL, if any.
func (f *ForwardAuth) LogoutURL() (string, bool) { return f.logoutURL, f.logoutURL != "" }

// Identify resolves the username asserted by the proxy. ok is false when the
// request cannot be trusted: peer outside the allow-list, header missing or
// repeated, or a username that fails NormalizeUsername.
func (f *ForwardAuth) Identify(r *http.Request) (user string, ok bool) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "", false
	}
	// Dual-stack listeners report IPv4 peers as ::ffff:a.b.c.d. A zone is
	// dropped because Prefix.Contains never matches a zoned address.
	if !f.trusted.Contains(peer.Addr().Unmap().WithZone("")) {
		return "", false
	}
	// A repeated header (a client value the proxy failed to strip plus its own)
	// is rejected: picking either one is a spoofing hazard.
	values := r.Header.Values(f.header)
	if len(values) != 1 || !isVisibleASCII(values[0]) {
		return "", false
	}
	return NormalizeUsername(values[0])
}

// NormalizeUsername trims and validates a username: non-empty, at most
// MaxUsernameLen characters, and free of control characters (which could
// smuggle terminal escapes into logs). It is the one rule for every way an
// account is created; sign-in deliberately does not apply it, so accounts that
// predate it can still log in.
func NormalizeUsername(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || utf8.RuneCountInString(trimmed) > MaxUsernameLen {
		return "", false
	}
	if strings.IndexFunc(trimmed, unicode.IsControl) >= 0 {
		return "", false
	}
	return trimmed, true
}

// isVisibleASCII mirrors the Rust HeaderValue::to_str rule: visible ASCII,
// space and tab only.
func isVisibleASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '\t' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}

func isHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		isToken := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
		if !isToken {
			return false
		}
	}
	return true
}
