package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mustForwardAuth(t *testing.T, header, cidrs, logout string) *ForwardAuth {
	t.Helper()
	forward, err := NewForwardAuth(header, cidrs, logout)
	if err != nil || forward == nil {
		t.Fatalf("NewForwardAuth: %v, %v", forward, err)
	}
	return forward
}

func requestFrom(peer string, headers ...string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = peer
	for i := 0; i+1 < len(headers); i += 2 {
		request.Header.Add(headers[i], headers[i+1])
	}
	return request
}

// Rust: both_empty_disables_forward_auth and the from_args error cases.
func TestNewForwardAuthConfiguration(t *testing.T) {
	if forward, err := NewForwardAuth("", "", ""); forward != nil || err != nil {
		t.Fatalf("both empty must disable: %v %v", forward, err)
	}
	if _, err := NewForwardAuth("Remote-User", "", ""); !errors.Is(err, ErrForwardAuthMissingTrustedProxies) {
		t.Errorf("header without CIDRs: %v", err)
	}
	if _, err := NewForwardAuth("", "127.0.0.1/32", ""); !errors.Is(err, ErrForwardAuthMissingHeader) {
		t.Errorf("CIDRs without header: %v", err)
	}
	if _, err := NewForwardAuth("Remote-User", ",,", ""); !errors.Is(err, ErrForwardAuthMissingTrustedProxies) {
		t.Errorf("CIDRs that parse to nothing: %v", err)
	}
	if _, err := NewForwardAuth("bad header\n", "127.0.0.1/32", ""); err == nil || !strings.Contains(err.Error(), "invalid header name") {
		t.Errorf("bad header name: %v", err)
	}
	if _, err := NewForwardAuth("Remote-User", "not-a-cidr", ""); err == nil || !strings.Contains(err.Error(), "invalid CIDR in --forward-auth-trusted-proxies") {
		t.Errorf("bad CIDR: %v", err)
	}
}

func TestForwardAuthLogoutURL(t *testing.T) {
	forward := mustForwardAuth(t, "Remote-User", "10.0.0.0/8", "  https://sso.example/logout  ")
	if url, ok := forward.LogoutURL(); !ok || url != "https://sso.example/logout" {
		t.Fatalf("url=%q ok=%v", url, ok)
	}
	if _, ok := mustForwardAuth(t, "Remote-User", "10.0.0.0/8", "   ").LogoutURL(); ok {
		t.Fatal("blank logout URL must be absent")
	}
	if forward.TrustedLen() != 1 || forward.Header() == "" {
		t.Fatal("startup logging accessors")
	}
}

func TestIdentify(t *testing.T) {
	forward := mustForwardAuth(t, "Remote-User", "10.0.0.0/8", "")
	long := strings.Repeat("a", MaxUsernameLen+1)
	cases := []struct {
		name    string
		request *http.Request
		want    string
	}{
		{"untrusted loopback peer", requestFrom("127.0.0.1:1", "Remote-User", "alice"), ""},
		{"outside the allow-list", requestFrom("192.168.1.5:1", "Remote-User", "alice"), ""},
		{"unparseable peer", requestFrom("garbage", "Remote-User", "alice"), ""},
		{"no header", requestFrom("10.0.0.5:1"), ""},
		{"empty username", requestFrom("10.0.0.5:1", "Remote-User", "   "), ""},
		{"oversized username", requestFrom("10.0.0.5:1", "Remote-User", long), ""},
		{"control character", requestFrom("10.0.0.5:1", "Remote-User", "ali\tce"), ""},
		{"non-ASCII header bytes", requestFrom("10.0.0.5:1", "Remote-User", "al\xe9ice"), ""},
		{"duplicated header", requestFrom("10.0.0.5:1", "Remote-User", "alice", "Remote-User", "bob"), ""},
		{"trims and returns", requestFrom("10.0.0.5:1", "Remote-User", "alice "), "alice"},
		{"mapped IPv4 peer", requestFrom("[::ffff:10.0.0.5]:1", "Remote-User", "alice"), "alice"},
		{"case-insensitive header", requestFrom("10.0.0.5:1", "remote-user", "alice"), "alice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			user, ok := forward.Identify(c.request)
			if ok != (c.want != "") || user != c.want {
				t.Fatalf("user=%q ok=%v, want %q", user, ok, c.want)
			}
		})
	}
}

func TestIdentifyIgnoresForwardedForSpoofing(t *testing.T) {
	forward := mustForwardAuth(t, "Remote-User", "10.0.0.0/8", "")
	request := requestFrom("203.0.113.9:1", "Remote-User", "root", "X-Forwarded-For", "10.0.0.5")
	if _, ok := forward.Identify(request); ok {
		t.Fatal("X-Forwarded-For must not vouch for the peer")
	}
}

func TestNormalizeUsername(t *testing.T) {
	if name, ok := NormalizeUsername("  伊莉雅  "); !ok || name != "伊莉雅" {
		t.Fatalf("name=%q ok=%v", name, ok)
	}
	if _, ok := NormalizeUsername(strings.Repeat("字", MaxUsernameLen)); !ok {
		t.Fatal("64 characters (not bytes) must pass")
	}
	for _, bad := range []string{"", " ", strings.Repeat("字", MaxUsernameLen+1), "a\x00b", "a\u0085b"} {
		if _, ok := NormalizeUsername(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
