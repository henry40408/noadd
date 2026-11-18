package dnsserver

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/henry40408/noadd/internal/cache"
	"github.com/henry40408/noadd/internal/dns"
)

func TestFormDecodeEscapeBoundaries(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"a+b":          "a b",
		"%41":          "A",
		"%61%7a":       "az",
		"%2f%3A":       "/:",
		"%00%1f":       "\x00\x1f",
		"%e3%81%82":    "あ",
		"100%25+ok":    "100% ok",
		"end%41":       "endA",
		"%41end":       "Aend",
		"%41%":         "A%",
		"%A%41":        "%AA",
		"%":            "%",
		"%4":           "%4",
		"x%4":          "x%4",
		"%zz":          "%zz",
		"%4z":          "%4z",
		"%z4":          "%z4",
		"%G1":          "%G1",
		"%g1":          "%g1",
		"%/0":          "%/0",
		"%:0":          "%:0",
		"%@0":          "%@0",
		"%`0":          "%`0",
		"%ff":          "\ufffd",
		"%f0%9f%98%80": "😀",
	}
	for input, want := range cases {
		if got := formDecode(input); got != want {
			t.Errorf("formDecode(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestUnhexBoundaries(t *testing.T) {
	t.Parallel()
	cases := map[byte]byte{'0': 0, '9': 9, 'a': 10, 'f': 15, 'A': 10, 'F': 15}
	for digit, want := range cases {
		if got := unhex(digit); got != want {
			t.Errorf("unhex(%q) = %d, want %d", digit, got, want)
		}
	}
}

func TestPostContentTypeBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"plain", "application/dns-message", true},
		{"tilde is the last printable byte", "application/dns-message; x=~", true},
		{"tab is allowed", "application/dns-message;\tx=1", true},
		{"space is allowed", "application/dns-message; charset=utf-8", true},
		{"delete is refused", "application/dns-message; x=\x7f", false},
		{"other control byte is refused", "application/dns-message; x=\x01", false},
		{"non ASCII is refused", "application/dns-message; x=é", false},
		{"control byte in the first position", "\x01application/dns-message", false},
		{"other type", "text/plain", false},
	}
	for _, c := range cases {
		header := http.Header{"Content-Type": {c.value}}
		if got := postContentTypeOK(header); got != c.want {
			t.Errorf("%s: postContentTypeOK(%q) = %v, want %v", c.name, c.value, got, c.want)
		}
	}
	if !postContentTypeOK(http.Header{}) {
		t.Error("an absent Content-Type must be accepted")
	}
}

func TestNewDoHUsesTheGivenLogger(t *testing.T) {
	t.Parallel()
	logger := quietLogger()
	if got := NewDoH(DoHConfig{Slog: logger}).log; got != logger {
		t.Fatal("the configured logger was replaced")
	}
	if NewDoH(DoHConfig{}).log == nil {
		t.Fatal("a missing logger must fall back to the default")
	}
}

func TestNewSizesTheInflightLimits(t *testing.T) {
	t.Parallel()
	limited := New(Config{MaxInflight: 3})
	t.Cleanup(limited.Close)
	if cap(limited.permits) != 3 || cap(limited.datagramSlots) != 3*datagramBacklogFactor {
		t.Fatalf("permits %d, datagram slots %d", cap(limited.permits), cap(limited.datagramSlots))
	}
	unlimited := New(Config{})
	t.Cleanup(unlimited.Close)
	if unlimited.permits != nil || unlimited.datagramSlots != nil {
		t.Fatal("MaxInflight 0 must mean no limit")
	}
}

func TestLowerASCII(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"A": "a", "Z": "z", "ADS": "ads", "Ads": "ads", "adS": "ads",
		"ads": "ads", "a.b-c.d1": "a.b-c.d1", "@[`{": "@[`{", "A.COM": "a.com",
	}
	for input, want := range cases {
		if got := lowerASCII(input); got != want {
			t.Errorf("lowerASCII(%q) = %q, want %q", input, got, want)
		}
	}
}

func cachedAnswerBytes(t *testing.T, ttl uint32) []byte {
	t.Helper()
	return mustPack(t, plainAnswerWithTTL(ttl))
}

func plainAnswerWithTTL(ttl uint32) *mdns.Msg {
	request := new(mdns.Msg)
	request.SetQuestion("a.example.com.", mdns.TypeA)
	response := plainAnswer(request, false)
	response.Answer[0].Header().Ttl = ttl
	return response
}

func mustPack(t *testing.T, message *mdns.Msg) []byte {
	t.Helper()
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestAnswerFromCacheAgesTheTTLsAndReportsTheRemainder(t *testing.T) {
	t.Parallel()
	wire := cachedAnswerBytes(t, 100)
	entry := cache.Entry{
		Bytes: wire, TTL: 100 * time.Second, Elapsed: 30 * time.Second,
		TTLOffsets: dns.TTLOffsets(wire), AuthenticatedData: true,
	}
	got := answerFromCache(entry, 0xBEEF)
	message := unpack(t, got.bytes)
	if message.Id != 0xBEEF || message.Answer[0].Header().Ttl != 70 {
		t.Fatalf("id %#x, ttl %d, want 0xbeef and 70", message.Id, message.Answer[0].Header().Ttl)
	}
	if got.minTTL != 70 || !got.cached || !got.authenticated {
		t.Fatalf("answer = %+v", got)
	}
	if !bytes.Equal(entry.Bytes, wire) {
		t.Fatal("the cached bytes must not be modified")
	}
}

func TestAnswerFromCacheClampsTheRemainingTTL(t *testing.T) {
	t.Parallel()
	expired := answerFromCache(cache.Entry{TTL: 10 * time.Second, Elapsed: 25 * time.Second}, 1)
	if expired.minTTL != 0 {
		t.Fatalf("an expired entry reports max-age %d, want 0", expired.minTTL)
	}
	const centuries = 200 * 365 * 24 * time.Hour
	huge := answerFromCache(cache.Entry{TTL: centuries}, 1)
	if huge.minTTL != 1<<32-1 {
		t.Fatalf("max-age = %d, want the uint32 maximum", huge.minTTL)
	}
}

func TestAnswerFromCachePatchesTheIDOfAMinimalMessage(t *testing.T) {
	t.Parallel()
	got := answerFromCache(cache.Entry{Bytes: []byte{0, 0}}, 0x1234)
	if len(got.bytes) != 2 || binary.BigEndian.Uint16(got.bytes) != 0x1234 {
		t.Fatalf("bytes = %x", got.bytes)
	}
}

// syncBuffer lets a background refresh write the log while the test reads it.
type syncBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}

func debugLogger(sink *syncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestStaleRefreshPanicIsLogged(t *testing.T) {
	t.Parallel()
	var sink syncBuffer
	handler := New(Config{Slog: debugLogger(&sink)})
	t.Cleanup(handler.cancelLifetime)
	handler.startStaleRefresh(cache.Key{}, []byte{0, 1})
	handler.refreshes.Wait()
	if !strings.Contains(sink.String(), "cache.stale_refresh_panicked") {
		t.Fatalf("log = %q, want the panic reported", sink.String())
	}
}

func TestFailedStaleRefreshIsLoggedAndCachesNothing(t *testing.T) {
	t.Parallel()
	var sink syncBuffer
	handler := newTestHandler(t, handlerOptions{upstreamTimeout: 100 * time.Millisecond})
	handler.log = debugLogger(&sink)
	key := cache.Key{Domain: "a.example.com.", QueryType: mdns.TypeA}
	handler.refresh(key, queryBytes(t, 7, "a.example.com.", mdns.TypeA))
	if !strings.Contains(sink.String(), "cache.stale_refresh_failed") {
		t.Fatalf("log = %q, want the failure reported", sink.String())
	}
	if _, state := handler.cache.Get(key); state != cache.Miss {
		t.Fatal("a failed refresh must not store anything")
	}
}

func TestIsHexBoundaries(t *testing.T) {
	t.Parallel()
	for _, digit := range []byte("09afAF") {
		if !isHex(digit) {
			t.Errorf("isHex(%q) = false, want true", digit)
		}
	}
	for _, other := range []byte("/:`g@G") {
		if isHex(other) {
			t.Errorf("isHex(%q) = true, want false", other)
		}
	}
}
