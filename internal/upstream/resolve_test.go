package upstream

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type fakeResolver struct {
	addrs []netip.Addr
	err   error
	calls int
}

func (r *fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls++
	return r.addrs, r.err
}

func TestFirstAddressSkipsLookupForAnIPLiteral(t *testing.T) {
	resolver := &fakeResolver{}
	forwarder := New(context.Background(), Config{Servers: []string{"127.0.0.1:1"}, Resolver: resolver})
	addr, ok := forwarder.firstAddress(context.Background(), "192.0.2.5:53", "192.0.2.5")
	if !ok || addr != netip.MustParseAddr("192.0.2.5") || resolver.calls != 0 {
		t.Fatalf("addr=%v ok=%v lookups=%d", addr, ok, resolver.calls)
	}
}

func TestFirstAddressTakesTheFirstResolvedAddress(t *testing.T) {
	resolver := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}}
	forwarder := New(context.Background(), Config{Servers: []string{"127.0.0.1:1"}, Resolver: resolver})
	addr, ok := forwarder.firstAddress(context.Background(), "dns.example:853", "dns.example")
	if !ok || addr != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("addr=%v ok=%v", addr, ok)
	}
}

func TestFirstAddressFailsOnLookupErrorOrEmptyAnswer(t *testing.T) {
	for name, resolver := range map[string]*fakeResolver{
		"lookup error": {err: errors.New("no such host")},
		"empty answer": {},
	} {
		forwarder := New(context.Background(), Config{Servers: []string{"127.0.0.1:1"}, Resolver: resolver})
		if addr, ok := forwarder.firstAddress(context.Background(), "dns.example:853", "dns.example"); ok {
			t.Errorf("%s: resolved to %v", name, addr)
		}
	}
}

func TestNetResolverResolvesAnIPLiteralWithoutTheNetwork(t *testing.T) {
	addrs, err := netResolver{}.LookupNetIP(context.Background(), "ip", "127.0.0.1")
	if err != nil || len(addrs) != 1 || addrs[0].Unmap() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("addrs=%v err=%v", addrs, err)
	}
}
