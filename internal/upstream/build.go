package upstream

import (
	"context"
	"crypto/tls"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type netResolver struct{}

func (netResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// buildSet resolves the hosts concurrently, so slow lookups do not make startup
// linear in the upstream count, and builds one exchanger per server.
func (f *Forwarder) buildSet(ctx context.Context, servers []string) *upstreamSet {
	set := &upstreamSet{
		servers:   servers,
		timeout:   max(f.cfg.Timeout, f.cfg.MinTimeout),
		entries:   make([]*entry, len(servers)),
		latencies: make([]atomic.Uint64, len(servers)),
	}
	for i := range set.latencies {
		set.latencies[i].Store(math.Float64bits(math.Inf(1)))
	}

	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			set.entries[i] = f.buildEntry(ctx, server)
		}()
	}
	wg.Wait()
	return set
}

// buildEntry returns nil, after logging why, when the server cannot be used.
func (f *Forwarder) buildEntry(ctx context.Context, server string) *entry {
	target, err := parseSpec(server)
	if err != nil {
		f.cfg.Logger.Warn("skipping unparseable upstream entry", "event", "upstream.spec_invalid",
			"server", server, "error", err)
		return nil
	}
	addr, ok := f.firstAddress(ctx, server, target.host)
	if !ok {
		return nil
	}
	dialAddr := net.JoinHostPort(addr.String(), strconv.Itoa(int(target.port)))
	return &entry{label: server, exchanger: f.newExchanger(target, dialAddr)}
}

func (f *Forwarder) newExchanger(target spec, dialAddr string) exchanger {
	switch target.transport {
	case transportTLS:
		return &tlsExchanger{addr: dialAddr, tlsConfig: f.tlsConfigFor(target.host), now: f.cfg.Now}
	case transportHTTPS:
		return newDoHExchanger(target, dialAddr, f.tlsConfigFor(target.host))
	default:
		return &udpExchanger{addr: dialAddr, retransmit: f.cfg.RetransmitInterval}
	}
}

func (f *Forwarder) tlsConfigFor(serverName string) *tls.Config {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if f.cfg.TLSConfig != nil {
		config = f.cfg.TLSConfig.Clone()
	}
	config.ServerName = serverName
	return config
}

// firstAddress is the first resolved address; an IP literal needs no lookup.
func (f *Forwarder) firstAddress(ctx context.Context, server, host string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, true
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := f.cfg.Resolver.LookupNetIP(lookupCtx, "ip", host)
	if err != nil {
		f.cfg.Logger.Warn("failed to resolve upstream host", "event", "upstream.resolve_failed",
			"server", server, "error", err)
		return netip.Addr{}, false
	}
	if len(addrs) == 0 {
		f.cfg.Logger.Warn("no addresses returned for upstream", "event", "upstream.resolve_empty", "server", server)
		return netip.Addr{}, false
	}
	return addrs[0], true
}
