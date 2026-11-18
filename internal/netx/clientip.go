package netx

import (
	"net/http"
	"net/netip"
	"strings"
)

// maxForwardedHops bounds how many X-Forwarded-For hops are inspected,
// counting from the right, so a client cannot pad the head into many parses.
const maxForwardedHops = 32

// RequestClientIP resolves the originating client of r from its TCP peer.
// An unparseable RemoteAddr never trusts headers: Go always supplies one, so
// that case is a bug upstream, and failing closed is the safe direction.
func RequestClientIP(r *http.Request, trusted TrustedProxies) netip.Addr {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return ClientIP(peer.Addr(), r.Header, trusted)
}

// ClientIP resolves the originating client IP for logging and rate limiting.
//
// peer is the TCP peer; the zero Addr means "no connection info" (tests that
// bypass the listener), and then headers are trusted. X-Forwarded-For is
// walked right to left and the first non-proxy hop wins: proxies append, so
// the leftmost entry is attacker-controlled.
func ClientIP(peer netip.Addr, header http.Header, trusted TrustedProxies) netip.Addr {
	// A dual-stack listener reports IPv4 peers as ::ffff:a.b.c.d; one form per
	// client keeps rate-limit keys and query-log entries consistent.
	peer = peer.Unmap().WithZone("")

	trustHeaders := !peer.IsValid() || peer.IsLoopback() || trusted.Contains(peer)
	if trustHeaders {
		if ip, ok := clientFromForwardedFor(header.Get("X-Forwarded-For"), trusted); ok {
			return ip
		}
		if ip, err := netip.ParseAddr(strings.TrimSpace(header.Get("X-Real-IP"))); err == nil && ip.Zone() == "" {
			return ip.Unmap()
		}
	}
	if peer.IsValid() {
		return peer
	}
	return netip.AddrFrom4([4]byte{127, 0, 0, 1})
}

// clientFromForwardedFor walks the header from the right. When every hop read
// is a proxy the outermost one is used; when the innermost entry is
// unreadable the caller falls through to X-Real-IP or the peer.
func clientFromForwardedFor(value string, trusted TrustedProxies) (netip.Addr, bool) {
	var outermostProxy netip.Addr
	rest := value
	for hops := 0; value != "" && hops < maxForwardedHops; hops++ {
		cut := strings.LastIndexByte(rest, ',')
		hop := rest[cut+1:]
		ip, ok := parseForwardedHop(hop)
		// Skipping an unreadable hop would walk into unvouched entries.
		if !ok {
			break
		}
		ip = ip.Unmap()
		if !trusted.isProxyHop(ip) {
			return ip, true
		}
		outermostProxy = ip
		if cut < 0 {
			break
		}
		rest = rest[:cut]
	}
	return outermostProxy, outermostProxy.IsValid()
}

// parseForwardedHop reads one entry, tolerating the forms proxies emit:
// bare addresses, "1.2.3.4:53821", bracketed IPv6 with or without a port, and
// RFC 7239 "for=" syntax.
func parseForwardedHop(hop string) (netip.Addr, bool) {
	hop = strings.TrimSpace(hop)
	if len(hop) >= 4 && strings.EqualFold(hop[:4], "for=") {
		hop = hop[4:]
	}
	hop = strings.TrimSpace(strings.Trim(hop, `"`))

	if rest, found := strings.CutPrefix(hop, "["); found {
		addr, _, closed := strings.Cut(rest, "]")
		return parseAddrNoZone(addr, closed)
	}
	if ip, ok := parseAddrNoZone(hop, true); ok {
		return ip, true
	}
	// A bare IPv6 parsed above, so a colon here means "1.2.3.4:443".
	cut := strings.LastIndexByte(hop, ':')
	if cut < 0 {
		return netip.Addr{}, false
	}
	ip, ok := parseAddrNoZone(hop[:cut], true)
	return ip, ok && ip.Is4()
}

func parseAddrNoZone(text string, present bool) (netip.Addr, bool) {
	if !present {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(text)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	return ip, true
}
