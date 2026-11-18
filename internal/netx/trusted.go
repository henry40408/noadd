// Package netx holds the network helpers shared by the DoH and admin HTTP
// layers: trusted-proxy CIDR sets and client-IP resolution.
package netx

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ParseCIDR parses "addr" or "addr/prefix". A bare address is a host route
// (/32 for IPv4, /128 for IPv6). Zones are rejected, as the Rust parser does.
func ParseCIDR(text string) (netip.Prefix, error) {
	text = strings.TrimSpace(text)
	addrPart, prefixPart, hasPrefix := strings.Cut(text, "/")

	base, err := netip.ParseAddr(addrPart)
	if err != nil || base.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid IP address in CIDR `%s`", text)
	}
	maxPrefix := base.BitLen()
	if !hasPrefix {
		return netip.PrefixFrom(base, maxPrefix), nil
	}

	prefixLen, err := strconv.ParseUint(strings.TrimSpace(prefixPart), 10, 8)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid prefix length in CIDR `%s`", text)
	}
	if int(prefixLen) > maxPrefix {
		family := "IPv6"
		if maxPrefix == 32 {
			family = "IPv4"
		}
		return netip.Prefix{}, fmt.Errorf("prefix length %d out of range for %s in `%s`", prefixLen, family, text)
	}
	return netip.PrefixFrom(base, int(prefixLen)), nil
}

// TrustedProxies is the set of CIDRs whose peers may set client-IP headers.
// The zero value is the empty set.
type TrustedProxies struct {
	cidrs []netip.Prefix
}

// ParseTrustedProxies parses a comma-separated CIDR list. Empty entries are
// ignored so a stray comma does not break startup.
func ParseTrustedProxies(input string) (TrustedProxies, error) {
	var set TrustedProxies
	for _, chunk := range strings.Split(input, ",") {
		trimmed := strings.TrimSpace(chunk)
		if trimmed == "" {
			continue
		}
		cidr, err := ParseCIDR(trimmed)
		if err != nil {
			return TrustedProxies{}, err
		}
		set.cidrs = append(set.cidrs, cidr)
	}
	return set, nil
}

// IsEmpty reports whether no CIDR is configured.
func (t TrustedProxies) IsEmpty() bool { return len(t.cidrs) == 0 }

// Len is the number of configured CIDRs.
func (t TrustedProxies) Len() int { return len(t.cidrs) }

// Contains reports whether ip is in any configured CIDR. Cross-family checks
// are false: callers on the request path Unmap first, so a mapped peer is
// matched as the IPv4 address it wraps.
func (t TrustedProxies) Contains(ip netip.Addr) bool {
	for _, cidr := range t.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (t TrustedProxies) isProxyHop(ip netip.Addr) bool {
	return ip.IsLoopback() || t.Contains(ip)
}
