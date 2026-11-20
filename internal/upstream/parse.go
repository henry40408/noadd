// Package upstream forwards DNS queries to the configured resolvers over UDP,
// DoT and DoH, and picks the server by strategy.
package upstream

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type transport int

const (
	transportUDP transport = iota
	transportTLS
	transportHTTPS
)

const (
	defaultUDPPort   = 53
	defaultTLSPort   = 853
	defaultHTTPSPort = 443
	defaultDoHPath   = "/dns-query"
)

// spec is a validated upstream entry before its host is resolved.
type spec struct {
	// host is a hostname (DoT/DoH) or an IP literal (UDP).
	host      string
	port      uint16
	transport transport
	// path is the DoH request path.
	path string
}

// parseSpec parses `tls://`, `https://` or plain UDP (`IP:port`, or a bare IP
// on port 53). A bare hostname has no transport to infer and is rejected.
func parseSpec(input string) (spec, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return spec{}, errors.New("empty upstream entry")
	}
	if rest, ok := strings.CutPrefix(trimmed, "tls://"); ok {
		host, port, err := parseHostPort(rest, defaultTLSPort)
		return spec{host: host, port: port, transport: transportTLS}, err
	}
	if rest, ok := strings.CutPrefix(trimmed, "https://"); ok {
		hostPort, path := rest, defaultDoHPath
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			hostPort, path = rest[:slash], rest[slash:]
		}
		host, port, err := parseHostPort(hostPort, defaultHTTPSPort)
		return spec{host: host, port: port, transport: transportHTTPS, path: path}, err
	}
	if addrPort, err := netip.ParseAddrPort(trimmed); err == nil {
		return spec{host: addrPort.Addr().String(), port: addrPort.Port()}, nil
	}
	// Parsed as an address rather than tested for ':', which would misread every
	// bare IPv6 literal as carrying a port.
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return spec{host: addr.String(), port: defaultUDPPort}, nil
	}
	return spec{}, fmt.Errorf("invalid UDP upstream %q: expected an IP address, "+
		"optionally with a port (e.g. `1.1.1.1`, `1.1.1.1:53`, `[::1]:53`)", trimmed)
}

// canonical is the entry string with port and path explicit and IPv6 bracketed,
// so `1.1.1.1` and `1.1.1.1:53` are one upstream.
func (s spec) canonical() string {
	host := s.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := strconv.Itoa(int(s.port))
	switch s.transport {
	case transportTLS:
		return "tls://" + host + ":" + port
	case transportHTTPS:
		return "https://" + host + ":" + port + s.path
	default:
		return host + ":" + port
	}
}

// ParseUpstreams parses newline- or comma-separated input into canonical
// entries, deduplicated in first-seen order. It fails on the first invalid
// entry and on empty input.
func ParseUpstreams(input string) ([]string, error) {
	var servers []string
	for _, raw := range strings.FieldsFunc(input, func(r rune) bool { return r == '\n' || r == ',' }) {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		parsed, err := parseSpec(entry)
		if err != nil {
			return nil, err
		}
		canonical := parsed.canonical()
		if !slices.Contains(servers, canonical) {
			servers = append(servers, canonical)
		}
	}
	if len(servers) == 0 {
		return nil, errors.New("at least one upstream server is required")
	}
	return servers, nil
}

// parseHostPort parses `host[:port]`, including `[::1]:853`.
func parseHostPort(s string, defaultPort uint16) (string, uint16, error) {
	if s == "" {
		return "", 0, errors.New("missing host")
	}
	if rest, ok := strings.CutPrefix(s, "["); ok {
		return parseBracketedHost(rest, defaultPort)
	}
	colon := strings.LastIndexByte(s, ':')
	if colon < 0 {
		return s, defaultPort, nil
	}
	if colon == 0 {
		return "", 0, errors.New("missing host")
	}
	port, err := parsePort(s[colon+1:])
	return s[:colon], port, err
}

func parseBracketedHost(rest string, defaultPort uint16) (string, uint16, error) {
	end := strings.IndexByte(rest, ']')
	if end < 0 {
		return "", 0, errors.New("unclosed `[` in IPv6 literal")
	}
	host, after := rest[:end], rest[end+1:]
	if after == "" {
		return host, defaultPort, nil
	}
	portText, ok := strings.CutPrefix(after, ":")
	if !ok {
		return "", 0, fmt.Errorf("unexpected text after IPv6 literal: %q", after)
	}
	port, err := parsePort(portText)
	return host, port, err
}

func parsePort(text string) (uint16, error) {
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: %w", text, err)
	}
	return uint16(port), nil
}

// hostPort joins an address and port for dialing.
func hostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}
