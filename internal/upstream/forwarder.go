package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	// emaAlpha is the EMA smoothing factor: 30% weight for a new observation.
	emaAlpha = 0.3

	// DefaultMinTimeout is the lowest per-attempt timeout: mobile clients often
	// need more than 2s for the first query after a network switch.
	DefaultMinTimeout = 5 * time.Second

	// DefaultRetransmitInterval is how often a UDP query is resent while it waits.
	DefaultRetransmitInterval = 333 * time.Millisecond

	probeAttempts = 2
)

// DefaultServers are privacy-oriented public resolvers: Cloudflare (US;
// truncates client IPs, purges logs within 25h) and Quad9 (CH; keeps no client
// IPs). The DoT entry shares Quad9's operator with the second, so it adds
// transport (encrypted, untampered AD verdict) rather than operator diversity.
var DefaultServers = []string{"1.1.1.1:53", "9.9.9.9:53", "tls://dns.quad9.net:853"}

var (
	// ErrAllFailed means no upstream returned a usable answer.
	ErrAllFailed = errors.New("all upstreams failed")
	// ErrBadQuery means the client's query bytes are not a DNS message.
	ErrBadQuery = errors.New("malformed query")
)

// Resolver looks up an upstream hostname.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Config tunes a Forwarder. Zero values take the production defaults.
type Config struct {
	// Servers are the entries, as returned by ParseUpstreams. Empty takes
	// DefaultServers.
	Servers []string
	// Timeout is per attempt on one upstream. It is raised to MinTimeout.
	Timeout            time.Duration
	MinTimeout         time.Duration
	RetransmitInterval time.Duration
	// TLSConfig is the base for DoT and DoH, so tests can trust a private CA.
	// The server name is set per upstream.
	TLSConfig *tls.Config
	Resolver  Resolver
	Logger    *slog.Logger
	Now       func() time.Time
}

func (c Config) withDefaults() Config {
	if len(c.Servers) == 0 {
		c.Servers = DefaultServers
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultMinTimeout
	}
	if c.MinTimeout == 0 {
		c.MinTimeout = DefaultMinTimeout
	}
	if c.RetransmitInterval == 0 {
		c.RetransmitInterval = DefaultRetransmitInterval
	}
	if c.Resolver == nil {
		c.Resolver = netResolver{}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Result is a forwarded response.
type Result struct {
	// Bytes is the response, tailored to the client's request.
	Bytes []byte
	// Upstream is the label of the server that answered.
	Upstream string
	// AuthenticatedData is the upstream's AD bit, read before it is cleared for
	// a client that did not request DNSSEC, so the query log still sees it.
	AuthenticatedData bool
}

// HealthResult is the outcome of probing one upstream.
type HealthResult struct {
	Server    string
	OK        bool
	LatencyMS int64
}

type entry struct {
	label string
	exchanger
}

// upstreamSet is the reconfigurable server set, swapped atomically. servers,
// entries and latencies are index-aligned.
type upstreamSet struct {
	servers []string
	timeout time.Duration
	// entries[i] is nil when server i failed to parse or resolve at build time.
	entries []*entry
	// latencies hold the EMA in ms as float64 bits; +Inf until observed, which
	// sorts last so LowestLatency tries unobserved upstreams last.
	latencies []atomic.Uint64
}

// Forwarder forwards DNS queries to upstreams by strategy.
type Forwarder struct {
	cfg        Config
	set        atomic.Pointer[upstreamSet]
	strategy   atomic.Pointer[Strategy]
	rrCounter  atomic.Uint64
	dnssecOn   atomic.Bool
	reconfigMu sync.Mutex
}

// New creates a Forwarder. Hostnames resolve once, to their first address, so
// geo-routed providers pin to the PoP picked at startup.
func New(ctx context.Context, cfg Config) *Forwarder {
	f := &Forwarder{cfg: cfg.withDefaults()}
	sequential := Sequential
	f.strategy.Store(&sequential)
	f.dnssecOn.Store(true)
	f.set.Store(f.buildSet(ctx, f.cfg.Servers))
	return f
}

// Reconfigure replaces the upstream set, keeping the timeout. Hosts that fail
// to resolve are logged and left unavailable, as in New. Latencies reset.
func (f *Forwarder) Reconfigure(ctx context.Context, servers []string) {
	f.reconfigMu.Lock()
	defer f.reconfigMu.Unlock()
	old := f.set.Swap(f.buildSet(ctx, servers))
	for _, e := range old.entries {
		if e != nil {
			e.closeIdle()
		}
	}
}

// Servers returns the configured entries of the current set.
func (f *Forwarder) Servers() []string { return f.set.Load().servers }

// Strategy returns the active strategy.
func (f *Forwarder) Strategy() Strategy { return *f.strategy.Load() }

// SetStrategy sets the active strategy.
func (f *Forwarder) SetStrategy(strategy Strategy) { f.strategy.Store(&strategy) }

// SetDNSSECEnabled turns forcing the DO bit on upstream requests on or off.
func (f *Forwarder) SetDNSSECEnabled(enabled bool) { f.dnssecOn.Store(enabled) }

// DNSSECEnabled reports whether DO forcing is on.
func (f *Forwarder) DNSSECEnabled() bool { return f.dnssecOn.Load() }

// ServerOrder is the try-order for the current strategy, as indexes into the
// configured servers.
func (f *Forwarder) ServerOrder() []int { return f.orderFor(f.set.Load()) }

func (f *Forwarder) orderFor(set *upstreamSet) []int {
	count := len(set.entries)
	if count == 0 {
		return nil
	}
	order := make([]int, count)
	for i := range order {
		order[i] = i
	}
	switch f.Strategy() {
	case RoundRobin:
		start := int(f.rrCounter.Load() % uint64(count))
		for i := range order {
			order[i] = (start + i) % count
		}
	case LowestLatency:
		sortByLatency(order, set)
	}
	return order
}

// sortByLatency is a stable insertion sort: equal (unobserved) latencies keep
// their configured order, and there are only a few servers.
func sortByLatency(order []int, set *upstreamSet) {
	for i := 1; i < len(order); i++ {
		for j := i; j > 0 && set.latency(order[j]) < set.latency(order[j-1]); j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}
}

func (s *upstreamSet) latency(index int) float64 {
	return math.Float64frombits(s.latencies[index].Load())
}

// updateLatency folds ms into the EMA of server index with a CAS loop. An index
// outside the set is a no-op, not a panic. It writes through the given set, so
// a write after a swap lands harmlessly in the old one.
func (s *upstreamSet) updateLatency(index int, ms float64) {
	if index < 0 || index >= len(s.latencies) {
		return
	}
	cell := &s.latencies[index]
	for {
		previousBits := cell.Load()
		previous := math.Float64frombits(previousBits)
		next := ms
		if !math.IsInf(previous, 0) {
			next = emaAlpha*ms + (1-emaAlpha)*previous
		}
		if cell.CompareAndSwap(previousBits, math.Float64bits(next)) {
			return
		}
	}
}

// UpdateLatency folds a latency observation into server index's EMA.
func (f *Forwarder) UpdateLatency(index int, ms float64) { f.set.Load().updateLatency(index, ms) }

// Latencies returns the EMA latency in ms by server label; unobserved servers
// are omitted.
func (f *Forwarder) Latencies() map[string]float64 {
	set := f.set.Load()
	observed := make(map[string]float64)
	for i, label := range set.servers {
		if ms := set.latency(i); !math.IsInf(ms, 0) {
			observed[label] = ms
		}
	}
	return observed
}

// Forward forwards a query using the current strategy, trying the next upstream
// when one fails.
func (f *Forwarder) Forward(ctx context.Context, queryBytes []byte) (Result, error) {
	set := f.set.Load()
	clientRequest := new(dns.Msg)
	if err := clientRequest.Unpack(queryBytes); err != nil {
		return Result{}, ErrBadQuery
	}
	upstreamRequest := prepareUpstreamRequest(clientRequest, f.DNSSECEnabled())

	order := f.orderFor(set)
	if f.Strategy() == RoundRobin {
		f.rrCounter.Add(1)
	}
	for _, index := range order {
		target := set.entries[index]
		if target == nil {
			continue
		}
		if result, ok := f.tryUpstream(ctx, set, index, upstreamRequest, clientRequest); ok {
			return result, nil
		}
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
	}
	return Result{}, ErrAllFailed
}

func (f *Forwarder) tryUpstream(ctx context.Context, set *upstreamSet, index int, upstreamRequest, clientRequest *dns.Msg) (Result, bool) {
	target := set.entries[index]
	started := time.Now()
	response, err := set.exchange(ctx, target, upstreamRequest)
	if err != nil {
		f.cfg.Logger.Warn("upstream forward failed", "event", "upstream.forward_failed",
			"upstream", target.label, "error", err)
		return Result{}, false
	}

	var tailored *dns.Msg
	authenticated := false
	switch classify(response) {
	case verdictFailure:
		f.cfg.Logger.Warn("upstream forward failed", "event", "upstream.forward_failed",
			"upstream", target.label, "error", failureReason(response))
		return Result{}, false
	case verdictNegative:
		// NXDOMAIN and NODATA are valid answers: no failover. The rebuilt message
		// has no AD, so it is logged as unauthenticated.
		tailored = buildNegativeResponse(response, clientRequest)
	default:
		response.Id = clientRequest.Id
		authenticated = response.AuthenticatedData
		prepareResponseForClient(response, clientRequest)
		tailored = response
	}
	set.updateLatency(index, float64(time.Since(started))/float64(time.Millisecond))

	tailored.Compress = true
	wire, err := tailored.Pack()
	if err != nil {
		f.cfg.Logger.Warn("failed to re-encode upstream response", "event", "upstream.reencode_failed",
			"upstream", target.label, "error", err)
		return Result{}, false
	}
	return Result{Bytes: wire, Upstream: target.label, AuthenticatedData: authenticated}, true
}

// exchange sends one request within the per-attempt timeout, under a fresh
// random ID so a late reply to an earlier attempt cannot match a later one.
func (s *upstreamSet) exchange(ctx context.Context, target *entry, request *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	sent := *request
	sent.Id = dns.Id()
	return target.exchange(ctx, &sent)
}

// HealthCheck probes every configured upstream.
func (f *Forwarder) HealthCheck(ctx context.Context) []HealthResult {
	set := f.set.Load()
	results := make([]HealthResult, 0, len(set.servers))
	for _, server := range set.servers {
		results = append(results, HealthResult{Server: server})
	}
	for i, target := range set.entries {
		if target == nil {
			continue
		}
		started := time.Now()
		results[i].OK = f.probe(ctx, set, target)
		results[i].LatencyMS = time.Since(started).Milliseconds()
	}
	return results
}

// ProbeAll probes every upstream and updates the EMA latencies.
func (f *Forwarder) ProbeAll(ctx context.Context) {
	set := f.set.Load()
	for i, target := range set.entries {
		if target == nil {
			continue
		}
		started := time.Now()
		if f.probe(ctx, set, target) {
			set.updateLatency(i, float64(time.Since(started))/float64(time.Millisecond))
		}
	}
}

// probe sends a root NS query to one upstream, not A: the root has no A record,
// and the empty NOERROR would count as a failure. It retries once: the first
// send on a DoT/DoH connection that went stale fails before it reconnects, and
// unlike Forward a probe has no other upstream to fail over to.
func (f *Forwarder) probe(ctx context.Context, set *upstreamSet, target *entry) bool {
	for attempt := 1; attempt <= probeAttempts; attempt++ {
		request := new(dns.Msg)
		request.SetQuestion(".", dns.TypeNS)
		request.RecursionDesired = true
		response, err := set.exchange(ctx, target, request)
		if err == nil && classify(response) == verdictPositive {
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		f.cfg.Logger.Warn("upstream health probe attempt failed", "event", "upstream.probe_attempt_failed",
			"upstream", target.label, "attempt", attempt, "attempts", probeAttempts, "error", err)
	}
	return false
}

type verdict int

const (
	verdictPositive verdict = iota
	verdictNegative
	verdictFailure
)

// failureRcodes are the response codes hickory turns into errors, so the
// forwarder moves on to the next upstream instead of relaying them.
var failureRcodes = map[int]bool{
	dns.RcodeFormatError: true, dns.RcodeServerFailure: true, dns.RcodeNotImplemented: true,
	dns.RcodeRefused: true, dns.RcodeYXDomain: true, dns.RcodeYXRrset: true, dns.RcodeNXRrset: true,
	dns.RcodeNotAuth: true, dns.RcodeNotZone: true,
	16: true, 17: true, 18: true, 19: true, 20: true, 21: true, 22: true, 23: true, // BADVERS..BADCOOKIE
}

// classify mirrors hickory's response handling. Any truncated response is a
// failure: the Rust pool had no TCP connection to retry on, so a UDP response
// with TC=1 ended as SERVFAIL for the client (pinned by the wire fixtures).
// An NXDOMAIN or NOERROR without an answer is a negative answer.
func classify(response *dns.Msg) verdict {
	if response.Truncated || failureRcodes[response.Rcode] {
		return verdictFailure
	}
	if (response.Rcode == dns.RcodeSuccess || response.Rcode == dns.RcodeNameError) && !containsAnswer(response) {
		return verdictNegative
	}
	return verdictPositive
}

// containsAnswer mirrors hickory's DnsResponse::contains_answer for the first
// question: any record about the name (ANY), an SOA whose zone covers the name
// (SOA), or otherwise a non-empty answer section or a record of the type and
// name in any section.
func containsAnswer(response *dns.Msg) bool {
	if len(response.Question) == 0 {
		return false
	}
	question := response.Question[0]
	switch question.Qtype {
	case dns.TypeANY:
		return anyRecord(response, func(rr dns.RR) bool { return sameName(rr.Header().Name, question.Name) })
	case dns.TypeSOA:
		return anyRecord(response, func(rr dns.RR) bool {
			return rr.Header().Rrtype == dns.TypeSOA && dns.IsSubDomain(rr.Header().Name, question.Name)
		})
	}
	if len(response.Answer) > 0 {
		return true
	}
	return anyRecord(response, func(rr dns.RR) bool {
		return rr.Header().Rrtype == question.Qtype && sameName(rr.Header().Name, question.Name)
	})
}

func anyRecord(response *dns.Msg, match func(dns.RR) bool) bool {
	for _, section := range [][]dns.RR{response.Answer, response.Ns, withoutOPT(append([]dns.RR(nil), response.Extra...))} {
		for _, record := range section {
			if match(record) {
				return true
			}
		}
	}
	return false
}

func sameName(a, b string) bool { return strings.EqualFold(dns.Fqdn(a), dns.Fqdn(b)) }

// failureReason names why classify rejected a response. The code is not
// masked: an extended code such as BADVERS must not read as NOERROR.
func failureReason(response *dns.Msg) string {
	if response.Truncated {
		return "truncated response (TC=1)"
	}
	name, known := dns.RcodeToString[response.Rcode]
	if !known {
		name = strconv.Itoa(response.Rcode)
	}
	return "response code " + name
}
