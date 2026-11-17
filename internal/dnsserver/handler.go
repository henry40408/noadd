// Package dnsserver answers DNS queries: the filter, cache, forward pipeline
// and the UDP and TCP listeners in front of it.
//
// It is not part of package dns because the cache imports dns.
package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/henry40408/noadd/internal/cache"
	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/dns"
	"github.com/henry40408/noadd/internal/filter"
	"github.com/henry40408/noadd/internal/upstream"
)

// blockedResponseTTLSeconds must match the TTL dns.BuildBlocked writes.
const blockedResponseTTLSeconds = 300

var (
	// ErrNoQuery means the message has no question.
	ErrNoQuery = errors.New("no queries in message")
	// ErrBadQuery means the bytes are not a DNS message.
	ErrBadQuery = errors.New("failed to parse DNS query")
)

// QueryLogger accepts one log entry without blocking; *querylog.Logger does.
type QueryLogger interface {
	Log(entry db.QueryLogEntry) bool
}

// Config configures a Handler.
type Config struct {
	Filter    *filter.Holder
	Cache     *cache.Cache
	Forwarder *upstream.Forwarder
	Logger    QueryLogger
	// Limiter is optional; nil means no per-IP limit.
	Limiter *Limiter
	// MaxInflight bounds concurrent Handle calls across all listeners. 0 means
	// no limit.
	MaxInflight int
	// LogQueryResults parses every response again to fill the log's result
	// column. It is off by default: it is the largest cost on the cache-hit path.
	LogQueryResults bool
	Block           dns.BlockConfig
	// InflightWait caps how long a coalesced waiter waits; 0 means 3 s.
	InflightWait time.Duration
	Slog         *slog.Logger
	Now          func() time.Time
}

// Request is one query to answer.
type Request struct {
	Bytes    []byte
	ClientIP netip.Addr
	// DoHToken is the name of the DoH token used; empty for plain DNS.
	DoHToken string
}

// Response is the answer plus what callers would otherwise re-parse for.
type Response struct {
	Bytes []byte
	// MinTTL is the lowest TTL in seconds of the served response; the DoH
	// adapter's Cache-Control max-age.
	MinTTL uint32
}

// Handler implements the filter, cache, forward pipeline. It is safe for
// concurrent use and is shared by the UDP, TCP and DoH listeners. Call Close
// when done so background refreshes end.
type Handler struct {
	cfg        Config
	log        *slog.Logger
	now        func() time.Time
	block      atomic.Pointer[dns.BlockConfig]
	inflight   *dns.Group[cache.Key]
	refreshing *dns.RefreshSet[cache.Key]
	// truncate is a field so a test can make it panic.
	truncate func(query, response []byte) []byte
	permits  chan struct{} // nil means unlimited

	// lifetime bounds background refreshes; Close cancels it.
	lifetime       context.Context
	cancelLifetime context.CancelFunc
	refreshes      sync.WaitGroup
}

// New creates a Handler.
func New(cfg Config) *Handler {
	h := &Handler{
		cfg:        cfg,
		log:        cfg.Slog,
		now:        cfg.Now,
		inflight:   dns.NewGroup[cache.Key](cfg.InflightWait),
		refreshing: dns.NewRefreshSet[cache.Key](),
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.now == nil {
		h.now = time.Now
	}
	if cfg.MaxInflight > 0 {
		h.permits = make(chan struct{}, cfg.MaxInflight)
	}
	h.truncate = dns.TruncateForUDP
	h.SetBlockConfig(cfg.Block)
	h.lifetime, h.cancelLifetime = context.WithCancel(context.Background())
	return h
}

// SetBlockConfig replaces the block-response configuration at runtime.
func (h *Handler) SetBlockConfig(config dns.BlockConfig) { h.block.Store(&config) }

// BlockConfig returns the current block-response configuration.
func (h *Handler) BlockConfig() dns.BlockConfig { return *h.block.Load() }

// Close stops background stale refreshes and waits for them.
func (h *Handler) Close() {
	h.cancelLifetime()
	h.refreshes.Wait()
}

// question is a parsed query and what the pipeline needs to answer it.
type question struct {
	message *mdns.Msg
	raw     []byte
	// domain has no trailing dot.
	domain    string
	queryType uint16
	profile   cache.Profile
}

// answer is what the pipeline decided for one query, before it is logged.
type answer struct {
	bytes         []byte
	minTTL        uint32
	blocked       bool
	cached        bool
	upstream      string
	authenticated bool
}

// Handle answers one raw DNS query. An error means no answer could be made and
// the listener should send SERVFAIL (dns.BuildServfail).
func (h *Handler) Handle(ctx context.Context, request Request) (Response, error) {
	start := h.now()

	// Held for the whole call, bounding active queries however many goroutines
	// the listeners started.
	release, err := h.acquirePermit(ctx)
	if err != nil {
		return Response{}, err
	}
	defer release()

	message := new(mdns.Msg)
	if err := message.Unpack(request.Bytes); err != nil {
		return Response{}, errors.Join(ErrBadQuery, err)
	}
	if unsupported, ok, err := unsupportedQueryResponse(message); ok || err != nil {
		return unsupported, err
	}
	if len(message.Question) == 0 {
		return Response{}, ErrNoQuery
	}

	clientIP := request.ClientIP.Unmap()
	asked := h.newQuestion(message, request.Bytes)

	// REFUSED says "unwilling", not "broken" as SERVFAIL would.
	if h.isRateLimited(clientIP) {
		refused, err := dns.BuildRefused(message)
		if err != nil {
			return Response{}, err
		}
		decided := answer{bytes: refused}
		h.logQuery(request, asked, decided, start, "")
		return Response{Bytes: refused}, nil
	}

	decided, err := h.decide(ctx, asked)
	if err != nil {
		return Response{}, err
	}
	var result string
	if h.cfg.LogQueryResults {
		result = resultSummary(decided.bytes)
	}
	h.logQuery(request, asked, decided, start, result)
	return Response{Bytes: decided.bytes, MinTTL: decided.minTTL}, nil
}

func (h *Handler) acquirePermit(ctx context.Context) (release func(), err error) {
	if h.permits == nil {
		return func() {}, nil
	}
	select {
	case h.permits <- struct{}{}:
		return func() { <-h.permits }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *Handler) newQuestion(message *mdns.Msg, raw []byte) question {
	first := message.Question[0]
	opt := message.IsEdns0()
	return question{
		message:   message,
		raw:       raw,
		domain:    strings.TrimRight(first.Name, "."),
		queryType: first.Qtype,
		profile: cache.Profile{
			HasEDNS:               opt != nil,
			DNSSECOK:              opt != nil && opt.Do(),
			CheckingDisabled:      message.CheckingDisabled,
			UpstreamDNSSECEnabled: h.cfg.Forwarder.DNSSECEnabled(),
		},
	}
}

// unsupportedQueryResponse answers non-standard opcodes with NOTIMP and EDNS
// versions above 0 with BADVERS (RFC 6891 section 6.1.3), before the filter,
// cache or upstream. Neither is logged or rate limited.
func unsupportedQueryResponse(message *mdns.Msg) (response Response, unsupported bool, err error) {
	if message.Opcode != mdns.OpcodeQuery {
		bytes, err := dns.BuildNotimp(message)
		return Response{Bytes: bytes}, true, err
	}
	if opt := message.IsEdns0(); opt != nil && opt.Version() > 0 {
		bytes, err := dns.BuildBadvers(message)
		return Response{Bytes: bytes}, true, err
	}
	return Response{}, false, nil
}

func (h *Handler) isRateLimited(ip netip.Addr) bool {
	return h.cfg.Limiter != nil && !h.cfg.Limiter.Allow(ip, h.now())
}

// decide runs the filter first, so a new block rule applies before any cached
// answer. The filter is loaded once per query.
func (h *Handler) decide(ctx context.Context, asked question) (answer, error) {
	verdict := h.cfg.Filter.Load().Check(asked.domain)
	if verdict.Blocked {
		return h.decideBlocked(asked)
	}
	return h.decideAllowed(ctx, asked)
}

func (h *Handler) decideBlocked(asked question) (answer, error) {
	bytes, err := dns.BuildBlocked(asked.message, h.BlockConfig())
	if err != nil {
		return answer{}, err
	}
	return answer{bytes: bytes, minTTL: blockedResponseTTLSeconds, blocked: true}, nil
}

func (h *Handler) decideAllowed(ctx context.Context, asked question) (answer, error) {
	key := cache.Key{Domain: lowerASCII(asked.domain), QueryType: asked.queryType, Profile: asked.profile}
	queryID := asked.message.Id

	if entry, state := h.cfg.Cache.Get(key); state != cache.Miss {
		if state == cache.Stale {
			h.startStaleRefresh(key, asked.raw)
		}
		return answerFromCache(entry, queryID), nil
	}

	fetch := h.beginFetch(ctx, key)
	if fetch != nil {
		defer fetch.Finish()
	}
	// The fetcher we waited for may have filled the cache.
	if entry, state := h.cfg.Cache.Get(key); state != cache.Miss {
		return answerFromCache(entry, queryID), nil
	}
	// A fetcher, or a waiter whose fetcher failed or timed out.
	return h.forwardAndCache(ctx, asked.raw, key)
}

// lowerASCII skips the allocation for the common all-lowercase name.
func lowerASCII(domain string) string {
	for i := 0; i < len(domain); i++ {
		if domain[i] >= 'A' && domain[i] <= 'Z' {
			return strings.ToLower(domain)
		}
	}
	return domain
}

// beginFetch coalesces misses. The one caller that gets a non-nil Fetch must
// fetch; a waiter returns nil once the fetcher finishes or the wait cap passes.
func (h *Handler) beginFetch(ctx context.Context, key cache.Key) *dns.Fetch[cache.Key] {
	fetch, done := h.inflight.Begin(key)
	if fetch != nil {
		return fetch
	}
	if _, state := h.cfg.Cache.Get(key); state == cache.Miss {
		h.inflight.Wait(ctx, done)
	}
	return nil
}

func (h *Handler) forwardAndCache(ctx context.Context, raw []byte, key cache.Key) (answer, error) {
	result, err := h.cfg.Forwarder.Forward(ctx, raw)
	if err != nil {
		return answer{}, err
	}
	decided := answer{bytes: result.Bytes, upstream: result.Upstream, authenticated: result.AuthenticatedData}
	ttl, cacheable := dns.CacheTTL(result.Bytes)
	if !cacheable {
		return decided, nil
	}
	h.cfg.Cache.Put(key, result.Bytes, ttl, result.AuthenticatedData)
	// DoH max-age: the stored TTL, or 0 if uncacheable.
	decided.minTTL = uint32(ttl / time.Second)
	return decided, nil
}

// startStaleRefresh refreshes key in the background, at most once per key at a
// time.
func (h *Handler) startStaleRefresh(key cache.Key, raw []byte) {
	if !h.refreshing.TryStart(key) {
		return
	}
	query := append([]byte(nil), raw...)
	h.refreshes.Add(1)
	go func() {
		defer h.refreshes.Done()
		// Clears the marker even on panic, or one bad refresh would block the
		// key forever.
		defer h.refreshing.End(key)
		// A malformed upstream answer can panic the DNS library; a background
		// task must not take the whole process down.
		defer func() {
			if recovered := recover(); recovered != nil {
				h.log.Error("stale refresh panicked", "event", "cache.stale_refresh_panicked",
					"panic", fmt.Sprint(recovered))
			}
		}()
		h.refresh(key, query)
	}()
}

func (h *Handler) refresh(key cache.Key, query []byte) {
	result, err := h.cfg.Forwarder.Forward(h.lifetime, query)
	if err != nil {
		h.log.Debug("stale refresh failed", "event", "cache.stale_refresh_failed", "error", err)
		return
	}
	ttl, cacheable := dns.CacheTTL(result.Bytes)
	if !cacheable {
		h.log.Debug("stale refresh got non-cacheable response", "event", "cache.stale_refresh_uncacheable")
		return
	}
	h.cfg.Cache.Put(key, result.Bytes, ttl, result.AuthenticatedData)
}

// answerFromCache ages the TTLs and patches in the client's ID: two writes at
// known offsets on one copy, with no parse or re-encode.
func answerFromCache(entry cache.Entry, queryID uint16) answer {
	bytes := append([]byte(nil), entry.Bytes...)
	dns.ApplyElapsed(bytes, entry.TTLOffsets, uint32(entry.Elapsed/time.Second))
	if len(bytes) >= 2 {
		bytes[0], bytes[1] = byte(queryID>>8), byte(queryID)
	}
	remaining := max(entry.TTL-entry.Elapsed, 0)
	return answer{
		bytes:         bytes,
		minTTL:        uint32(min(remaining/time.Second, 1<<32-1)),
		cached:        true,
		authenticated: entry.AuthenticatedData,
	}
}

// logQuery queues the query's log row. Logging never blocks, but a dropped row
// makes every statistic under-report for good, hence the error level.
func (h *Handler) logQuery(request Request, asked question, decided answer, start time.Time, result string) {
	entry := db.QueryLogEntry{
		Timestamp:         h.now().UnixMilli(),
		Domain:            asked.domain,
		QueryType:         queryTypeName(asked.queryType),
		ClientIP:          request.ClientIP.Unmap().String(),
		Blocked:           decided.blocked,
		Cached:            decided.cached,
		ResponseMs:        h.now().Sub(start).Milliseconds(),
		Upstream:          optionalString(decided.upstream),
		DohToken:          optionalString(request.DoHToken),
		Result:            optionalString(result),
		AuthenticatedData: decided.authenticated,
	}
	if !h.cfg.Logger.Log(entry) {
		h.log.Error("query log event dropped, logger cannot keep up", "event", "querylog.dropped")
	}
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
