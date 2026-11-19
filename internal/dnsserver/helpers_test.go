package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/henry40408/noadd/internal/cache"
	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/filter"
	"github.com/henry40408/noadd/internal/upstream"
)

var localhost = netip.MustParseAddr("127.0.0.1")

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// recordingLogger keeps the entries it is given. Past capacity it refuses
// them, like a full querylog.Logger queue; capacity 0 means unbounded.
type recordingLogger struct {
	mu       sync.Mutex
	capacity int
	entries  []db.QueryLogEntry
}

func (r *recordingLogger) Log(entry db.QueryLogEntry) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.capacity > 0 && len(r.entries) >= r.capacity {
		return false
	}
	r.entries = append(r.entries, entry)
	return true
}

func (r *recordingLogger) snapshot() []db.QueryLogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]db.QueryLogEntry(nil), r.entries...)
}

func queryBytes(t testing.TB, id uint16, name string, qtype uint16) []byte {
	t.Helper()
	query := new(mdns.Msg)
	query.SetQuestion(name, qtype)
	query.Id = id
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func unpack(t testing.TB, wire []byte) *mdns.Msg {
	t.Helper()
	message := new(mdns.Msg)
	if err := message.Unpack(wire); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return message
}

// fakeUpstream is a UDP DNS server on loopback that counts datagrams. The
// delay keeps a fetch open while concurrent queries arrive; keep it under the
// forwarder's 333 ms retransmit interval so no query is resent and counted
// twice.
type fakeUpstream struct {
	addr          string
	received      atomic.Int64
	delay         time.Duration
	authenticated bool
	// respond overrides the default one-A-record answer when set.
	respond func(request *mdns.Msg) *mdns.Msg
}

// Options run before the server starts, so tests never write fields it reads.
func startUpstream(t testing.TB, delay time.Duration, options ...func(*fakeUpstream)) *fakeUpstream {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	upstreamServer := &fakeUpstream{addr: conn.LocalAddr().String(), delay: delay}
	for _, option := range options {
		option(upstreamServer)
	}
	go upstreamServer.serve(conn)
	return upstreamServer
}

func (u *fakeUpstream) serve(conn net.PacketConn) {
	buffer := make([]byte, 4096)
	for {
		length, from, err := conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		u.received.Add(1)
		request := new(mdns.Msg)
		if request.Unpack(buffer[:length]) != nil {
			continue
		}
		go func() {
			time.Sleep(u.delay)
			response := u.answer(request)
			if response == nil {
				return
			}
			if wire, err := response.Pack(); err == nil {
				_, _ = conn.WriteTo(wire, from)
			}
		}()
	}
}

func (u *fakeUpstream) answer(request *mdns.Msg) *mdns.Msg {
	if u.respond != nil {
		return u.respond(request)
	}
	return plainAnswer(request, u.authenticated)
}

// plainAnswer is the default answer: one A record, TTL 60.
func plainAnswer(request *mdns.Msg, authenticated bool) *mdns.Msg {
	response := new(mdns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = true
	response.AuthenticatedData = authenticated
	response.Answer = []mdns.RR{&mdns.A{
		Hdr: mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
		A:   net.IPv4(203, 0, 113, 10),
	}}
	return response
}

type testHandler struct {
	*Handler
	cache  *cache.Cache
	logger *recordingLogger
}

type handlerOptions struct {
	upstreamAddr string
	blocked      []string
	limiter      *Limiter
	maxInflight  int
	logCapacity  int
	logResults   bool
	// upstreamTimeout defaults to 10 s.
	upstreamTimeout time.Duration
}

func newTestHandler(t testing.TB, options handlerOptions) *testHandler {
	t.Helper()
	var block []filter.NamedBlockRule
	for _, domain := range options.blocked {
		block = append(block, filter.NamedBlockRule{
			Rule: filter.ParsedRule{Domain: domain, Action: filter.ActionBlock, IsSubdomain: true},
			List: "test-list",
		})
	}
	servers := []string{"127.0.0.1:9"} // discard port: never reached by blocked-only tests
	if options.upstreamAddr != "" {
		servers = []string{options.upstreamAddr}
	}
	timeout := options.upstreamTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	forwarder := upstream.New(context.Background(), upstream.Config{
		Servers: servers, Timeout: timeout, Logger: quietLogger(),
	})
	responses := cache.New(cache.Config{CapacityBytes: 64 << 20})
	logger := &recordingLogger{capacity: options.logCapacity}
	handler := New(Config{
		Filter:          filter.NewHolder(filter.NewFromNamed(block, nil)),
		Cache:           responses,
		Forwarder:       forwarder,
		Logger:          logger,
		Limiter:         options.limiter,
		MaxInflight:     options.maxInflight,
		LogQueryResults: options.logResults,
		Slog:            quietLogger(),
	})
	t.Cleanup(handler.Close)
	return &testHandler{Handler: handler, cache: responses, logger: logger}
}

func (h *testHandler) ask(t testing.TB, id uint16, name string, qtype uint16) Response {
	t.Helper()
	response, err := h.Handle(context.Background(), Request{Bytes: queryBytes(t, id, name, qtype), ClientIP: localhost})
	if err != nil {
		t.Fatalf("Handle(%s): %v", name, err)
	}
	return response
}

// waitFor polls until condition holds, failing the test after a second.
func waitFor(t testing.TB, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func netipAddrPort() netip.AddrPort { return netip.MustParseAddrPort("127.0.0.1:5353") }

func answering(respond func(request *mdns.Msg) *mdns.Msg) func(*fakeUpstream) {
	return func(u *fakeUpstream) { u.respond = respond }
}

func authenticating(u *fakeUpstream) { u.authenticated = true }

func mustAddr(text string) netip.Addr { return netip.MustParseAddr(text) }
