package dnsserver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func startTCP(t *testing.T, handler *Handler) (addr string, stop func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handler.ServeTCP(ctx, listener) }()
	var stopped bool
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("ServeTCP: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("ServeTCP did not return after its context ended")
		}
	}
	t.Cleanup(stop)
	return listener.Addr().String(), stop
}

func startUDP(t *testing.T, handler *Handler) (addr string, stop func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- handler.ServeUDP(ctx, conn) }()
	var stopped bool
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("ServeUDP: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("ServeUDP did not return after its context ended")
		}
	}
	t.Cleanup(stop)
	return conn.LocalAddr().String(), stop
}

// queryOverTCP is one length-prefixed round trip.
func queryOverTCP(t *testing.T, conn net.Conn, query []byte) []byte {
	t.Helper()
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := conn.Write(append(frame, query...)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatalf("read length: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(prefix[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}

// Rust: tcp_test.rs tcp_length_prefixed_framing
func TestTCPLengthPrefixedFraming(t *testing.T) {
	addr, _ := startTCP(t, blockingHandler(t).Handler)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	response := unpack(t, queryOverTCP(t, conn, queryBytes(t, 0xABCD, blockedDomain+".", mdns.TypeA)))
	if !response.Response || response.Id != 0xABCD || response.Rcode != mdns.RcodeSuccess {
		t.Fatalf("response = %+v", response.MsgHdr)
	}
	if len(response.Answer) == 0 || response.Answer[0].(*mdns.A).A.String() != "0.0.0.0" {
		t.Fatalf("answer = %v", response.Answer)
	}
}

// Rust: tcp_connection_reuse_serves_multiple_queries
func TestTCPConnectionReuseServesMultipleQueries(t *testing.T) {
	addr, _ := startTCP(t, blockingHandler(t).Handler)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	for _, id := range []uint16{1, 2, 3} {
		response := unpack(t, queryOverTCP(t, conn, queryBytes(t, id, blockedDomain+".", mdns.TypeA)))
		if response.Id != id || len(response.Answer) == 0 {
			t.Fatalf("query %d: id %d, %d answers", id, response.Id, len(response.Answer))
		}
	}
}

func TestTCPGarbageGetsServfailAndTheConnectionSurvives(t *testing.T) {
	addr, _ := startTCP(t, blockingHandler(t).Handler)
	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()

	servfail := unpack(t, queryOverTCP(t, conn, []byte{0xAB, 0xCD, 1, 2, 3}))
	if servfail.Rcode != mdns.RcodeServerFailure || servfail.Id != 0xABCD {
		t.Fatalf("garbage answer = %+v", servfail.MsgHdr)
	}
	if next := unpack(t, queryOverTCP(t, conn, queryBytes(t, 9, blockedDomain+".", mdns.TypeA))); next.Id != 9 {
		t.Fatal("the connection should survive a bad query")
	}
}

func TestTCPZeroLengthFrameClosesTheConnection(t *testing.T) {
	addr, _ := startTCP(t, blockingHandler(t).Handler)
	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	if _, err := conn.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read after a zero-length frame = %v, want EOF", err)
	}
}

func TestTCPShutdownClosesIdleConnectionsAndFinishesAQueryInFlight(t *testing.T) {
	fake := startUpstream(t, 150*time.Millisecond)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	addr, stop := startTCP(t, handler.Handler)

	idle, _ := net.Dial("tcp", addr)
	defer idle.Close()
	busy, _ := net.Dial("tcp", addr)
	defer busy.Close()
	query := queryBytes(t, 5, "inflight.example.com.", mdns.TypeA)
	if _, err := busy.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the query to reach the upstream", func() bool { return fake.received.Load() == 1 })

	stop()

	_ = busy.SetReadDeadline(time.Now().Add(3 * time.Second))
	var prefix [2]byte
	if _, err := io.ReadFull(busy, prefix[:]); err != nil {
		t.Fatalf("the in-flight query got no response after shutdown: %v", err)
	}
	_ = idle.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := idle.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("idle connection read = %v, want EOF", err)
	}
}

func roundTripUDP(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 65535)
	length, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("no UDP response: %v", err)
	}
	return buffer[:length]
}

func TestUDPAnswersABlockedQuery(t *testing.T) {
	addr, _ := startUDP(t, blockingHandler(t).Handler)
	response := unpack(t, roundTripUDP(t, addr, queryBytes(t, 0x1234, blockedDomain+".", mdns.TypeA)))
	if response.Id != 0x1234 || len(response.Answer) == 0 {
		t.Fatalf("response = %+v", response)
	}
}

func TestUDPGarbageGetsServfail(t *testing.T) {
	addr, _ := startUDP(t, blockingHandler(t).Handler)
	response := roundTripUDP(t, addr, []byte{0xAB, 0xCD, 1, 2, 3})
	if len(response) < 4 || response[0] != 0xAB || response[1] != 0xCD || response[3]&0x0F != mdns.RcodeServerFailure {
		t.Fatalf("response = %x, want a SERVFAIL carrying the raw ID", response)
	}
}

// An oversized answer to a client without EDNS is cut to 512 bytes with TC set.
func TestUDPTruncatesAnOversizedAnswerForAPlainClient(t *testing.T) {
	fake := startUpstream(t, 0, answering(func(request *mdns.Msg) *mdns.Msg {
		response := plainAnswer(request, false)
		for i := range 60 {
			response.Answer = append(response.Answer, &mdns.A{
				Hdr: mdns.RR_Header{Name: request.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
				A:   net.IPv4(203, 0, 113, byte(i)),
			})
		}
		return response
	}))
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	addr, _ := startUDP(t, handler.Handler)

	wire := roundTripUDP(t, addr, queryBytes(t, 7, "big.example.com.", mdns.TypeA))
	response := unpack(t, wire)
	if !response.Truncated || len(wire) > 512 || len(response.Answer) != 0 || response.Id != 7 {
		t.Fatalf("len %d truncated %v answers %d", len(wire), response.Truncated, len(response.Answer))
	}
	// The same answer over TCP is whole.
	tcpAddr, _ := startTCP(t, handler.Handler)
	conn, _ := net.Dial("tcp", tcpAddr)
	defer conn.Close()
	if full := unpack(t, queryOverTCP(t, conn, queryBytes(t, 8, "big.example.com.", mdns.TypeA))); full.Truncated || len(full.Answer) != 61 {
		t.Fatalf("TCP answer: truncated %v, %d answers", full.Truncated, len(full.Answer))
	}
}

func TestUDPClientIPIsTheSourceAddress(t *testing.T) {
	handler := blockingHandler(t)
	addr, _ := startUDP(t, handler.Handler)
	roundTripUDP(t, addr, queryBytes(t, 1, blockedDomain+".", mdns.TypeA))
	if entries := handler.logger.snapshot(); len(entries) != 1 || entries[0].ClientIP != "127.0.0.1" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestUDPShutdownWaitsForInflightQueriesAndLeaksNothing(t *testing.T) {
	fake := startUpstream(t, 150*time.Millisecond)
	handler := newTestHandler(t, handlerOptions{upstreamAddr: fake.addr})
	before := runtime.NumGoroutine()
	addr, stop := startUDP(t, handler.Handler)

	conn, _ := net.Dial("udp", addr)
	defer conn.Close()
	if _, err := conn.Write(queryBytes(t, 3, "late.example.com.", mdns.TypeA)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the query to reach the upstream", func() bool { return fake.received.Load() == 1 })

	stop()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 4096)); err != nil {
		t.Fatalf("the in-flight query was dropped on shutdown: %v", err)
	}
	waitFor(t, "listener goroutines to exit", func() bool { return runtime.NumGoroutine() <= before+4 })
}
