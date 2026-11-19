package dnsserver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ServeTCP serves length-prefixed DNS (RFC 1035 section 4.2.2) on ln, one
// goroutine per connection, with connection reuse (RFC 7766). Queries on one
// connection are answered in order. There is no idle timeout.
//
// When ctx ends it closes ln and makes every connection's next read fail, so
// a query being answered still gets its response, then waits for all
// connections and returns nil.
func (h *Handler) ServeTCP(ctx context.Context, ln net.Listener) error {
	h.log.Info("DNS listener started", "event", "dns.listener_started", "transport", "tcp", "addr", ln.Addr())

	connections := newConnSet()
	stopped := context.AfterFunc(ctx, func() {
		_ = ln.Close()
		connections.interruptReads()
	})
	defer stopped()
	defer func() { _ = ln.Close() }()
	var serving sync.WaitGroup
	defer serving.Wait()

	for {
		conn, err := ln.Accept()
		if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			h.log.Debug("failed to accept connection", "event", "dns.accept_failed", "transport", "tcp", "error", err)
			continue
		}
		connections.add(conn)
		if ctx.Err() != nil {
			// Shutdown's interrupt may have run before this connection was in the set.
			_ = conn.SetReadDeadline(time.Now())
		}
		serving.Add(1)
		go func() {
			defer serving.Done()
			defer connections.remove(conn)
			defer func() { _ = conn.Close() }()
			h.serveConn(ctx, conn)
		}()
	}
}

// tcpWriteTimeout bounds each response write; a variable so a test can shorten it.
var tcpWriteTimeout = 10 * time.Second

func (h *Handler) serveConn(ctx context.Context, conn net.Conn) {
	peer := peerAddrPort(conn)
	for {
		query, err := readFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				h.log.Debug("failed to read query", "event", "dns.recv_failed", "transport", "tcp",
					"client", peer, "error", err)
			}
			return
		}
		if query == nil {
			return
		}
		response := h.respond(ctx, Request{Bytes: query, ClientIP: peer.Addr()}, "tcp", peer)
		// A client that never reads would otherwise block this goroutine, and
		// so shutdown, forever.
		_ = conn.SetWriteDeadline(time.Now().Add(tcpWriteTimeout))
		if err := writeFrame(conn, response); err != nil {
			h.log.Debug("failed to send response", "event", "dns.send_failed", "transport", "tcp",
				"client", peer, "error", err)
			return
		}
	}
}

func peerAddrPort(conn net.Conn) netip.AddrPort {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.AddrPort()
	}
	return netip.AddrPort{}
}

// readFrame reads one length-prefixed message. A zero length ends the
// connection: it returns nil bytes and no error.
func readFrame(conn io.Reader) ([]byte, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(prefix[:])
	if length == 0 {
		return nil, nil
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// writeFrame sends the prefix and body in one write. A DNS message is at most
// 65535 bytes, so the prefix cannot overflow.
func writeFrame(conn io.Writer, message []byte) error {
	frame := make([]byte, 2, 2+len(message))
	binary.BigEndian.PutUint16(frame, uint16(len(message)))
	_, err := conn.Write(append(frame, message...))
	return err
}

// connSet tracks open connections so shutdown can interrupt their reads.
type connSet struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newConnSet() *connSet { return &connSet{conns: make(map[net.Conn]struct{})} }

func (s *connSet) add(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[conn] = struct{}{}
}

func (s *connSet) remove(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

// interruptReads makes every blocked or future read fail now, leaving writes
// alone.
func (s *connSet) interruptReads() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.conns {
		_ = conn.SetReadDeadline(time.Now())
	}
}
