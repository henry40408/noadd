package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/henry40408/noadd/internal/dns"
)

// maxUDPSize is the receive buffer: 4096 for EDNS (RFC 6891), not the classic
// 512.
const maxUDPSize = 4096

// ServeUDP answers queries arriving on conn, one goroutine per datagram, until
// ctx ends. It then waits for the queries still in flight, which can still
// answer, closes conn and returns nil. A read error is logged and skipped, as
// the Rust listener does.
//
// Running queries are bounded by the handler's MaxInflight; up to as many more
// wait for a permit, and datagrams beyond that are dropped.
func (h *Handler) ServeUDP(ctx context.Context, conn *net.UDPConn) error {
	// Interrupts the blocked read but leaves writes working for the queries in
	// flight.
	stopped := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stopped()
	h.log.Info("DNS listener started", "event", "dns.listener_started", "transport", "udp", "addr", conn.LocalAddr())

	defer func() { _ = conn.Close() }()
	var inflight sync.WaitGroup
	defer inflight.Wait()

	buffer := make([]byte, maxUDPSize)
	for {
		length, source, err := conn.ReadFromUDPAddrPort(buffer)
		if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			h.log.Debug("failed to receive datagram", "event", "dns.recv_failed", "transport", "udp", "error", err)
			continue
		}
		release, admitted := h.reserveDatagramSlot()
		if !admitted {
			h.log.Debug("dropped datagram; too many queries in flight", "event", "dns.datagram_dropped", "transport", "udp", "client", source)
			continue
		}
		query := append([]byte(nil), buffer[:length]...)
		inflight.Add(1)
		go func() {
			defer inflight.Done()
			defer release()
			h.answerDatagram(ctx, conn, source, query)
		}()
	}
}

func (h *Handler) answerDatagram(ctx context.Context, conn *net.UDPConn, source netip.AddrPort, query []byte) {
	response := h.respond(ctx, Request{Bytes: query, ClientIP: source.Addr()}, "udp", source)
	response = h.truncateRecovering(query, response)
	if _, err := conn.WriteToUDPAddrPort(response, source); err != nil {
		h.log.Debug("failed to send response", "event", "dns.send_failed", "transport", "udp",
			"client", source, "error", err)
	}
}

// truncateRecovering truncates (TC) the response to the client's advertised
// size, 512 without EDNS, so it retries over TCP. It re-parses upstream data,
// which can panic the DNS library; that must not end the process, so the
// client gets SERVFAIL instead.
func (h *Handler) truncateRecovering(query, response []byte) (result []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			h.log.Error("UDP truncation panicked; answering SERVFAIL", "event", "dns.truncate_panicked",
				"panic", fmt.Sprint(recovered))
			result = dns.BuildServfail(query)
		}
	}()
	return h.truncate(query, response)
}
