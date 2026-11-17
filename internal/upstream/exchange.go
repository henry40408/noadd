package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// exchanger sends one request to one upstream and returns its response.
type exchanger interface {
	exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error)
	// closeIdle drops pooled connections after the set is replaced.
	closeIdle()
}

// matches reports whether response answers request: same ID and question.
// A mismatch is dropped, so a stray or spoofed datagram cannot be taken for the
// answer.
func matches(request, response *dns.Msg) bool {
	if response.Id != request.Id || !response.Response || len(response.Question) != len(request.Question) {
		return false
	}
	for i, question := range request.Question {
		got := response.Question[i]
		if got.Qtype != question.Qtype || got.Qclass != question.Qclass || !strings.EqualFold(got.Name, question.Name) {
			return false
		}
	}
	return true
}

var udpBuffers = sync.Pool{New: func() any { buffer := make([]byte, 65535); return &buffer }}

// udpExchanger sends over UDP, resending every retransmit interval until the
// context ends. Truncation is not retried over TCP: the forwarder treats TC as
// a failure, like the Rust build whose pool had no TCP connection configured.
type udpExchanger struct {
	addr       string
	retransmit time.Duration
}

func (u *udpExchanger) exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	wire, err := request.Pack()
	if err != nil {
		return nil, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", u.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	buffer := udpBuffers.Get().(*[]byte)
	defer udpBuffers.Put(buffer)

	deadline, hasDeadline := ctx.Deadline()
	for {
		if _, err := conn.Write(wire); err != nil {
			return nil, ctxOr(ctx, err)
		}
		resendAt := time.Now().Add(u.retransmit)
		if hasDeadline && deadline.Before(resendAt) {
			resendAt = deadline
		}
		response, err := readMatching(conn, *buffer, request, resendAt)
		if response != nil {
			return response, nil
		}
		if !isTimeout(err) || ctx.Err() != nil || (hasDeadline && !time.Now().Before(deadline)) {
			return nil, ctxOr(ctx, err)
		}
	}
}

// readMatching reads datagrams until one answers request or the deadline passes.
func readMatching(conn net.Conn, buffer []byte, request *dns.Msg, deadline time.Time) (*dns.Msg, error) {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return nil, err
		}
		response := new(dns.Msg)
		if response.Unpack(buffer[:n]) == nil && matches(request, response) {
			return response, nil
		}
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// ctxOr prefers the context's error: a deadline set to wake a blocked read
// shows up as a timeout that is really a cancellation.
func ctxOr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

const (
	maxIdleStreams  = 4
	streamIdleLimit = 30 * time.Second
)

// tlsExchanger sends over DNS-over-TLS and reuses idle connections.
type tlsExchanger struct {
	addr      string
	tlsConfig *tls.Config
	now       func() time.Time

	mu   sync.Mutex
	idle []idleStream
}

type idleStream struct {
	conn  *dns.Conn
	since time.Time
}

func (t *tlsExchanger) exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	if conn := t.takeIdle(); conn != nil {
		response, err := roundTrip(ctx, conn, request)
		if err == nil {
			t.putIdle(conn)
			return response, nil
		}
		_ = conn.Close()
		// A stale idle connection fails on first use: dial a fresh one once.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	conn, err := t.dial(ctx)
	if err != nil {
		return nil, err
	}
	response, err := roundTrip(ctx, conn, request)
	if err != nil {
		_ = conn.Close()
		return nil, ctxOr(ctx, err)
	}
	t.putIdle(conn)
	return response, nil
}

func (t *tlsExchanger) dial(ctx context.Context) (*dns.Conn, error) {
	dialer := tls.Dialer{Config: t.tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, err
	}
	return &dns.Conn{Conn: conn}, nil
}

func (t *tlsExchanger) takeIdle() *dns.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(t.idle) > 0 {
		last := len(t.idle) - 1
		stream := t.idle[last]
		t.idle = t.idle[:last]
		if t.now().Sub(stream.since) < streamIdleLimit {
			return stream.conn
		}
		_ = stream.conn.Close()
	}
	return nil
}

func (t *tlsExchanger) putIdle(conn *dns.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.idle) >= maxIdleStreams {
		_ = conn.Close()
		return
	}
	t.idle = append(t.idle, idleStream{conn: conn, since: t.now()})
}

// roundTrip writes one request on a stream and reads its response, skipping
// any message that is not the answer.
func roundTrip(ctx context.Context, conn *dns.Conn, request *dns.Msg) (*dns.Msg, error) {
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(time.Minute)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if err := conn.WriteMsg(request); err != nil {
		return nil, err
	}
	for {
		response, err := conn.ReadMsg()
		if err != nil {
			return nil, err
		}
		if matches(request, response) {
			// The deadline must not outlive this exchange on a pooled connection.
			return response, conn.SetDeadline(time.Time{})
		}
	}
}

// dohExchanger sends over DNS-over-HTTPS (RFC 8484 POST). The http.Client
// pools HTTP/2 connections.
type dohExchanger struct {
	url    string
	client *http.Client
}

func newDoHExchanger(target spec, addr string, tlsConfig *tls.Config) *dohExchanger {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		// The address was resolved once at startup; the URL host is the SNI.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: maxIdleStreams,
		IdleConnTimeout:     90 * time.Second,
	}
	return &dohExchanger{
		url:    "https://" + hostPort(target.host, target.port) + target.path,
		client: &http.Client{Transport: transport},
	}
}

func (d *dohExchanger) exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	// RFC 8484 section 4.1: ID 0 keeps the request cache-friendly.
	sent := request.Copy()
	sent.Id = 0
	wire, err := sent.Pack()
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/dns-message")
	httpRequest.Header.Set("Accept", "application/dns-message")

	httpResponse, err := d.client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", httpResponse.StatusCode)
	}
	if mediaType, _, _ := strings.Cut(httpResponse.Header.Get("Content-Type"), ";"); mediaType != "application/dns-message" {
		return nil, fmt.Errorf("doh content type %q", mediaType)
	}
	body, err := io.ReadAll(io.LimitReader(httpResponse.Body, 65535))
	if err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return nil, err
	}
	response.Id = request.Id
	return response, nil
}

func (*udpExchanger) closeIdle() {}

func (d *dohExchanger) closeIdle() { d.client.CloseIdleConnections() }

func (t *tlsExchanger) closeIdle() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, stream := range t.idle {
		_ = stream.conn.Close()
	}
	t.idle = nil
}
