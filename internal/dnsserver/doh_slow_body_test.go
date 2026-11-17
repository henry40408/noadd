package dnsserver

import (
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

// A client that promises a body and never finishes it must be cut off rather
// than hold a goroutine before any authorisation happens.
func TestDoHPostBodyReadIsBounded(t *testing.T) {
	previous := dohBodyTimeout
	dohBodyTimeout = 200 * time.Millisecond
	t.Cleanup(func() { dohBodyTimeout = previous })

	fixture := newDoHFixture(t, handlerOptions{})
	server := httptest.NewServer(fixture.mux)
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := "POST /dns-query HTTP/1.1\r\nHost: x\r\nContent-Type: application/dns-message\r\nContent-Length: 100\r\n\r\nabc"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 512)
	length, err := conn.Read(buffer)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the server kept waiting for the rest of the body")
	}
	if length > 0 && string(buffer[:12]) == "HTTP/1.1 200" {
		t.Fatalf("a truncated body must not succeed: %q", buffer[:length])
	}
}
