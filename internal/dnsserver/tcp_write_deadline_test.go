package dnsserver

import (
	"net"
	"testing"
	"time"
)

// net.Pipe has no buffer, so a client that never reads blocks the write for
// good unless a write deadline is set.
func TestTCPServeConnGivesUpOnAClientThatNeverReads(t *testing.T) {
	previous := tcpWriteTimeout
	tcpWriteTimeout = 100 * time.Millisecond
	t.Cleanup(func() { tcpWriteTimeout = previous })
	handler := New(Config{})
	t.Cleanup(handler.cancelLifetime)

	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.serveConn(t.Context(), server)
	}()
	query := []byte{0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	if _, err := client.Write(append([]byte{0, byte(len(query))}, query...)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("serveConn is stuck writing to a client that never reads")
	}
}
