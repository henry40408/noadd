package dnsserver

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// Without the recover in answerDatagram a panic in truncation ends the test
// binary.
func TestUDPTruncationPanicAnswersServfail(t *testing.T) {
	handler := New(Config{})
	t.Cleanup(handler.cancelLifetime)
	handler.truncate = func(query, response []byte) []byte { panic("boom") }

	server, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	query := []byte{0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	handler.answerDatagram(t.Context(), server, client.LocalAddr().(*net.UDPAddr).AddrPort(), query)

	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 512)
	length, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if length < 4 || buffer[0] != 0xAB || buffer[1] != 0xCD || buffer[3]&0x0F != 2 {
		t.Fatalf("response % x is not a SERVFAIL for the query", buffer[:length])
	}
}
