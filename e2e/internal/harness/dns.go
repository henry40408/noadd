package harness

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
)

// SendDNSQuery sends one A query for name to the UDP listener on port. No
// reply is read: the query is logged either way, and that is what callers poll
// for.
func SendDNSQuery(port int, name string) error {
	conn, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.Write(queryPacket(name))
	return err
}

// queryPacket is a minimal A query: one question, recursion desired, no EDNS.
func queryPacket(name string) []byte {
	const (
		transactionID = 0x1234
		recursionWant = 0x0100
		typeA         = 1
		classIN       = 1
	)
	packet := binary.BigEndian.AppendUint16(nil, transactionID)
	packet = binary.BigEndian.AppendUint16(packet, recursionWant)
	packet = binary.BigEndian.AppendUint16(packet, 1) // QDCOUNT
	packet = append(packet, 0, 0, 0, 0, 0, 0)         // AN, NS, AR counts
	for _, label := range strings.Split(name, ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0)
	packet = binary.BigEndian.AppendUint16(packet, typeA)
	return binary.BigEndian.AppendUint16(packet, classIN)
}
