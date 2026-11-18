package server

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// contentETag returns the strong, quoted ETag for body: the SipHash-1-3 digest
// (zero keys) of the 8-byte little-endian length followed by the bytes, which
// is what Rust's DefaultHasher computes for a byte slice. Keeping the digest
// means a client's cached copy stays valid across the Rust to Go switch.
func contentETag(body []byte) string {
	prefixed := make([]byte, 8, 8+len(body))
	binary.LittleEndian.PutUint64(prefixed, uint64(len(body)))
	prefixed = append(prefixed, body...)
	return fmt.Sprintf("\"%016x\"", sipHash13(prefixed))
}

// sipHash13 is SipHash-1-3 with both keys zero.
func sipHash13(data []byte) uint64 {
	v0 := uint64(0x736f6d6570736575)
	v1 := uint64(0x646f72616e646f6d)
	v2 := uint64(0x6c7967656e657261)
	v3 := uint64(0x7465646279746573)

	round := func() {
		v0 += v1
		v1 = bits.RotateLeft64(v1, 13)
		v1 ^= v0
		v0 = bits.RotateLeft64(v0, 32)
		v2 += v3
		v3 = bits.RotateLeft64(v3, 16)
		v3 ^= v2
		v0 += v3
		v3 = bits.RotateLeft64(v3, 21)
		v3 ^= v0
		v2 += v1
		v1 = bits.RotateLeft64(v1, 17)
		v1 ^= v2
		v2 = bits.RotateLeft64(v2, 32)
	}

	length := len(data)
	for len(data) >= 8 {
		word := binary.LittleEndian.Uint64(data)
		v3 ^= word
		round()
		v0 ^= word
		data = data[8:]
	}

	last := uint64(length) << 56
	for i, b := range data {
		last |= uint64(b) << (8 * uint(i))
	}
	v3 ^= last
	round()
	v0 ^= last

	v2 ^= 0xff
	round()
	round()
	round()
	return v0 ^ v1 ^ v2 ^ v3
}
