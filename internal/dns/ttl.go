package dns

import (
	"encoding/binary"
	"math"
	"time"

	mdns "github.com/miekg/dns"
)

// Locating and rewriting the TTL fields of a DNS response in place. A cache hit
// reduces the TTLs by the entry's age. The offsets are found once at insert and
// patched per hit, so a served response keeps the upstream's exact bytes.

const (
	headerLen       = 12
	typeAndClassLen = 4
	ttlLen          = 4
	rdlengthLen     = 2

	// An OPT "TTL" carries the extended RCODE, version and DO flag (RFC 6891
	// section 6.1.3). A TSIG TTL must be sent as 0 (RFC 8945 section 4.2).
	typeOPT  = 41
	typeTSIG = 250

	// negativeTTLCap bounds how long a negative answer is cached.
	negativeTTLCap = 60 * time.Second
)

// TTLOffsets returns the byte offset of every TTL in response that may be
// decremented. It is empty when the message cannot be walked, so the message
// is then served with its original TTLs.
//
// The walk skips names instead of decoding them: a compression pointer ends a
// name, so there is no pointer to follow and no loop to guard against.
func TTLOffsets(response []byte) []uint32 {
	offsets, ok := scanTTLOffsets(response)
	if !ok {
		return nil
	}
	return offsets
}

// ApplyElapsed reduces every TTL at offsets by elapsedSeconds, reading the
// original from the buffer. A result is floored at 1: a zero TTL would stop the
// client caching the answer. Offsets that do not fit a four-byte field are
// skipped.
func ApplyElapsed(buf []byte, offsets []uint32, elapsedSeconds uint32) {
	if elapsedSeconds == 0 {
		return
	}
	for _, offset := range offsets {
		end := uint64(offset) + ttlLen
		if end > uint64(len(buf)) {
			continue
		}
		field := buf[offset:end]
		original := binary.BigEndian.Uint32(field)
		remaining := uint32(1)
		if original > elapsedSeconds {
			remaining = max(original-elapsedSeconds, 1)
		}
		binary.BigEndian.PutUint32(field, remaining)
	}
}

// PatchTTL returns a copy of response with every TTL reduced by elapsedSeconds.
// It is for one-off patching; a response served repeatedly should use
// TTLOffsets once and ApplyElapsed per hit.
func PatchTTL(response []byte, elapsedSeconds uint32) []byte {
	patched := append([]byte(nil), response...)
	ApplyElapsed(patched, TTLOffsets(response), elapsedSeconds)
	return patched
}

// skipName returns the offset after the domain name that starts at pos.
func skipName(buf []byte, pos int) (int, bool) {
	for {
		if pos >= len(buf) {
			return 0, false
		}
		length := buf[pos]
		switch length & 0xC0 {
		case 0x00:
			pos++
			if length == 0 {
				return pos, true
			}
			pos += int(length)
		case 0xC0:
			if pos+1 >= len(buf) {
				return 0, false
			}
			return pos + 2, true
		default:
			// 0x40 (deprecated extended label) and 0x80 (reserved).
			return 0, false
		}
	}
}

func scanTTLOffsets(buf []byte) ([]uint32, bool) {
	if len(buf) < headerLen {
		return nil, false
	}
	count := func(at int) int { return int(binary.BigEndian.Uint16(buf[at:])) }
	questions := count(4)
	records := count(6) + count(8) + count(10)

	pos := headerLen
	for range questions {
		next, ok := skipName(buf, pos)
		if !ok {
			return nil, false
		}
		pos = next + typeAndClassLen
	}

	offsets := make([]uint32, 0, records)
	for range records {
		next, ok := skipName(buf, pos)
		if !ok {
			return nil, false
		}
		pos = next
		rdlengthAt := pos + typeAndClassLen + ttlLen
		if rdlengthAt+rdlengthLen > len(buf) {
			return nil, false
		}
		recordType := binary.BigEndian.Uint16(buf[pos:])
		if recordType != typeOPT && recordType != typeTSIG {
			offsets = append(offsets, uint32(pos+typeAndClassLen))
		}
		pos = rdlengthAt + rdlengthLen + int(binary.BigEndian.Uint16(buf[rdlengthAt:]))
		if pos > len(buf) {
			return nil, false
		}
	}
	return offsets, true
}

// CacheTTL says how long to cache a response. ok is false when it must not be
// cached, so transient upstream failures cannot poison the cache: SERVFAIL,
// REFUSED and any other error code, and unparseable responses.
func CacheTTL(response []byte) (ttl time.Duration, ok bool) {
	msg := new(mdns.Msg)
	if msg.Unpack(response) != nil {
		return 0, false
	}
	switch msg.Rcode {
	case mdns.RcodeSuccess:
		if minimum, found := MinTTL(msg.Answer); found {
			return minimum, true
		}
		return NegativeTTL(msg), true
	case mdns.RcodeNameError:
		return NegativeTTL(msg), true
	}
	return 0, false
}

// MinTTL is the smallest TTL among records; found is false for an empty slice.
func MinTTL(records []mdns.RR) (minimum time.Duration, found bool) {
	smallest := uint32(math.MaxUint32)
	for _, record := range records {
		smallest = min(smallest, record.Header().Ttl)
		found = true
	}
	return time.Duration(smallest) * time.Second, found
}

// NegativeTTL is the SOA minimum of the authority section, capped at 60 s. It
// is the cap itself when there is no SOA.
func NegativeTTL(msg *mdns.Msg) time.Duration {
	smallest := negativeTTLCap
	for _, record := range msg.Ns {
		if soa, isSOA := record.(*mdns.SOA); isSOA {
			smallest = min(smallest, time.Duration(soa.Minttl)*time.Second)
		}
	}
	return smallest
}
