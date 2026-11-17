package filter

import (
	"cmp"
	"slices"
)

// exactEntry is one rule that matches only its own domain. seq keeps input
// order, so a duplicate resolves to the entry that came first.
type exactEntry struct {
	domain string
	list   uint16
	seq    uint32
}

func sortExactEntries(entries []exactEntry) {
	slices.SortFunc(entries, func(a, b exactEntry) int {
		if c := cmp.Compare(a.domain, b.domain); c != 0 {
			return c
		}
		return cmp.Compare(a.seq, b.seq)
	})
}

// exactSet is a sorted, de-duplicated set of domains packed into one byte
// buffer, so the garbage collector sees three pointer-free slices however many
// rules there are. Domain i is data[offsets[i]:offsets[i+1]].
type exactSet struct {
	data    []byte
	offsets []uint32
	// lists holds the owning list index per domain; nil for an allow set.
	lists []uint16
}

// packExactSet packs entries that sortExactEntries has sorted. For duplicate
// domains the first entry wins.
func packExactSet(sorted []exactEntry, withLists bool) exactSet {
	distinct, totalBytes := 0, 0
	for i, entry := range sorted {
		if i > 0 && entry.domain == sorted[i-1].domain {
			continue
		}
		distinct++
		totalBytes += len(entry.domain)
	}
	set := exactSet{
		data:    make([]byte, 0, totalBytes),
		offsets: make([]uint32, 0, distinct+1),
	}
	if withLists {
		set.lists = make([]uint16, 0, distinct)
	}
	for i, entry := range sorted {
		if i > 0 && entry.domain == sorted[i-1].domain {
			continue
		}
		set.offsets = append(set.offsets, uint32(len(set.data)))
		set.data = append(set.data, entry.domain...)
		if withLists {
			set.lists = append(set.lists, entry.list)
		}
	}
	set.offsets = append(set.offsets, uint32(len(set.data)))
	return set
}

func (s *exactSet) len() int { return len(s.offsets) - 1 }

// find returns the index of domain, if present.
func (s *exactSet) find(domain string) (int, bool) {
	low, high := 0, s.len()
	for low < high {
		mid := int(uint(low+high) >> 1)
		if string(s.data[s.offsets[mid]:s.offsets[mid+1]]) < domain {
			low = mid + 1
		} else {
			high = mid
		}
	}
	if low == s.len() || string(s.data[s.offsets[low]:s.offsets[low+1]]) != domain {
		return 0, false
	}
	return low, true
}

func (s *exactSet) heapBytes() int {
	return cap(s.data) + 4*cap(s.offsets) + 2*cap(s.lists)
}
