// Package cache holds encoded DNS responses for optimistic serving.
//
// It stores wire bytes, not RRsets, so responses for clients with different
// EDNS or DNSSEC profiles must never share an entry: the profile is part of
// the key.
package cache

import (
	"container/list"
	"hash/maphash"
	"math"
	"sync"
	"time"

	"github.com/henry40408/noadd/internal/dns"
)

const (
	shardCount = 16

	// EntryOverheadBytes is the per-entry cost beyond the variable parts: the
	// list element, map slot, key and TTL-offsets header. It keeps the Rust
	// value so the byte bound means the same thing; BenchmarkCacheMemory checks
	// it against the real heap use.
	EntryOverheadBytes = 365

	// DefaultStaleWindow is how long an entry outlives its TTL.
	DefaultStaleWindow = 5 * time.Minute
)

// Profile is the client capabilities that affect the DNS wire response.
type Profile struct {
	HasEDNS          bool
	DNSSECOK         bool
	CheckingDisabled bool
	// UpstreamDNSSECEnabled is the upstream DO-forcing policy at request time,
	// so a request in flight before a runtime toggle cannot repopulate an entry
	// used after it.
	UpstreamDNSSECEnabled bool
}

// Key identifies a client-ready DNS wire response.
type Key struct {
	Domain    string
	QueryType uint16
	Profile   Profile
}

// State says how an entry may be used.
type State int

const (
	// Miss: nothing usable is cached.
	Miss State = iota
	// Fresh: within the original TTL.
	Fresh
	// Stale: past the TTL but inside the stale window. Serve it and refresh in
	// the background.
	Stale
)

// Entry is a cached response. Bytes and TTLOffsets are shared with the cache
// and must not be modified; copy Bytes before applying elapsed TTLs.
type Entry struct {
	// Bytes is the original (not TTL-decremented) upstream response.
	Bytes []byte
	// TTL is the original upstream TTL.
	TTL time.Duration
	// Elapsed is the age of the entry when it was read.
	Elapsed time.Duration
	// AuthenticatedData is the upstream's AD verdict, kept because a non-DO
	// client's Bytes have AD stripped but the query log still needs it.
	AuthenticatedData bool
	// TTLOffsets locates the TTL fields in Bytes, found once at Put so serving
	// never re-parses the response.
	TTLOffsets []uint32
}

// Config tunes a Cache. Zero values take the production defaults.
type Config struct {
	// CapacityBytes bounds the total weight of all entries.
	CapacityBytes int64
	// StaleWindow is how long an entry is kept beyond its TTL.
	StaleWindow time.Duration
	// Now returns the current time.
	Now func() time.Time
}

// Cache is a byte-bounded, sharded LRU of DNS responses. Get serves an entry
// for up to TTL + StaleWindow and drops it on read after that.
//
// The bound is per shard (CapacityBytes/16), so an entry heavier than that is
// never stored.
type Cache struct {
	shards      [shardCount]shard
	seed        maphash.Seed
	staleWindow time.Duration
	now         func() time.Time
}

type shard struct {
	mu       sync.Mutex
	items    map[Key]*list.Element
	order    *list.List // front = most recently used
	weight   int64
	capacity int64
}

type item struct {
	key        Key
	entry      Entry
	insertedAt time.Time
	weight     int64
}

// New creates a cache.
func New(cfg Config) *Cache {
	c := &Cache{
		seed:        maphash.MakeSeed(),
		staleWindow: cfg.StaleWindow,
		now:         cfg.Now,
	}
	if c.staleWindow == 0 {
		c.staleWindow = DefaultStaleWindow
	}
	if c.now == nil {
		c.now = time.Now
	}
	for i := range c.shards {
		c.shards[i] = shard{
			items:    make(map[Key]*list.Element),
			order:    list.New(),
			capacity: cfg.CapacityBytes / shardCount,
		}
	}
	return c
}

// Weight is the resident cost of one entry. It saturates at MaxUint32 like the
// Rust weigher, so a huge response cannot wrap into looking small.
func Weight(key Key, entry Entry) int64 {
	variable := int64(len(key.Domain)) + int64(len(entry.Bytes)) + 4*int64(len(entry.TTLOffsets))
	return min(EntryOverheadBytes+variable, math.MaxUint32)
}

func (c *Cache) shardFor(key Key) *shard {
	var h maphash.Hash
	h.SetSeed(c.seed)
	h.WriteString(key.Domain)
	h.WriteByte(byte(key.QueryType >> 8))
	h.WriteByte(byte(key.QueryType))
	h.WriteByte(profileBits(key.Profile))
	return &c.shards[h.Sum64()%shardCount]
}

func profileBits(p Profile) byte {
	var bits byte
	for i, set := range [...]bool{p.HasEDNS, p.DNSSECOK, p.CheckingDisabled, p.UpstreamDNSSECEnabled} {
		if set {
			bits |= 1 << i
		}
	}
	return bits
}

// Get returns the entry for key, including a stale one still inside the stale
// window. An entry past the window is removed and reported as a Miss.
func (c *Cache) Get(key Key) (Entry, State) {
	s := c.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	element, ok := s.items[key]
	if !ok {
		return Entry{}, Miss
	}
	it := element.Value.(*item)
	elapsed := c.now().Sub(it.insertedAt)
	if elapsed > it.entry.TTL+c.staleWindow {
		s.remove(element)
		return Entry{}, Miss
	}
	s.order.MoveToFront(element)

	entry := it.entry
	entry.Elapsed = elapsed
	if elapsed > entry.TTL {
		return entry, Stale
	}
	return entry, Fresh
}

// Put caches a response. The bytes are copied to an exact-size buffer, so the
// caller's spare capacity is not retained.
func (c *Cache) Put(key Key, response []byte, ttl time.Duration, authenticatedData bool) {
	owned := make([]byte, len(response))
	copy(owned, response)
	entry := Entry{
		Bytes:             owned,
		TTL:               ttl,
		AuthenticatedData: authenticatedData,
		TTLOffsets:        dns.TTLOffsets(owned),
	}
	it := &item{key: key, entry: entry, insertedAt: c.now(), weight: Weight(key, entry)}

	s := c.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.put(it)
}

func (s *shard) put(it *item) {
	if old, ok := s.items[it.key]; ok {
		s.remove(old)
	}
	// An entry that can never fit is refused instead of flushing the shard.
	if it.weight > s.capacity {
		return
	}
	s.items[it.key] = s.order.PushFront(it)
	s.weight += it.weight
	for s.weight > s.capacity {
		s.remove(s.order.Back())
	}
}

func (s *shard) remove(element *list.Element) {
	it := s.order.Remove(element).(*item)
	delete(s.items, it.key)
	s.weight -= it.weight
}

// InvalidateAll drops every entry. Called when the filter rules change.
func (c *Cache) InvalidateAll() {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		clear(s.items)
		s.order.Init()
		s.weight = 0
		s.mu.Unlock()
	}
}

// Len returns the number of entries, expired ones included until read.
func (c *Cache) Len() int {
	total := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		total += len(s.items)
		s.mu.Unlock()
	}
	return total
}
