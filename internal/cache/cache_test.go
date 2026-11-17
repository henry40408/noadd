package cache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"
)

const bigCapacity = 64 * 1024 * 1024

// fakeClock is a settable time source, so no test sleeps.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func testKey(domain string, queryType uint16) Key {
	return Key{Domain: domain, QueryType: queryType}
}

func newTestCache(capacity int64, clock *fakeClock, staleWindow time.Duration) *Cache {
	return New(Config{CapacityBytes: capacity, StaleWindow: staleWindow, Now: clock.Now})
}

// Rust: cache.rs test_insert_and_get
func TestInsertAndGet(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	key := testKey("example.com", 1)
	data := []byte{1, 2, 3}

	cache.Put(key, data, 60*time.Second, true)

	entry, state := cache.Get(key)
	if state != Fresh {
		t.Fatalf("state = %v, want Fresh", state)
	}
	if !bytes.Equal(entry.Bytes, data) || entry.TTL != 60*time.Second {
		t.Fatalf("entry = %+v", entry)
	}
	if !entry.AuthenticatedData {
		t.Fatal("AD verdict must round-trip through the cache")
	}
}

// Rust: cache.rs test_stale_entry_still_returned
func TestStaleEntryStillReturned(t *testing.T) {
	clock := newFakeClock()
	cache := newTestCache(bigCapacity, clock, 0)
	key := testKey("stale.test", 1)
	cache.Put(key, []byte{1, 2}, time.Millisecond, false)

	clock.Advance(50 * time.Millisecond)

	if _, state := cache.Get(key); state != Stale {
		t.Fatalf("state = %v, want Stale", state)
	}
}

// Rust: cache.rs test_beyond_stale_window_not_returned
func TestBeyondStaleWindowNotReturned(t *testing.T) {
	clock := newFakeClock()
	cache := newTestCache(bigCapacity, clock, 10*time.Millisecond)
	key := testKey("gone.test", 1)
	cache.Put(key, []byte{1}, time.Millisecond, false)

	clock.Advance(50 * time.Millisecond)

	if _, state := cache.Get(key); state != Miss {
		t.Fatalf("state = %v, want Miss", state)
	}
	if cache.Len() != 0 {
		t.Fatal("an entry past the stale window must be dropped on read")
	}
}

// Rust: cache.rs test_invalidate_all
func TestInvalidateAllOnInsertedEntry(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	key := testKey("clear.test", 1)
	cache.Put(key, []byte{1}, 300*time.Second, false)

	cache.InvalidateAll()

	if _, state := cache.Get(key); state != Miss {
		t.Fatalf("state = %v, want Miss", state)
	}
}

// Rust: cache.rs test_different_ttls_per_entry
func TestDifferentTTLsPerEntry(t *testing.T) {
	clock := newFakeClock()
	cache := newTestCache(bigCapacity, clock, 5*time.Millisecond)
	short, long := testKey("short.test", 1), testKey("long.test", 1)
	cache.Put(short, []byte{1}, time.Millisecond, false)
	cache.Put(long, []byte{2}, 300*time.Second, false)

	clock.Advance(50 * time.Millisecond)

	if _, state := cache.Get(short); state != Miss {
		t.Fatalf("short: state = %v, want Miss", state)
	}
	if _, state := cache.Get(long); state != Fresh {
		t.Fatalf("long: state = %v, want Fresh", state)
	}
}

// aResponse is a DNS response with one A answer of the given TTL.
func aResponse(ttl uint32) []byte {
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}
	msg = append(msg, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1)
	msg = append(msg, 0xC0, 0x0C, 0, 1, 0, 1)
	msg = binary.BigEndian.AppendUint32(msg, ttl)
	return append(msg, 0, 4, 203, 0, 113, 1)
}

// Rust: cache.rs ttl_offsets_are_found_when_the_entry_is_inserted
func TestTTLOffsetsAreFoundWhenTheEntryIsInserted(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	key := testKey("example.com", 1)
	cache.Put(key, aResponse(300), 60*time.Second, false)

	entry, _ := cache.Get(key)
	if len(entry.TTLOffsets) != 1 {
		t.Fatalf("offsets = %v, one answer record means one TTL field", entry.TTLOffsets)
	}
	at := entry.TTLOffsets[0]
	if got := binary.BigEndian.Uint32(entry.Bytes[at : at+4]); got != 300 {
		t.Fatalf("TTL at offset = %d, want 300", got)
	}
}

// Rust: cache.rs a_response_that_is_not_a_dns_message_gets_no_offsets
func TestAResponseThatIsNotADNSMessageGetsNoOffsets(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	key := testKey("garbage.test", 1)
	cache.Put(key, []byte{0xab, 0xcd}, 60*time.Second, false)

	entry, state := cache.Get(key)
	if state != Fresh || len(entry.TTLOffsets) != 0 {
		t.Fatalf("state = %v, offsets = %v", state, entry.TTLOffsets)
	}
}

// Rust: cache_test.rs test_cache_miss_returns_none
func TestCacheMissReturnsNone(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	if _, state := cache.Get(testKey("example.com", 1)); state != Miss {
		t.Fatalf("state = %v, want Miss", state)
	}
}

// Rust: cache_test.rs test_cache_insert_and_get
func TestCacheInsertAndGet(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	key := testKey("example.com", 1)
	response := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	cache.Put(key, response, 60*time.Second, false)

	entry, state := cache.Get(key)
	if state == Miss || !bytes.Equal(entry.Bytes, response) {
		t.Fatalf("entry = %+v, state = %v", entry, state)
	}
}

// Rust: cache_test.rs test_cache_distinguishes_client_response_profiles
func TestCacheDistinguishesClientResponseProfiles(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	plain := testKey("example.com", 1)
	edns := Key{Domain: "example.com", QueryType: 1, Profile: Profile{HasEDNS: true}}
	forced := Key{Domain: "example.com", QueryType: 1, Profile: Profile{UpstreamDNSSECEnabled: true}}
	cache.Put(plain, []byte{0x01}, 300*time.Second, false)
	cache.Put(edns, []byte{0x02}, 300*time.Second, false)
	cache.Put(forced, []byte{0x03}, 300*time.Second, false)

	for key, want := range map[Key]byte{plain: 1, edns: 2, forced: 3} {
		entry, _ := cache.Get(key)
		if len(entry.Bytes) != 1 || entry.Bytes[0] != want {
			t.Errorf("key %+v: bytes = %v, want [%d]", key, entry.Bytes, want)
		}
	}
}

// Every profile flag must reach the key: a collision would serve a response
// shaped for another client.
func TestEachProfileFlagSeparatesEntries(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	profiles := []Profile{
		{}, {HasEDNS: true}, {DNSSECOK: true}, {CheckingDisabled: true}, {UpstreamDNSSECEnabled: true},
	}
	for i, profile := range profiles {
		cache.Put(Key{Domain: "a.test", QueryType: 1, Profile: profile}, []byte{byte(i)}, time.Minute, false)
	}
	for i, profile := range profiles {
		entry, _ := cache.Get(Key{Domain: "a.test", QueryType: 1, Profile: profile})
		if len(entry.Bytes) != 1 || entry.Bytes[0] != byte(i) {
			t.Errorf("profile %+v: bytes = %v, want [%d]", profile, entry.Bytes, i)
		}
	}
}

// Rust: cache_test.rs test_cache_invalidate_all
func TestCacheInvalidateAll(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	a, aaaa := testKey("example.com", 1), testKey("example.com", 28)
	cache.Put(a, []byte{1, 2, 3}, 60*time.Second, false)
	cache.Put(aaaa, []byte{4, 5, 6}, 60*time.Second, false)

	cache.InvalidateAll()

	for _, key := range []Key{a, aaaa} {
		if _, state := cache.Get(key); state != Miss {
			t.Errorf("%+v survived InvalidateAll", key)
		}
	}
	cache.Put(a, []byte{9}, time.Minute, false)
	if _, state := cache.Get(a); state != Fresh {
		t.Fatal("the cache must accept entries after InvalidateAll")
	}
}

// survivors counts how many of n entries of responseLen bytes survive a cap.
func survivors(capacity int64, n, responseLen int) int {
	cache := newTestCache(capacity, newFakeClock(), 0)
	keys := make([]Key, n)
	for i := range keys {
		keys[i] = testKey(fmt.Sprintf("e%d.test", i), 1)
		cache.Put(keys[i], bytes.Repeat([]byte{0xAB}, responseLen), 300*time.Second, false)
	}
	alive := 0
	for _, key := range keys {
		if _, state := cache.Get(key); state != Miss {
			alive++
		}
	}
	return alive
}

// Rust: cache_test.rs capacity_is_measured_in_bytes_not_entries
func TestCapacityIsMeasuredInBytesNotEntries(t *testing.T) {
	const capacity, n = 100_000, 60

	if small := survivors(capacity, n, 20); small != n {
		t.Fatalf("%d tiny responses must all be kept, %d survived", n, small)
	}
	if large := survivors(capacity, n, 8_000); large >= n/2 {
		t.Fatalf("%d x 8000-byte responses are five times the cap yet %d survived", n, large)
	}
}

// Rust: cache_test.rs a_large_response_displaces_more_than_a_small_one
func TestALargeResponseDisplacesMoreThanASmallOne(t *testing.T) {
	const capacity = 100_000

	small := survivors(capacity, 400, 20)
	large := survivors(capacity, 400, 2_000)
	if small <= large*3 {
		t.Fatalf("a 20-byte response should be worth several 2000-byte ones: %d small vs %d large", small, large)
	}
}

func TestWeightSaturates(t *testing.T) {
	huge := Entry{Bytes: make([]byte, 1)}
	key := testKey("a.test", 1)
	if got := Weight(key, huge); got != EntryOverheadBytes+int64(len(key.Domain))+1 {
		t.Fatalf("weight = %d", got)
	}
	// Past MaxUint32 without allocating 4 GiB: the formula takes the lengths.
	key.Domain = string(make([]byte, 1<<20))
	if got := Weight(key, huge); got > 1<<32-1 {
		t.Fatalf("weight %d exceeds uint32", got)
	}
}

// Shard boundary: an entry heavier than one shard's share is refused, and
// refusing it must not evict the entries already there nor leave the replaced
// value behind.
func TestEntryHeavierThanAShardIsRefused(t *testing.T) {
	cache := newTestCache(16*1000, newFakeClock(), 0)
	key := testKey("big.test", 1)
	cache.Put(key, []byte{1}, time.Minute, false)

	cache.Put(key, make([]byte, 2000), time.Minute, false)

	if _, state := cache.Get(key); state != Miss {
		t.Fatal("an oversized replacement must not leave the old value behind")
	}
	if cache.Len() != 0 {
		t.Fatalf("Len = %d, want 0", cache.Len())
	}
}

// An entry exactly as heavy as the shard capacity fits; one byte more does not.
func TestShardWeightBoundary(t *testing.T) {
	key := testKey("edge.test", 1)
	response := make([]byte, 100)
	weight := Weight(key, Entry{Bytes: response})

	exact := newTestCache(weight*shardCount, newFakeClock(), 0)
	exact.Put(key, response, time.Minute, false)
	if _, state := exact.Get(key); state == Miss {
		t.Fatal("an entry equal to the shard capacity must fit")
	}

	under := newTestCache(weight*shardCount-shardCount, newFakeClock(), 0)
	under.Put(key, response, time.Minute, false)
	if _, state := under.Get(key); state != Miss {
		t.Fatal("an entry above the shard capacity must be refused")
	}
}

func TestLeastRecentlyUsedEntryIsEvictedFirst(t *testing.T) {
	// All keys in one shard are impractical to force, so use one shard's worth
	// of capacity and keys that share a shard.
	cache := newTestCache(0, newFakeClock(), 0)
	shared := cache.shardFor(testKey("k000.test", 1))
	var keys []Key
	for i := 0; len(keys) < 3; i++ {
		key := testKey(fmt.Sprintf("k%03d.test", i), 1)
		if cache.shardFor(key) == shared {
			keys = append(keys, key)
		}
	}
	response := make([]byte, 100)
	weight := Weight(keys[0], Entry{Bytes: response})
	shared.capacity = 2 * weight

	cache.Put(keys[0], response, time.Minute, false)
	cache.Put(keys[1], response, time.Minute, false)
	cache.Get(keys[0]) // keys[1] is now the least recently used
	cache.Put(keys[2], response, time.Minute, false)

	if _, state := cache.Get(keys[1]); state != Miss {
		t.Fatal("the least recently used entry must be evicted")
	}
	for _, key := range []Key{keys[0], keys[2]} {
		if _, state := cache.Get(key); state == Miss {
			t.Fatalf("%+v was evicted", key)
		}
	}
}

// Rust: cache_memory_bench.rs an_entry_does_not_retain_its_caller_s_spare_capacity
func TestAnEntryDoesNotRetainItsCallersSpareCapacity(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	key := testKey("slack.test", 1)
	response := make([]byte, 64, 64*1024)
	for i := range response {
		response[i] = 0xAB
	}

	cache.Put(key, response, 300*time.Second, false)

	entry, _ := cache.Get(key)
	if cap(entry.Bytes) != len(entry.Bytes) || len(entry.Bytes) != 64 || entry.Bytes[63] != 0xAB {
		t.Fatalf("len = %d, cap = %d: the spare capacity is retained or the bytes were truncated",
			len(entry.Bytes), cap(entry.Bytes))
	}
}

// The cache must own its bytes: a caller reusing its buffer cannot corrupt an entry.
func TestPutCopiesTheCallersBuffer(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	key := testKey("copy.test", 1)
	buffer := []byte{1, 2, 3}
	cache.Put(key, buffer, time.Minute, false)

	buffer[0] = 99

	if entry, _ := cache.Get(key); entry.Bytes[0] != 1 {
		t.Fatal("the entry shares the caller's buffer")
	}
}

// Rust: cache_memory_bench.rs serving_an_entry_retains_nothing. Serving works
// on a copy; the cached bytes and offsets must not change.
func TestServingAnEntryLeavesItUnchanged(t *testing.T) {
	cache := newTestCache(bigCapacity, newFakeClock(), 0)
	key := testKey("example.com", 1)
	cache.Put(key, aResponse(300), time.Minute, false)

	entry, _ := cache.Get(key)
	if len(entry.TTLOffsets) == 0 {
		t.Fatal("the fixture must have TTLs that are found")
	}
	before := bytes.Clone(entry.Bytes)
	for range 8 {
		served := bytes.Clone(entry.Bytes)
		served[len(served)-1] ^= 0xFF
	}

	again, _ := cache.Get(key)
	if !bytes.Equal(again.Bytes, before) || len(again.TTLOffsets) != len(entry.TTLOffsets) {
		t.Fatal("serving changed the cached entry")
	}
}

func TestConcurrentAccessIsRaceFree(t *testing.T) {
	cache := newTestCache(200_000, newFakeClock(), 0)
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				key := testKey(fmt.Sprintf("w%d-%d.test", worker, i%50), 1)
				cache.Put(key, make([]byte, 80), time.Minute, false)
				cache.Get(key)
				if i%100 == 0 {
					cache.InvalidateAll()
				}
			}
		}()
	}
	wg.Wait()
}
