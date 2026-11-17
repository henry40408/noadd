package dns

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFirstCallerBecomesFetcher(t *testing.T) {
	group := NewGroup[string](0)
	fetch, wait := group.Begin("a.com")
	if fetch == nil || wait != nil {
		t.Fatal("first caller should be the fetcher")
	}
	if group.Len() != 1 {
		t.Fatalf("Len = %d, want 1", group.Len())
	}
}

func TestSecondCallerBecomesWaiter(t *testing.T) {
	group := NewGroup[string](0)
	group.Begin("a.com")
	fetch, wait := group.Begin("a.com")
	if fetch != nil || wait == nil {
		t.Fatal("second caller should be a waiter")
	}
}

func TestDifferentKeysAreIndependent(t *testing.T) {
	group := NewGroup[string](0)
	group.Begin("a.com")
	if fetch, _ := group.Begin("b.com"); fetch == nil {
		t.Fatal("a different key should get its own fetcher slot")
	}
}

func TestFinishNotifiesAndClears(t *testing.T) {
	group := NewGroup[string](0)
	fetch, _ := group.Begin("a.com")
	_, wait := group.Begin("a.com")

	go func() {
		time.Sleep(20 * time.Millisecond)
		fetch.Finish()
	}()

	select {
	case <-wait:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("the waiter was not notified when the fetcher finished")
	}
	if group.Len() != 0 {
		t.Fatalf("Len = %d, want 0", group.Len())
	}
}

func TestFinishTwiceIsHarmless(t *testing.T) {
	group := NewGroup[string](0)
	fetch, _ := group.Begin("a.com")
	fetch.Finish()
	next, _ := group.Begin("a.com")
	fetch.Finish() // must not release the next fetcher's slot
	if again, _ := group.Begin("a.com"); again != nil {
		t.Fatal("a second Finish released the slot of the next fetcher")
	}
	next.Finish()
}

func TestWaitGivesUpAfterTheCap(t *testing.T) {
	group := NewGroup[string](30 * time.Millisecond)
	group.Begin("wedged.com")
	_, wait := group.Begin("wedged.com")

	started := time.Now()
	group.Wait(context.Background(), wait)

	if elapsed := time.Since(started); elapsed < 25*time.Millisecond || elapsed > time.Second {
		t.Fatalf("Wait returned after %v, want about 30ms", elapsed)
	}
}

func TestWaitReturnsWhenContextEnds(t *testing.T) {
	group := NewGroup[string](time.Minute)
	group.Begin("a.com")
	_, wait := group.Begin("a.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	returned := make(chan struct{})
	go func() {
		group.Wait(ctx, wait)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("Wait ignored the cancelled context")
	}
}

// Rust: coalescing_test.rs test_cold_miss_coalesces_concurrent_queries, at the
// group level (the handler-level test belongs to Step 12): 50 concurrent misses
// on one key make one fetch and every caller then sees the stored result.
func TestColdMissCoalescesConcurrentQueries(t *testing.T) {
	group := NewGroup[string](0)
	var stored atomic.Pointer[string]
	var fetches atomic.Int32

	const callers = 50
	var ready, finished sync.WaitGroup
	ready.Add(callers)
	finished.Add(callers)
	release := make(chan struct{})
	for range callers {
		go func() {
			defer finished.Done()
			ready.Done()
			<-release
			fetch, wait := group.Begin("coalesce-me")
			if fetch == nil {
				group.Wait(context.Background(), wait)
				return
			}
			defer fetch.Finish()
			fetches.Add(1)
			time.Sleep(100 * time.Millisecond)
			answer := "answer"
			stored.Store(&answer)
		}()
	}
	ready.Wait()
	close(release)
	finished.Wait()

	if got := fetches.Load(); got != 1 {
		t.Fatalf("%d concurrent cold misses made %d fetches, want 1", callers, got)
	}
	if stored.Load() == nil {
		t.Fatal("the waiters returned before the fetcher stored its result")
	}
	if group.Len() != 0 {
		t.Fatal("the slot was not released")
	}
}

// Rust: coalescing_test.rs test_different_keys_do_not_coalesce
func TestDifferentKeysDoNotCoalesce(t *testing.T) {
	group := NewGroup[string](0)
	var fetches atomic.Int32
	var wg sync.WaitGroup
	for _, key := range []string{"one", "two", "three"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fetch, _ := group.Begin(key)
			if fetch == nil {
				return
			}
			defer fetch.Finish()
			fetches.Add(1)
			time.Sleep(50 * time.Millisecond)
		}()
	}
	wg.Wait()
	if fetches.Load() != 3 {
		t.Fatalf("fetches = %d, each distinct key needs its own", fetches.Load())
	}
}

// Rust: coalescing_test.rs test_slot_released_after_fetcher_completes
func TestSlotReleasedAfterFetcherCompletes(t *testing.T) {
	group := NewGroup[string](0)
	first, _ := group.Begin("slot")
	first.Finish()
	if second, _ := group.Begin("slot"); second == nil {
		t.Fatal("a miss after the fetcher finished must fetch again")
	}
}

// A fetcher that panics must not wedge the key: Finish is deferred.
func TestPanickingFetcherReleasesTheKey(t *testing.T) {
	group := NewGroup[string](0)
	func() {
		defer func() { _ = recover() }()
		fetch, _ := group.Begin("boom")
		defer fetch.Finish()
		panic("fetch failed")
	}()
	if fetch, _ := group.Begin("boom"); fetch == nil {
		t.Fatal("the key stayed wedged after a panic")
	}
}

// No goroutine may be left behind by waiters that time out or are woken.
func TestWaitersLeaveNoGoroutines(t *testing.T) {
	group := NewGroup[string](10 * time.Millisecond)
	fetch, _ := group.Begin("a")
	baseline := countGoroutines()

	var wg sync.WaitGroup
	for range 100 {
		_, wait := group.Begin("a")
		wg.Add(1)
		go func() {
			defer wg.Done()
			group.Wait(context.Background(), wait)
		}()
	}
	wg.Wait()
	fetch.Finish()

	deadline := time.Now().Add(time.Second)
	for countGoroutines() > baseline && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := countGoroutines(); got > baseline {
		t.Fatalf("goroutines = %d, baseline %d", got, baseline)
	}
}

// Rust: stale_stampede_test.rs test_stale_refresh_is_deduplicated
func TestStaleRefreshIsDeduplicated(t *testing.T) {
	set := NewRefreshSet[string]()
	var refreshes atomic.Int32

	var ready, finished sync.WaitGroup
	const readers = 50
	ready.Add(readers)
	finished.Add(readers)
	release := make(chan struct{})
	for range readers {
		go func() {
			defer finished.Done()
			ready.Done()
			<-release
			if !set.TryStart("stampede") {
				return
			}
			defer set.End("stampede")
			refreshes.Add(1)
			time.Sleep(100 * time.Millisecond)
		}()
	}
	ready.Wait()
	close(release)
	finished.Wait()

	if got := refreshes.Load(); got != 1 {
		t.Fatalf("%d concurrent stale reads started %d refreshes, want 1", readers, got)
	}
}

// Rust: stale_stampede_test.rs test_refresh_lock_released_after_completion
func TestRefreshLockReleasedAfterCompletion(t *testing.T) {
	set := NewRefreshSet[string]()
	for round := 1; round <= 2; round++ {
		if !set.TryStart("relock") {
			t.Fatalf("round %d: the lock was not released", round)
		}
		if set.TryStart("relock") {
			t.Fatalf("round %d: a second refresh started while one was running", round)
		}
		set.End("relock")
	}
}

// Rust: stale_stampede_test.rs test_different_domains_refresh_independently
func TestDifferentDomainsRefreshIndependently(t *testing.T) {
	set := NewRefreshSet[string]()
	if !set.TryStart("alpha") || !set.TryStart("beta") {
		t.Fatal("different keys must not block each other")
	}
}

// Rust: dashmap RefreshGuard test (handler.rs refresh_guard_removes_key_on_drop)
func TestRefreshEndAfterPanicReleasesTheKey(t *testing.T) {
	set := NewRefreshSet[string]()
	func() {
		defer func() { _ = recover() }()
		set.TryStart("k")
		defer set.End("k")
		panic("refresh failed")
	}()
	if !set.TryStart("k") {
		t.Fatal("the key stayed claimed after a panic")
	}
}

func countGoroutines() int { return runtime.NumGoroutine() }
