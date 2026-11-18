package dnsserver

import (
	"testing"

	"github.com/henry40408/noadd/internal/cache"
)

// A nil forwarder makes the refresh panic, standing in for a library panic on
// malformed upstream data. Without the recover the test binary dies.
func TestStaleRefreshPanicDoesNotCrashAndReleasesTheKey(t *testing.T) {
	handler := New(Config{})
	t.Cleanup(handler.cancelLifetime)
	key := cache.Key{}
	handler.startStaleRefresh(key, []byte{0, 1})
	handler.refreshes.Wait()
	if !handler.refreshing.TryStart(key) {
		t.Fatal("the refresh marker was left set after the panic")
	}
}
