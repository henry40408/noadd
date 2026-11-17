package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/henry40408/noadd/internal/db"
)

func newTestManager(t *testing.T) (*Manager, *fakeClock, *db.DB) {
	t.Helper()
	clock := newFakeClock()
	database := openDB(t)
	return NewManager(ManagerConfig{DB: database, Now: clock.Now}), clock, database
}

func infoAt(userID, createdAt, lastSeen int64) SessionInfo {
	return SessionInfo{SessionID: 1, UserID: userID, CreatedAt: createdAt, LastSeen: lastSeen, LastReauthAt: createdAt}
}

func unixOf(clock *fakeClock) int64 { return clock.Now().Unix() }

// Rust: test_session_create_and_validate
func TestSessionCreateAndValidate(t *testing.T) {
	manager, clock, _ := newTestManager(t)
	now := unixOf(clock)
	manager.Store("token", infoAt(42, now, now))
	if user, ok := manager.Validate("token"); !ok || user != 42 {
		t.Fatalf("user=%d ok=%v", user, ok)
	}
	if _, ok := manager.Validate("nope"); ok {
		t.Fatal("unknown token validated")
	}
}

// Rust: test_revoke_session_removes_only_that_token
func TestRevokeRemovesOnlyThatToken(t *testing.T) {
	manager, clock, _ := newTestManager(t)
	now := unixOf(clock)
	manager.Store("a", infoAt(1, now, now))
	manager.Store("b", infoAt(2, now, now))
	if _, found := manager.Revoke("a"); !found {
		t.Fatal("Revoke must report a live session")
	}
	if _, found := manager.Revoke("fabricated"); found {
		t.Fatal("Revoke must not report a fabricated token")
	}
	if _, ok := manager.Validate("a"); ok {
		t.Fatal("revoked session validated")
	}
	if user, ok := manager.Validate("b"); !ok || user != 2 {
		t.Fatal("other session lost")
	}
}

// Rust: session_expires_after_idle_timeout and idle_session_is_removed_from_the_store
func TestSessionExpiresAfterIdleTimeoutAndIsEvicted(t *testing.T) {
	manager, clock, _ := newTestManager(t)
	now := unixOf(clock)
	// Absolute timeout not reached, but the idle window is.
	manager.Store("t", infoAt(1, now, now-SessionIdleTimeout-1))
	if _, ok := manager.Validate("t"); ok {
		t.Fatal("idle session validated")
	}
	if manager.Len() != 0 {
		t.Fatal("expired session still in the store")
	}
}

// Rust: active_session_survives_past_the_idle_window
func TestActiveSessionRefreshesLastSeen(t *testing.T) {
	manager, clock, _ := newTestManager(t)
	now := unixOf(clock)
	stale := now - SessionIdleTimeout + 600
	manager.Store("t", infoAt(1, now, stale))
	if _, ok := manager.Validate("t"); !ok {
		t.Fatal("rejected inside the idle window")
	}
	info, _ := manager.Get("t")
	if info.LastSeen != now {
		t.Fatalf("last_seen = %d, want %d", info.LastSeen, now)
	}
	clock.Advance(SessionIdleTimeout*time.Second - time.Second)
	if _, ok := manager.Validate("t"); !ok {
		t.Fatal("refresh did not extend the idle window")
	}
}

// Boundary of the >= comparisons: exactly the timeout is expired.
func TestSessionExpiryBoundaries(t *testing.T) {
	manager, clock, _ := newTestManager(t)
	now := unixOf(clock)
	manager.Store("idle-edge", infoAt(1, now, now-SessionIdleTimeout))
	manager.Store("idle-just-inside", infoAt(1, now, now-SessionIdleTimeout+1))
	manager.Store("abs-edge", infoAt(1, now-SessionMaxAge, now))
	manager.Store("abs-just-inside", infoAt(1, now-SessionMaxAge+1, now))
	for token, want := range map[string]bool{
		"idle-edge": false, "idle-just-inside": true, "abs-edge": false, "abs-just-inside": true,
	} {
		if _, ok := manager.Validate(token); ok != want {
			t.Errorf("%s: ok=%v, want %v", token, ok, want)
		}
	}
}

// Rust: session_expires_after_absolute_timeout_even_when_active
func TestSessionExpiresAfterAbsoluteTimeoutEvenWhenActive(t *testing.T) {
	manager, clock, _ := newTestManager(t)
	now := unixOf(clock)
	manager.Store("t", infoAt(1, now-SessionMaxAge-1, now))
	if _, ok := manager.Validate("t"); ok {
		t.Fatal("session past the absolute limit validated")
	}
}

// A backwards clock reads as "not expired", the documented direction.
func TestBackwardsClockDoesNotExpireSessions(t *testing.T) {
	manager, clock, _ := newTestManager(t)
	now := unixOf(clock)
	manager.Store("t", infoAt(1, now+1000, now+1000))
	if _, ok := manager.Validate("t"); !ok {
		t.Fatal("future-dated session expired")
	}
}

// Rust: prune_expired_evicts_only_expired_entries
func TestPruneExpiredEvictsOnlyExpiredEntries(t *testing.T) {
	manager, clock, _ := newTestManager(t)
	now := unixOf(clock)
	manager.Store("active", infoAt(1, now, now))
	manager.Store("idle", infoAt(2, now, now-SessionIdleTimeout-1))
	manager.Store("absolute", infoAt(3, now-SessionMaxAge-1, now))
	if manager.PruneExpired() != 2 || manager.Len() != 1 {
		t.Fatal("prune evicted the wrong entries")
	}
}

// Rust: sweep_expired_reports_both_counts
func TestSweepReportsBothCounts(t *testing.T) {
	manager, clock, database := newTestManager(t)
	ctx := context.Background()
	now := unixOf(clock)
	userID, err := database.CreateUser(ctx, "judy", "h", 0)
	if err != nil {
		t.Fatal(err)
	}
	// Matching database rows, since the purge reads last_seen from disk.
	for token, lastSeen := range map[string]int64{"active": now, "idle": now - SessionIdleTimeout - 1} {
		if _, err := database.InsertSession(ctx, db.NewSession{
			TokenHash: token, UserID: userID, CreatedAt: now - 1000, LastSeen: lastSeen,
		}); err != nil {
			t.Fatal(err)
		}
		manager.Store(token, infoAt(userID, now-1000, lastSeen))
	}

	evicted, deleted, err := manager.Sweep(ctx)
	if err != nil || evicted != 1 || deleted != 1 {
		t.Fatalf("evicted=%d deleted=%d err=%v", evicted, deleted, err)
	}
	if _, ok := manager.Validate("active"); !ok {
		t.Fatal("active session lost")
	}
	if _, ok := manager.Validate("idle"); ok {
		t.Fatal("idle session survived")
	}
	remaining, err := database.ListSessions(ctx)
	if err != nil || len(remaining) != 1 || remaining[0].TokenHash != "active" {
		t.Fatalf("remaining=%v err=%v", remaining, err)
	}
}

func TestLoadRestoresSessionsAndPurgesExpired(t *testing.T) {
	manager, clock, database := newTestManager(t)
	ctx := context.Background()
	now := unixOf(clock)
	userID, _ := database.CreateUser(ctx, "judy", "h", 0)
	for token, lastSeen := range map[string]int64{"live": now - 10, "dead": now - SessionIdleTimeout} {
		if _, err := database.InsertSession(ctx, db.NewSession{TokenHash: token, UserID: userID, CreatedAt: now - 100, LastSeen: lastSeen}); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.Load(ctx); err != nil {
		t.Fatal(err)
	}
	info, found := manager.Get("live")
	if !found || info.UserID != userID || info.LastReauthAt != info.CreatedAt {
		t.Fatalf("info=%+v found=%v", info, found)
	}
	if _, found := manager.Get("dead"); found {
		t.Fatal("expired session restored")
	}
}

func TestFlushLastSeenPersists(t *testing.T) {
	manager, clock, database := newTestManager(t)
	ctx := context.Background()
	now := unixOf(clock)
	userID, _ := database.CreateUser(ctx, "judy", "h", 0)
	if _, err := database.InsertSession(ctx, db.NewSession{TokenHash: "t", UserID: userID, CreatedAt: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	manager.Store("t", infoAt(userID, now, now))
	clock.Advance(90 * time.Second)
	if _, ok := manager.Validate("t"); !ok {
		t.Fatal("validate failed")
	}
	if err := manager.FlushLastSeen(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _ := database.ListSessions(ctx)
	if len(rows) != 1 || rows[0].LastSeen != now+90 {
		t.Fatalf("rows=%+v", rows)
	}
}

func TestReauthWindow(t *testing.T) {
	manager, clock, _ := newTestManager(t)
	now := unixOf(clock)
	manager.Store("t", infoAt(1, now, now))
	if !manager.HasFreshReauth("t") {
		t.Fatal("login counts as a proof")
	}
	clock.Advance(ReauthWindow * time.Second)
	if manager.HasFreshReauth("t") {
		t.Fatal("stale at the window edge")
	}
	if !manager.MarkReauthenticated("t") || !manager.HasFreshReauth("t") {
		t.Fatal("reauth did not refresh")
	}
	if manager.MarkReauthenticated("unknown") || manager.HasFreshReauth("unknown") {
		t.Fatal("unknown token is never fresh")
	}
}

func seedTwoUsers(t *testing.T, manager *Manager, clock *fakeClock, database *db.DB) (alice, bob int64) {
	t.Helper()
	ctx := context.Background()
	now := unixOf(clock)
	alice, _ = database.CreateUser(ctx, "alice", "h", 0)
	bob, _ = database.CreateUser(ctx, "bob", "h", 0)
	for token, owner := range map[string]int64{"a1": alice, "a2": alice, "b1": bob} {
		if _, err := database.InsertSession(ctx, db.NewSession{TokenHash: token, UserID: owner, CreatedAt: now, LastSeen: now}); err != nil {
			t.Fatal(err)
		}
		manager.Store(token, infoAt(owner, now, now))
	}
	return alice, bob
}

func TestRevokeOthersKeepsOnlyTheNamedSession(t *testing.T) {
	manager, clock, database := newTestManager(t)
	seedTwoUsers(t, manager, clock, database)
	keep := "a1"
	if removed, err := manager.RevokeOthers(context.Background(), &keep); err != nil || removed != 2 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	if manager.Len() != 1 {
		t.Fatalf("len=%d", manager.Len())
	}
	if _, found := manager.Get("a1"); !found {
		t.Fatal("kept session lost")
	}
}

func TestRevokeOthersWithoutKeepRevokesAll(t *testing.T) {
	manager, clock, database := newTestManager(t)
	seedTwoUsers(t, manager, clock, database)
	if removed, err := manager.RevokeOthers(context.Background(), nil); err != nil || removed != 3 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	if manager.Len() != 0 {
		t.Fatal("sessions remain")
	}
}

func TestRevokeUserSessionsExceptLeavesOtherOperatorsAlone(t *testing.T) {
	manager, clock, database := newTestManager(t)
	alice, _ := seedTwoUsers(t, manager, clock, database)
	keep := "a1"
	evicted, err := manager.RevokeUserSessionsExcept(context.Background(), alice, &keep)
	if err != nil || evicted != 1 {
		t.Fatalf("evicted=%d err=%v", evicted, err)
	}
	for token, want := range map[string]bool{"a1": true, "a2": false, "b1": true} {
		if _, found := manager.Get(token); found != want {
			t.Errorf("%s present=%v, want %v", token, found, want)
		}
	}
	if evicted, _ := manager.RevokeUserSessionsExcept(context.Background(), alice, nil); evicted != 1 {
		t.Fatalf("nil keep must revoke all of the user's sessions, evicted=%d", evicted)
	}
}

func TestLoadOrCreateSessionLogSalt(t *testing.T) {
	database := openDB(t)
	ctx := context.Background()
	first, err := LoadOrCreateSessionLogSalt(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := LoadOrCreateSessionLogSalt(ctx, database)
	if first != second || first == ([SessionLogSaltLen]byte{}) {
		t.Fatal("salt must be generated once and persisted")
	}
	// Rust: decode_hex_salt_rejects_*: a malformed setting gets a fresh salt.
	for _, bad := range []string{"", "a", "g" + strings.Repeat("a", 31), strings.Repeat("a", 33)} {
		if err := database.SetSetting(ctx, SessionLogSaltKey, bad); err != nil {
			t.Fatal(err)
		}
		fresh, err := LoadOrCreateSessionLogSalt(ctx, database)
		if err != nil || fresh == first {
			t.Fatalf("%q: err=%v, salt not regenerated", bad, err)
		}
	}
}

func TestDecodeSaltRoundTrip(t *testing.T) {
	var want, got [SessionLogSaltLen]byte
	for i := range want {
		want[i] = byte(i)
	}
	if !decodeSalt("000102030405060708090a0b0c0d0e0f", &got) || got != want {
		t.Fatalf("got %x", got)
	}
	for _, bad := range []string{"0001", "g0102030405060708090a0b0c0d0e0f0", "000102030405060708090a0b0c0d0e0f00"} {
		if decodeSalt(bad, &got) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRunFlushesOnTick(t *testing.T) {
	// Run's ticker uses real time, so this only checks that it stops on cancel.
	manager, _, _ := newTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { manager.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
