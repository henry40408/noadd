package db

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

// One-to-one ports of tests/db_test.rs. The session timeouts are the
// constants of internal/auth (not ported yet): 7 days absolute, 48 h idle.
const (
	sessionMaxAgeSecs     = 7 * 24 * 3600
	sessionIdleTimeoutSec = 48 * 3600
)

func rustTestDB(t *testing.T) *DB { return fileDB(t) }

func plainLog(timestamp int64, domain, queryType, clientIP string, blocked bool, responseMs int64) QueryLogEntry {
	return QueryLogEntry{Timestamp: timestamp, Domain: domain, QueryType: queryType, ClientIP: clientIP, Blocked: blocked, ResponseMs: responseMs}
}

func insertLogs(t *testing.T, database *DB, entries ...QueryLogEntry) {
	t.Helper()
	must(t, database.InsertQueryLogs(context.Background(), entries))
}

func logDomains(t *testing.T, database *DB, filter QueryLogFilter, limit, offset int64) []string {
	t.Helper()
	rows, err := database.QueryLogs(context.Background(), filter, limit, offset)
	must(t, err)
	domains := make([]string, len(rows))
	for i, row := range rows {
		domains[i] = row.Domain
	}
	return domains
}

func TestDatabaseCreatesTables(t *testing.T) {
	tables, err := rustTestDB(t).ListTables(context.Background())
	must(t, err)
	for _, want := range []string{"settings", "query_logs", "filter_lists", "custom_rules", "filter_list_content"} {
		if !slices.Contains(tables, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestSettingsGetSet(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	must(t, database.SetSetting(ctx, "dns_port", "5353"))
	if value, found, _ := database.GetSetting(ctx, "dns_port"); !found || value != "5353" {
		t.Fatalf("got %q %v", value, found)
	}
	must(t, database.SetSetting(ctx, "dns_port", "1053"))
	if value, found, _ := database.GetSetting(ctx, "dns_port"); !found || value != "1053" {
		t.Fatalf("got %q %v", value, found)
	}
}

func TestSettingsGetMissingReturnsNone(t *testing.T) {
	if _, found, err := rustTestDB(t).GetSetting(context.Background(), "nonexistent"); err != nil || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

func TestHasAnyQueryLogsReportsWhetherTheApplianceHasServedTraffic(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	if has, err := database.HasAnyQueryLogs(ctx); err != nil || has {
		t.Fatalf("a fresh appliance has served nothing: %v %v", has, err)
	}
	insertLogs(t, database, plainLog(1_000_000, "example.com", "A", "192.168.1.1", false, 5))
	if has, err := database.HasAnyQueryLogs(ctx); err != nil || !has {
		t.Fatalf("has=%v err=%v", has, err)
	}
}

func TestInsertAndQueryLogs(t *testing.T) {
	database := rustTestDB(t)
	insertLogs(t, database,
		plainLog(1_000_000, "example.com", "A", "192.168.1.1", false, 5),
		plainLog(2_000_000, "ads.tracker.com", "AAAA", "192.168.1.2", true, 1))

	if got := logDomains(t, database, QueryLogFilter{}, 100, 0); !slices.Equal(got, []string{"ads.tracker.com", "example.com"}) {
		t.Fatalf("newest first: %v", got)
	}
	if got := logDomains(t, database, QueryLogFilter{Blocked: ptr(true)}, 100, 0); !slices.Equal(got, []string{"ads.tracker.com"}) {
		t.Fatalf("blocked: %v", got)
	}
	if got := logDomains(t, database, QueryLogFilter{Search: ptr("example")}, 100, 0); !slices.Equal(got, []string{"example.com"}) {
		t.Fatalf("search: %v", got)
	}
}

func TestQueryLogsSearchPrefixFastpath(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	insertLogs(t, database,
		plainLog(1_000_000, "example.com", "A", "10.0.0.1", false, 1),
		plainLog(1_000_001, "api.example.com", "A", "10.0.0.1", false, 1),
		plainLog(1_000_002, "subexample.net", "A", "10.0.0.1", false, 1),
		plainLog(1_000_003, "tracker.io", "A", "10.0.0.1", false, 1))

	// A plain term is a prefix match: not api.example.com, not subexample.net.
	if got := logDomains(t, database, QueryLogFilter{Search: ptr("example")}, 100, 0); !slices.Equal(got, []string{"example.com"}) {
		t.Fatalf("prefix: %v", got)
	}
	if total, err := database.CountLogs(ctx, QueryLogFilter{Search: ptr("example")}); err != nil || total != 1 {
		t.Fatalf("prefix total %d %v", total, err)
	}
	// The term is lowercased before matching.
	if got := logDomains(t, database, QueryLogFilter{Search: ptr("ExAmPlE")}, 100, 0); !slices.Equal(got, []string{"example.com"}) {
		t.Fatalf("mixed case: %v", got)
	}
	// Wildcards fall back to a substring LIKE.
	for _, term := range []string{"*example*", "%example%"} {
		if got := logDomains(t, database, QueryLogFilter{Search: ptr(term)}, 100, 0); len(got) != 3 {
			t.Fatalf("%s: %v", term, got)
		}
	}
	// A blank search is no filter.
	if got := logDomains(t, database, QueryLogFilter{Search: ptr("   ")}, 100, 0); len(got) != 4 {
		t.Fatalf("blank: %v", got)
	}
}

func TestQueryLogsPagination(t *testing.T) {
	database := rustTestDB(t)
	entries := make([]QueryLogEntry, 25)
	for i := range entries {
		entries[i] = plainLog(1_000_000+int64(i)*1000, fmt.Sprintf("domain%d.com", i), "A", "192.168.1.1", false, 1)
	}
	insertLogs(t, database, entries...)

	page1 := logDomains(t, database, QueryLogFilter{}, 10, 0)
	page2 := logDomains(t, database, QueryLogFilter{}, 10, 10)
	page3 := logDomains(t, database, QueryLogFilter{}, 10, 20)
	if len(page1) != 10 || page1[0] != "domain24.com" {
		t.Fatalf("page1 %v", page1)
	}
	if len(page2) != 10 || page2[0] != "domain14.com" {
		t.Fatalf("page2 %v", page2)
	}
	if len(page3) != 5 {
		t.Fatalf("page3 %v", page3)
	}
}

func TestFilterListsCrudPort(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	id, err := database.AddFilterList(ctx, "EasyList", "https://easylist.example.com/list.txt", true)
	must(t, err)
	if id <= 0 {
		t.Fatalf("id %d", id)
	}
	lists, _ := database.GetFilterLists(ctx)
	if len(lists) != 1 || lists[0].Name != "EasyList" || lists[0].URL != "https://easylist.example.com/list.txt" || !lists[0].Enabled || lists[0].RuleCount != 0 {
		t.Fatalf("%+v", lists)
	}
	must(t, database.UpdateFilterListEnabled(ctx, id, false))
	lists, _ = database.GetFilterLists(ctx)
	if lists[0].Enabled {
		t.Fatal("still enabled")
	}
	must(t, database.UpdateFilterListStats(ctx, id, 42000, 9001))
	lists, _ = database.GetFilterLists(ctx)
	if lists[0].RuleCount != 9001 || lists[0].LastUpdated != 42000 {
		t.Fatalf("%+v", lists[0])
	}
	must(t, database.DeleteFilterList(ctx, id))
	if lists, _ = database.GetFilterLists(ctx); len(lists) != 0 {
		t.Fatalf("%+v", lists)
	}
}

func TestCustomRulesCrudPort(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	id, err := database.AddCustomRule(ctx, "||ads.example.com^", "block")
	must(t, err)
	if id <= 0 {
		t.Fatalf("id %d", id)
	}
	_, err = database.AddCustomRule(ctx, "@@||allowed.example.com^", "allow")
	must(t, err)

	block, _ := database.GetCustomRulesByType(ctx, "block")
	if len(block) != 1 || block[0].Rule != "||ads.example.com^" {
		t.Fatalf("%+v", block)
	}
	allow, _ := database.GetCustomRulesByType(ctx, "allow")
	if len(allow) != 1 || allow[0].Rule != "@@||allowed.example.com^" {
		t.Fatalf("%+v", allow)
	}
	must(t, database.DeleteCustomRule(ctx, id))
	if block, _ = database.GetCustomRulesByType(ctx, "block"); len(block) != 0 {
		t.Fatalf("%+v", block)
	}
	if allow, _ = database.GetCustomRulesByType(ctx, "allow"); len(allow) != 1 {
		t.Fatalf("%+v", allow)
	}
}

func TestFilterListContent(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	id, err := database.AddFilterList(ctx, "TestList", "https://example.com/list.txt", true)
	must(t, err)
	if _, found, _ := database.GetFilterListContent(ctx, id); found {
		t.Fatal("no content initially")
	}
	for _, content := range []string{"||ads.example.com^\n||tracker.example.com^", "||newrule.com^"} {
		must(t, database.SetFilterListContent(ctx, id, content))
		if got, found, _ := database.GetFilterListContent(ctx, id); !found || got != content {
			t.Fatalf("got %q %v", got, found)
		}
	}
}

func TestCountQueriesSince(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	insertLogs(t, database,
		plainLog(1_000_000, "old.com", "A", "10.0.0.1", false, 5),
		plainLog(2_000_000, "recent.com", "A", "10.0.0.1", false, 3),
		plainLog(3_000_000, "blocked.com", "A", "10.0.0.2", true, 1))
	if got, _ := database.CountQueriesSince(ctx, 1500); got != 2 {
		t.Fatalf("since 1500: %d", got)
	}
	if got, _ := database.CountQueriesSince(ctx, 0); got != 3 {
		t.Fatalf("since 0: %d", got)
	}
}

func TestTopDomainsSince(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	insertLogs(t, database,
		plainLog(1_000_000, "popular.com", "A", "10.0.0.1", false, 1),
		plainLog(2_000_000, "popular.com", "A", "10.0.0.1", false, 1),
		plainLog(3_000_000, "rare.com", "A", "10.0.0.1", false, 1))
	top, err := database.TopDomainsSince(ctx, 0, 10)
	must(t, err)
	if len(top) != 2 || top[0] != (TopDomain{"popular.com", 2}) || top[1] != (TopDomain{"rare.com", 1}) {
		t.Fatalf("%+v", top)
	}
	if top, _ = database.TopDomainsSince(ctx, 0, 1); len(top) != 1 {
		t.Fatalf("%+v", top)
	}
}

func TestReadConnOpensAndBasicRoundtripWorks(t *testing.T) {
	database := rustTestDB(t)
	insertLogs(t, database, plainLog(1_700_000_000_000, "example.com", "A", "127.0.0.1", false, 1))
	if got := logDomains(t, database, QueryLogFilter{}, 10, 0); !slices.Equal(got, []string{"example.com"}) {
		t.Fatalf("%v", got)
	}
}

func TestUsersCrud(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	count := func() int64 {
		n, err := database.CountUsers(ctx)
		must(t, err)
		return n
	}
	if count() != 0 {
		t.Fatal("not empty")
	}
	id, err := database.CreateUser(ctx, "alice", "hash-a", 1000)
	must(t, err)
	if count() != 1 {
		t.Fatal("count")
	}
	auth, found, _ := database.GetUserAuth(ctx, "alice")
	if !found || auth.ID != id || auth.PasswordHash != "hash-a" {
		t.Fatalf("%+v %v", auth, found)
	}
	if _, found, _ = database.GetUserAuth(ctx, "nobody"); found {
		t.Fatal("nobody found")
	}
	if name, found, _ := database.GetUsername(ctx, id); !found || name != "alice" {
		t.Fatalf("%q", name)
	}
	must(t, database.UpdateUserPassword(ctx, id, "hash-b"))
	if hash, found, _ := database.GetUserPasswordHash(ctx, id); !found || hash != "hash-b" {
		t.Fatalf("%q", hash)
	}
	if users, _ := database.ListUsers(ctx); len(users) != 1 || users[0].Username != "alice" {
		t.Fatalf("%+v", users)
	}

	// The last operator cannot be deleted.
	if outcome, err := database.DeleteUser(ctx, id); err != nil || outcome != ErrLastOperator {
		t.Fatalf("%v %v", outcome, err)
	}
	id2, err := database.CreateUser(ctx, "bob", "hash-b2", 2000)
	must(t, err)
	if outcome, _ := database.DeleteUser(ctx, id2); outcome != UserDeleted {
		t.Fatalf("%v", outcome)
	}
	if count() != 1 {
		t.Fatal("count after delete")
	}
	_, err = database.CreateUser(ctx, "carol", "hash-c", 3000)
	must(t, err)
	if outcome, _ := database.DeleteUser(ctx, 99999); outcome != UserNotFound {
		t.Fatalf("%v", outcome)
	}
	if count() != 2 {
		t.Fatal("count at end")
	}
}

func TestCreateUserNoPassword(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	id, err := database.CreateUserNoPassword(ctx, "dave", 1000)
	must(t, err)
	auth, found, _ := database.GetUserAuth(ctx, "dave")
	if !found || auth.ID != id || auth.PasswordHash != NoPasswordSentinel {
		t.Fatalf("%+v", auth)
	}
	if hash, _, _ := database.GetUserPasswordHash(ctx, id); hash != NoPasswordSentinel {
		t.Fatalf("%q", hash)
	}
	// Not ported here: the Rust test also asserts verify_password errors on the
	// sentinel; that belongs to internal/auth (password step).
	if _, err := database.CreateUserNoPassword(ctx, "dave", 2000); err == nil {
		t.Fatal("username UNIQUE must still apply")
	}
}

func TestDuplicateUsernameRejected(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	_, err := database.CreateUser(ctx, "bob", "h", 1)
	must(t, err)
	if _, err := database.CreateUser(ctx, "bob", "h2", 2); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func newSession(tokenHash string, userID, createdAt, lastSeen int64) NewSession {
	return NewSession{TokenHash: tokenHash, UserID: userID, CreatedAt: createdAt, LastSeen: lastSeen}
}

func insertSession(t *testing.T, database *DB, session NewSession) int64 {
	t.Helper()
	id, err := database.InsertSession(context.Background(), session)
	must(t, err)
	return id
}

func sessionTokens(t *testing.T, database *DB) []string {
	t.Helper()
	rows, err := database.ListSessions(context.Background())
	must(t, err)
	tokens := make([]string, len(rows))
	for i, row := range rows {
		tokens[i] = row.TokenHash
	}
	return tokens
}

func TestSessionsCrudAndCascade(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	userID, err := database.CreateUser(ctx, "carol", "h", 100)
	must(t, err)
	session := newSession("tok-1", userID, 100, 100)
	session.IP, session.UserAgent = ptr("1.2.3.4"), ptr("UA")
	sessionID := insertSession(t, database, session)

	list, _ := database.ListSessions(ctx)
	if len(list) != 1 || list[0].Username != "carol" || list[0].TokenHash != "tok-1" || list[0].IP == nil || *list[0].IP != "1.2.3.4" {
		t.Fatalf("%+v", list)
	}
	if token, found, _ := database.DeleteSessionByID(ctx, sessionID); !found || token != "tok-1" {
		t.Fatalf("%q %v", token, found)
	}
	if len(sessionTokens(t, database)) != 0 {
		t.Fatal("not empty")
	}
	if _, found, _ := database.DeleteSessionByID(ctx, sessionID); found {
		t.Fatal("deleted twice")
	}

	// Deleting the user cascades; a second operator keeps carol from being last.
	insertSession(t, database, newSession("tok-2", userID, 100, 100))
	_, err = database.CreateUser(ctx, "carol2", "h", 200)
	must(t, err)
	if outcome, _ := database.DeleteUser(ctx, userID); outcome != UserDeleted {
		t.Fatalf("%v", outcome)
	}
	if len(sessionTokens(t, database)) != 0 {
		t.Fatal("sessions survived their user")
	}
}

func TestLoadSessionsDropsExpired(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	userID, _ := database.CreateUser(ctx, "dave", "h", 0)
	insertSession(t, database, newSession("fresh", userID, 1_050, 1_050))
	insertSession(t, database, newSession("stale", userID, 1, 1))

	loaded, err := database.LoadSessions(ctx, 100, 10_000, 1_100)
	must(t, err)
	if len(loaded) != 1 || loaded[0].TokenHash != "fresh" {
		t.Fatalf("%+v", loaded)
	}
	if !slices.Equal(sessionTokens(t, database), []string{"fresh"}) {
		t.Fatal("stale row not purged")
	}
}

func TestLoadSessionsPurgesIdleRows(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	userID, _ := database.CreateUser(ctx, "frank", "h", 0)
	const now = 10_000_000
	insertSession(t, database, newSession("idle", userID, now-1_000, now-sessionIdleTimeoutSec-1))
	insertSession(t, database, newSession("active", userID, now-1_000, now))

	loaded, err := database.LoadSessions(ctx, sessionMaxAgeSecs, sessionIdleTimeoutSec, now)
	must(t, err)
	if len(loaded) != 1 || loaded[0].TokenHash != "active" {
		t.Fatalf("%+v", loaded)
	}
	if !slices.Equal(sessionTokens(t, database), []string{"active"}) {
		t.Fatal("idle row not purged")
	}
}

func TestFlushLastSeen(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	userID, _ := database.CreateUser(ctx, "erin", "h", 0)
	insertSession(t, database, newSession("tok", userID, 0, 0))
	must(t, database.FlushSessionsLastSeen(ctx, []SessionLastSeen{{TokenHash: "tok", LastSeen: 555}}))
	if list, _ := database.ListSessions(ctx); list[0].LastSeen != 555 {
		t.Fatalf("%+v", list)
	}
}

// Four sessions: one live, and one expired by each timeout alone and by both.
func insertPurgeFixture(t *testing.T, database *DB, userID, now int64) {
	insertSession(t, database, newSession("normal", userID, now-1_000, now))
	insertSession(t, database, newSession("stale-created", userID, now-sessionMaxAgeSecs-1, now))
	insertSession(t, database, newSession("stale-seen", userID, now-1_000, now-sessionIdleTimeoutSec-1))
	insertSession(t, database, newSession("stale-both", userID, now-sessionMaxAgeSecs-1, now-sessionIdleTimeoutSec-1))
}

func TestPurgeExpiredSessionsRemovesAbsoluteAndIdleExpiredRows(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	userID, _ := database.CreateUser(ctx, "gina", "h", 0)
	const now = 10_000_000
	insertPurgeFixture(t, database, userID, now)
	deleted, err := database.PurgeExpiredSessions(ctx, sessionMaxAgeSecs, sessionIdleTimeoutSec, now)
	must(t, err)
	if deleted != 3 || !slices.Equal(sessionTokens(t, database), []string{"normal"}) {
		t.Fatalf("deleted %d, left %v", deleted, sessionTokens(t, database))
	}
}

func TestPurgeExpiredSessionsIsIdempotent(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	userID, _ := database.CreateUser(ctx, "hank", "h", 0)
	const now = 10_000_000
	insertPurgeFixture(t, database, userID, now)
	if first, _ := database.PurgeExpiredSessions(ctx, sessionMaxAgeSecs, sessionIdleTimeoutSec, now); first != 3 {
		t.Fatalf("first %d", first)
	}
	if second, _ := database.PurgeExpiredSessions(ctx, sessionMaxAgeSecs, sessionIdleTimeoutSec, now); second != 0 {
		t.Fatalf("second %d", second)
	}
}

// The Rust test compares the SQL predicate with auth::prune_expired (the
// in-memory twin). internal/auth does not exist yet, so the in-memory side is
// restated here as the same >= comparison validate_session uses; the auth step
// must replace memoryExpired with the real predicate.
func memoryExpired(now, createdAt, lastSeen int64) bool {
	return now-createdAt >= sessionMaxAgeSecs || now-lastSeen >= sessionIdleTimeoutSec
}

func TestPurgeExpiredSessionsMatchesInMemoryPredicateAtBoundaries(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		label                       string
		createdOffset, lastSeenOffs int64
		expectExpired               bool
	}{
		{"created_at exactly at the absolute-timeout boundary", -sessionMaxAgeSecs, 0, true},
		{"created_at one second inside the absolute-timeout boundary", -sessionMaxAgeSecs + 1, 0, false},
		{"created_at one second past the absolute-timeout boundary", -sessionMaxAgeSecs - 1, 0, true},
		{"last_seen exactly at the idle-timeout boundary", -1, -sessionIdleTimeoutSec, true},
		{"last_seen one second inside the idle-timeout boundary", -1, -sessionIdleTimeoutSec + 1, false},
		{"last_seen one second past the idle-timeout boundary", -1, -sessionIdleTimeoutSec - 1, true},
		{"both fields fresh", -1, 0, false},
		{"both fields well past their boundaries", -sessionMaxAgeSecs - 100, -sessionIdleTimeoutSec - 100, true},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			now := time.Now().Unix()
			createdAt, lastSeen := now+tc.createdOffset, now+tc.lastSeenOffs
			evicted := memoryExpired(now, createdAt, lastSeen)
			database := rustTestDB(t)
			userID, _ := database.CreateUser(ctx, "op", "h", 0)
			insertSession(t, database, newSession("tok", userID, createdAt, lastSeen))
			purged, err := database.PurgeExpiredSessions(ctx, sessionMaxAgeSecs, sessionIdleTimeoutSec, now)
			must(t, err)
			if evicted != tc.expectExpired || (purged == 1) != tc.expectExpired {
				t.Fatalf("memory=%v sql=%d want %v", evicted, purged, tc.expectExpired)
			}
		})
	}
}

func TestFilterListURLFetchesOneRowByID(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	first, _ := database.AddFilterList(ctx, "EasyList", "https://easylist.example.com/list.txt", true)
	second, _ := database.AddFilterList(ctx, "Other", "https://other.example.com/hosts.txt", true)
	if url, found, _ := database.FilterListURL(ctx, first); !found || url != "https://easylist.example.com/list.txt" {
		t.Fatalf("%q", url)
	}
	if url, found, _ := database.FilterListURL(ctx, second); !found || url != "https://other.example.com/hosts.txt" {
		t.Fatalf("%q", url)
	}
	if url, found, _ := database.FilterListURL(ctx, first+second+1); found {
		t.Fatalf("an unknown id fell through to %q", url)
	}
}

func TestTheLogCountFollowsEveryWriteThatChangesIt(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	logAtMs := func(timestamp int64) QueryLogEntry {
		return plainLog(timestamp, "example.com", "A", "10.0.0.1", false, 1)
	}
	assertHolds := func(expected int64) {
		t.Helper()
		rows, err := database.QueryLogs(ctx, QueryLogFilter{}, 1<<62, 0)
		must(t, err)
		total, _ := database.TotalLogCount(ctx)
		unfiltered, _ := database.CountLogs(ctx, QueryLogFilter{})
		blank, _ := database.CountLogs(ctx, QueryLogFilter{Search: ptr("  ")})
		if int64(len(rows)) != expected || total != expected || unfiltered != expected || blank != expected {
			t.Fatalf("expected %d: rows %d total %d unfiltered %d blank %d", expected, len(rows), total, unfiltered, blank)
		}
	}
	assertHolds(0)
	insertLogs(t, database, logAtMs(1_000_000), logAtMs(1_500_000), logAtMs(3_000_000))
	assertHolds(3)
	insertLogs(t, database, logAtMs(4_000_000))
	assertHolds(4)

	// Seconds in, milliseconds stored: this drops the two before 2000 s.
	if pruned, _ := database.PruneLogsBefore(ctx, 2_000); pruned != 2 {
		t.Fatalf("pruned %d", pruned)
	}
	assertHolds(2)
	if pruned, _ := database.PruneLogsBefore(ctx, 2_000); pruned != 0 {
		t.Fatalf("pruned %d", pruned)
	}
	assertHolds(2)
	must(t, database.DeleteAllLogs(ctx))
	assertHolds(0)
}

// A query-type filter is answered as two runs merged into one page; it must
// equal the plain statement's page for every limit and offset /api/logs
// accepts, including negatives.
func TestAQueryTypeFilterPagesExactlyLikeTheTable(t *testing.T) {
	ctx := context.Background()
	database := rustTestDB(t)
	entries := make([]QueryLogEntry, 300)
	for i := range entries {
		n := int64(i)
		queryType := "A"
		if n%3 == 0 {
			queryType = "AAAA"
		}
		entries[i] = plainLog(1_000_000+n*1000, fmt.Sprintf("d%d.example", n), queryType, "10.0.0.1", (n/7)%3 == 0 || n%11 == 0, 1)
	}
	insertLogs(t, database, entries...)

	for _, queryType := range []string{"A", "AAAA", "TXT"} {
		for _, page := range [][2]int64{{10, 0}, {10, 40}, {50, 90}, {7, 193}, {50, 180}, {10, 1_000}, {0, 0}, {-1, 0}, {-1, 30}, {10, -5}} {
			limit, offset := page[0], page[1]
			rows, err := database.reader.QueryContext(ctx,
				"SELECT domain FROM query_logs WHERE query_type = ?1 ORDER BY timestamp DESC LIMIT ?2 OFFSET ?3", queryType, limit, offset)
			must(t, err)
			var expected []string
			for rows.Next() {
				var domain string
				must(t, rows.Scan(&domain))
				expected = append(expected, domain)
			}
			must(t, rows.Close())
			got := logDomains(t, database, QueryLogFilter{QueryType: ptr(queryType)}, limit, offset)
			if !slices.Equal(got, expected) {
				t.Fatalf("type %s limit %d offset %d: got %v want %v", queryType, limit, offset, got, expected)
			}
		}
	}
}
