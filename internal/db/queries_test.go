package db

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func memoryDB(t *testing.T) *DB {
	t.Helper()
	return openDB(t, ":memory:")
}

func fileDB(t *testing.T) *DB {
	t.Helper()
	return openDB(t, filepath.Join(t.TempDir(), "q.sqlite3"))
}

func ptr[T any](value T) *T { return &value }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func logAt(timestampMs int64, domain string) QueryLogEntry {
	return QueryLogEntry{Timestamp: timestampMs, Domain: domain, QueryType: "A", ClientIP: "10.0.0.1", ResponseMs: 5}
}

// Numbered parameters reused and out of order must bind by number.
func TestNumberedParametersBindByNumber(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	var first, second, again int64
	err := database.reader.QueryRowContext(ctx, "SELECT ?2, ?1, ?2", int64(10), int64(20)).Scan(&first, &second, &again)
	must(t, err)
	if first != 20 || second != 10 || again != 20 {
		t.Fatalf("got %d %d %d", first, second, again)
	}
}

func TestSettings(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	if _, found, err := database.GetSetting(ctx, "missing"); err != nil || found {
		t.Fatalf("missing setting: found=%v err=%v", found, err)
	}
	must(t, database.SetSetting(ctx, "k", "v1"))
	must(t, database.SetSetting(ctx, "k", "v2"))
	if value, found, _ := database.GetSetting(ctx, "k"); !found || value != "v2" {
		t.Fatalf("got %q %v", value, found)
	}
	tables, err := database.ListTables(ctx)
	must(t, err)
	for _, want := range []string{"query_logs", "sessions", "users", "settings"} {
		if !slices.Contains(tables, want) {
			t.Errorf("missing table %s", want)
		}
	}
}

func TestFilterListsCRUD(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	id, err := database.AddFilterList(ctx, "L", "https://x/list", true)
	must(t, err)
	if url, found, _ := database.FilterListURL(ctx, id); !found || url != "https://x/list" {
		t.Fatalf("url %q %v", url, found)
	}
	must(t, database.UpdateFilterList(ctx, id, "L2", "https://y/list"))
	must(t, database.UpdateFilterListEnabled(ctx, id, false))
	must(t, database.UpdateFilterListStats(ctx, id, 1234, 77))
	lists, err := database.GetFilterLists(ctx)
	must(t, err)
	if len(lists) != 1 || lists[0].Name != "L2" || lists[0].URL != "https://y/list" || lists[0].Enabled || lists[0].RuleCount != 77 {
		t.Fatalf("%+v", lists)
	}
	must(t, database.SetFilterListContent(ctx, id, "a\nb"))
	must(t, database.SetFilterListContent(ctx, id, "c"))
	if content, found, _ := database.GetFilterListContent(ctx, id); !found || content != "c" {
		t.Fatalf("content %q %v", content, found)
	}
	must(t, database.DeleteFilterList(ctx, id))
	if _, found, _ := database.GetFilterListContent(ctx, id); found {
		t.Fatal("content survived delete")
	}
	if _, found, _ := database.FilterListURL(ctx, id); found {
		t.Fatal("list survived delete")
	}
}

func TestCustomRulesCRUD(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	blockID, err := database.AddCustomRule(ctx, "||ads.example^", "block")
	must(t, err)
	_, err = database.AddCustomRule(ctx, "@@||ok.example^", "allow")
	must(t, err)
	if has, _ := database.HasCustomRule(ctx, "||ads.example^"); !has {
		t.Fatal("rule not found")
	}
	if has, _ := database.HasCustomRule(ctx, "nope"); has {
		t.Fatal("phantom rule")
	}
	all, _ := database.GetAllCustomRules(ctx)
	blocks, _ := database.GetCustomRulesByType(ctx, "block")
	if len(all) != 2 || len(blocks) != 1 || blocks[0].Rule != "||ads.example^" {
		t.Fatalf("%+v %+v", all, blocks)
	}
	must(t, database.DeleteCustomRule(ctx, blockID))
	if has, _ := database.HasCustomRule(ctx, "||ads.example^"); has {
		t.Fatal("rule survived delete")
	}
}

func TestDohTokens(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	if has, _ := database.HasDohTokens(ctx); has {
		t.Fatal("tokens on empty db")
	}
	id, err := database.AddDohToken(ctx, "secret")
	must(t, err)
	if _, err := database.AddDohToken(ctx, "secret"); !IsUniqueViolation(err) {
		t.Fatalf("duplicate token: %v", err)
	}
	if _, valid, _ := database.ValidateDohToken(ctx, "secret"); !valid {
		t.Fatal("valid token rejected")
	}
	if _, valid, _ := database.ValidateDohToken(ctx, "other"); valid {
		t.Fatal("unknown token accepted")
	}
	must(t, database.DeleteDohToken(ctx, id))
	if _, valid, _ := database.ValidateDohToken(ctx, "secret"); valid {
		t.Fatal("deleted token accepted")
	}
}

func TestUsers(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	id, err := database.CreateUser(ctx, "alice", "hash1", 100)
	must(t, err)
	if _, err := database.CreateUser(ctx, "alice", "hash2", 101); !IsUniqueViolation(err) {
		t.Fatalf("duplicate username: %v", err)
	}
	auth, found, _ := database.GetUserAuth(ctx, "alice")
	if !found || auth.ID != id || auth.PasswordHash != "hash1" {
		t.Fatalf("%+v %v", auth, found)
	}
	must(t, database.UpdateUserPassword(ctx, id, "hash3"))
	if hash, _, _ := database.GetUserPasswordHash(ctx, id); hash != "hash3" {
		t.Fatalf("hash %q", hash)
	}
	if name, _, _ := database.GetUsername(ctx, id); name != "alice" {
		t.Fatalf("name %q", name)
	}
	noPassword, err := database.CreateUserNoPassword(ctx, "bob", 102)
	must(t, err)
	if hash, _, _ := database.GetUserPasswordHash(ctx, noPassword); hash != NoPasswordSentinel {
		t.Fatalf("sentinel %q", hash)
	}
	users, _ := database.ListUsers(ctx)
	if count, _ := database.CountUsers(ctx); count != 2 || len(users) != 2 {
		t.Fatalf("count %d %+v", count, users)
	}
	if outcome, _ := database.DeleteUser(ctx, 9999); outcome != UserNotFound {
		t.Fatalf("outcome %v", outcome)
	}
	if outcome, _ := database.DeleteUser(ctx, noPassword); outcome != UserDeleted {
		t.Fatalf("outcome %v", outcome)
	}
	if outcome, _ := database.DeleteUser(ctx, id); outcome != ErrLastOperator {
		t.Fatalf("last operator deleted: %v", outcome)
	}
}

func TestCreateFirstUserOnlyOnce(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	if _, created, err := database.CreateFirstUser(ctx, "root", "h", 1); err != nil || !created {
		t.Fatalf("first: %v %v", created, err)
	}
	if _, created, err := database.CreateFirstUser(ctx, "other", "h", 2); err != nil || created {
		t.Fatalf("second: %v %v", created, err)
	}
}

func TestSessionsCRUDAndCascade(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	alice, _ := database.CreateUser(ctx, "alice", "h", 1)
	bob, _ := database.CreateUser(ctx, "bob", "h", 1)
	for _, session := range []NewSession{
		{TokenHash: "a1", UserID: alice, CreatedAt: 100, LastSeen: 100, IP: ptr("1.1.1.1")},
		{TokenHash: "a2", UserID: alice, CreatedAt: 100, LastSeen: 100},
		{TokenHash: "b1", UserID: bob, CreatedAt: 100, LastSeen: 100, UserAgent: ptr("ua")},
	} {
		_, err := database.InsertSession(ctx, session)
		must(t, err)
	}
	listed, _ := database.ListSessions(ctx)
	if len(listed) != 3 {
		t.Fatalf("%+v", listed)
	}
	if removed, _ := database.DeleteUserSessionsExcept(ctx, alice, ptr("a1")); removed != 1 {
		t.Fatalf("removed %d", removed)
	}
	if removed, _ := database.DeleteUserSessionsExcept(ctx, alice, nil); removed != 1 {
		t.Fatalf("removed %d", removed)
	}
	if removed, _ := database.DeleteSessionsExcept(ctx, "nothing"); removed != 1 {
		t.Fatalf("removed %d", removed)
	}
	_, err := database.InsertSession(ctx, NewSession{TokenHash: "b2", UserID: bob, CreatedAt: 1, LastSeen: 1})
	must(t, err)
	must(t, database.DeleteSessionByTokenHash(ctx, "b2"))
	_, err = database.InsertSession(ctx, NewSession{TokenHash: "b3", UserID: bob, CreatedAt: 1, LastSeen: 1})
	must(t, err)
	// Deleting the user cascades to the session.
	_, _ = database.CreateUser(ctx, "carol", "h", 1)
	if outcome, _ := database.DeleteUser(ctx, bob); outcome != UserDeleted {
		t.Fatalf("outcome %v", outcome)
	}
	if left, _ := database.ListSessions(ctx); len(left) != 0 {
		t.Fatalf("cascade left %+v", left)
	}
}

func TestDeleteSessionByIDReturnsTokenHash(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	user, _ := database.CreateUser(ctx, "alice", "h", 1)
	id, err := database.InsertSession(ctx, NewSession{TokenHash: "th", UserID: user, CreatedAt: 1, LastSeen: 1})
	must(t, err)
	if hash, found, _ := database.DeleteSessionByID(ctx, id); !found || hash != "th" {
		t.Fatalf("%q %v", hash, found)
	}
	if _, found, _ := database.DeleteSessionByID(ctx, id); found {
		t.Fatal("deleted twice")
	}
	if n, _ := database.DeleteAllSessions(ctx); n != 0 {
		t.Fatalf("n=%d", n)
	}
}

// Expiry is inclusive: a session exactly at the limit is purged.
func TestPurgeExpiredSessionsBoundaries(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	user, _ := database.CreateUser(ctx, "alice", "h", 1)
	const now, maxAge, idle = 10_000, 1000, 100
	fixtures := []struct {
		hash            string
		createdAt, seen int64
		survivesPurge   bool
	}{
		{"fresh", now - 10, now - 10, true},
		{"age-exact", now - maxAge, now - 1, false},
		{"age-just-inside", now - maxAge + 1, now - 1, true},
		{"idle-exact", now - 10, now - idle, false},
		{"idle-just-inside", now - 10, now - idle + 1, true},
	}
	for _, fixture := range fixtures {
		_, err := database.InsertSession(ctx, NewSession{TokenHash: fixture.hash, UserID: user, CreatedAt: fixture.createdAt, LastSeen: fixture.seen})
		must(t, err)
	}
	loaded, err := database.LoadSessions(ctx, maxAge, idle, now)
	must(t, err)
	survivors := map[string]bool{}
	for _, session := range loaded {
		survivors[session.TokenHash] = true
	}
	for _, fixture := range fixtures {
		if survivors[fixture.hash] != fixture.survivesPurge {
			t.Errorf("%s: survived=%v want %v", fixture.hash, survivors[fixture.hash], fixture.survivesPurge)
		}
	}
	if n, _ := database.PurgeExpiredSessions(ctx, maxAge, idle, now); n != 0 {
		t.Fatalf("purge not idempotent: %d", n)
	}
}

func TestFlushSessionsLastSeen(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	user, _ := database.CreateUser(ctx, "alice", "h", 1)
	_, err := database.InsertSession(ctx, NewSession{TokenHash: "s", UserID: user, CreatedAt: 1, LastSeen: 1})
	must(t, err)
	must(t, database.FlushSessionsLastSeen(ctx, []SessionLastSeen{{"s", 500}, {"ghost", 9}}))
	listed, _ := database.ListSessions(ctx)
	if len(listed) != 1 || listed[0].LastSeen != 500 {
		t.Fatalf("%+v", listed)
	}
}

func TestAPIKeys(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	owner, _ := database.CreateUser(ctx, "alice", "h", 1)
	other, _ := database.CreateUser(ctx, "bob", "h", 1)
	const now = 1_000_000
	id, err := database.InsertAPIKey(ctx, NewAPIKey{UserID: owner, Name: "k", TokenHash: "hash", Prefix: "nk_ab", CreatedAt: now - 500})
	must(t, err)
	expiring, err := database.InsertAPIKey(ctx, NewAPIKey{UserID: owner, Name: "e", TokenHash: "hash2", Prefix: "nk_cd", CreatedAt: now - 500, ExpiresAt: ptr(int64(now))})
	must(t, err)
	_ = expiring

	if user, found, _ := database.ValidateAPIKey(ctx, "hash", now); !found || user != owner {
		t.Fatalf("%d %v", user, found)
	}
	if _, found, _ := database.ValidateAPIKey(ctx, "hash2", now); found {
		t.Fatal("key accepted at its expiry second")
	}
	if _, found, _ := database.ValidateAPIKey(ctx, "hash2", now-1); !found {
		t.Fatal("key rejected before expiry")
	}
	if _, found, _ := database.ValidateAPIKey(ctx, "unknown", now); found {
		t.Fatal("unknown key accepted")
	}

	touched := func() *int64 {
		keys, _ := database.ListAPIKeysForUser(ctx, owner)
		for _, key := range keys {
			if key.ID == id {
				return key.LastUsedAt
			}
		}
		t.Fatal("key missing")
		return nil
	}
	if got := touched(); got == nil || *got != now {
		t.Fatalf("last_used_at %v", got)
	}
	_, _, _ = database.ValidateAPIKey(ctx, "hash", now+10)
	if got := touched(); *got != now {
		t.Fatalf("touch not throttled: %d", *got)
	}
	_, _, _ = database.ValidateAPIKey(ctx, "hash", now+60)
	if got := touched(); *got != now+60 {
		t.Fatalf("touch missed: %d", *got)
	}

	if deleted, _ := database.DeleteAPIKey(ctx, id, other); deleted {
		t.Fatal("deleted another user's key")
	}
	if deleted, _ := database.DeleteAPIKey(ctx, id, owner); !deleted {
		t.Fatal("owner could not delete")
	}
}

func TestQueryLogsRoundTripAndFilters(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	entries := []QueryLogEntry{
		{Timestamp: 1000, Domain: "ads.example.com", QueryType: "A", ClientIP: "1.1.1.1", Blocked: true, ResponseMs: 1},
		{Timestamp: 2000, Domain: "good.example.com", QueryType: "AAAA", ClientIP: "1.1.1.2", Cached: true, ResponseMs: 2,
			Upstream: ptr("u1"), DohToken: ptr("tok"), Result: ptr("1.2.3.4"), AuthenticatedData: true},
		{Timestamp: 3000, Domain: "a_b.org", QueryType: "A", ClientIP: "1.1.1.3", ResponseMs: 3},
	}
	must(t, database.InsertQueryLogs(ctx, entries))
	rows, err := database.QueryLogs(ctx, QueryLogFilter{}, 10, 0)
	must(t, err)
	if len(rows) != 3 || rows[0].Timestamp != 3000 || rows[2].Timestamp != 1000 {
		t.Fatalf("order: %+v", rows)
	}
	got, want := rows[1], entries[1]
	if got.Domain != want.Domain || got.QueryType != want.QueryType || !got.Cached || !got.AuthenticatedData ||
		got.Upstream == nil || *got.Upstream != "u1" || got.DohToken == nil || *got.DohToken != "tok" ||
		got.Result == nil || *got.Result != "1.2.3.4" || rows[0].Upstream != nil {
		t.Fatalf("round trip: %+v", rows[1])
	}

	count := func(filter QueryLogFilter) int64 {
		n, err := database.CountLogs(ctx, filter)
		must(t, err)
		return n
	}
	if count(QueryLogFilter{}) != 3 {
		t.Fatal("unfiltered count")
	}
	if count(QueryLogFilter{Blocked: ptr(true)}) != 1 {
		t.Fatal("blocked filter")
	}
	if count(QueryLogFilter{Token: ptr("tok")}) != 1 {
		t.Fatal("token filter")
	}
	if count(QueryLogFilter{Search: ptr("ads")}) != 1 {
		t.Fatal("prefix search")
	}
	if count(QueryLogFilter{Search: ptr("example")}) != 0 {
		t.Fatal("prefix search must not be a substring search")
	}
	if count(QueryLogFilter{Search: ptr("%example%")}) != 2 {
		t.Fatal("wildcard search")
	}
	if count(QueryLogFilter{QueryType: ptr("AAAA")}) != 1 {
		t.Fatal("query type filter")
	}
	paged, _ := database.QueryLogs(ctx, QueryLogFilter{}, 1, 1)
	if len(paged) != 1 || paged[0].Timestamp != 2000 {
		t.Fatalf("page: %+v", paged)
	}
}

// The query-type-only page uses the type index and matches the plain query.
func TestQueryTypeOnlyPageMatchesTable(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	var entries []QueryLogEntry
	for i := range int64(40) {
		entry := logAt(1000+i, "d.example")
		entry.QueryType = []string{"A", "AAAA", "TXT"}[i%3]
		entry.Blocked = i%2 == 0
		entries = append(entries, entry)
	}
	must(t, database.InsertQueryLogs(ctx, entries))
	for _, offset := range []int64{0, 3, 11} {
		got, err := database.QueryLogs(ctx, QueryLogFilter{QueryType: ptr("A")}, 5, offset)
		must(t, err)
		rows, err := database.reader.QueryContext(ctx,
			"SELECT timestamp FROM query_logs WHERE query_type = 'A' ORDER BY timestamp DESC LIMIT 5 OFFSET ?1", offset)
		must(t, err)
		var want []int64
		for rows.Next() {
			var ts int64
			must(t, rows.Scan(&ts))
			want = append(want, ts)
		}
		rows.Close()
		var gotTs []int64
		for _, entry := range got {
			gotTs = append(gotTs, entry.Timestamp)
		}
		if !slices.Equal(gotTs, want) {
			t.Fatalf("offset %d: %v != %v", offset, gotTs, want)
		}
	}
}

func queryPlan(t *testing.T, database *DB, query string, args ...any) string {
	t.Helper()
	rows, err := database.reader.Query("EXPLAIN QUERY PLAN "+query, args...)
	must(t, err)
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		must(t, rows.Scan(&id, &parent, &unused, &detail))
		plan = append(plan, detail)
	}
	return strings.Join(plan, "\n")
}

func TestLogPagesUseIndexes(t *testing.T) {
	database := fileDB(t)
	plan := queryPlan(t, database, "SELECT "+queryLogColumns+" FROM query_logs ORDER BY timestamp DESC LIMIT 50 OFFSET 0")
	if !strings.Contains(plan, "USING INDEX idx_query_logs_timestamp") && !strings.Contains(plan, "USING COVERING INDEX idx_query_logs_timestamp") {
		t.Fatalf("plan:\n%s", plan)
	}
	statement, args := queryTypeOnlyPage("A", 50, 0)
	plan = queryPlan(t, database, statement, args...)
	if !strings.Contains(plan, "idx_query_logs_type_blocked_ts") {
		t.Fatalf("plan:\n%s", plan)
	}
}

func TestLogCountFollowsEveryWrite(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	assertCount := func(want int64) {
		t.Helper()
		got, err := database.TotalLogCount(ctx)
		must(t, err)
		var actual int64
		must(t, database.reader.QueryRow("SELECT COUNT(*) FROM query_logs").Scan(&actual))
		if got != want || actual != want {
			t.Fatalf("maintained=%d actual=%d want %d", got, actual, want)
		}
	}
	assertCount(0)
	must(t, database.InsertQueryLogs(ctx, []QueryLogEntry{logAt(1000, "a"), logAt(2000, "b"), logAt(9_000_000, "c")}))
	assertCount(3)
	deleted, err := database.PruneLogsBefore(ctx, 5)
	must(t, err)
	if deleted != 2 {
		t.Fatalf("deleted %d", deleted)
	}
	assertCount(1)
	must(t, database.DeleteAllLogs(ctx))
	assertCount(0)
	if has, _ := database.HasAnyQueryLogs(ctx); has {
		t.Fatal("logs after clear")
	}
}

func TestFloorDivAndFirstWholeUnit(t *testing.T) {
	for _, c := range []struct{ a, b, want int64 }{{7, 2, 3}, {-7, 2, -4}, {-8, 2, -4}, {0, 5, 0}} {
		if got := floorDiv(c.a, c.b); got != c.want {
			t.Errorf("floorDiv(%d,%d)=%d", c.a, c.b, got)
		}
	}
	if got := firstWholeUnit(900_000, rollupQuarterMs); got != 1 {
		t.Errorf("on boundary: %d", got)
	}
	if got := firstWholeUnit(900_001, rollupQuarterMs); got != 2 {
		t.Errorf("past boundary: %d", got)
	}
	if got := firstWholeUnit(0, rollupQuarterMs); got != 0 {
		t.Errorf("zero: %d", got)
	}
}

const hourMs = 3_600_000

// Stats read through the rollups must equal direct counts, before and after
// a prune that cuts through a quarter.
func TestStatsAgreeWithTableAcrossPrune(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	base := int64(100 * hourMs)
	var entries []QueryLogEntry
	for i := range int64(200) {
		entry := logAt(base+i*400_000, []string{"a.com", "b.com", "c.com"}[i%3])
		entry.Blocked = i%5 == 0
		entry.Cached = i%7 == 0
		entry.ClientIP = []string{"1.1.1.1", "2.2.2.2"}[i%2]
		if i%4 == 0 {
			entry.Upstream = ptr("up")
		}
		entries = append(entries, entry)
	}
	must(t, database.InsertQueryLogs(ctx, entries))

	check := func(sinceSecs int64) {
		t.Helper()
		var wantTotal, wantBlocked int64
		sinceMs := sinceSecs * 1000
		must(t, database.reader.QueryRow(
			"SELECT COUNT(*), COALESCE(SUM(blocked),0) FROM query_logs WHERE timestamp >= ?1", sinceMs).Scan(&wantTotal, &wantBlocked))
		windows, err := database.SummaryMultiSince(ctx, sinceSecs, sinceSecs, sinceSecs)
		must(t, err)
		for i, window := range windows {
			if window.Total != wantTotal || window.Blocked != wantBlocked {
				t.Fatalf("since %d window %d: %+v want %d/%d", sinceSecs, i, window, wantTotal, wantBlocked)
			}
		}
		if n, _ := database.CountQueriesSince(ctx, sinceSecs); n != wantTotal {
			t.Fatalf("count %d want %d", n, wantTotal)
		}
		scan, err := database.StatsScanSince(ctx, sinceSecs, sinceSecs)
		must(t, err)
		var seriesTotal, heatTotal int64
		for i := range scan.Series.Total {
			seriesTotal += scan.Series.Total[i]
			heatTotal += scan.Series.Heatmap[i]
		}
		if seriesTotal != wantTotal || heatTotal != wantTotal {
			t.Fatalf("series %d heat %d want %d", seriesTotal, heatTotal, wantTotal)
		}
		timeline, err := database.TimelineMultiSince(ctx, sinceSecs, 3600, 0)
		must(t, err)
		var timelineTotal int64
		for _, point := range timeline {
			timelineTotal += point.Total
		}
		if timelineTotal != wantTotal {
			t.Fatalf("timeline %d want %d", timelineTotal, wantTotal)
		}
		simple, err := database.TimelineSince(ctx, sinceSecs, 900)
		must(t, err)
		var simpleTotal int64
		for _, point := range simple {
			simpleTotal += point.Total
		}
		if simpleTotal != wantTotal {
			t.Fatalf("simple timeline %d want %d", simpleTotal, wantTotal)
		}
		cells, err := database.HourlyHeatmapSince(ctx, sinceSecs, 8*3600)
		must(t, err)
		var cellTotal int64
		for _, cell := range cells {
			cellTotal += cell.Count
		}
		if cellTotal != wantTotal {
			t.Fatalf("heatmap %d want %d", cellTotal, wantTotal)
		}
		domains, err := database.DomainStatsSince(ctx, sinceSecs, 10)
		must(t, err)
		var domainTotal int64
		for _, top := range domains.Top {
			domainTotal += top.Count
		}
		if domainTotal != wantTotal {
			t.Fatalf("domains %d want %d", domainTotal, wantTotal)
		}
		lists, err := database.TrafficListsSince(ctx, sinceSecs, 10)
		must(t, err)
		var clientTotal int64
		for _, client := range lists.Clients {
			clientTotal += client.Count
		}
		if clientTotal != wantTotal || lists.Domains.Unique != domains.Unique {
			t.Fatalf("clients %d unique %d/%d", clientTotal, lists.Domains.Unique, domains.Unique)
		}
		metrics, err := database.WindowMetricsSince(ctx, sinceSecs)
		must(t, err)
		if metrics.Latency.SampleCount == 0 || metrics.Latency.P50Ms != 5 {
			t.Fatalf("latency %+v", metrics.Latency)
		}
	}

	baseSecs := base / 1000
	// Unaligned starts exercise the table-side partial first unit.
	for _, offset := range []int64{0, 1, 899, 900, 901, 3599, 3600, 7500, 40_000} {
		check(baseSecs + offset)
	}

	upstreams, err := database.TopUpstreamsSince(ctx, baseSecs, 5)
	must(t, err)
	if len(upstreams) != 1 || upstreams[0].Count != 50 || upstreams[0].AvgMs != 5 {
		t.Fatalf("%+v", upstreams)
	}

	cutoff := baseSecs + 10_000
	if _, err := database.PruneLogsBefore(ctx, cutoff); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int64{10_000, 10_001, 12_000, 20_000} {
		check(baseSecs + offset)
	}
	// Rollups hold nothing for pruned rows: a window reaching before the
	// cutoff must still equal what the table holds.
	var remaining int64
	must(t, database.reader.QueryRow("SELECT COUNT(*) FROM query_logs").Scan(&remaining))
	summaries, err := database.SummaryMultiSince(ctx, baseSecs-100_000, baseSecs-100_000, baseSecs-100_000)
	must(t, err)
	if summaries[2].Total != remaining {
		t.Fatalf("prune left rollup residue: %d vs %d", summaries[2].Total, remaining)
	}
	must(t, database.DeleteAllLogs(ctx))
	var rollupRows int64
	must(t, database.reader.QueryRow("SELECT (SELECT COUNT(*) FROM query_stats_quarter) + (SELECT COUNT(*) FROM query_stats_metrics_hour)").Scan(&rollupRows))
	if rollupRows != 0 {
		t.Fatalf("rollup rows after clear: %d", rollupRows)
	}
}

func TestEarliestLatestAndStorage(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	if _, found, _ := database.EarliestLogTimestamp(ctx); found {
		t.Fatal("earliest on empty db")
	}
	must(t, database.InsertQueryLogs(ctx, []QueryLogEntry{logAt(5, "a"), logAt(9, "b")}))
	first, _, _ := database.EarliestLogTimestamp(ctx)
	last, _, _ := database.LatestLogTimestamp(ctx)
	if first != 5 || last != 9 {
		t.Fatalf("%d %d", first, last)
	}
	storage, err := database.DBStorageStats(ctx)
	must(t, err)
	if storage.MainBytes <= 0 {
		t.Fatalf("%+v", storage)
	}
	must(t, database.RunMaintenance(ctx))
}

func TestMemoryDBSharesWriterAndReader(t *testing.T) {
	ctx := context.Background()
	database := memoryDB(t)
	must(t, database.InsertQueryLogs(ctx, []QueryLogEntry{logAt(1000, "a")}))
	if n, _ := database.CountLogs(ctx, QueryLogFilter{Search: ptr("a")}); n != 1 {
		t.Fatalf("n=%d", n)
	}
}

// Concurrent readers during a write see consistent counts and nothing locks.
func TestConcurrentReadsAndWrites(t *testing.T) {
	ctx := context.Background()
	database := fileDB(t)
	done := make(chan error, 4)
	for worker := range 4 {
		go func() {
			var err error
			for i := range int64(30) {
				if worker%2 == 0 {
					err = database.InsertQueryLogs(ctx, []QueryLogEntry{logAt(i*1000, "w.example")})
				} else {
					_, err = database.QueryLogs(ctx, QueryLogFilter{}, 10, 0)
				}
				if err != nil {
					break
				}
			}
			done <- err
		}()
	}
	for range 4 {
		must(t, <-done)
	}
	if n, _ := database.TotalLogCount(ctx); n != 60 {
		t.Fatalf("count %d", n)
	}
}
