package db

import (
	"context"
	"path/filepath"
	"testing"
)

// Every method must surface a failed read or write instead of reporting an
// empty result, so callers can tell "nothing there" from "could not look".
func TestEveryMethodReportsAClosedDatabase(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(ctx); err != nil {
		t.Fatal(err)
	}

	calls := map[string]func() error{
		"InsertAPIKey":   func() error { _, err := database.InsertAPIKey(ctx, NewAPIKey{UserID: 1, TokenHash: "h"}); return err },
		"ListAPIKeys":    func() error { _, err := database.ListAPIKeysForUser(ctx, 1); return err },
		"DeleteAPIKey":   func() error { _, err := database.DeleteAPIKey(ctx, 1, 1); return err },
		"ValidateKey":    func() error { _, _, err := database.ValidateAPIKey(ctx, "h", 1); return err },
		"AddFilterList":  func() error { _, err := database.AddFilterList(ctx, "n", "u", true); return err },
		"FilterListURL":  func() error { _, _, err := database.FilterListURL(ctx, 1); return err },
		"GetFilterLists": func() error { _, err := database.GetFilterLists(ctx); return err },
		"UpdateList":     func() error { return database.UpdateFilterList(ctx, 1, "n", "u") },
		"UpdateEnabled":  func() error { return database.UpdateFilterListEnabled(ctx, 1, true) },
		"UpdateStats":    func() error { return database.UpdateFilterListStats(ctx, 1, 1, 1) },
		"DeleteList":     func() error { return database.DeleteFilterList(ctx, 1) },
		"GetContent":     func() error { _, _, err := database.GetFilterListContent(ctx, 1); return err },
		"SetContent":     func() error { return database.SetFilterListContent(ctx, 1, "x") },
		"GetDohTokens":   func() error { _, err := database.GetDohTokens(ctx); return err },
		"AddDohToken":    func() error { _, err := database.AddDohToken(ctx, "t"); return err },
		"DeleteDoh":      func() error { return database.DeleteDohToken(ctx, 1) },
		"ValidateDoh":    func() error { _, _, err := database.ValidateDohToken(ctx, "t"); return err },
		"HasDohTokens":   func() error { _, err := database.HasDohTokens(ctx); return err },
		"PruneLogs":      func() error { _, err := database.PruneLogsBefore(ctx, 1); return err },
		"Maintenance":    func() error { return database.RunMaintenance(ctx) },
		"HasCustomRule":  func() error { _, err := database.HasCustomRule(ctx, "r"); return err },
		"AddCustomRule":  func() error { _, err := database.AddCustomRule(ctx, "r", "block"); return err },
		"AllRules":       func() error { _, err := database.GetAllCustomRules(ctx); return err },
		"RulesByType":    func() error { _, err := database.GetCustomRulesByType(ctx, "block"); return err },
		"DeleteRule":     func() error { return database.DeleteCustomRule(ctx, 1) },
		"InsertLogs":     func() error { return database.InsertQueryLogs(ctx, []QueryLogEntry{{Domain: "a"}}) },
		"QueryLogs":      func() error { _, err := database.QueryLogs(ctx, QueryLogFilter{}, 1, 0); return err },
		"HasAnyLogs":     func() error { _, err := database.HasAnyQueryLogs(ctx); return err },
		"CountLogs":      func() error { _, err := database.CountLogs(ctx, QueryLogFilter{}); return err },
		"DeleteAllLogs":  func() error { return database.DeleteAllLogs(ctx) },
		"GetSetting":     func() error { _, _, err := database.GetSetting(ctx, "k"); return err },
		"SetSetting":     func() error { return database.SetSetting(ctx, "k", "v") },
		"ListTables":     func() error { _, err := database.ListTables(ctx); return err },
		"Earliest":       func() error { _, _, err := database.EarliestLogTimestamp(ctx); return err },
		"Latest":         func() error { _, _, err := database.LatestLogTimestamp(ctx); return err },
		"CountSince":     func() error { _, err := database.CountQueriesSince(ctx, 1); return err },
		"SummaryMulti":   func() error { _, err := database.SummaryMultiSince(ctx, 1, 2, 3); return err },
		"TopDomains":     func() error { _, err := database.TopDomainsSince(ctx, 1, 1); return err },
		"DomainStats":    func() error { _, err := database.DomainStatsSince(ctx, 1, 1); return err },
		"TopClients":     func() error { _, err := database.TopClientsSince(ctx, 1, 1); return err },
		"TrafficLists":   func() error { _, err := database.TrafficListsSince(ctx, 1, 1); return err },
		"TopUpstreams":   func() error { _, err := database.TopUpstreamsSince(ctx, 1, 1); return err },
		"TimelineMulti":  func() error { _, err := database.TimelineMultiSince(ctx, 1, 3600, 0); return err },
		"WindowMetrics":  func() error { _, err := database.WindowMetricsSince(ctx, 1); return err },
		"StatsScan":      func() error { _, err := database.StatsScanSince(ctx, 1, 1); return err },
		"Heatmap":        func() error { _, err := database.HourlyHeatmapSince(ctx, 1, 0); return err },
		"QueryTypes":     func() error { _, err := database.QueryTypeBreakdownSince(ctx, 1); return err },
		"Outcomes":       func() error { _, err := database.OutcomeBreakdownSince(ctx, 1); return err },
		"UniqueDomains":  func() error { _, err := database.UniqueDomainsSince(ctx, 1); return err },
		"Latency":        func() error { _, err := database.LatencySummarySince(ctx, 1); return err },
		"Storage":        func() error { _, err := database.DBStorageStats(ctx); return err },
		"TotalLogs":      func() error { _, err := database.TotalLogCount(ctx); return err },
		"Timeline":       func() error { _, err := database.TimelineSince(ctx, 1, 60); return err },
		"InsertSession":  func() error { _, err := database.InsertSession(ctx, NewSession{TokenHash: "h", UserID: 1}); return err },
		"DelByHash":      func() error { return database.DeleteSessionByTokenHash(ctx, "h") },
		"DelByID":        func() error { _, _, err := database.DeleteSessionByID(ctx, 1); return err },
		"DelAll":         func() error { _, err := database.DeleteAllSessions(ctx); return err },
		"DelExcept":      func() error { _, err := database.DeleteSessionsExcept(ctx, "h"); return err },
		"DelUserExcept":  func() error { _, err := database.DeleteUserSessionsExcept(ctx, 1, nil); return err },
		"ListSessions":   func() error { _, err := database.ListSessions(ctx); return err },
		"PurgeSessions":  func() error { _, err := database.PurgeExpiredSessions(ctx, 1, 1, 1); return err },
		"LoadSessions":   func() error { _, err := database.LoadSessions(ctx, 1, 1, 1); return err },
		"FlushLastSeen": func() error {
			return database.FlushSessionsLastSeen(ctx, []SessionLastSeen{{TokenHash: "h", LastSeen: 1}})
		},
		"CreateUser":   func() error { _, err := database.CreateUser(ctx, "u", "p", 1); return err },
		"CreateFirst":  func() error { _, _, err := database.CreateFirstUser(ctx, "u", "p", 1); return err },
		"CreateNoPass": func() error { _, err := database.CreateUserNoPassword(ctx, "u", 1); return err },
		"GetUserAuth":  func() error { _, _, err := database.GetUserAuth(ctx, "u"); return err },
		"GetHash":      func() error { _, _, err := database.GetUserPasswordHash(ctx, 1); return err },
		"UpdatePass":   func() error { return database.UpdateUserPassword(ctx, 1, "p") },
		"ListUsers":    func() error { _, err := database.ListUsers(ctx); return err },
		"CountUsers":   func() error { _, err := database.CountUsers(ctx); return err },
		"DeleteUser":   func() error { _, err := database.DeleteUser(ctx, 1); return err },
		"GetUsername":  func() error { _, _, err := database.GetUsername(ctx, 1); return err },
	}
	for name, call := range calls {
		if err := call(); err == nil {
			t.Errorf("%s: no error from a closed database", name)
		}
	}
}
