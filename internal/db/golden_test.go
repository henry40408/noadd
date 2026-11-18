package db

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

type dumpTable struct {
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}

func loadDump(t *testing.T) map[string]dumpTable {
	t.Helper()
	raw, err := os.ReadFile("testdata/rust-v17.dump.json")
	must(t, err)
	var dump struct {
		Tables map[string]dumpTable `json:"tables"`
	}
	must(t, json.Unmarshal(raw, &dump))
	return dump.Tables
}

// asInt64 reads a JSON number; the dump decodes numbers as float64.
func asInt64(value any) int64 { return int64(value.(float64)) }

func optionalInt(value any) *int64 {
	if value == nil {
		return nil
	}
	return ptr(asInt64(value))
}

func optionalString(value any) *string {
	if value == nil {
		return nil
	}
	return ptr(value.(string))
}

func equalOptional[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// Every read function must return what the Rust binary stored in v17.
func TestReadFunctionsMatchRustFixture(t *testing.T) {
	ctx := context.Background()
	database := openDB(t, copyFixture(t, "rust-v17.sqlite3"))
	dump := loadDump(t)

	users, err := database.ListUsers(ctx)
	must(t, err)
	if len(users) != len(dump["users"].Rows) {
		t.Fatalf("users %d", len(users))
	}
	for i, row := range dump["users"].Rows {
		if users[i].ID != asInt64(row[0]) || users[i].Username != row[1] || users[i].CreatedAt != asInt64(row[2]) {
			t.Errorf("user %d: %+v vs %v", i, users[i], row)
		}
	}

	tokens, err := database.GetDohTokens(ctx)
	must(t, err)
	for i, row := range dump["doh_tokens"].Rows {
		if tokens[i].ID != asInt64(row[0]) || tokens[i].Token != row[1] {
			t.Errorf("token %d: %+v", i, tokens[i])
		}
	}
	if _, valid, _ := database.ValidateDohToken(ctx, "alpha-token"); !valid {
		t.Error("alpha-token rejected")
	}

	rules, err := database.GetAllCustomRules(ctx)
	must(t, err)
	for i, row := range dump["custom_rules"].Rows {
		if rules[i].ID != asInt64(row[0]) || rules[i].Rule != row[1] || rules[i].RuleType != row[2] {
			t.Errorf("rule %d: %+v", i, rules[i])
		}
	}

	lists, err := database.GetFilterLists(ctx)
	must(t, err)
	if len(lists) != len(dump["filter_lists"].Rows) {
		t.Fatalf("lists %d", len(lists))
	}
	for i, row := range dump["filter_lists"].Rows {
		list := lists[i]
		if list.ID != asInt64(row[0]) || list.Name != row[1] || list.URL != row[2] ||
			list.Enabled != (asInt64(row[3]) != 0) || list.LastUpdated != asInt64(row[4]) || list.RuleCount != asInt64(row[5]) {
			t.Errorf("list %d: %+v vs %v", i, list, row)
		}
	}
	for _, row := range dump["filter_list_content"].Rows {
		if content, found, _ := database.GetFilterListContent(ctx, asInt64(row[0])); !found || content == "" {
			t.Errorf("content of list %v missing", row[0])
		}
	}

	for _, row := range dump["api_keys"].Rows {
		userID := asInt64(row[1])
		keys, err := database.ListAPIKeysForUser(ctx, userID)
		must(t, err)
		var match *APIKeyRow
		for i := range keys {
			if keys[i].ID == asInt64(row[0]) {
				match = &keys[i]
			}
		}
		if match == nil || match.Name != row[2] || match.Prefix != row[3] || match.CreatedAt != asInt64(row[4]) ||
			!equalOptional(match.LastUsedAt, optionalInt(row[5])) || !equalOptional(match.ExpiresAt, optionalInt(row[6])) {
			t.Errorf("api key %v: %+v", row, match)
		}
	}

	sessions, err := database.ListSessions(ctx)
	must(t, err)
	row := dump["sessions"].Rows[0]
	if len(sessions) != 1 || sessions[0].CreatedAt != asInt64(row[2]) || sessions[0].LastSeen != asInt64(row[3]) ||
		!equalOptional(sessions[0].IP, optionalString(row[4])) || !equalOptional(sessions[0].UserAgent, optionalString(row[5])) {
		t.Errorf("session: %+v vs %v", sessions, row)
	}

	for _, row := range dump["settings"].Rows {
		if row[0] == "session_log_salt" || row[0] == queryLogCountKey {
			continue
		}
		if value, found, _ := database.GetSetting(ctx, row[0].(string)); !found || value != row[1] {
			t.Errorf("setting %v = %q", row[0], value)
		}
	}
}

func TestQueryLogsMatchRustFixture(t *testing.T) {
	ctx := context.Background()
	database := openDB(t, copyFixture(t, "rust-v17.sqlite3"))
	rows := loadDump(t)["query_logs"].Rows
	if total, _ := database.TotalLogCount(ctx); total != int64(len(rows)) {
		t.Fatalf("maintained count %d vs %d", total, len(rows))
	}
	got, err := database.QueryLogs(ctx, QueryLogFilter{}, int64(len(rows)), 0)
	must(t, err)
	if len(got) != len(rows) {
		t.Fatalf("rows %d", len(got))
	}
	// QueryLogs is newest first; ties break by id descending.
	byTimestamp := map[int64][]QueryLogEntry{}
	for _, entry := range got {
		byTimestamp[entry.Timestamp] = append(byTimestamp[entry.Timestamp], entry)
	}
	blocked, cached := 0, 0
	for _, row := range rows {
		matches := byTimestamp[asInt64(row[1])]
		found := false
		for _, entry := range matches {
			if entry.Domain == row[2] && entry.QueryType == row[3] && entry.ClientIP == row[4] &&
				entry.Blocked == (asInt64(row[5]) != 0) && entry.Cached == (asInt64(row[6]) != 0) &&
				entry.ResponseMs == asInt64(row[7]) && equalOptional(entry.Upstream, optionalString(row[8])) &&
				equalOptional(entry.DohToken, optionalString(row[9])) && equalOptional(entry.Result, optionalString(row[10])) &&
				entry.AuthenticatedData == (asInt64(row[11]) != 0) {
				found = true
			}
		}
		if !found {
			t.Errorf("row not read back: %v", row)
		}
		blocked += int(asInt64(row[5]))
		cached += int(asInt64(row[6]))
	}
	if n, _ := database.CountLogs(ctx, QueryLogFilter{Blocked: ptr(true)}); n != int64(blocked) {
		t.Errorf("blocked %d vs %d", n, blocked)
	}

	// Rust's rollups must read back to the same totals as the table.
	first, _, _ := database.EarliestLogTimestamp(ctx)
	windows, err := database.SummaryMultiSince(ctx, first/1000-3600, first/1000-3600, first/1000-3600)
	must(t, err)
	if windows[0].Total != int64(len(rows)) || windows[0].Blocked != int64(blocked) || windows[0].CacheHits > int64(cached) {
		t.Errorf("summary %+v vs %d/%d/%d", windows[0], len(rows), blocked, cached)
	}
	domains, err := database.DomainStatsSince(ctx, first/1000-3600, 100)
	must(t, err)
	var sum int64
	for _, top := range domains.Top {
		sum += top.Count
	}
	if sum != int64(len(rows)) {
		t.Errorf("domain rollup %d vs %d", sum, len(rows))
	}
}
