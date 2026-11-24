package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var whitespace = regexp.MustCompile(`\s+`)

// copyFixture builds a database from legacySQL in a temp dir, as a WAL one:
// opening migrates in place.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	statements, ok := legacySQL[name]
	if !ok {
		t.Fatalf("no fixture named %s", name)
	}
	path := filepath.Join(t.TempDir(), name)
	buildLegacyDatabase(t, path, statements)
	return path
}

func buildLegacyDatabase(t *testing.T, path, statements string) {
	t.Helper()
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// One connection, so the journal mode and the statements share it.
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec("PRAGMA journal_mode = WAL"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(statements); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func openDB(t *testing.T, path string) *DB {
	t.Helper()
	database, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close(context.Background()) })
	return database
}

// schemaObjects lists sqlite_master with whitespace normalised, skipping the
// internal sqlite_stat tables, whose rows are not part of the schema contract.
func schemaObjects(t *testing.T, conn *sql.DB) []string {
	t.Helper()
	rows, err := conn.Query(`SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master
		WHERE name NOT LIKE 'sqlite_stat%' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var objects []string
	for rows.Next() {
		var kind, name, table, ddl string
		if err := rows.Scan(&kind, &name, &table, &ddl); err != nil {
			t.Fatal(err)
		}
		ddl = strings.TrimSpace(whitespace.ReplaceAllString(ddl, " "))
		objects = append(objects, fmt.Sprintf("%s|%s|%s|%s", kind, name, table, ddl))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return objects
}

func rustV17Schema(t *testing.T) []string {
	t.Helper()
	conn, err := sql.Open("sqlite", dsn(copyFixture(t, "rust-v17.sqlite3"), nil, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	return schemaObjects(t, conn)
}

// TestUpgradeMatchesRustV17Structure compares columns and indexes rather than
// DDL text: the legacy fixtures are hand-written, so their untouched tables
// keep their own spelling, exactly as they do under Rust.
func TestUpgradeMatchesRustV17Structure(t *testing.T) {
	rust, err := sql.Open("sqlite", dsn(copyFixture(t, "rust-v17.sqlite3"), nil, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rust.Close() }()
	want := structure(t, rust)
	for _, name := range []string{"rust-v0.sqlite3", "rust-v4.sqlite3", "rust-v8.sqlite3", "rust-v15.sqlite3"} {
		t.Run(name, func(t *testing.T) {
			database := openDB(t, copyFixture(t, name))
			assertUserVersion(t, database, 17)
			if got := structure(t, database.writer); got != want {
				t.Fatalf("structure differs from Rust v17\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

func TestUpgradeOfV17KeepsRustSchemaText(t *testing.T) {
	want := rustV17Schema(t)
	database := openDB(t, copyFixture(t, "rust-v17.sqlite3"))
	assertUserVersion(t, database, 17)
	if got := schemaObjects(t, database.writer); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatal("opening a v17 database changed its schema")
	}
}

// structure lists every table's xinfo, every index's xinfo and the trigger
// text, in a stable order.
func structure(t *testing.T, conn *sql.DB) string {
	t.Helper()
	var lines []string
	rows, err := conn.Query(`SELECT m.type, m.name, m.tbl_name, COALESCE(m.sql, '') FROM sqlite_master m
		WHERE m.name NOT LIKE 'sqlite_stat%' ORDER BY m.type, m.name`)
	if err != nil {
		t.Fatal(err)
	}
	type object struct{ kind, name, table, ddl string }
	var objects []object
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.kind, &o.name, &o.table, &o.ddl); err != nil {
			t.Fatal(err)
		}
		objects = append(objects, o)
	}
	_ = rows.Close()
	for _, o := range objects {
		switch o.kind {
		case "table":
			lines = append(lines, "table "+o.name+": "+pragmaRows(t, conn, "table_xinfo", o.name))
		case "index":
			lines = append(lines, "index "+o.name+" on "+o.table+": "+pragmaRows(t, conn, "index_xinfo", o.name))
		default:
			lines = append(lines, o.kind+" "+o.name+": "+whitespace.ReplaceAllString(o.ddl, " "))
		}
	}
	return strings.Join(lines, "\n")
}

func pragmaRows(t *testing.T, conn *sql.DB, pragma, name string) string {
	t.Helper()
	rows, err := conn.Query(fmt.Sprintf("SELECT * FROM pragma_%s(?)", pragma), name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	columns, _ := rows.Columns()
	var out []string
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprint(values...))
	}
	return strings.Join(out, ";")
}

func TestEmptyDatabaseMatchesRustV17Schema(t *testing.T) {
	database := openDB(t, filepath.Join(t.TempDir(), "fresh.sqlite3"))
	assertUserVersion(t, database, 17)
	got := schemaObjects(t, database.writer)
	if want := rustV17Schema(t); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("fresh schema differs from Rust v17\n got: %s\nwant: %s",
			strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
}

func assertUserVersion(t *testing.T, database *DB, want int) {
	t.Helper()
	var got int
	if err := database.writer.QueryRow("PRAGMA user_version").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("user_version = %d, want %d", got, want)
	}
}

type migratedDump struct {
	UserVersion int `json:"user_version"`
	Tables      map[string]struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
	} `json:"tables"`
}

// TestUpgradeMatchesRustMigratedRows compares every table the Rust binary
// dumped after migrating the same legacy file: user data survives, legacy
// sessions are dropped and the rollups are backfilled the same way.
func TestUpgradeMatchesRustMigratedRows(t *testing.T) {
	for _, version := range []string{"v0", "v4", "v8", "v15"} {
		t.Run(version, func(t *testing.T) {
			var dump migratedDump
			if err := json.Unmarshal([]byte(rustMigratedDumps[version]), &dump); err != nil {
				t.Fatal(err)
			}
			database := openDB(t, copyFixture(t, "rust-"+version+".sqlite3"))
			assertUserVersion(t, database, dump.UserVersion)
			for table, want := range dump.Tables {
				if table == "sessions" {
					// The Rust server purges expired sessions on start-up, which
					// is not a migration; TestV9DropsPlaintextSessions covers v9.
					continue
				}
				if table == "settings" {
					want.Rows = withoutKey(want.Rows, "session_log_salt")
				}
				got := selectRows(t, database.writer, table, want.Columns)
				if table == "settings" {
					got = withoutSalt(got)
				}
				if len(got) != len(want.Rows) {
					t.Errorf("%s: %d rows, Rust has %d", table, len(got), len(want.Rows))
					continue
				}
				wantRows := normalizeRows(t, want.Rows)
				for i := range got {
					if got[i] != wantRows[i] {
						t.Errorf("%s row %d: got %s, Rust has %s", table, i, got[i], wantRows[i])
					}
				}
			}
		})
	}
}

func withoutKey(rows [][]any, key string) [][]any {
	var kept [][]any
	for _, row := range rows {
		if row[0] != key {
			kept = append(kept, row)
		}
	}
	return kept
}

// withoutSalt drops the session_log_salt row, which the server (not the
// migrations) creates with a random value.
func withoutSalt(rows []string) []string {
	var kept []string
	for _, row := range rows {
		if !strings.Contains(row, `"session_log_salt"`) {
			kept = append(kept, row)
		}
	}
	return kept
}

// selectRows returns the rows as sorted JSON so the comparison does not
// depend on row order or on int-versus-float decoding.
func selectRows(t *testing.T, conn *sql.DB, table string, columns []string) []string {
	t.Helper()
	rows, err := conn.Query(fmt.Sprintf("SELECT %s FROM %s", strings.Join(columns, ", "), table))
	if err != nil {
		t.Fatalf("%s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	var out [][]any
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			t.Fatal(err)
		}
		for i, v := range values {
			if b, ok := v.([]byte); ok {
				values[i] = string(b)
			}
		}
		out = append(out, values)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return normalizeRows(t, out)
}

func normalizeRows(t *testing.T, rows [][]any) []string {
	t.Helper()
	out := make([]string, len(rows))
	for i, row := range rows {
		encoded, err := json.Marshal(normalizeNumbers(row))
		if err != nil {
			t.Fatal(err)
		}
		out[i] = string(encoded)
	}
	sort.Strings(out)
	return out
}

// normalizeNumbers turns whole float64 values (what encoding/json decodes
// every number to) into int64 so they match what the driver returns.
func normalizeNumbers(row []any) []any {
	out := make([]any, len(row))
	for i, v := range row {
		if f, ok := v.(float64); ok && f == float64(int64(f)) {
			out[i] = int64(f)
			continue
		}
		out[i] = v
	}
	return out
}

func TestUpgradeKeepsRowCounts(t *testing.T) {
	counts := func(conn *sql.DB) map[string]int {
		out := map[string]int{}
		for _, table := range []string{"query_logs", "filter_lists", "custom_rules", "doh_tokens", "users", "api_keys"} {
			var n int
			if err := conn.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
				t.Fatal(err)
			}
			out[table] = n
		}
		return out
	}
	for _, name := range []string{"rust-v4.sqlite3", "rust-v8.sqlite3", "rust-v15.sqlite3", "rust-v17.sqlite3"} {
		t.Run(name, func(t *testing.T) {
			path := copyFixture(t, name)
			before, err := sql.Open("sqlite", dsn(path, nil, "ro"))
			if err != nil {
				t.Fatal(err)
			}
			wantCounts := map[string]int{}
			func() {
				defer func() { _ = before.Close() }()
				for _, table := range []string{"query_logs", "filter_lists", "custom_rules", "doh_tokens"} {
					var n int
					if err := before.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
						t.Fatal(err)
					}
					wantCounts[table] = n
				}
			}()
			database := openDB(t, path)
			got := counts(database.writer)
			for table, want := range wantCounts {
				if got[table] != want {
					t.Errorf("%s: %d rows after upgrade, %d before", table, got[table], want)
				}
			}
		})
	}
}

func TestMaintainStatsTriggerExists(t *testing.T) {
	database := openDB(t, filepath.Join(t.TempDir(), "trigger.sqlite3"))
	var name string
	err := database.writer.QueryRow(
		"SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = 'query_logs_maintain_stats'").Scan(&name)
	if err != nil {
		t.Fatalf("trigger missing: %v", err)
	}
}

// TestV9DropsPlaintextSessions pins the security-relevant step: raw session
// tokens must not survive the upgrade, and the renamed column must work.
func TestV9DropsPlaintextSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v8.sqlite3")
	raw, err := sql.Open("sqlite", dsn(path, nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
		INSERT INTO users (username, password_hash, created_at) VALUES ('op', 'x', 100);
		CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, ip TEXT, user_agent TEXT);
		INSERT INTO sessions (token, user_id, created_at, last_seen) VALUES ('plaintext-token', 1, 100, 100);
		PRAGMA user_version = 8;`)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()

	database := openDB(t, path)
	var sessions int
	if err := database.writer.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("%d sessions survived v9", sessions)
	}
	if _, err := database.writer.Exec(
		"INSERT INTO sessions (token_hash, user_id, created_at, last_seen) VALUES ('hash', 1, 200, 200)"); err != nil {
		t.Fatalf("token_hash column missing: %v", err)
	}
	var users int
	if err := database.writer.QueryRow("SELECT COUNT(*) FROM users").Scan(&users); err != nil || users != 1 {
		t.Fatalf("users = %d, err %v", users, err)
	}
}

func TestV8AddsAPIKeysTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v7.sqlite3")
	raw, err := sql.Open("sqlite", dsn(path, nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
		INSERT INTO users (username, password_hash, created_at) VALUES ('op', 'x', 100);
		CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, ip TEXT, user_agent TEXT);
		PRAGMA user_version = 7;`)
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()

	database := openDB(t, path)
	if _, err := database.writer.Exec(`INSERT INTO api_keys (user_id, name, token_hash, prefix, created_at)
		VALUES (1, 'ci', 'deadbeef', 'noadd_dead', 200)`); err != nil {
		t.Fatalf("api_keys unusable: %v", err)
	}
}

func TestDeletingUserCascadesAPIKeys(t *testing.T) {
	database := openDB(t, filepath.Join(t.TempDir(), "cascade.sqlite3"))
	for _, stmt := range []string{
		"INSERT INTO users (username, password_hash, created_at) VALUES ('a', 'x', 100)",
		"INSERT INTO api_keys (user_id, name, token_hash, prefix, created_at) VALUES (1, 'k', 'h', 'noadd_cccc', 100)",
		"DELETE FROM users WHERE id = 1",
	} {
		if _, err := database.writer.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	var keys int
	if err := database.writer.QueryRow("SELECT COUNT(*) FROM api_keys").Scan(&keys); err != nil || keys != 0 {
		t.Fatalf("api_keys = %d, err %v (foreign_keys pragma not applied?)", keys, err)
	}
}

func TestFailedMigrationRollsBackAndKeepsVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.sqlite3")
	raw, err := sql.Open("sqlite", dsn(path, nil, ""))
	if err != nil {
		t.Fatal(err)
	}
	// A "sessions" view makes the v9 DELETE fail after v6..v8 ran.
	_, err = raw.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
		CREATE TABLE sessions (id INTEGER PRIMARY KEY, token TEXT);
		PRAGMA user_version = 8;`)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = raw.Exec("DROP TABLE sessions")
	_ = raw.Close()

	_, err = Open(context.Background(), path)
	if err == nil {
		t.Fatal("expected migration v9 to fail without a sessions table")
	}
	raw, err = sql.Open("sqlite", dsn(path, nil, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	var version int
	if err := raw.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 8 {
		t.Fatalf("user_version = %d, err %v; want 8", version, err)
	}
}
