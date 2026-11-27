package db

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// openRaw opens a database file without running any migration.
func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", dsn(path, nil, ""))
	must(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}

func newRawDatabase(t *testing.T) *sql.DB {
	t.Helper()
	return openRaw(t, filepath.Join(t.TempDir(), "raw.sqlite3"))
}

func mustExec(t *testing.T, conn *sql.DB, script string) {
	t.Helper()
	_, err := conn.Exec(script)
	must(t, err)
}

func schemaVersion(t *testing.T, conn *sql.DB) int64 {
	t.Helper()
	version, err := userVersion(context.Background(), conn)
	must(t, err)
	return version
}

func shippedMigrations(t *testing.T) []migration {
	t.Helper()
	files, err := fs.Sub(embeddedMigrations, "migrations")
	must(t, err)
	shipped, err := loadMigrations(files)
	must(t, err)
	return shipped
}

func applyTo(t *testing.T, conn *sql.DB, migrations []migration) {
	t.Helper()
	must(t, applyMigrations(context.Background(), conn, migrations))
}

// A start may stop between two files; the next one carries on from there.
func TestAnUpgradeResumedAtAnyVersionEndsAtTheFreshSchema(t *testing.T) {
	fresh := openDB(t, filepath.Join(t.TempDir(), "fresh.sqlite3"))
	want := structure(t, fresh.writer)
	for _, m := range shippedMigrations(t) {
		path, _ := databaseAtVersion(t, m.version)
		database := openDB(t, path)
		assertUserVersion(t, database, 17)
		if got := structure(t, database.writer); got != want {
			t.Errorf("from version %d\n got: %s\nwant: %s", m.version, got, want)
		}
	}
}

func TestOpenRefusesADatabaseItCannotUpgradeAndKeepsItsSchema(t *testing.T) {
	const noVersion = "user_version is 0"
	changed := func(create func(*testing.T) string, change string) func(*testing.T) string {
		return func(t *testing.T) string {
			path := create(t)
			mustExec(t, openRaw(t, path), change)
			return path
		}
	}
	empty := func(t *testing.T) string { return filepath.Join(t.TempDir(), "other.sqlite3") }
	unversioned := func(t *testing.T) string { return copyFixture(t, "rust-v0.sqlite3") }
	current := func(t *testing.T) string { return copyFixture(t, "rust-v17.sqlite3") }
	tests := map[string]struct {
		create func(*testing.T) string
		want   string
	}{
		"with tables and no version": {unversioned, noVersion},
		"that lost its version":      {changed(current, "PRAGMA user_version = 0"), noVersion},
		"of another program":         {changed(empty, "CREATE TABLE notes (body TEXT)"), noVersion},
		"with only a view":           {changed(empty, "CREATE VIEW one AS SELECT 1"), noVersion},
		"with a negative version":    {changed(unversioned, "PRAGMA user_version = -1"), noVersion},
		"from a newer noadd":         {changed(current, "PRAGMA user_version = 18"), "newer than 17"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := test.create(t)
			raw := openRaw(t, path)
			version, schema := schemaVersion(t, raw), schemaObjects(t, raw)

			database, err := Open(context.Background(), path)
			if err == nil {
				_ = database.Close(context.Background())
				t.Fatal("the database was opened")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err = %v, want it to say %q", err, test.want)
			}
			if got := schemaVersion(t, raw); got != version {
				t.Fatalf("user_version = %d, was %d", got, version)
			}
			if got := schemaObjects(t, raw); !slices.Equal(got, schema) {
				t.Fatalf("schema changed\nbefore: %v\n after: %v", schema, got)
			}
		})
	}
}

// Another process may be creating tables while this one starts. A check made
// before taking the write lock would still see the database as it was before.
func TestTheEmptyCheckWaitsForOtherWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.sqlite3")
	other := openRaw(t, path)
	mustExec(t, other, "PRAGMA journal_mode = WAL")
	tx, err := other.Begin()
	must(t, err)
	_, err = tx.Exec("CREATE TABLE notes (body TEXT)")
	must(t, err)

	opened := make(chan error, 1)
	go func() {
		database, err := Open(context.Background(), path)
		if err == nil {
			_ = database.Close(context.Background())
		}
		opened <- err
	}()
	// Long enough for Open to reach the lock, far shorter than its busy_timeout.
	time.Sleep(200 * time.Millisecond)
	must(t, tx.Commit())

	if err := <-opened; err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

// A second noadd may hold the write lock while this one starts.
func TestAnUpToDateDatabaseNeedsNoWriteLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked.sqlite3")
	openDB(t, path)
	holder := openRaw(t, path)
	tx, err := holder.Begin()
	must(t, err)
	defer func() { _ = tx.Rollback() }()

	applyTo(t, openRaw(t, path), shippedMigrations(t))
}

func TestLaterMigrationsApplyOnceAndInOrder(t *testing.T) {
	raw := newRawDatabase(t)
	pending := []migration{
		{version: 1, sql: "CREATE TABLE later (id INTEGER)"},
		{version: 3, sql: "ALTER TABLE later ADD COLUMN name TEXT"},
	}

	// Neither statement can run twice.
	for range 2 {
		applyTo(t, raw, pending)
		if got := schemaVersion(t, raw); got != 3 {
			t.Fatalf("user_version = %d", got)
		}
	}
}

func TestApplyMigrationSkipsOneAlreadyApplied(t *testing.T) {
	raw := newRawDatabase(t)
	mustExec(t, raw, "PRAGMA user_version = 8")
	done := migration{version: 8, sql: "this is not SQL"}
	must(t, applyMigration(context.Background(), raw, done, 8))
}

// A newer noadd may upgrade the database between the first read and the write lock.
func TestApplyMigrationRefusesADatabaseThatBecameNewer(t *testing.T) {
	raw := newRawDatabase(t)
	mustExec(t, raw, "PRAGMA user_version = 9")
	pending := migration{version: 8, sql: "this is not SQL"}
	err := applyMigration(context.Background(), raw, pending, 8)
	if err == nil || !strings.Contains(err.Error(), "newer than") {
		t.Fatalf("err = %v", err)
	}
}

func TestFailedMigrationLeavesNothingBehind(t *testing.T) {
	raw := newRawDatabase(t)
	broken := []migration{
		{version: 1, sql: "CREATE TABLE done (id INTEGER)"},
		{version: 2, sql: "CREATE TABLE half_done (id INTEGER); INSERT INTO no_such_table VALUES (1);"},
	}

	err := applyMigrations(context.Background(), raw, broken)
	if err == nil || !strings.Contains(err.Error(), "migration 2") {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Join(schemaObjects(t, raw), "\n"); strings.Contains(got, "half_done") {
		t.Fatalf("the half-applied table survived: %s", got)
	}
	if got := schemaVersion(t, raw); got != 1 {
		t.Fatalf("user_version = %d, want the last migration that succeeded", got)
	}
}

func TestAVersionThatCannotBeRecordedRollsTheMigrationBack(t *testing.T) {
	raw := newRawDatabase(t)
	// query_only makes the write of user_version fail after the script ran.
	unrecordable := []migration{{version: 1, sql: "CREATE TABLE unrecorded (id INTEGER); PRAGMA query_only = 1"}}

	if err := applyMigrations(context.Background(), raw, unrecordable); err == nil {
		t.Fatal("the migration was reported as applied")
	}
	if got := schemaObjects(t, raw); len(got) != 0 {
		t.Fatalf("the table survived without its version: %v", got)
	}
}

func TestMigrationsReportADatabaseTheyCannotRead(t *testing.T) {
	raw := newRawDatabase(t)
	must(t, raw.Close())
	err := applyMigrations(context.Background(), raw, shippedMigrations(t))
	if err == nil || !strings.Contains(err.Error(), "read schema version") {
		t.Fatalf("err = %v", err)
	}
	err = requireEmpty(context.Background(), raw)
	if err == nil || !strings.Contains(err.Error(), "inspect database") {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyMigrationStopsWhenCancelled(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	err := applyMigration(cancelled, newRawDatabase(t), shippedMigrations(t)[0], 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadMigrationsReportsAFileItCannotRead(t *testing.T) {
	// A directory named like a migration.
	if _, err := loadMigrations(fstest.MapFS{"0001_directory.sql/nested": {}}); err == nil {
		t.Fatal("the directory was loaded")
	}
}

func TestLoadMigrationsOrdersByVersion(t *testing.T) {
	fsys := fstest.MapFS{
		"0010_late_one.sql":  {Data: []byte("SELECT 10;")},
		"0002_early.sql":     {Data: []byte("SELECT 2;")},
		"2147483647_end.sql": {Data: []byte("SELECT 3;")},
		"notes.txt":          {Data: []byte("ignored")},
	}
	got, err := loadMigrations(fsys)
	must(t, err)
	want := []migration{{2, "SELECT 2;"}, {10, "SELECT 10;"}, {2147483647, "SELECT 3;"}}
	if !slices.Equal(got, want) {
		t.Fatalf("migrations = %+v, want %+v", got, want)
	}
}

func TestLoadMigrationsRejectsBadNames(t *testing.T) {
	// user_version holds 1 to 2147483647 here.
	names := []string{"init.sql", "x_init.sql", "0001.sql", "0000_zero.sql", "2147483648_big.sql"}
	for _, name := range names {
		fsys := fstest.MapFS{name: {Data: []byte("SELECT 1;")}}
		if _, err := loadMigrations(fsys); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestLoadMigrationsRejectsDuplicateVersions(t *testing.T) {
	fsys := fstest.MapFS{
		"0001_a.sql":  {Data: []byte("SELECT 1;")},
		"00001_b.sql": {Data: []byte("SELECT 1;")},
	}
	if _, err := loadMigrations(fsys); err == nil {
		t.Fatal("two files with version 1 were accepted")
	}
}

func TestLoadMigrationsRejectsAnEmptySet(t *testing.T) {
	if _, err := loadMigrations(fstest.MapFS{}); err == nil {
		t.Fatal("no files were accepted")
	}
}
