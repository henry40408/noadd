package db

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReaderIsReadOnly(t *testing.T) {
	database := openDB(t, filepath.Join(t.TempDir(), "ro.sqlite3"))
	_, err := database.reader.Exec("INSERT INTO settings (key, value) VALUES ('k', 'v')")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "readonly") {
		t.Fatalf("reader accepted a write: %v", err)
	}
}

func TestReaderDoesNotSeeUncommittedRows(t *testing.T) {
	ctx := context.Background()
	database := openDB(t, filepath.Join(t.TempDir(), "wal.sqlite3"))
	tx, err := database.writer.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO settings (key, value) VALUES ('pending', '1')"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := database.reader.QueryRow("SELECT COUNT(*) FROM settings WHERE key = 'pending'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("reader saw an uncommitted row")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := database.reader.QueryRow("SELECT COUNT(*) FROM settings WHERE key = 'pending'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("reader missed the committed row: %d, %v", count, err)
	}
}

func TestPragmasApplyToEveryReaderConnection(t *testing.T) {
	ctx := context.Background()
	database := openDB(t, filepath.Join(t.TempDir(), "pragma.sqlite3"))
	for range readPoolSize {
		conn, err := database.reader.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		var timeout int
		if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&timeout); err != nil || timeout != 5000 {
			t.Fatalf("busy_timeout = %d, err %v", timeout, err)
		}
	}
	var mode string
	if err := database.writer.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q, err %v", mode, err)
	}
	var foreignKeys int
	if err := database.writer.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, err %v", foreignKeys, err)
	}
}

func TestCloseRemovesWALSidecarFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noadd.sqlite3")
	database, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Stat(sidecar); err != nil {
			t.Fatalf("%s should exist while open: %v", sidecar, err)
		}
	}
	if err := database.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, sidecar := range []string{path + "-wal", path + "-shm"} {
		if _, err := os.Stat(sidecar); !os.IsNotExist(err) {
			t.Errorf("%s should be gone after Close: %v", sidecar, err)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("main file should remain: %v", err)
	}
}

func TestOpenPathWithURISyntax(t *testing.T) {
	path := filepath.Join(t.TempDir(), "odd name?x#y%z.sqlite3")
	database := openDB(t, path)
	if _, err := database.writer.Exec("INSERT INTO settings (key, value) VALUES ('k', 'v')"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database not created at the literal path: %v", err)
	}
}

func TestOpenInMemoryUsesOneDatabase(t *testing.T) {
	database := openDB(t, memoryPath)
	if _, err := database.writer.Exec("INSERT INTO settings (key, value) VALUES ('k', 'v')"); err != nil {
		t.Fatal(err)
	}
	var value string
	if err := database.reader.QueryRow("SELECT value FROM settings WHERE key = 'k'").Scan(&value); err != nil || value != "v" {
		t.Fatalf("reader does not share the writer: %q, %v", value, err)
	}
}
