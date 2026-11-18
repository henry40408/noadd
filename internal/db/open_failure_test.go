package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenFailsWhenTheDirectoryIsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "noadd.db")
	if database, err := Open(context.Background(), path); err == nil {
		_ = database.Close(context.Background())
		t.Fatal("Open succeeded in a missing directory")
	}
}

func TestOpenFailsOnAFileThatIsNotADatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.db")
	if err := os.WriteFile(path, []byte("this is not an sqlite database, just text padding it past a header"), 0o600); err != nil {
		t.Fatal(err)
	}
	if database, err := Open(context.Background(), path); err == nil {
		_ = database.Close(context.Background())
		t.Fatal("Open succeeded on a non-database file")
	}
}

func TestOpenFailsWhenThePathIsADirectory(t *testing.T) {
	if database, err := Open(context.Background(), t.TempDir()); err == nil {
		_ = database.Close(context.Background())
		t.Fatal("Open succeeded on a directory")
	}
}

func TestRemoveIfExistsIgnoresMissingFilesButReportsOtherErrors(t *testing.T) {
	dir := t.TempDir()
	if err := removeIfExists(filepath.Join(dir, "absent")); err != nil {
		t.Fatalf("missing file: %v", err)
	}
	nonEmpty := filepath.Join(dir, "full")
	if err := os.MkdirAll(filepath.Join(nonEmpty, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeIfExists(nonEmpty); err == nil {
		t.Fatal("a non-empty directory was reported as removed")
	}
}
