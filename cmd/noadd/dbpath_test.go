package main

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestPickDefaultDBPath(t *testing.T) {
	cases := []struct {
		newExists, legacyExists bool
		want                    string
	}{
		{false, false, defaultDBPath}, // a fresh install
		{true, false, defaultDBPath},
		{true, true, defaultDBPath}, // never silently switch to the legacy file
		{false, true, legacyDBPath}, // an upgrade keeps its data
	}
	for _, c := range cases {
		if got := pickDefaultDBPath(c.newExists, c.legacyExists); got != c.want {
			t.Errorf("%+v = %s", c, got)
		}
	}
}

func inDir(t *testing.T, files ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range files {
		if err := os.WriteFile(dir+"/"+name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
}

func TestResolveDBPathHonoursAnExplicitPathVerbatim(t *testing.T) {
	inDir(t, legacyDBPath)
	explicit := "/custom/place.sqlite3"
	if got := resolveDBPath(&explicit, slog.New(slog.DiscardHandler)); got != explicit {
		t.Fatal(got)
	}
}

func TestResolveDBPathDefaultsToTheNewNameInAnEmptyDirectory(t *testing.T) {
	inDir(t)
	if got := resolveDBPath(nil, slog.New(slog.DiscardHandler)); got != defaultDBPath {
		t.Fatal(got)
	}
}

func TestResolveDBPathAdoptsTheLegacyFileWithAWarning(t *testing.T) {
	inDir(t, legacyDBPath)
	var logged strings.Builder
	got := resolveDBPath(nil, slog.New(slog.NewTextHandler(&logged, nil)))
	if got != legacyDBPath || !strings.Contains(logged.String(), "legacy database") {
		t.Fatalf("got %s, log %q", got, logged.String())
	}
}

func TestResolveDBPathPrefersTheNewFileWhenBothExist(t *testing.T) {
	inDir(t, defaultDBPath, legacyDBPath)
	if got := resolveDBPath(nil, slog.New(slog.NewTextHandler(io.Discard, nil))); got != defaultDBPath {
		t.Fatal(got)
	}
}
