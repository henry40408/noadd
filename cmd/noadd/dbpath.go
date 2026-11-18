package main

import (
	"log/slog"
	"os"
)

const (
	defaultDBPath = "noadd.sqlite3"
	// legacyDBPath is the filename older releases used; it is opened only when
	// it is the sole file, so an upgrade keeps its data.
	legacyDBPath = "noadd.db"
)

// pickDefaultDBPath prefers the current name and never silently switches to
// the legacy file when both exist.
func pickDefaultDBPath(newExists, legacyExists bool) string {
	if !newExists && legacyExists {
		return legacyDBPath
	}
	return defaultDBPath
}

// resolveDBPath returns an explicit --db-path verbatim, and otherwise the
// default, warning when it adopts the legacy file.
func resolveDBPath(explicit *string, logger *slog.Logger) string {
	if explicit != nil {
		return *explicit
	}
	chosen := pickDefaultDBPath(fileExists(defaultDBPath), fileExists(legacyDBPath))
	if chosen == legacyDBPath {
		logger.Warn("opening legacy database `"+legacyDBPath+"`; rename it to `"+defaultDBPath+
			"` to adopt the current default and silence this warning", "path", legacyDBPath)
	}
	return chosen
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
