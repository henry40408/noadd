package main

import (
	"fmt"
	"strings"
)

// legacyEnvVar pairs a retired environment variable with its replacement.
type legacyEnvVar struct{ old, replacement string }

// legacyEnvVars lists the retired variables. Update it whenever an environment
// variable is added, renamed or removed: a silently ignored one is worse than
// a startup failure. LOG_FORMAT is not here: it is still read.
var legacyEnvVars = []legacyEnvVar{
	// A global RUST_LOG would otherwise be ignored without a word.
	{"RUST_LOG", "NOADD_LOG_LEVEL"},
}

// ensureNoLegacyEnvVars fails when a retired variable is set, even empty.
func ensureNoLegacyEnvVars(lookupEnv func(string) (string, bool)) error {
	var found []string
	for _, legacy := range legacyEnvVars {
		if _, ok := lookupEnv(legacy.old); ok {
			found = append(found, fmt.Sprintf("  %s -> %s", legacy.old, legacy.replacement))
		}
	}
	if len(found) == 0 {
		return nil
	}
	return fmt.Errorf("these environment variables no longer exist; "+
		"rename (or unset) them to continue:\n%s", strings.Join(found, "\n"))
}
