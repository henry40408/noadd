package main

import (
	"strings"
	"testing"
)

func envOf(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestNoLegacyEnvVarsIsNotAnError(t *testing.T) {
	if err := ensureNoLegacyEnvVars(envOf(map[string]string{"NOADD_LOG_LEVEL": "debug", "LOG_FORMAT": "json"})); err != nil {
		t.Fatal(err)
	}
}

func TestAnEmptyLegacyEnvVarStillFails(t *testing.T) {
	if err := ensureNoLegacyEnvVars(envOf(map[string]string{"RUST_LOG": ""})); err == nil {
		t.Fatal("an empty RUST_LOG was ignored")
	}
}

func TestLegacyEnvVarErrorNamesTheReplacement(t *testing.T) {
	err := ensureNoLegacyEnvVars(envOf(map[string]string{"RUST_LOG": "debug"}))
	if err == nil {
		t.Fatal("RUST_LOG was ignored")
	}
	want := "these environment variables no longer exist; rename (or unset) them to continue:\n  RUST_LOG -> NOADD_LOG_LEVEL"
	if err.Error() != want {
		t.Fatalf("err = %q", err)
	}
	if strings.Contains(err.Error(), "LOG_FORMAT ->") {
		t.Fatal("LOG_FORMAT is still a live variable")
	}
}
