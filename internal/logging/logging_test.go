package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func lookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestLevelFromEnv(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError,
	}
	for text, want := range cases {
		got, err := LevelFromEnv(lookup(map[string]string{LevelEnv: text}))
		if err != nil || got != want {
			t.Errorf("%s = %v, %v", text, got, err)
		}
	}
}

func TestLevelDefaultsToInfoWhenUnsetOrEmpty(t *testing.T) {
	for _, env := range []map[string]string{{}, {LevelEnv: ""}} {
		if got, err := LevelFromEnv(lookup(env)); err != nil || got != slog.LevelInfo {
			t.Errorf("%v = %v, %v", env, got, err)
		}
	}
}

func TestLevelRejectsAnythingElse(t *testing.T) {
	_, err := LevelFromEnv(lookup(map[string]string{LevelEnv: "bogus"}))
	if err == nil || !strings.Contains(err.Error(), LevelEnv) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewHonoursFormatAndLevel(t *testing.T) {
	var text, json bytes.Buffer
	New(&text, "full", slog.LevelWarn).Info("hidden")
	New(&text, "compact", slog.LevelWarn).Warn("shown")
	New(&json, "json", slog.LevelInfo).Info("hello", "event", "x")
	if strings.Contains(text.String(), "hidden") || !strings.Contains(text.String(), "msg=shown") {
		t.Errorf("text = %q", text.String())
	}
	if !strings.HasPrefix(json.String(), "{") || !strings.Contains(json.String(), `"event":"x"`) {
		t.Errorf("json = %q", json.String())
	}
}
