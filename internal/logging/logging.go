// Package logging builds the process logger from the command line and
// environment.
package logging

import (
	"fmt"
	"io"
	"log/slog"
)

// LevelEnv names the variable that sets the log level.
const LevelEnv = "NOADD_LOG_LEVEL"

// ParseLevel reads debug, info, warn or error.
func ParseLevel(text string) (slog.Level, error) {
	switch text {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want debug, info, warn or error)", text)
}

// LevelFromEnv reads NOADD_LOG_LEVEL. Unset or empty means info; the empty
// case matters because a container image may export an empty variable to
// mean "no value".
func LevelFromEnv(lookupEnv func(string) (string, bool)) (slog.Level, error) {
	text, ok := lookupEnv(LevelEnv)
	if !ok || text == "" {
		return slog.LevelInfo, nil
	}
	level, err := ParseLevel(text)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q for %s: %w", text, LevelEnv, err)
	}
	return level, nil
}

// New writes JSON lines when format is "json" and key=value text otherwise.
// slog has no compact or pretty layout; those names stay valid on the command
// line, for deployments that set them, and map to the text layout.
func New(w io.Writer, format string, level slog.Level) *slog.Logger {
	options := &slog.HandlerOptions{Level: level}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(w, options))
	}
	return slog.New(slog.NewTextHandler(w, options))
}
