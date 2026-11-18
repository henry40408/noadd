// Command noadd is a DNS ad-blocker with an admin UI.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/henry40408/noadd/internal/version"
)

const (
	exitFailure = 1
	exitUsage   = 2
)

// process is everything run needs from the outside world.
type process struct {
	args      []string
	lookupEnv func(string) (string, bool)
	stdout    io.Writer
	stderr    io.Writer
}

func main() {
	os.Exit(run(process{
		args:      os.Args[1:],
		lookupEnv: os.LookupEnv,
		stdout:    os.Stdout,
		stderr:    os.Stderr,
	}))
}

// run returns the exit code. Logs go to stdout; stderr carries the setup token
// and fatal errors only.
func run(p process) int {
	// First, before flags: a retired variable must stop startup however the
	// rest of the command line looks.
	if err := ensureNoLegacyEnvVars(p.lookupEnv); err != nil {
		return reportFatal(p.stderr, err)
	}
	opts, err := parseOptions(p.args, p.lookupEnv, p.stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		return reportFatal(p.stderr, err)
	}
	if opts.showVersion {
		_, _ = fmt.Fprintf(p.stdout, "noadd %s\n", version.Version())
		return 0
	}
	if err := serve(p, opts); err != nil {
		return reportFatal(p.stderr, err)
	}
	return 0
}

func reportFatal(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
	var usage usageError
	if errors.As(err, &usage) {
		return exitUsage
	}
	return exitFailure
}
