// Package harness drives noadd instances and a browser for the e2e suite.
package harness

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	startupTimeout = 60 * time.Second
	shutdownGrace  = 10 * time.Second
	// setupTokenMarker precedes the first-run token on stderr, the only place
	// the server prints it.
	setupTokenMarker = "first-run setup token: "
)

// BinaryEnv names the variable that pins the server binary under test.
const BinaryEnv = "E2E_BINARY"

// ServerLogEnv names a file that receives every server's stderr, for
// diagnosing a crash the browser only reports as a refused connection.
const ServerLogEnv = "E2E_SERVER_LOG"

// Server is one noadd instance: its ports, its database and its process.
type Server struct {
	HTTPPort int
	DNSPort  int
	// BaseURL is the origin every page object navigates against.
	BaseURL string

	dbPath string
	cmd    *exec.Cmd
	done   chan struct{}

	tokenMu    sync.Mutex
	setupToken string
}

// NewServer starts a fresh instance with an empty database. The DNS port is
// the HTTP port plus 1000.
func NewServer(name string, httpPort int) (*Server, error) {
	dataDir, err := os.MkdirTemp("", "noadd-e2e-"+name+"-")
	if err != nil {
		return nil, err
	}
	server := &Server{
		HTTPPort: httpPort,
		DNSPort:  httpPort + 1000,
		BaseURL:  "http://127.0.0.1:" + strconv.Itoa(httpPort),
		dbPath:   filepath.Join(dataDir, name+".db"),
	}
	if err := server.Start(); err != nil {
		server.Stop()
		_ = os.RemoveAll(dataDir)
		return nil, err
	}
	return server, nil
}

// Start runs the process against the existing database. It is a no-op while
// the process is running.
func (s *Server) Start() error {
	if s.cmd != nil {
		return nil
	}
	binary, err := ensureBinary()
	if err != nil {
		return err
	}
	cmd := exec.Command(binary,
		"--db-path", s.dbPath,
		"--http-addr", "127.0.0.1:"+strconv.Itoa(s.HTTPPort),
		"--dns-addr", "127.0.0.1:"+strconv.Itoa(s.DNSPort),
		"--log-format", "json",
	)
	cmd.Dir = RepoRoot()
	// Teardown stops the server mid-request; its log would bury real failures.
	cmd.Stdout = nil
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawning %s: %w", binary, err)
	}
	s.cmd = cmd
	s.done = make(chan struct{})
	go s.readStderr(stderr)
	go func() {
		_ = cmd.Wait()
		close(s.done)
	}()
	return s.waitUntilHealthy()
}

// readStderr remembers the setup token, then keeps draining so the server
// never blocks on a full pipe.
func (s *Server) readStderr(stderr io.Reader) {
	if path := os.Getenv(ServerLogEnv); path != "" {
		if file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			defer file.Close()
			stderr = io.TeeReader(stderr, file)
		}
	}
	lines := bufio.NewScanner(stderr)
	for lines.Scan() {
		_, token, found := strings.Cut(lines.Text(), setupTokenMarker)
		if !found {
			continue
		}
		s.tokenMu.Lock()
		s.setupToken = strings.TrimSpace(token)
		s.tokenMu.Unlock()
	}
	_, _ = io.Copy(io.Discard, stderr)
}

// SetupToken is the first-run token printed at startup. It is empty on an
// instance that already has an operator.
func (s *Server) SetupToken() string {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	return s.setupToken
}

// Stop ends the process gracefully (SIGTERM, so the WAL is checkpointed) and
// kills it when it ignores the signal. Safe to call twice.
func (s *Server) Stop() {
	if s.cmd == nil {
		return
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(shutdownGrace):
		_ = s.cmd.Process.Kill()
		<-s.done
	}
	s.cmd = nil
}

// Remove stops the instance and deletes its database directory.
func (s *Server) Remove() {
	s.Stop()
	_ = os.RemoveAll(filepath.Dir(s.dbPath))
}

func (s *Server) waitUntilHealthy() error {
	deadline := time.Now().Add(startupTimeout)
	for time.Now().Before(deadline) {
		response, err := http.Get(s.BaseURL + "/api/health")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("noadd did not answer %s/api/health within %v", s.BaseURL, startupTimeout)
}

// ensureBinary returns the server binary: E2E_BINARY, else bin/noadd, built
// first when it is not there. An existing binary is never rebuilt, so rebuild
// by hand after changing server code: the UI is embedded.
func ensureBinary() (string, error) {
	if pinned := os.Getenv(BinaryEnv); pinned != "" {
		if !isFile(pinned) {
			return "", fmt.Errorf("%s=%s is not a file", BinaryEnv, pinned)
		}
		return filepath.Abs(pinned)
	}
	binary := filepath.Join(RepoRoot(), "bin", "noadd")
	if isFile(binary) {
		return binary, nil
	}
	fmt.Fprintf(os.Stderr, "e2e: %s is missing, building it\n", binary)
	build := exec.Command("go", "build", "-mod=vendor", "-o", "bin/noadd", "./cmd/noadd")
	build.Dir = RepoRoot()
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("running go build: %w", err)
	}
	return binary, nil
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// RepoRoot is the repository root, three levels above e2e/internal/harness. It
// comes from this file's compile-time path, so the suite works from any
// working directory.
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

// recountLogs recomputes the maintained query_logs row count that a seed
// bypasses. An upsert: the row exists only once noadd has migrated.
const recountLogs = "INSERT INTO settings (key, value) SELECT 'query_log_count', COUNT(*) FROM query_logs WHERE true " +
	"ON CONFLICT(key) DO UPDATE SET value = excluded.value;\n"

// Seed runs SQL against the stopped database with the sqlite3 CLI: history
// that real DNS traffic would be slow to produce. The instance must be
// stopped, because fixtures rewrite settings noadd reads at boot.
func (s *Server) Seed(sql string) error {
	if s.cmd != nil {
		return fmt.Errorf("seed the database while the server is stopped: %s is still running", s.dbPath)
	}
	// Output is discarded: PRAGMA results would land in the test log.
	seeding := exec.Command("sqlite3", s.dbPath)
	seeding.Stdin = strings.NewReader(sql + "\n" + recountLogs)
	seeding.Stderr = os.Stderr
	if err := seeding.Run(); err != nil {
		return fmt.Errorf("running sqlite3 (install it, or the seeded specs cannot run): %w", err)
	}
	return nil
}
