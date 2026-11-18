package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// waitFor bounds a wedged binary rather than pacing the tests; generous so a
// loaded machine never reaches it.
const waitFor = 30 * time.Second

var noaddBinary string

// coverDir is where a -cover binary writes its profile; empty builds it plain.
var coverDir = os.Getenv("NOADD_COVERDIR")

func TestMain(m *testing.M) {
	os.Exit(buildAndRun(m))
}

// buildAndRun builds the binary once, so the process tests drive the real thing.
func buildAndRun(m *testing.M) int {
	dir, err := os.MkdirTemp("", "noadd-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	noaddBinary = filepath.Join(dir, "noadd")
	buildArgs := []string{"build", "-mod=vendor"}
	if coverDir != "" {
		if err := os.MkdirAll(coverDir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		buildArgs = append(buildArgs, "-cover", "-coverpkg=github.com/henry40408/noadd/...")
	}
	build := exec.Command("go", append(buildArgs, "-o", noaddBinary, ".")...)
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "go build failed: %v\n%s", err, out)
		return 1
	}
	return m.Run()
}

// syncBuffer is a bytes.Buffer a running process and a test can share.
type syncBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}

// freePort returns a port nothing listens on, for both TCP and UDP.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// instance is one running noadd.
type instance struct {
	cmd      *exec.Cmd
	stdout   *syncBuffer
	stderr   *syncBuffer
	done     chan struct{}
	exitCode int
	dir      string
	httpPort int
	dnsPort  int
}

// baseEnv is a minimal environment, with HOME inside the test's directory so
// nothing touches the real one.
func baseEnv(dir string) []string {
	env := []string{"HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "GIT_CONFIG_GLOBAL=" + filepath.Join(dir, "gitconfig")}
	if coverDir != "" {
		env = append(env, "GOCOVERDIR="+coverDir)
	}
	return env
}

// start launches noadd in dir with extra env and args, after the standard
// address flags (unless the caller supplies its own through env or args).
func start(t *testing.T, dir string, env []string, args ...string) *instance {
	t.Helper()
	inst := &instance{dir: dir, httpPort: freePort(t), dnsPort: freePort(t), stdout: &syncBuffer{}, stderr: &syncBuffer{}, done: make(chan struct{})}
	full := append([]string{
		"--http-addr", fmt.Sprintf("127.0.0.1:%d", inst.httpPort),
		"--dns-addr", fmt.Sprintf("127.0.0.1:%d", inst.dnsPort),
	}, args...)
	inst.cmd = exec.Command(noaddBinary, full...)
	inst.cmd.Dir = dir
	inst.cmd.Env = append(baseEnv(dir), env...)
	inst.cmd.Stdout, inst.cmd.Stderr = inst.stdout, inst.stderr
	if err := inst.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = inst.cmd.Wait()
		inst.exitCode = inst.cmd.ProcessState.ExitCode()
		close(inst.done)
	}()
	t.Cleanup(func() {
		select {
		case <-inst.done:
		default:
			_ = inst.cmd.Process.Kill()
			<-inst.done
		}
	})
	return inst
}

// run executes noadd to completion.
func run1(t *testing.T, env []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), waitFor)
	defer cancel()
	cmd := exec.CommandContext(ctx, noaddBinary, args...)
	cmd.Dir = dir
	cmd.Env = append(baseEnv(dir), env...)
	var out, errw bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errw
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("noadd did not exit: %s", errw.String())
	}
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return out.String(), errw.String(), exit.ExitCode()
		}
		t.Fatal(err)
	}
	return out.String(), errw.String(), 0
}

// healthy waits until /api/health answers.
func (i *instance) healthy(t *testing.T) {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/api/health", i.httpPort)
	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		select {
		case <-i.done:
			t.Fatalf("noadd exited early (%d): %s%s", i.exitCode, i.stdout.String(), i.stderr.String())
		default:
		}
		if resp, err := http.Get(url); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("noadd never became healthy: %s%s", i.stdout.String(), i.stderr.String())
}

func (i *instance) terminate(t *testing.T) {
	t.Helper()
	if err := i.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-i.done:
	case <-time.After(waitFor):
		t.Fatalf("noadd ignored SIGTERM: %s", i.stdout.String())
	}
}

func TestVersionFlagPrintsTheVersion(t *testing.T) {
	out, _, code := run1(t, nil, "--version")
	if code != 0 || !strings.HasPrefix(out, "noadd ") {
		t.Fatalf("code %d out %q", code, out)
	}
}

func TestHelpExitsZeroAndPrintsUsage(t *testing.T) {
	_, errOut, code := run1(t, nil, "-h")
	if code != 0 || !strings.Contains(errOut, "Usage: noadd") {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
}

func TestAUsageErrorExitsTwo(t *testing.T) {
	_, errOut, code := run1(t, nil, "--hsts", "false")
	if code != exitUsage || !strings.Contains(errOut, "Error: unexpected argument") {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
}

func TestARetiredEnvVarStopsStartupEvenWhenEmpty(t *testing.T) {
	_, errOut, code := run1(t, []string{"RUST_LOG="})
	if code != exitFailure || !strings.Contains(errOut, "  RUST_LOG -> NOADD_LOG_LEVEL") {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
}

func TestABogusLogLevelFailsStartup(t *testing.T) {
	_, errOut, code := run1(t, []string{"NOADD_LOG_LEVEL=bogus"})
	if code != exitUsage || !strings.Contains(errOut, "NOADD_LOG_LEVEL") {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
}

func TestStartsServesAndSIGTERMRemovesTheWAL(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "n.sqlite3")
	inst := start(t, dir, nil, "--db-path", dbPath)
	inst.healthy(t)
	if _, err := os.Stat(dbPath + "-wal"); err != nil {
		t.Fatalf("a running database has no WAL: %v", err)
	}
	inst.terminate(t)
	if inst.exitCode != 0 {
		t.Fatalf("exit %d: %s%s", inst.exitCode, inst.stdout.String(), inst.stderr.String())
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(dbPath + suffix); !os.IsNotExist(err) {
			t.Errorf("%s survived shutdown: %v", suffix, err)
		}
	}
	if !strings.Contains(inst.stdout.String(), "event=shutdown.complete") {
		t.Errorf("no shutdown.complete in %q", inst.stdout.String())
	}
}

func TestTheSetupTokenGoesToStderrNeverToTheLog(t *testing.T) {
	dir := t.TempDir()
	inst := start(t, dir, nil, "--db-path", filepath.Join(dir, "n.sqlite3"))
	inst.healthy(t)
	const prefix = "noadd: first-run setup token: "
	_, token, found := strings.Cut(inst.stderr.String(), prefix)
	token = strings.TrimSpace(token)
	if !found || token == "" {
		t.Fatalf("stderr = %q", inst.stderr.String())
	}
	if strings.Contains(inst.stdout.String(), token) {
		t.Fatal("the setup token reached the log")
	}
}

func TestNOADDLogLevelDebugLogsDebugLines(t *testing.T) {
	dir := t.TempDir()
	// A datagram that is no DNS message makes the handler log at debug level.
	garbage := func(inst *instance) {
		conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", inst.dnsPort))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("not a dns message"))
		time.Sleep(300 * time.Millisecond)
	}
	quiet := start(t, dir, nil, "--db-path", filepath.Join(dir, "a.sqlite3"))
	quiet.healthy(t)
	garbage(quiet)
	quiet.terminate(t)
	loud := start(t, dir, []string{"NOADD_LOG_LEVEL=debug"}, "--db-path", filepath.Join(dir, "b.sqlite3"))
	loud.healthy(t)
	garbage(loud)
	loud.terminate(t)
	if strings.Contains(quiet.stdout.String(), "level=DEBUG") {
		t.Error("the default level logged debug lines")
	}
	if !strings.Contains(loud.stdout.String(), "level=DEBUG") {
		t.Errorf("no debug line at NOADD_LOG_LEVEL=debug: %q", loud.stdout.String())
	}
}

func TestJSONLogFormat(t *testing.T) {
	dir := t.TempDir()
	inst := start(t, dir, []string{"LOG_FORMAT=json"}, "--db-path", filepath.Join(dir, "n.sqlite3"))
	inst.healthy(t)
	inst.terminate(t)
	if first, _, _ := strings.Cut(inst.stdout.String(), "\n"); !strings.HasPrefix(first, `{"time"`) {
		t.Fatalf("first line = %q", first)
	}
}

func TestAnExistingLegacyDatabaseIsAdoptedWithAWarning(t *testing.T) {
	dir := t.TempDir()
	// A database created by a first run under the legacy name.
	seed := start(t, dir, nil, "--db-path", filepath.Join(dir, legacyDBPath))
	seed.healthy(t)
	seed.terminate(t)

	inst := start(t, dir, nil)
	inst.healthy(t)
	inst.terminate(t)
	if !strings.Contains(inst.stdout.String(), "opening legacy database `noadd.db`") {
		t.Errorf("no legacy warning in %q", inst.stdout.String())
	}
	if _, err := os.Stat(filepath.Join(dir, defaultDBPath)); !os.IsNotExist(err) {
		t.Errorf("a new database was created beside the legacy one: %v", err)
	}
}

func TestABusyDNSPortFailsStartupWithExitOne(t *testing.T) {
	dir := t.TempDir()
	taken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	addr := taken.LocalAddr().String()
	_, errOut, code := run1(t, nil, "--db-path", filepath.Join(dir, "n.sqlite3"), "--dns-addr", addr,
		"--http-addr", fmt.Sprintf("127.0.0.1:%d", freePort(t)))
	if code != exitFailure || !strings.Contains(errOut, "bind UDP") {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
}

func TestABusyHTTPPortFailsStartupWithExitOne(t *testing.T) {
	dir := t.TempDir()
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	_, errOut, code := run1(t, nil, "--db-path", filepath.Join(dir, "n.sqlite3"), "--http-addr", taken.Addr().String(),
		"--dns-addr", fmt.Sprintf("127.0.0.1:%d", freePort(t)))
	if code != exitFailure || !strings.Contains(errOut, "bind HTTP") {
		t.Fatalf("code %d stderr %q", code, errOut)
	}
}
