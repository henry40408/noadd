package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// serveOptions are options that bind loopback ports the kernel picks, with the
// database inside the test's directory.
func serveOptions(t *testing.T) options {
	t.Helper()
	opts := newOptions()
	dbPath := filepath.Join(t.TempDir(), "n.sqlite3")
	opts.dbPath = &dbPath
	opts.dnsAddr, opts.httpAddr = "127.0.0.1:0", "127.0.0.1:0"
	return opts
}

func serveFails(t *testing.T, opts options, wantFragment string) {
	t.Helper()
	err := serve(process{stdout: &syncBuffer{}, stderr: &syncBuffer{}}, opts)
	if err == nil || !strings.Contains(err.Error(), wantFragment) {
		t.Fatalf("got %v, want an error containing %q", err, wantFragment)
	}
}

func TestServeRejectsAnUnparsableDNSAddress(t *testing.T) {
	opts := serveOptions(t)
	opts.dnsAddr = "not-an-address"
	serveFails(t, opts, "invalid --dns-addr")
}

func TestServeRejectsBadTrustedProxies(t *testing.T) {
	opts := serveOptions(t)
	opts.trustedProxies = "not-a-cidr"
	serveFails(t, opts, "--trusted-proxies")
}

func TestServeRejectsBadForwardAuth(t *testing.T) {
	opts := serveOptions(t)
	opts.forwardAuthHeader = "X-User"
	opts.forwardAuthProxies = "not-a-cidr"
	serveFails(t, opts, "forward auth")
}

func TestServeFailsWhenTheDatabaseCannotBeOpened(t *testing.T) {
	opts := serveOptions(t)
	// A directory cannot be a database file.
	dir := t.TempDir()
	opts.dbPath = &dir
	serveFails(t, opts, "open database")
}

func TestServeFailsWhenTheTLSFilesAreMissing(t *testing.T) {
	opts := serveOptions(t)
	opts.tlsCert = filepath.Join(t.TempDir(), "missing.crt")
	opts.tlsKey = filepath.Join(t.TempDir(), "missing.key")
	serveFails(t, opts, "http server")
}

func TestDeriveACMEPublicURLSetsOnlyAnUnsetValue(t *testing.T) {
	ctx := context.Background()
	var out bytes.Buffer
	app := &appliance{opts: newOptions(), logger: testLogger(&out), database: openTestDB(t)}

	app.opts.acmeDomains = nil
	if err := app.deriveACMEPublicURL(ctx); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := app.database.GetSetting(ctx, "public_url"); found {
		t.Fatal("set without an ACME domain")
	}

	app.opts.acmeDomains = []string{"dns.example.com", "other.example.com"}
	if err := app.deriveACMEPublicURL(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := app.database.GetSetting(ctx, "public_url"); got != "https://dns.example.com" {
		t.Fatalf("got %q", got)
	}

	// An operator's value wins.
	if err := app.database.SetSetting(ctx, "public_url", "https://mine.example"); err != nil {
		t.Fatal(err)
	}
	if err := app.deriveACMEPublicURL(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := app.database.GetSetting(ctx, "public_url"); got != "https://mine.example" {
		t.Fatalf("overwritten: %q", got)
	}
}

func TestDeriveACMEPublicURLReportsADatabaseFailure(t *testing.T) {
	database := openTestDB(t)
	_ = database.Close(context.Background())
	app := &appliance{opts: newOptions(), logger: testLogger(&bytes.Buffer{}), database: database}
	app.opts.acmeDomains = []string{"dns.example.com"}
	if err := app.deriveACMEPublicURL(context.Background()); err == nil {
		t.Fatal("no error")
	}
}

func TestLoadForwarderIgnoresCorruptSettings(t *testing.T) {
	ctx := context.Background()
	var out bytes.Buffer
	app := &appliance{opts: newOptions(), logger: testLogger(&out), database: openTestDB(t), lifetime: ctx}
	for key, value := range map[string]string{"upstream_servers": "%%%", "upstream_strategy": "bogus", "dnssec_disabled": "true"} {
		if err := app.database.SetSetting(ctx, key, value); err != nil {
			t.Fatal(err)
		}
	}
	if forwarder := app.loadForwarder(ctx); forwarder == nil {
		t.Fatal("no forwarder")
	}
	if !strings.Contains(out.String(), "event=config.invalid_setting") {
		t.Fatalf("bad upstreams not reported:\n%s", out.String())
	}
}

func TestRunMapsFailuresToExitCodes(t *testing.T) {
	lookup := func(string) (string, bool) { return "", false }
	var stdout, stderr bytes.Buffer
	if code := run(process{args: []string{"--version"}, lookupEnv: lookup, stdout: &stdout, stderr: &stderr}); code != 0 || !strings.HasPrefix(stdout.String(), "noadd ") {
		t.Fatalf("version: code %d out %q", code, stdout.String())
	}
	if code := run(process{args: []string{"--nope"}, lookupEnv: lookup, stdout: &stdout, stderr: &stderr}); code != exitUsage {
		t.Fatalf("usage: code %d", code)
	}
	if code := reportFatal(&stderr, context.DeadlineExceeded); code != exitFailure {
		t.Fatalf("failure: code %d", code)
	}
}

func TestParseBoolishRejectsGarbage(t *testing.T) {
	for _, value := range []string{"YES", "off", "1", "F"} {
		if _, err := parseBoolish(value); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
	if _, err := parseBoolish("maybe"); err == nil {
		t.Fatal("accepted maybe")
	}
}
