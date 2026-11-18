package main

import (
	"bytes"
	"errors"
	"flag"
	"log/slog"
	"strings"
	"testing"
)

func parse(t *testing.T, env map[string]string, args ...string) (options, error) {
	t.Helper()
	return parseOptions(args, envOf(env), &bytes.Buffer{})
}

func mustParse(t *testing.T, env map[string]string, args ...string) options {
	t.Helper()
	opts, err := parse(t, env, args...)
	if err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return opts
}

func TestDefaults(t *testing.T) {
	opts := mustParse(t, nil)
	if opts.dbPath != nil || opts.dnsAddr != "0.0.0.0:53" || opts.httpAddr != "127.0.0.1:8080" ||
		opts.acmeCache != "acme-cache" || opts.hstsMaxAge != 31_536_000 || opts.logFormat != "full" ||
		opts.maxInflightQueries != 2048 || opts.rateLimitQPS != 100 || opts.rateLimitBurst != 200 ||
		opts.cookieSecure != nil || opts.hsts != nil || opts.logLevel != slog.LevelInfo {
		t.Fatalf("defaults = %+v", opts)
	}
}

func TestEveryFlagIsReadFromItsEnvironmentVariable(t *testing.T) {
	opts := mustParse(t, map[string]string{
		"NOADD_DB_PATH": "/data/n.db", "NOADD_DNS_ADDR": "0.0.0.0:5353", "NOADD_HTTP_ADDR": "0.0.0.0:8080",
		"NOADD_TLS_CERT": "c.pem", "NOADD_TLS_KEY": "k.pem", "NOADD_ACME_DOMAIN": "a.example, b.example",
		"NOADD_ACME_EMAIL": "ops@example.com", "NOADD_ACME_CACHE": "/cache", "NOADD_ACME_PROD": "true",
		"NOADD_COOKIE_SECURE": "false", "NOADD_HSTS": "true", "NOADD_HSTS_MAX_AGE": "60",
		"LOG_FORMAT": "json", "NOADD_LOG_LEVEL": "debug", "NOADD_MAX_INFLIGHT_QUERIES": "0",
		"NOADD_RATE_LIMIT_QPS": "7", "NOADD_RATE_LIMIT_BURST": "9", "NOADD_LOG_QUERY_RESULTS": "1",
		"NOADD_TRUSTED_PROXIES": "10.0.0.0/8", "NOADD_FORWARD_AUTH_HEADER": "Remote-User",
		"NOADD_FORWARD_AUTH_TRUSTED_PROXIES": "172.18.0.0/16", "NOADD_FORWARD_AUTH_LOGOUT_URL": "/logout",
	})
	if opts.dbPath == nil || *opts.dbPath != "/data/n.db" || opts.dnsAddr != "0.0.0.0:5353" ||
		opts.httpAddr != "0.0.0.0:8080" || opts.tlsCert != "c.pem" || opts.tlsKey != "k.pem" ||
		strings.Join(opts.acmeDomains, "|") != "a.example|b.example" || opts.acmeEmail != "ops@example.com" ||
		opts.acmeCache != "/cache" || !opts.acmeProd || opts.cookieSecure == nil || *opts.cookieSecure ||
		opts.hsts == nil || !*opts.hsts || opts.hstsMaxAge != 60 || opts.logFormat != "json" ||
		opts.logLevel != slog.LevelDebug || opts.maxInflightQueries != 0 || opts.rateLimitQPS != 7 ||
		opts.rateLimitBurst != 9 || !opts.logQueryResults || opts.trustedProxies != "10.0.0.0/8" ||
		opts.forwardAuthHeader != "Remote-User" || opts.forwardAuthProxies != "172.18.0.0/16" ||
		opts.forwardAuthLogoutURL != "/logout" {
		t.Fatalf("opts = %+v", opts)
	}
}

func TestAFlagBeatsTheEnvironment(t *testing.T) {
	opts := mustParse(t, map[string]string{"NOADD_DNS_ADDR": "1.1.1.1:53", "NOADD_HSTS": "false"},
		"--dns-addr", "127.0.0.1:5300", "--hsts")
	if opts.dnsAddr != "127.0.0.1:5300" || opts.hsts == nil || !*opts.hsts {
		t.Fatalf("opts = %+v", opts)
	}
}

func TestAnEmptyEnvironmentVariableIsUnset(t *testing.T) {
	opts := mustParse(t, map[string]string{"NOADD_DNS_ADDR": "", "NOADD_DB_PATH": "", "NOADD_LOG_LEVEL": ""})
	if opts.dnsAddr != defaultDNSAddr || opts.dbPath != nil {
		t.Fatalf("opts = %+v", opts)
	}
}

func TestOptionalValueBooleans(t *testing.T) {
	cases := map[string]*bool{"--hsts": ptrTo(true), "--hsts=true": ptrTo(true), "--hsts=false": ptrTo(false)}
	for arg, want := range cases {
		got := mustParse(t, nil, arg).hsts
		if got == nil || *got != *want {
			t.Errorf("%s = %v", arg, got)
		}
	}
	if got := mustParse(t, nil, "--cookie-secure").cookieSecure; got == nil || !*got {
		t.Errorf("--cookie-secure = %v", got)
	}
}

func ptrTo[T any](value T) *T { return &value }

// "--hsts false" was measured against the Rust image: rejected, exit 2.
func TestASeparatedBooleanValueIsAPositionalArgumentAndRefused(t *testing.T) {
	for _, args := range [][]string{{"--hsts", "false"}, {"--hsts", "maybe"}, {"stray"}} {
		_, err := parse(t, nil, args...)
		var usage usageError
		if !errors.As(err, &usage) || !strings.Contains(err.Error(), "unexpected argument") {
			t.Errorf("%v = %v", args, err)
		}
	}
}

func TestBadValuesAreUsageErrors(t *testing.T) {
	cases := [][]string{
		{"--hsts=maybe"}, {"--hsts-max-age", "-1"}, {"--rate-limit-qps", "x"},
		{"--max-inflight-queries", "-3"}, {"--log-format", "xml"}, {"--no-such-flag"},
	}
	for _, args := range cases {
		_, err := parse(t, nil, args...)
		var usage usageError
		if !errors.As(err, &usage) {
			t.Errorf("%v = %v", args, err)
		}
	}
	for _, env := range []map[string]string{
		{"NOADD_COOKIE_SECURE": "yes"}, {"LOG_FORMAT": "xml"}, {"NOADD_LOG_LEVEL": "bogus"}, {"NOADD_RATE_LIMIT_BURST": "1.5"},
	} {
		_, err := parse(t, env)
		var usage usageError
		if !errors.As(err, &usage) {
			t.Errorf("%v = %v", env, err)
		}
	}
}

func TestACMEDomainsAccumulateAcrossRepeatedFlags(t *testing.T) {
	opts := mustParse(t, nil, "--acme-domain", "a.example,b.example", "--acme-domain", "c.example")
	if strings.Join(opts.acmeDomains, "|") != "a.example|b.example|c.example" {
		t.Fatalf("domains = %v", opts.acmeDomains)
	}
}

func TestVersionFlag(t *testing.T) {
	if !mustParse(t, nil, "--version").showVersion {
		t.Fatal("--version not set")
	}
}

func TestHelpPrintsUsageToTheErrorWriter(t *testing.T) {
	var out bytes.Buffer
	_, err := parseOptions([]string{"-h"}, envOf(nil), &out)
	if !errors.Is(err, flag.ErrHelp) || !strings.Contains(out.String(), "-forward-auth-header") {
		t.Fatalf("err = %v, out = %q", err, out.String())
	}
}

func TestTLSEnabledNeedsBothHalvesOrADomain(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"--tls-cert", "c"}, false},
		{[]string{"--tls-cert", "c", "--tls-key", "k"}, true},
		{[]string{"--acme-domain", "a.example"}, true},
	}
	for _, c := range cases {
		opts := mustParse(t, nil, c.args...)
		if opts.tlsEnabled() != c.want {
			t.Errorf("%v: tlsEnabled = %v", c.args, opts.tlsEnabled())
		}
	}
}
