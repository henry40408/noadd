package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"github.com/henry40408/noadd/internal/logging"
)

const (
	defaultDNSAddr        = "0.0.0.0:53"
	defaultHTTPAddr       = "127.0.0.1:8080"
	defaultACMECache      = "acme-cache"
	defaultHSTSMaxAge     = 31_536_000
	defaultLogFormat      = "full"
	defaultMaxInflight    = 2048
	defaultRateLimitQPS   = 100
	defaultRateLimitBurst = 200
)

// usageError marks a bad command line or environment value; main exits 2.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

// options holds the parsed configuration. A nil pointer means "not given",
// which matters where the absence has a meaning (a database path defaulting by
// what is on disk, TLS settings defaulting to whether noadd terminates TLS).
type options struct {
	dbPath       *string
	dnsAddr      string
	httpAddr     string
	tlsCert      string
	tlsKey       string
	acmeDomains  []string
	acmeEmail    string
	acmeCache    string
	acmeProd     bool
	cookieSecure *bool
	hsts         *bool
	hstsMaxAge   uint64
	logFormat    string
	logLevel     slog.Level

	maxInflightQueries   int
	rateLimitQPS         uint32
	rateLimitBurst       uint32
	logQueryResults      bool
	trustedProxies       string
	forwardAuthHeader    string
	forwardAuthProxies   string
	forwardAuthLogoutURL string
	showVersion          bool
}

// flagSpec describes one setting. Precedence is flag, then env, then default:
// the environment is applied first and a flag parsed afterwards overrides it.
type flagSpec struct {
	name    string
	env     string
	usage   string
	boolean bool
	set     func(value string) error
}

func newOptions() options {
	return options{
		dnsAddr:            defaultDNSAddr,
		httpAddr:           defaultHTTPAddr,
		acmeCache:          defaultACMECache,
		hstsMaxAge:         defaultHSTSMaxAge,
		logFormat:          defaultLogFormat,
		logLevel:           slog.LevelInfo,
		maxInflightQueries: defaultMaxInflight,
		rateLimitQPS:       defaultRateLimitQPS,
		rateLimitBurst:     defaultRateLimitBurst,
	}
}

func (o *options) specs() []flagSpec {
	return []flagSpec{
		{name: "db-path", env: "NOADD_DB_PATH", set: setStringPointer(&o.dbPath),
			usage: "SQLite database path (default noadd.sqlite3; an existing noadd.db is adopted when it is the only one)"},
		{name: "dns-addr", env: "NOADD_DNS_ADDR", set: setString(&o.dnsAddr),
			usage: "DNS listen address (default " + defaultDNSAddr + ")"},
		{name: "http-addr", env: "NOADD_HTTP_ADDR", set: setString(&o.httpAddr),
			usage: "HTTP listen address for DoH and the admin UI (default " + defaultHTTPAddr + ")"},
		{name: "tls-cert", env: "NOADD_TLS_CERT", set: setString(&o.tlsCert),
			usage: "TLS certificate file (manual TLS, needs --tls-key)"},
		{name: "tls-key", env: "NOADD_TLS_KEY", set: setString(&o.tlsKey),
			usage: "TLS private key file (manual TLS, needs --tls-cert)"},
		{name: "acme-domain", env: "NOADD_ACME_DOMAIN", set: o.addACMEDomains,
			usage: "domain for an automatic Let's Encrypt certificate; repeat or comma-separate"},
		{name: "acme-email", env: "NOADD_ACME_EMAIL", set: setString(&o.acmeEmail),
			usage: "contact email for Let's Encrypt"},
		{name: "acme-cache", env: "NOADD_ACME_CACHE", set: setString(&o.acmeCache),
			usage: "directory to cache ACME certificates (default " + defaultACMECache + ")"},
		{name: "acme-prod", env: "NOADD_ACME_PROD", boolean: true, set: setBool(&o.acmeProd),
			usage: "use Let's Encrypt production (default is staging)"},
		{name: "cookie-secure", env: "NOADD_COOKIE_SECURE", boolean: true, set: setBoolPointer(&o.cookieSecure),
			usage: "set Secure on the session cookie (default: on when noadd terminates TLS)"},
		{name: "hsts", env: "NOADD_HSTS", boolean: true, set: setBoolPointer(&o.hsts),
			usage: "send Strict-Transport-Security (default: on when noadd terminates TLS)"},
		{name: "hsts-max-age", env: "NOADD_HSTS_MAX_AGE", set: setUint64(&o.hstsMaxAge),
			usage: "max-age in seconds for Strict-Transport-Security (default 31536000)"},
		{name: "log-format", env: "LOG_FORMAT", set: o.setLogFormat,
			usage: "log format: full, compact, pretty or json (default " + defaultLogFormat + ")"},
		{name: "max-inflight-queries", env: "NOADD_MAX_INFLIGHT_QUERIES", set: setInt(&o.maxInflightQueries),
			usage: "maximum concurrent DNS queries, 0 for no limit (default 2048)"},
		{name: "rate-limit-qps", env: "NOADD_RATE_LIMIT_QPS", set: setUint32(&o.rateLimitQPS),
			usage: "per-client-IP queries per second, 0 for no limit (default 100)"},
		{name: "rate-limit-burst", env: "NOADD_RATE_LIMIT_BURST", set: setUint32(&o.rateLimitBurst),
			usage: "per-client-IP burst allowance (default 200)"},
		{name: "log-query-results", env: "NOADD_LOG_QUERY_RESULTS", boolean: true, set: setBool(&o.logQueryResults),
			usage: "record each query's result in the query log (costs an extra parse per query)"},
		{name: "trusted-proxies", env: "NOADD_TRUSTED_PROXIES", set: setString(&o.trustedProxies),
			usage: "comma-separated CIDRs of reverse proxies whose X-Forwarded-For is honoured"},
		{name: "forward-auth-header", env: "NOADD_FORWARD_AUTH_HEADER", set: setString(&o.forwardAuthHeader),
			usage: "request header carrying the username a reverse proxy authenticated"},
		{name: "forward-auth-trusted-proxies", env: "NOADD_FORWARD_AUTH_TRUSTED_PROXIES", set: setString(&o.forwardAuthProxies),
			usage: "comma-separated CIDRs of proxies whose forward-auth header is honoured"},
		{name: "forward-auth-logout-url", env: "NOADD_FORWARD_AUTH_LOGOUT_URL", set: setString(&o.forwardAuthLogoutURL),
			usage: "URL to redirect to on logout under forward auth"},
		{name: "version", boolean: true, set: setBool(&o.showVersion),
			usage: "print the version and exit"},
	}
}

// parseOptions reads the environment, then args. The caller prints the returned
// error; errw receives only the usage text.
func parseOptions(args []string, lookupEnv func(string) (string, bool), errw io.Writer) (options, error) {
	opts := newOptions()
	specs := opts.specs()
	if err := applyEnv(specs, lookupEnv); err != nil {
		return options{}, usageError{err}
	}
	level, err := logging.LevelFromEnv(lookupEnv)
	if err != nil {
		return options{}, usageError{err}
	}
	opts.logLevel = level
	flags := newFlagSet(specs)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// Only a request for help prints usage; a bad flag is reported once,
			// by the caller.
			flags.SetOutput(errw)
			flags.Usage()
		}
		return options{}, usageError{err}
	}
	// clap rejected positional arguments, so `--hsts false` is an error here
	// too rather than a quietly ignored word.
	if rest := flags.Args(); len(rest) > 0 {
		return options{}, usageError{fmt.Errorf("unexpected argument %q found", rest[0])}
	}
	return opts, nil
}

func newFlagSet(specs []flagSpec) *flag.FlagSet {
	flags := flag.NewFlagSet("noadd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	for _, spec := range specs {
		if spec.boolean {
			flags.BoolFunc(spec.name, spec.usage, spec.set)
			continue
		}
		flags.Func(spec.name, spec.usage, spec.set)
	}
	flags.Usage = func() {
		_, _ = fmt.Fprintln(flags.Output(), "Usage: noadd [flags]")
		flags.PrintDefaults()
	}
	return flags
}

// applyEnv treats an empty variable as unset: a container image may export one
// empty to mean "no value".
func applyEnv(specs []flagSpec, lookupEnv func(string) (string, bool)) error {
	for _, spec := range specs {
		value, ok := lookupEnv(spec.env)
		if spec.env == "" || !ok || value == "" {
			continue
		}
		if err := spec.set(value); err != nil {
			return fmt.Errorf("invalid value %q for %s: %w", value, spec.env, err)
		}
	}
	return nil
}

func setString(target *string) func(string) error {
	return func(value string) error {
		*target = value
		return nil
	}
}

func setStringPointer(target **string) func(string) error {
	return func(value string) error {
		*target = &value
		return nil
	}
}

// parseBoolish accepts what clap's boolean parser does for a plain switch.
func parseBoolish(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "true", "t", "yes", "y", "on", "1":
		return true, nil
	case "false", "f", "no", "n", "off", "0":
		return false, nil
	}
	return false, errors.New("must be true or false")
}

// parseStrictBool accepts only true and false, like clap's value parser for an
// optional-value flag.
func parseStrictBool(value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, errors.New("must be true or false")
}

func setBool(target *bool) func(string) error {
	return func(value string) error {
		parsed, err := parseBoolish(value)
		if err != nil {
			return err
		}
		*target = parsed
		return nil
	}
}

func setBoolPointer(target **bool) func(string) error {
	return func(value string) error {
		parsed, err := parseStrictBool(value)
		if err != nil {
			return err
		}
		*target = &parsed
		return nil
	}
}

func setUint64(target *uint64) func(string) error {
	return func(value string) error {
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return err
		}
		*target = parsed
		return nil
	}
}

func setUint32(target *uint32) func(string) error {
	return func(value string) error {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return err
		}
		*target = uint32(parsed)
		return nil
	}
}

func setInt(target *int) func(string) error {
	return func(value string) error {
		parsed, err := strconv.ParseUint(value, 10, 31)
		if err != nil {
			return err
		}
		*target = int(parsed)
		return nil
	}
}

// addACMEDomains appends, so repeating the flag and a comma list both work.
func (o *options) addACMEDomains(value string) error {
	for _, domain := range strings.Split(value, ",") {
		if domain = strings.TrimSpace(domain); domain != "" {
			o.acmeDomains = append(o.acmeDomains, domain)
		}
	}
	return nil
}

func (o *options) setLogFormat(value string) error {
	switch value {
	case "full", "compact", "pretty", "json":
		o.logFormat = value
		return nil
	}
	return errors.New("want full, compact, pretty or json")
}

// tlsFiles reports whether manual TLS is configured: both halves are needed.
func (o *options) tlsFiles() bool { return o.tlsCert != "" && o.tlsKey != "" }

// tlsEnabled is whether noadd terminates TLS itself, by either route.
func (o *options) tlsEnabled() bool { return o.tlsFiles() || len(o.acmeDomains) > 0 }
