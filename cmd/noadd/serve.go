package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/henry40408/noadd/internal/auth"
	"github.com/henry40408/noadd/internal/cache"
	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/dns"
	"github.com/henry40408/noadd/internal/dnsserver"
	"github.com/henry40408/noadd/internal/events"
	"github.com/henry40408/noadd/internal/filter"
	"github.com/henry40408/noadd/internal/logging"
	"github.com/henry40408/noadd/internal/netx"
	"github.com/henry40408/noadd/internal/querylog"
	"github.com/henry40408/noadd/internal/registry"
	"github.com/henry40408/noadd/internal/server"
	"github.com/henry40408/noadd/internal/tlsserve"
	"github.com/henry40408/noadd/internal/upstream"
	"github.com/henry40408/noadd/internal/version"
)

const (
	// dnsCacheCapacityBytes is about 10,000 entries at the ~499 bytes an entry
	// measures on ordinary traffic.
	dnsCacheCapacityBytes = 5 * 1024 * 1024
	registryCacheTTL      = time.Hour
	queryLogThreshold     = 500
	queryLogInterval      = time.Second
	loggerFlushTimeout    = 5 * time.Second
	rebuildSettleTimeout  = 5 * time.Second
	eventsBuffer          = 8
	loginAttempts         = 5
	loginWindow           = 60 * time.Second
)

// appliance is the running server: the stores and DNS pipeline every listener
// and background job shares.
type appliance struct {
	opts       options
	logger     *slog.Logger
	database   *db.DB
	holder     *filter.Holder
	lists      *filter.Manager
	rebuild    *filter.Coordinator
	forwarder  *upstream.Forwarder
	queryLog   *querylog.Logger
	dnsLimiter *dnsserver.Limiter
	handler    *dnsserver.Handler
	// responseCache is shared by the handler and the admin API, which clears it.
	responseCache *cache.Cache
	hub           *events.Hub
	// lifetime outlives the listeners: the forwarder and logger drain on it.
	lifetime       context.Context
	cancelLifetime context.CancelFunc
}

// serve runs the appliance until a signal or a fatal listener failure, then
// shuts down in the order of the Rust server.
func serve(p process, opts options) (err error) {
	logger := logging.New(p.stdout, opts.logFormat, opts.logLevel)
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	runCtx, endRun := context.WithCancel(signalCtx)
	defer endRun()

	app, err := openAppliance(runCtx, opts, logger)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, app.close()) }()

	return app.run(runCtx, endRun, p)
}

// openAppliance opens the database and builds everything that has no listener.
func openAppliance(ctx context.Context, opts options, logger *slog.Logger) (*appliance, error) {
	database, err := db.Open(ctx, resolveDBPath(opts.dbPath, logger))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	app := &appliance{opts: opts, logger: logger, database: database, lifetime: lifetime, cancelLifetime: cancelLifetime}
	if err := app.build(ctx); err != nil {
		app.cancelLifetime()
		_ = database.Close(context.Background())
		return nil, err
	}
	return app, nil
}

func (a *appliance) build(ctx context.Context) error {
	if err := a.deriveACMEPublicURL(ctx); err != nil {
		return err
	}
	if err := a.buildFilter(ctx); err != nil {
		return err
	}
	a.forwarder = a.loadForwarder(ctx)
	a.hub = events.New(eventsBuffer)
	a.queryLog = querylog.New(querylog.Config{
		Sink: a.database, FlushThreshold: queryLogThreshold, FlushInterval: queryLogInterval, Logger: a.logger,
	})
	a.responseCache = cache.New(cache.Config{CapacityBytes: dnsCacheCapacityBytes, StaleWindow: cache.DefaultStaleWindow})
	go a.queryLog.Run(a.lifetime)
	a.dnsLimiter = dnsserver.NewLimiter(a.opts.rateLimitQPS, a.opts.rateLimitBurst)
	a.handler = dnsserver.New(dnsserver.Config{
		Filter:          a.holder,
		Cache:           a.responseCache,
		Forwarder:       a.forwarder,
		Logger:          a.queryLog,
		Limiter:         a.dnsLimiter,
		MaxInflight:     a.opts.maxInflightQueries,
		LogQueryResults: a.opts.logQueryResults,
		Block:           a.loadBlockConfig(ctx),
		Slog:            a.logger,
	})
	a.logger.Info("DNS handler limits configured", "event", "dns.limits_configured",
		"max_inflight", a.opts.maxInflightQueries, "rate_limit_qps", a.opts.rateLimitQPS, "rate_limit_burst", a.opts.rateLimitBurst)
	return nil
}

// deriveACMEPublicURL sets public_url from the first ACME domain when the
// operator has not.
func (a *appliance) deriveACMEPublicURL(ctx context.Context) error {
	if len(a.opts.acmeDomains) == 0 {
		return nil
	}
	_, found, err := a.database.GetSetting(ctx, "public_url")
	if err != nil || found {
		return err
	}
	url := "https://" + a.opts.acmeDomains[0]
	if err := a.database.SetSetting(ctx, "public_url", url); err != nil {
		return err
	}
	a.logger.Info("auto-set public_url from ACME domain", "event", "config.public_url_derived", "url", url)
	return nil
}

// buildFilter seeds the default lists on a fresh database and builds the
// engine synchronously, so the first query is already filtered.
func (a *appliance) buildFilter(ctx context.Context) error {
	a.holder = filter.NewHolder(filter.NewFromNamed(nil, nil))
	a.lists = &filter.Manager{DB: a.database, Holder: a.holder, Downloader: filter.NewDownloader(version.UserAgent())}
	a.rebuild = filter.NewCoordinator()
	if err := a.lists.SeedDefaultLists(ctx); err != nil {
		return fmt.Errorf("seed default lists: %w", err)
	}
	if err := a.lists.Rebuild(ctx); err != nil {
		return fmt.Errorf("build filter: %w", err)
	}
	return nil
}

// setting reads one stored setting; unreadable counts as unset, because a
// corrupt value must never block boot.
func (a *appliance) setting(ctx context.Context, key string) (string, bool) {
	value, found, err := a.database.GetSetting(ctx, key)
	return value, err == nil && found
}

func (a *appliance) loadForwarder(ctx context.Context) *upstream.Forwarder {
	var servers []string
	if raw, ok := a.setting(ctx, "upstream_servers"); ok && raw != "" {
		parsed, err := upstream.ParseUpstreams(raw)
		if err != nil {
			a.logger.Warn("invalid setting; using defaults", "event", "config.invalid_setting", "setting", "upstream_servers", "error", err)
		} else {
			servers = parsed
		}
	}
	forwarder := upstream.New(a.lifetime, upstream.Config{Servers: servers, Logger: a.logger})
	if raw, ok := a.setting(ctx, "upstream_strategy"); ok {
		if strategy, err := upstream.ParseStrategy(raw); err == nil {
			forwarder.SetStrategy(strategy)
			a.logSettingLoaded("upstream_strategy", raw)
		}
	}
	if raw, ok := a.setting(ctx, "dnssec_disabled"); ok {
		forwarder.SetDNSSECEnabled(strings.TrimSpace(raw) != "true")
		a.logSettingLoaded("dnssec_disabled", raw)
	}
	return forwarder
}

func (a *appliance) loadBlockConfig(ctx context.Context) dns.BlockConfig {
	mode, _ := a.setting(ctx, "block_mode")
	v4, _ := a.setting(ctx, "block_custom_ipv4")
	v6, _ := a.setting(ctx, "block_custom_ipv6")
	config := dns.BlockConfigFromSettings(mode, v4, v6)
	a.logSettingLoaded("block_mode", string(config.Mode))
	return config
}

func (a *appliance) logSettingLoaded(setting, value string) {
	a.logger.Info("loaded setting from database", "event", "config.setting_loaded", "setting", setting, "value", value)
}

// run starts the listeners and jobs, serves until runCtx ends, and stops them
// in the shutdown order: HTTP drain, DNS listeners and jobs, handler, logger.
func (a *appliance) run(runCtx context.Context, endRun context.CancelFunc, p process) error {
	failures := &listenerFailures{end: endRun}
	dnsListeners, err := a.bindDNS()
	if err != nil {
		return err
	}
	httpListener, err := a.listenHTTP()
	if err != nil {
		dnsListeners.close()
		return err
	}
	srv, err := a.buildHTTPServer(p)
	if err != nil {
		dnsListeners.close()
		_ = httpListener.Close()
		return err
	}

	dnsCtx, stopDNS := context.WithCancel(context.Background())
	var dnsDone sync.WaitGroup
	a.startDNS(dnsCtx, &dnsDone, dnsListeners, failures)
	jobCtx, stopJobs := context.WithCancel(context.Background())
	var jobsDone sync.WaitGroup
	a.startJobs(jobCtx, &jobsDone, srv.deps)

	serveErr := make(chan error, 1)
	go func() { serveErr <- a.serveHTTP(srv.http, httpListener) }()

	var httpErr error
	select {
	case <-runCtx.Done():
	case httpErr = <-serveErr:
		endRun()
	}
	a.logger.Info("shutting down", "event", "shutdown.started")
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), httpDrainTimeout)
	defer cancelDrain()
	if err := srv.http.Shutdown(drainCtx); err != nil {
		_ = srv.http.Close()
	}
	stopDNS()
	dnsDone.Wait()
	stopJobs()
	jobsDone.Wait()

	if failures.failed.Load() {
		return errors.New("DNS listener failed; exiting with non-zero status")
	}
	if httpErr != nil && !errors.Is(httpErr, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", httpErr)
	}
	return nil
}

// close flushes the logger and closes the database, which removes -wal/-shm.
func (a *appliance) close() error {
	a.handler.Close()
	_ = a.queryLog.Close(loggerFlushTimeout)
	a.cancelLifetime()
	a.waitForRebuild(rebuildSettleTimeout)
	err := a.database.Close(context.Background())
	a.logger.Info("goodbye", "event", "shutdown.complete")
	return err
}

// waitForRebuild gives a running filter rebuild time to end, so it does not
// read a closed database.
func (a *appliance) waitForRebuild(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for a.rebuild.Status().Rebuilding && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
}

// dnsSockets are the bound DNS listeners. They are bound before anything
// serves, so a busy port fails startup instead of a background goroutine.
type dnsSockets struct {
	udp *net.UDPConn
	tcp net.Listener
}

func (s dnsSockets) close() {
	_ = s.udp.Close()
	_ = s.tcp.Close()
}

func (a *appliance) bindDNS() (dnsSockets, error) {
	addr, err := netip.ParseAddrPort(a.opts.dnsAddr)
	if err != nil {
		return dnsSockets{}, fmt.Errorf("invalid --dns-addr %q: %w", a.opts.dnsAddr, err)
	}
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return dnsSockets{}, fmt.Errorf("bind UDP %s: %w", addr, err)
	}
	tcp, err := net.Listen("tcp", addr.String())
	if err != nil {
		_ = udp.Close()
		return dnsSockets{}, fmt.Errorf("bind TCP %s: %w", addr, err)
	}
	return dnsSockets{udp: udp, tcp: tcp}, nil
}

func (a *appliance) startDNS(ctx context.Context, done *sync.WaitGroup, sockets dnsSockets, failures *listenerFailures) {
	report := func(transport string) func(error) {
		return func(err error) {
			a.logger.Error("DNS listener failed", "event", "dns.listener_failed", "transport", transport, "error", err)
		}
	}
	done.Add(2)
	go func() {
		defer done.Done()
		failures.supervise(ctx, func(ctx context.Context) error { return a.handler.ServeUDP(ctx, sockets.udp) }, report("udp"))
	}()
	go func() {
		defer done.Done()
		failures.supervise(ctx, func(ctx context.Context) error { return a.handler.ServeTCP(ctx, sockets.tcp) }, report("tcp"))
	}()
}

func (a *appliance) listenHTTP() (net.Listener, error) {
	listener, err := net.Listen("tcp", a.opts.httpAddr)
	if err != nil {
		return nil, fmt.Errorf("bind HTTP %s: %w", a.opts.httpAddr, err)
	}
	return listener, nil
}

// httpServer is the configured server and the deps its handler was built from.
type httpServer struct {
	http *http.Server
	deps server.APIDeps
}

func (a *appliance) buildHTTPServer(p process) (httpServer, error) {
	trusted, err := netx.ParseTrustedProxies(a.opts.trustedProxies)
	if err != nil {
		return httpServer{}, fmt.Errorf("failed to parse --trusted-proxies / NOADD_TRUSTED_PROXIES: %w", err)
	}
	if !trusted.IsEmpty() {
		a.logger.Info("trusted proxy CIDRs configured — X-Forwarded-For / X-Real-IP will be honoured for matching peers",
			"event", "config.trusted_proxies_configured", "count", trusted.Len())
	}
	forwardAuth, err := a.newForwardAuth()
	if err != nil {
		return httpServer{}, err
	}
	deps, err := a.apiDeps(p, trusted, forwardAuth)
	if err != nil {
		return httpServer{}, err
	}
	stop := make(chan struct{})
	deps.StopStreams = stop
	handler, err := server.New(server.Deps{
		DoH:               dnsserver.NewDoH(dnsserver.DoHConfig{Handler: a.handler, Store: a.database, Trusted: trusted, Slog: a.logger}),
		HSTS:              a.hstsEnabled(),
		HSTSMaxAgeSeconds: a.opts.hstsMaxAge,
		Slog:              a.logger,
		API:               &deps,
	})
	if err != nil {
		return httpServer{}, err
	}
	srv := server.NewHTTPServer(a.opts.httpAddr, handler)
	closeOnShutdown(srv, stop)
	return httpServer{http: srv, deps: deps}, nil
}

func (a *appliance) newForwardAuth() (*auth.ForwardAuth, error) {
	forwardAuth, err := auth.NewForwardAuth(a.opts.forwardAuthHeader, a.opts.forwardAuthProxies, a.opts.forwardAuthLogoutURL)
	if err != nil {
		return nil, fmt.Errorf("failed to configure forward auth: %w", err)
	}
	if forwardAuth != nil {
		a.logger.Info("forward auth enabled — the header is honoured only for peers matching --forward-auth-trusted-proxies",
			"event", "config.forward_auth_enabled", "header", forwardAuth.Header(), "cidrs", forwardAuth.TrustedLen())
	}
	return forwardAuth, nil
}

// cookieSecure and hstsEnabled follow whether noadd terminates TLS unless
// overridden. Neither is forced on: a browser drops a Secure cookie received
// over plain HTTP, and HSTS pins a browser to HTTPS, so on an HTTP-only
// deployment either one is a self-inflicted lockout.
func (a *appliance) cookieSecure() bool {
	return resolveTLSDefault(a.opts.cookieSecure, a.opts.tlsEnabled())
}

func (a *appliance) hstsEnabled() bool {
	enabled := resolveTLSDefault(a.opts.hsts, a.opts.tlsEnabled())
	if enabled {
		a.logger.Info("HSTS enabled", "event", "server.hsts_enabled", "max_age", a.opts.hstsMaxAge)
	}
	return enabled
}

func resolveTLSDefault(override *bool, tlsEnabled bool) bool {
	if override != nil {
		return *override
	}
	return tlsEnabled
}

func (a *appliance) apiDeps(p process, trusted netx.TrustedProxies, forwardAuth *auth.ForwardAuth) (server.APIDeps, error) {
	// Before anything can log a session event: one logged earlier would carry a
	// sid_hash under a temporary salt, breaking correlation.
	salt, err := auth.LoadOrCreateSessionLogSalt(a.lifetime, a.database)
	if err != nil {
		return server.APIDeps{}, fmt.Errorf("session log salt: %w", err)
	}
	sessions := auth.NewManager(auth.ManagerConfig{DB: a.database, Salt: salt, Logger: a.logger})
	if err := sessions.Load(a.lifetime); err != nil {
		return server.APIDeps{}, fmt.Errorf("load sessions: %w", err)
	}
	setupToken, err := a.announceSetupToken(p, forwardAuth != nil)
	if err != nil {
		return server.APIDeps{}, err
	}
	return server.APIDeps{
		DB:                    a.database,
		Sessions:              sessions,
		Work:                  auth.NewPasswordWork(0),
		LoginLimiter:          auth.NewLimiter(loginAttempts, loginWindow, nil),
		InvalidSessionLimiter: server.NewInvalidSessionLimiter(),
		Lockout:               auth.NewLockout(nil),
		SetupToken:            setupToken,
		ForwardAuth:           forwardAuth,
		Trusted:               trusted,
		CookieSecure:          a.cookieSecure(),
		ServerInfo:            server.ServerInfo{DNSAddr: a.opts.dnsAddr, HTTPAddr: a.opts.httpAddr, TLSEnabled: a.opts.tlsEnabled()},
		Version:               version.Version(),
		Filter:                a.holder,
		ListManager:           a.lists,
		Rebuild:               a.rebuild,
		Registry:              registry.NewClient(registry.DefaultURL, registryCacheTTL, version.UserAgent()),
		Forwarder:             a.forwarder,
		Cache:                 a.responseCache,
		Handler:               a.handler,
		Events:                a.hub,
		LogEvents:             a.queryLog,
	}, nil
}

// announceSetupToken mints the first-run token while no operator exists (and
// forward auth does not provision one) and prints it to stderr. Never to the
// logger: log lines get filtered, shipped and retained, and the token is a
// credential until setup completes.
func (a *appliance) announceSetupToken(p process, forwardAuth bool) (*auth.SetupToken, error) {
	if forwardAuth {
		return auth.NoSetupToken(nil), nil
	}
	operators, err := a.database.CountUsers(a.lifetime)
	if err != nil {
		return nil, fmt.Errorf("count operators: %w", err)
	}
	if operators > 0 {
		return auth.NoSetupToken(nil), nil
	}
	token := auth.GenerateSetupToken(nil)
	if shown, ok := token.Display(); ok {
		_, _ = fmt.Fprintf(p.stderr, "noadd: first-run setup token: %s\n", shown)
		a.logger.Info("first-run setup token issued; see stderr", "event", "setup.token_issued")
	}
	return token, nil
}

// serveHTTP serves DoH and the admin UI on one listener, deliberately (no
// admin-only address): a second listener would need its own TLS identity and
// per-listener cookie and HSTS settings, which risk locking the operator out.
// A reverse-proxy path rule separates them instead.
func (a *appliance) serveHTTP(srv *http.Server, listener net.Listener) error {
	switch {
	case len(a.opts.acmeDomains) > 0:
		manager, err := tlsserve.ACME(tlsserve.ACMEConfig{
			Domains: a.opts.acmeDomains, Email: a.opts.acmeEmail, Cache: a.opts.acmeCache, Prod: a.opts.acmeProd,
		})
		if err != nil {
			return err
		}
		srv.TLSConfig = manager.TLSConfig()
		a.logServerStarted("https", "acme")
		return srv.ServeTLS(listener, "", "")
	case a.opts.tlsFiles():
		config, err := tlsserve.Static(a.opts.tlsCert, a.opts.tlsKey)
		if err != nil {
			return err
		}
		srv.TLSConfig = config
		a.logServerStarted("https", "static_cert")
		return srv.ServeTLS(listener, "", "")
	}
	a.logServerStarted("http", "none")
	return srv.Serve(listener)
}

func (a *appliance) logServerStarted(scheme, tls string) {
	a.logger.Info("HTTP server started (DoH + Admin)", "event", "server.started",
		"scheme", scheme, "tls", tls, "http_addr", a.opts.httpAddr)
}

// startJobs launches the six background jobs. They stop when ctx ends.
func (a *appliance) startJobs(ctx context.Context, done *sync.WaitGroup, deps server.APIDeps) {
	targets := pruneTargets{
		dns: a.dnsLimiter, login: deps.LoginLimiter, invalidSession: deps.InvalidSessionLimiter, setupToken: deps.SetupToken,
	}
	jobs := []func(){
		func() { deps.Sessions.Run(ctx) },
		func() {
			a.hub.Run(ctx, events.Config{Interval: events.TickInterval, Source: dashboardSource(a.database), Logger: a.logger})
		},
		func() { pruneLogs(ctx, logPruneInterval, a.database, a.logger) },
		func() { updateLists(ctx, listUpdateEvery, a.lists, a.rebuild, a.logger) },
		func() { pruneRateLimits(ctx, rateLimitInterval, targets, a.logger) },
		func() { probeUpstreams(ctx, probeInterval, a.forwarder, a.logger) },
	}
	done.Add(len(jobs))
	for _, job := range jobs {
		go func() {
			defer done.Done()
			job()
		}()
	}
}
