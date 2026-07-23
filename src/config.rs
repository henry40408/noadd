use clap::{Parser, ValueEnum};
use std::path::{Path, PathBuf};
use tracing_subscriber::{
    EnvFilter, Layer, fmt::format::FmtSpan, layer::SubscriberExt, registry::LookupSpan,
    util::SubscriberInitExt,
};

/// Log output format.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum LogFormat {
    #[default]
    Full,
    Compact,
    Pretty,
    Json,
}

#[derive(Parser, Debug)]
#[command(name = "noadd", about = "DNS ad-blocker with DoH support")]
pub struct CliArgs {
    /// SQLite database path [default: noadd.sqlite3]. When unset, the path
    /// cascades: noadd.sqlite3 is used, but if that file is absent while a
    /// legacy noadd.db from an older release exists, the legacy file is opened
    /// so in-place upgrades keep their data (rename it to noadd.sqlite3 to
    /// silence the warning).
    #[allow(clippy::doc_markdown)]
    #[arg(long, env = "NOADD_DB_PATH")]
    pub db_path: Option<PathBuf>,

    #[arg(long, default_value = "0.0.0.0:53", env = "NOADD_DNS_ADDR")]
    pub dns_addr: String,

    // Defaults to loopback so a bare-metal run does not expose the admin UI on
    // all interfaces without opting in. The DNS listener above still defaults to
    // 0.0.0.0 (it must serve the LAN); the container image sets
    // NOADD_HTTP_ADDR=0.0.0.0:8080 so the dashboard is reachable there.
    #[arg(long, default_value = "127.0.0.1:8080", env = "NOADD_HTTP_ADDR")]
    pub http_addr: String,

    /// TLS certificate file (manual TLS, mutually exclusive with --acme-domain)
    #[arg(long, env = "NOADD_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file (manual TLS, mutually exclusive with --acme-domain)
    #[arg(long, env = "NOADD_TLS_KEY")]
    pub tls_key: Option<PathBuf>,

    /// Domain(s) for automatic Let's Encrypt certificate (can be specified multiple times)
    #[arg(long, env = "NOADD_ACME_DOMAIN", value_delimiter = ',')]
    pub acme_domain: Vec<String>,

    /// Contact email for Let's Encrypt
    #[arg(long, env = "NOADD_ACME_EMAIL")]
    pub acme_email: Option<String>,

    /// Directory to cache ACME certificates
    #[arg(long, default_value = "acme-cache", env = "NOADD_ACME_CACHE")]
    pub acme_cache: PathBuf,

    /// Use Let's Encrypt production (default is staging)
    #[arg(long, env = "NOADD_ACME_PROD")]
    pub acme_prod: bool,

    // Unset derives from whether noadd is terminating TLS itself; see
    // `resolve_cookie_secure` for why it is derived rather than defaulted on.
    // Set it explicitly when a reverse proxy terminates TLS in front of noadd,
    // since noadd only ever sees plain HTTP in that case.
    /// Set `Secure` on the admin session cookie [default: on when noadd
    /// terminates TLS]
    #[arg(long, env = "NOADD_COOKIE_SECURE", num_args = 0..=1, default_missing_value = "true")]
    pub cookie_secure: Option<bool>,

    /// Log output format
    #[arg(long, default_value = "full", env = "LOG_FORMAT")]
    pub log_format: LogFormat,

    /// Maximum concurrent in-flight DNS queries across UDP/TCP/DoH. Excess
    /// queries wait for a permit; bounds upstream/cache pressure and task
    /// memory under multi-client load. `0` disables the limit.
    #[arg(long, default_value = "2048", env = "NOADD_MAX_INFLIGHT_QUERIES")]
    pub max_inflight_queries: usize,

    /// Per-client-IP steady-state query rate limit (queries/sec). A single
    /// noisy client is capped here so it cannot starve others of upstream
    /// or cache capacity. `0` disables per-IP rate limiting.
    #[arg(long, default_value = "100", env = "NOADD_RATE_LIMIT_QPS")]
    pub rate_limit_qps: u32,

    /// Per-client-IP burst allowance (max tokens the bucket accumulates).
    /// A single page load can fan out 20–40 DNS queries in milliseconds;
    /// the burst must be high enough to absorb this without false positives.
    #[arg(long, default_value = "200", env = "NOADD_RATE_LIMIT_BURST")]
    pub rate_limit_burst: u32,

    /// Populate the admin-UI `result` column for every successful query.
    /// Costs an extra DNS-message parse per query (the third one on the
    /// hot path, after the inbound query parse and the cached-response
    /// TTL decrement). Off by default — turn on only when you actually
    /// need the per-query record summary in the query log.
    #[arg(long, env = "NOADD_LOG_QUERY_RESULTS")]
    pub log_query_results: bool,

    /// Comma-separated CIDR list of reverse-proxy peers permitted to set
    /// `X-Forwarded-For` / `X-Real-IP`. Loopback (127.0.0.0/8, `::1`) is
    /// always trusted; configure this when noadd sits behind a proxy on a
    /// non-loopback address — e.g. SWAG/nginx in a separate Docker
    /// container reaching noadd over the bridge network
    /// (`NOADD_TRUSTED_PROXIES=172.18.0.0/16`). Empty disables proxy
    /// header trust outside loopback.
    #[arg(long, default_value = "", env = "NOADD_TRUSTED_PROXIES")]
    pub trusted_proxies: String,

    /// Request header carrying the username authenticated by a reverse proxy
    /// (e.g. `Remote-User` for Authelia/Authentik). Empty disables forward
    /// auth. Requires `--forward-auth-trusted-proxies`: unlike the client-IP
    /// headers above, a forged forward-auth header grants full admin access,
    /// so loopback is NOT trusted implicitly and the proxy's address must be
    /// listed explicitly.
    #[arg(long, default_value = "", env = "NOADD_FORWARD_AUTH_HEADER")]
    pub forward_auth_header: String,

    /// Comma-separated CIDR list of reverse-proxy peers whose
    /// `--forward-auth-header` is honoured. No implicit loopback trust and no
    /// default — a request with no known peer address is never trusted.
    #[arg(long, default_value = "", env = "NOADD_FORWARD_AUTH_TRUSTED_PROXIES")]
    pub forward_auth_trusted_proxies: String,
}

/// Whether the admin session cookie should carry the `Secure` attribute.
///
/// `override_value` (`--cookie-secure` / `NOADD_COOKIE_SECURE`) wins when set;
/// otherwise the answer is `tls_enabled`, i.e. whether noadd is terminating
/// TLS itself. That is a runtime fact rather than a configuration string a
/// deployment can get wrong, which makes it a better default than deriving
/// from a declared public URL.
///
/// It is deliberately *not* forced on: when TLS terminates upstream noadd
/// cannot tell HTTPS from HTTP, and a browser silently discards a `Secure`
/// cookie delivered over plain HTTP — defaulting it on would lock those
/// operators out of the admin UI with no visible error. Such setups opt in
/// with the override.
pub fn resolve_cookie_secure(override_value: Option<bool>, tls_enabled: bool) -> bool {
    override_value.unwrap_or(tls_enabled)
}

/// Default on-disk database filename for a fresh install.
pub const DEFAULT_DB_PATH: &str = "noadd.sqlite3";

/// Legacy database filename from releases predating the `.sqlite3` default.
/// Retained only for the cascade fallback in [`resolve_db_path`]; new installs
/// never create a file with this name.
const LEGACY_DB_PATH: &str = "noadd.db";

/// Choose the default database filename given whether each candidate already
/// exists on disk. Prefers the current `noadd.sqlite3`, falling back to a
/// legacy `noadd.db` only when the new file is absent but the old one is
/// present — so an in-place upgrade keeps using its existing database instead
/// of silently starting a fresh one.
fn pick_default_db_path(new_exists: bool, legacy_exists: bool) -> &'static str {
    if !new_exists && legacy_exists {
        LEGACY_DB_PATH
    } else {
        DEFAULT_DB_PATH
    }
}

/// Resolve the database path to open. An explicit `--db-path` / `NOADD_DB_PATH`
/// is honoured verbatim; otherwise the default cascades from `noadd.sqlite3` to
/// a pre-existing legacy `noadd.db` (see [`pick_default_db_path`]), warning once
/// when the legacy file is adopted.
pub fn resolve_db_path(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(path) = explicit {
        return path;
    }
    let chosen = pick_default_db_path(
        Path::new(DEFAULT_DB_PATH).exists(),
        Path::new(LEGACY_DB_PATH).exists(),
    );
    if chosen == LEGACY_DB_PATH {
        tracing::warn!(
            path = LEGACY_DB_PATH,
            "opening legacy database `{LEGACY_DB_PATH}`; rename it to `{DEFAULT_DB_PATH}` to adopt the current default and silence this warning",
        );
    }
    PathBuf::from(chosen)
}

/// Environment filter for logging: honours `RUST_LOG`, otherwise defaults to
/// `error,noadd=info` — third-party crates limited to ERROR while noadd's own
/// INFO-level logs remain visible.
fn default_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("error,noadd=info"))
}

/// Emit span-close events only when the max enabled level is DEBUG or more
/// verbose (or unknown); at INFO and below they are pure noise.
fn span_events_for(max_level: Option<tracing::level_filters::LevelFilter>) -> FmtSpan {
    max_level.map_or(FmtSpan::CLOSE, |l| {
        if l >= tracing::Level::DEBUG {
            FmtSpan::CLOSE
        } else {
            FmtSpan::NONE
        }
    })
}

/// Build the boxed `fmt` layer for the chosen output format, applying the
/// env filter and honouring `NO_COLOR` for ANSI.
fn build_fmt_layer<S>(
    format: LogFormat,
    env_filter: EnvFilter,
    span_events: FmtSpan,
) -> Box<dyn Layer<S> + Send + Sync>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    let use_ansi = std::env::var_os("NO_COLOR").is_none();
    let layer = tracing_subscriber::fmt::layer()
        .with_span_events(span_events)
        .with_ansi(use_ansi);
    match format {
        LogFormat::Full => layer.with_filter(env_filter).boxed(),
        LogFormat::Compact => layer.compact().with_filter(env_filter).boxed(),
        LogFormat::Pretty => layer.pretty().with_filter(env_filter).boxed(),
        LogFormat::Json => layer.json().with_filter(env_filter).boxed(),
    }
}

/// Initialize the global `tracing` subscriber for the given log format.
///
/// Without `RUST_LOG` set, defaults to `error,noadd=info`: third-party crates
/// are limited to ERROR while noadd's own INFO-level logs remain visible.
pub fn init_tracing(format: LogFormat) {
    let env_filter = default_env_filter();
    let span_events = span_events_for(env_filter.max_level_hint());
    let layer = build_fmt_layer(format, env_filter, span_events);
    tracing_subscriber::registry().with(layer).init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::Registry;

    #[test]
    fn cookie_secure_defaults_to_tls_enabled() {
        // Unset → follow whether noadd is terminating TLS itself.
        assert!(resolve_cookie_secure(None, true));
        assert!(!resolve_cookie_secure(None, false));
    }

    #[test]
    fn cookie_secure_override_wins_in_both_directions() {
        // Reverse proxy terminates TLS: noadd sees plain HTTP but the cookie
        // must still be Secure.
        assert!(resolve_cookie_secure(Some(true), false));
        // And an explicit off beats the derived on (debugging a TLS install).
        assert!(!resolve_cookie_secure(Some(false), true));
    }

    #[test]
    fn resolve_db_path_honours_explicit() {
        let explicit = PathBuf::from("/custom/place.sqlite3");
        assert_eq!(resolve_db_path(Some(explicit.clone())), explicit);
    }

    #[test]
    fn pick_default_prefers_new_filename() {
        // Fresh install: neither file present -> new default.
        assert_eq!(pick_default_db_path(false, false), DEFAULT_DB_PATH);
        // Only the new file present.
        assert_eq!(pick_default_db_path(true, false), DEFAULT_DB_PATH);
        // Both present: never silently switch to the legacy file.
        assert_eq!(pick_default_db_path(true, true), DEFAULT_DB_PATH);
    }

    #[test]
    fn pick_default_falls_back_to_legacy() {
        // Upgrade from an older release: only noadd.db exists.
        assert_eq!(pick_default_db_path(false, true), LEGACY_DB_PATH);
    }

    // The following exercise resolve_db_path's filesystem cascade against a
    // real CWD. nextest runs each test in its own process, so mutating the
    // process-wide current directory here does not race other tests.
    #[test]
    fn resolve_db_path_defaults_to_new_in_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        assert_eq!(resolve_db_path(None), PathBuf::from(DEFAULT_DB_PATH));
    }

    #[test]
    fn resolve_db_path_uses_legacy_when_only_legacy_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LEGACY_DB_PATH), b"").unwrap();
        std::env::set_current_dir(&dir).unwrap();
        assert_eq!(resolve_db_path(None), PathBuf::from(LEGACY_DB_PATH));
    }

    #[test]
    fn resolve_db_path_prefers_new_when_both_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(DEFAULT_DB_PATH), b"").unwrap();
        std::fs::write(dir.path().join(LEGACY_DB_PATH), b"").unwrap();
        std::env::set_current_dir(&dir).unwrap();
        assert_eq!(resolve_db_path(None), PathBuf::from(DEFAULT_DB_PATH));
    }

    #[test]
    fn span_events_close_without_level_hint() {
        assert_eq!(span_events_for(None), FmtSpan::CLOSE);
    }

    #[test]
    fn span_events_off_at_info_and_below() {
        assert_eq!(span_events_for(Some(LevelFilter::ERROR)), FmtSpan::NONE);
        assert_eq!(span_events_for(Some(LevelFilter::WARN)), FmtSpan::NONE);
        assert_eq!(span_events_for(Some(LevelFilter::INFO)), FmtSpan::NONE);
    }

    #[test]
    fn span_events_close_at_debug_and_trace() {
        assert_eq!(span_events_for(Some(LevelFilter::DEBUG)), FmtSpan::CLOSE);
        assert_eq!(span_events_for(Some(LevelFilter::TRACE)), FmtSpan::CLOSE);
    }

    #[test]
    fn default_env_filter_is_constructible() {
        // Falls back to the built-in directive when RUST_LOG is unset in the
        // test environment; must not panic either way.
        let _ = default_env_filter().max_level_hint();
    }

    #[test]
    fn build_fmt_layer_covers_every_format() {
        for format in [
            LogFormat::Full,
            LogFormat::Compact,
            LogFormat::Pretty,
            LogFormat::Json,
        ] {
            let _: Box<dyn Layer<Registry> + Send + Sync> =
                build_fmt_layer(format, EnvFilter::new("info"), FmtSpan::NONE);
        }
    }

    #[test]
    fn init_tracing_installs_global_subscriber() {
        // nextest runs each test in its own process, so installing the global
        // subscriber here does not clash with other tests.
        init_tracing(LogFormat::Full);
    }
}
