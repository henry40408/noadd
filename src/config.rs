use clap::{Parser, ValueEnum};
use std::path::PathBuf;
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
    #[arg(long, default_value = "noadd.db", env = "NOADD_DB_PATH")]
    pub db_path: PathBuf,

    #[arg(long, default_value = "0.0.0.0:53", env = "NOADD_DNS_ADDR")]
    pub dns_addr: String,

    #[arg(long, default_value = "0.0.0.0:3000", env = "NOADD_HTTP_ADDR")]
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
