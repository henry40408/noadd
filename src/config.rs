use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "noadd", about = "DNS ad-blocker with DoH support")]
pub struct CliArgs {
    #[arg(long, default_value = "noadd.db")]
    pub db_path: PathBuf,

    #[arg(long, default_value = "0.0.0.0:53")]
    pub dns_addr: String,

    #[arg(long, default_value = "0.0.0.0:3000")]
    pub http_addr: String,

    /// TLS certificate file (manual TLS, mutually exclusive with --acme-domain)
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// TLS private key file (manual TLS, mutually exclusive with --acme-domain)
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Domain(s) for automatic Let's Encrypt certificate (can be specified multiple times)
    #[arg(long)]
    pub acme_domain: Vec<String>,

    /// Contact email for Let's Encrypt (e.g. mailto:you@example.com)
    #[arg(long)]
    pub acme_email: Option<String>,

    /// Directory to cache ACME certificates [default: ./acme-cache]
    #[arg(long, default_value = "acme-cache")]
    pub acme_cache: PathBuf,

    /// Use Let's Encrypt production (default is staging)
    #[arg(long)]
    pub acme_prod: bool,
}
