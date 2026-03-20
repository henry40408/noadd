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

    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    #[arg(long)]
    pub tls_key: Option<PathBuf>,
}
