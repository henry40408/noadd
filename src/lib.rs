pub mod admin;
pub mod cache;
pub mod config;
pub mod db;
pub mod dns;
pub mod filter;
pub mod logger;
pub mod shutdown;
pub mod tls;
pub mod upstream;

pub fn user_agent() -> String {
    let version = env!("GIT_VERSION");
    format!("noadd/{version} (DNS ad-blocker; +https://github.com/henry40408/noadd)")
}
