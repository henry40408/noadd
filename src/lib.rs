pub mod admin;
pub mod cache;
pub mod config;
pub mod db;
pub mod dns;
pub mod filter;
pub mod logger;
pub mod registry;
pub mod shutdown;
pub mod tls;
pub mod upstream;

pub fn user_agent() -> String {
    let version = env!("GIT_VERSION");
    format!("noadd/{version} (DNS ad-blocker; +https://github.com/henry40408/noadd)")
}

/// Current Unix timestamp in seconds. Returns 0 if the system clock is
/// before the Unix epoch (effectively impossible on a healthy host).
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
