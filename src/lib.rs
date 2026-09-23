pub mod admin;
pub mod cache;
pub mod config;
pub mod db;
pub mod dns;
pub mod filter;
pub mod headers;
pub mod logger;
pub mod net;
pub mod registry;
pub mod shutdown;
pub mod tls;
pub mod upstream;

pub fn user_agent() -> String {
    let version = env!("GIT_VERSION");
    format!("noadd/{version} (DNS ad-blocker; +https://github.com/henry40408/noadd)")
}

/// Force the allocator to return freed pages to the OS, so a filter rebuild's
/// transient `BuildNode` tree does not stay resident for mimalloc's purge
/// delay (~10s) on small hosts.
pub fn reclaim_memory() {
    // SAFETY: `mi_collect` is thread-safe; `true` also returns memory to the
    // OS. No safe wrapper exists.
    #[allow(unsafe_code)]
    unsafe {
        libmimalloc_sys::mi_collect(true);
    }
}

/// Current Unix timestamp in seconds; 0 if the clock is before the epoch.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Current Unix timestamp in milliseconds.
pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}
