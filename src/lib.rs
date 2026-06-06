pub mod admin;
pub mod cache;
pub mod config;
pub mod db;
pub mod dns;
pub mod filter;
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

/// Force the allocator to return freed pages to the OS.
///
/// The filter rebuild allocates a large transient `BuildNode` tree; once it is
/// flattened and dropped, mimalloc would otherwise hold those pages for up to
/// its purge delay (~10s). Calling this right after a rebuild collapses the
/// resident spike to the steady-state footprint immediately, which matters on
/// memory-constrained hosts (e.g. Raspberry Pi).
pub fn reclaim_memory() {
    // SAFETY: `mi_collect` is a thread-safe no-side-effect collection call;
    // `true` forces it to also return memory to the OS.
    unsafe { libmimalloc_sys::mi_collect(true) }
}

/// Current Unix timestamp in seconds. Returns 0 if the system clock is
/// before the Unix epoch (effectively impossible on a healthy host).
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Current Unix timestamp in milliseconds.
pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
