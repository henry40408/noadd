//! Isolates why concurrent readers in one process scaled negatively (parallel
//! wall time ~2x the sequential sum in `stats_parallel_bench`).
//!
//! Separate `sqlite3` processes scaled and an `mmap_size` sweep changed
//! nothing, which pointed at a process-global lock: `SQLITE_CONFIG_MEMSTATUS`,
//! on by default, updates global counters under a mutex on every
//! `sqlite3_malloc`/`sqlite3_free`. `src/db.rs` now disables it
//! (`disable_sqlite_memstatus`); this bench is kept to re-measure.
//!
//! Knobs, all env vars:
//! - `BENCH_DB` — path to a production DB copy (default `/tmp/noadd-bench.db`)
//! - `BENCH_ITERS` — passes over the statement list per thread (default 10)
//! - `BENCH_THREADS` — comma-separated thread counts to sweep (default `1,2,4,8`)
//! - `BENCH_MEMSTATUS` — `1` keeps `SQLITE_CONFIG_MEMSTATUS` on (default), `0`
//!   disables it before `SQLite` initializes
//! - `BENCH_MMAP` — per-connection `mmap_size` in bytes (default 268435456)
//! - `BENCH_CACHE` — per-connection `cache_size` (default -2000)
//! - `BENCH_TEMP_STORE` — `MEMORY` (default), `FILE` or `DEFAULT`
//! - `BENCH_THREADMODE` — `sqlite3_config` threading mode, 0 = build default
//!
//! Thread-vs-process control: compare N concurrent processes at
//! `BENCH_THREADS=1` against `BENCH_THREADS=N` in one process.
//!
//! ```text
//! BENCH_DB=/path/to/prod-copy.sqlite3 cargo nextest run --release \
//!   --no-capture --run-ignored all stats_contention_bench
//! ```

use std::sync::Arc;
use std::time::Instant;

use rusqlite::{Connection, OpenFlags};

/// The heavy per-window statements the Statistics page issued for `range=7d`
/// before the rollups. A fixed workload for this measurement, not what
/// `src/db.rs` runs today.
fn heavy_statements(now: i64, tz_offset_secs: i64) -> Vec<(&'static str, String)> {
    let d7 = (now - 7 * 86400) * 1000;
    let d30 = (now - 30 * 86400) * 1000;
    let off = tz_offset_secs;
    let off_ms = tz_offset_secs * 1000;
    vec![
        (
            "timeline_multi",
            format!(
                "SELECT ((timestamp+{off_ms})/3600000)*3600000-{off_ms} AS b, COUNT(*), \
                 COALESCE(SUM(blocked),0), COALESCE(SUM(cached),0) \
                 FROM query_logs WHERE timestamp>={d7} GROUP BY b ORDER BY b"
            ),
        ),
        (
            "heatmap",
            format!(
                "SELECT CAST(strftime('%w',timestamp/1000+{off},'unixepoch') AS INTEGER) w, \
                 CAST(strftime('%H',timestamp/1000+{off},'unixepoch') AS INTEGER) h, COUNT(*) \
                 FROM query_logs WHERE timestamp>={d30} GROUP BY w,h ORDER BY w,h"
            ),
        ),
        (
            "query_type",
            format!(
                "SELECT query_type, COUNT(*) c FROM query_logs WHERE timestamp>={d7} \
                 GROUP BY query_type ORDER BY c DESC"
            ),
        ),
        (
            "outcome",
            format!(
                "SELECT CASE WHEN blocked=1 THEN 'Blocked' WHEN cached=1 THEN 'Cached' \
                 WHEN result IS NOT NULL AND result!='' THEN 'Resolved' ELSE 'Empty' END o, \
                 COUNT(*) c FROM query_logs WHERE timestamp>={d7} GROUP BY o ORDER BY c DESC"
            ),
        ),
        (
            "unique_domains",
            format!("SELECT COUNT(DISTINCT domain) FROM query_logs WHERE timestamp>={d7}"),
        ),
        (
            "latency_hist",
            format!(
                "SELECT response_ms, COUNT(*) FROM query_logs WHERE timestamp>={d7} \
                 GROUP BY response_ms ORDER BY response_ms"
            ),
        ),
        (
            "top_domains",
            format!(
                "SELECT domain, COUNT(*) c FROM query_logs WHERE timestamp>={d7} \
                 GROUP BY domain ORDER BY c DESC LIMIT 15"
            ),
        ),
        (
            "top_clients",
            format!(
                "SELECT client_ip, doh_token, COUNT(*) c FROM query_logs WHERE timestamp>={d7} \
                 GROUP BY client_ip, doh_token ORDER BY c DESC LIMIT 15"
            ),
        ),
    ]
}

fn open_reader(path: &str, mmap_size: i64, cache_size: i64, temp_store: &str) -> Connection {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    let conn = Connection::open_with_flags(path, flags).unwrap();
    conn.execute_batch(&format!(
        "PRAGMA busy_timeout = 5000; \
         PRAGMA cache_size = {cache_size}; \
         PRAGMA mmap_size = {mmap_size}; \
         PRAGMA temp_store = {temp_store};"
    ))
    .unwrap();
    conn
}

/// Run one statement to completion, discarding rows.
fn drain(conn: &Connection, sql: &str) {
    let mut stmt = conn.prepare_cached(sql).unwrap();
    let mut rows = stmt.query([]).unwrap();
    while rows.next().unwrap().is_some() {}
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[test]
#[ignore = "benchmark; run manually with --run-ignored all"]
fn stats_contention_bench() {
    let db_path = std::env::var("BENCH_DB").unwrap_or_else(|_| "/tmp/noadd-bench.db".into());
    assert!(
        std::path::Path::new(&db_path).exists(),
        "BENCH_DB={db_path} not found — copy a production DB to a scratch path first"
    );
    let iters = env_usize("BENCH_ITERS", 10);
    let mmap: i64 = std::env::var("BENCH_MMAP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(268_435_456);
    let cache_size: i64 = std::env::var("BENCH_CACHE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(-2000);
    let temp_store = std::env::var("BENCH_TEMP_STORE").unwrap_or_else(|_| "MEMORY".into());
    assert!(
        matches!(temp_store.as_str(), "MEMORY" | "FILE" | "DEFAULT"),
        "BENCH_TEMP_STORE must be MEMORY, FILE or DEFAULT"
    );
    let memstatus = env_usize("BENCH_MEMSTATUS", 1) != 0;
    let thread_counts: Vec<usize> = std::env::var("BENCH_THREADS")
        .unwrap_or_else(|_| "1,2,4,8".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    // SQLITE_CONFIG_SINGLETHREAD=1, MULTITHREAD=2, SERIALIZED=3; 0 keeps the
    // build default (SERIALIZED).
    //
    // Should be a no-op: MULTITHREAD only clears the per-connection
    // `bFullMutex`, which `SQLITE_OPEN_NOMUTEX` (on every noadd connection)
    // already bypasses, and `bCoreMutex` — guarding the MEMSTATUS counters —
    // stays set. With MEMSTATUS off the modes measured within noise; a single
    // unreproduced run with it on had MULTITHREAD ~1.8x faster.
    let thread_mode = env_usize("BENCH_THREADMODE", 0);
    if thread_mode != 0 {
        // SAFETY: variadic C call with the documented (no) argument for these
        // ops, issued before SQLite is initialized and before any other thread
        // exists in this test.
        #[allow(unsafe_code, reason = "no safe rusqlite wrapper for sqlite3_config")]
        let rc = unsafe {
            rusqlite::ffi::sqlite3_config(i32::try_from(thread_mode).expect("mode fits in i32"))
        };
        assert_eq!(
            rc,
            rusqlite::ffi::SQLITE_OK,
            "sqlite3_config(threading mode {thread_mode}) failed"
        );
    }

    if !memstatus {
        // SQLITE_CONFIG_MEMSTATUS = 9; must precede any connection opening.
        // SAFETY: variadic C call with the documented (int) argument for this
        // op, made before SQLite is initialized and before any other thread
        // exists in this test.
        #[allow(unsafe_code, reason = "no safe rusqlite wrapper for sqlite3_config")]
        let rc = unsafe { rusqlite::ffi::sqlite3_config(9, 0_i32) };
        assert_eq!(
            rc,
            rusqlite::ffi::SQLITE_OK,
            "sqlite3_config(MEMSTATUS,0) failed"
        );
    }

    // Anchor the windows to the newest row, however old the copy is.
    let now = {
        let c = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        c.query_row("SELECT MAX(timestamp) FROM query_logs", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
            / 1000
    };
    let stmts = Arc::new(heavy_statements(now, 8 * 3600));
    eprintln!(
        "stats_contention_bench: db={db_path} stmts={} iters={iters} mmap={mmap} \
         cache={cache_size} temp_store={temp_store} memstatus={} threadmode={thread_mode}",
        stmts.len(),
        u8::from(memstatus),
    );

    for &threads in &thread_counts {
        // One connection per thread, like the read pool. Per-pass latency stays
        // flat as `threads` grows under perfect scaling; any rise is
        // inter-reader interference.
        let t = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..threads {
                let stmts = Arc::clone(&stmts);
                let db_path = db_path.clone();
                let temp_store = temp_store.clone();
                s.spawn(move || {
                    let conn = open_reader(&db_path, mmap, cache_size, &temp_store);
                    for (_, sql) in stmts.iter() {
                        drain(&conn, sql); // warm this connection
                    }
                    for _ in 0..iters {
                        for (_, sql) in stmts.iter() {
                            drain(&conn, sql);
                        }
                    }
                });
            }
        });
        let wall = t.elapsed();
        let per_pass = wall / u32::try_from(iters).unwrap();
        let throughput = (threads * iters) as f64 / wall.as_secs_f64();
        eprintln!(
            "  threads={threads:<2} per-pass={per_pass:>9.3?}  aggregate={throughput:>5.2} pass/s",
        );
    }
}
