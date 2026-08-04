//! Isolates *why* the statistics page's parallel fan-out scales negatively.
//!
//! `stats_parallel_bench` shows parallel wall time roughly 2x the sequential
//! sum, which imbalance alone cannot explain — parallel can never be slower
//! than sequential unless the concurrent readers actively fight each other.
//! Four separate `sqlite3` *processes* scanning the same file do scale, so the
//! contention is process-local. A `mmap_size` sweep ruled out the
//! page-fault/VM-lock theory (mapped and unmapped scale identically badly),
//! leaving a process-global lock inside `SQLite`: `SQLITE_CONFIG_MEMSTATUS`,
//! on by default, makes every `sqlite3_malloc`/`sqlite3_free` update global
//! counters under a shared mutex. Invisible to a multi-*process* test,
//! crippling for a multi-*threaded* read pool running aggregations that
//! allocate hard (temp b-trees, sorters).
//!
//! Knobs, all env vars:
//! - `BENCH_DB` — path to a production DB copy (default `/tmp/noadd-bench.db`)
//! - `BENCH_ITERS` — passes over the statement list per thread (default 10)
//! - `BENCH_THREADS` — comma-separated thread counts to sweep (default `1,2,4,8`)
//! - `BENCH_MEMSTATUS` — `1` keeps `SQLITE_CONFIG_MEMSTATUS` on (default), `0`
//!   disables it before `SQLite` initializes
//! - `BENCH_MMAP` — per-connection `mmap_size` in bytes (default 268435456)
//!
//! Thread-vs-process control: run with `BENCH_THREADS=1` as N concurrent
//! processes and compare per-pass wall against `BENCH_THREADS=N` in one
//! process.
//!
//! ```text
//! BENCH_DB=/path/to/prod-copy.sqlite3 cargo nextest run --release \
//!   --no-capture --run-ignored all stats_contention_bench
//! ```

use std::sync::Arc;
use std::time::Instant;

use rusqlite::{Connection, OpenFlags};

/// The heavy statements the Statistics page issues for `range=7d`, verbatim
/// from `src/db.rs` with the bind parameters folded in by the caller.
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

fn open_reader(path: &str, mmap_size: i64) -> Connection {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_URI;
    let conn = Connection::open_with_flags(path, flags).unwrap();
    conn.execute_batch(&format!(
        "PRAGMA busy_timeout = 5000; \
         PRAGMA cache_size = -2000; \
         PRAGMA mmap_size = {mmap_size}; \
         PRAGMA temp_store = MEMORY;"
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
    let memstatus = env_usize("BENCH_MEMSTATUS", 1) != 0;
    let thread_counts: Vec<usize> = std::env::var("BENCH_THREADS")
        .unwrap_or_else(|_| "1,2,4,8".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    if !memstatus {
        // SQLITE_CONFIG_MEMSTATUS = 9, expects an int argument. Must be called
        // before sqlite3_initialize, i.e. before any connection is opened.
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

    // Anchor the windows to the newest row so the 7d/30d ranges cover data
    // regardless of how old the copied DB is.
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
        "stats_contention_bench: db={db_path} stmts={} iters={iters} mmap={mmap} memstatus={}",
        stmts.len(),
        u8::from(memstatus),
    );

    for &threads in &thread_counts {
        // Each thread owns a connection (`Connection` is not `Sync`) and makes
        // `iters` passes over the whole statement list — the same
        // one-connection-per-worker shape as the read pool. Wall / iters is the
        // per-pass latency a single worker sees; with perfect scaling it stays
        // flat as `threads` grows, and any rise is inter-reader interference.
        let t = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..threads {
                let stmts = Arc::clone(&stmts);
                let db_path = db_path.clone();
                s.spawn(move || {
                    let conn = open_reader(&db_path, mmap);
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
