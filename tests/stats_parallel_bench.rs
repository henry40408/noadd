//! Parallel-load wall time of the statistics page's 7 endpoints against a
//! realistic DB. Manual-only — gated by `#[ignore]`.
//!
//!   BENCH_DB=/tmp/noadd-bench.db cargo nextest run --release \
//!     --no-capture --run-ignored only `stats_parallel_bench`
//!
//! Defaults to `/tmp/noadd-bench.db`. Times two scenarios:
//!   - sequential: 7 stats fns awaited one after the other (sum of latencies)
//!   - parallel:   7 stats fns under `tokio::join`! (what the admin UI actually does)
//!
//! Pre-pool, sequential and parallel should be ~identical (single read worker
//! serializes both). Post-pool, parallel drops noticeably while sequential
//! is unchanged.

use std::time::{Duration, Instant};

use noadd::admin::stats::{
    self, StatsRange, compute_breakdowns, compute_db_health, compute_heatmap, compute_highlights,
    compute_stats_timeline, compute_top_clients_ranged, compute_top_domains_ranged,
};
use noadd::db::Database;
use noadd::now_unix;

async fn run_sequential(db: &Database, now: i64, range: StatsRange) {
    compute_stats_timeline(db, now, range, 0).await.unwrap();
    compute_heatmap(db, now).await.unwrap();
    compute_breakdowns(db, now, range).await.unwrap();
    compute_db_health(db, now).await.unwrap();
    compute_highlights(db, now, range).await.unwrap();
    compute_top_domains_ranged(db, now, range, 15)
        .await
        .unwrap();
    compute_top_clients_ranged(db, now, range, 15)
        .await
        .unwrap();
}

async fn run_parallel(db: &Database, now: i64, range: StatsRange) -> [Duration; 7] {
    async fn timed<F, T>(f: F) -> Duration
    where
        F: std::future::Future<Output = Result<T, noadd::db::DbError>>,
    {
        let t = Instant::now();
        f.await.unwrap();
        t.elapsed()
    }
    let (a, b, c, d, e, f, g) = tokio::join!(
        timed(compute_stats_timeline(db, now, range, 0)),
        timed(compute_heatmap(db, now)),
        timed(compute_breakdowns(db, now, range)),
        timed(compute_db_health(db, now)),
        timed(compute_highlights(db, now, range)),
        timed(compute_top_domains_ranged(db, now, range, 15)),
        timed(compute_top_clients_ranged(db, now, range, 15)),
    );
    [a, b, c, d, e, f, g]
}

fn report(label: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let n = samples.len();
    let total: Duration = samples.iter().sum();
    let min = samples[0];
    let median = samples[n / 2];
    #[allow(
        clippy::cast_sign_loss,
        reason = "index derived from non-negative length times a positive fraction"
    )]
    let p95 = samples[((n as f64) * 0.95) as usize];
    let max = samples[n - 1];
    eprintln!(
        "  {label:<10}  n={n:>2}  total={total:>8.3?}  min={min:>9.3?}  median={median:>9.3?}  p95={p95:>9.3?}  max={max:>9.3?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "benchmark; run manually with --ignored"]
async fn stats_parallel_bench() {
    let db_path = std::env::var("BENCH_DB").unwrap_or_else(|_| "/tmp/noadd-bench.db".into());
    let iters: usize = std::env::var("BENCH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let range = match std::env::var("BENCH_RANGE").ok().as_deref() {
        Some("7d") => StatsRange::Days7,
        Some("90d") => StatsRange::Days90,
        _ => StatsRange::Days30,
    };

    assert!(
        std::path::Path::new(&db_path).exists(),
        "BENCH_DB={db_path} not found — copy production DB to a scratch path before running"
    );

    let db = Database::open(&db_path).await.unwrap();
    let now = now_unix();
    // sanity: ensure stats compile + return non-empty heatmap
    let cells = stats::compute_heatmap(&db, now).await.unwrap();
    eprintln!(
        "stats_parallel_bench: db={db_path} range={range:?} iters={iters} heatmap_cells={}",
        cells.len()
    );

    // Warmup so OS page cache and SQLite cache are populated for both
    // scenarios; we're measuring steady-state, not first-load.
    for _ in 0..3 {
        run_sequential(&db, now, range).await;
        run_parallel(&db, now, range).await;
    }

    let labels = [
        "timeline",
        "heatmap",
        "breakdown",
        "health",
        "highlight",
        "top-dom",
        "top-cli",
    ];

    let mut seq = Vec::with_capacity(iters);
    let mut par = Vec::with_capacity(iters);
    let mut per_fn: Vec<Vec<Duration>> = vec![Vec::with_capacity(iters); labels.len()];
    for _ in 0..iters {
        let t = Instant::now();
        run_sequential(&db, now, range).await;
        seq.push(t.elapsed());

        let t = Instant::now();
        let times = run_parallel(&db, now, range).await;
        par.push(t.elapsed());
        for (i, d) in times.iter().enumerate() {
            per_fn[i].push(*d);
        }
    }

    eprintln!();
    report("sequential", seq);
    report("parallel", par);
    eprintln!("  per-fn under parallel load:");
    for (label, samples) in labels.iter().zip(per_fn.into_iter()) {
        report(label, samples);
    }
}
