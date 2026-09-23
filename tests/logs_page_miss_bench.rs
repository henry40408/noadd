//! What the query log page costs in **page misses** (see
//! `stats_page_miss_bench`). Manual-only.
//!
//!   BENCH_DB=/tmp/noadd-bench.db cargo nextest run --release \
//!     --no-capture --run-ignored only `logs_page_miss`
//!
//! `/logs` has no time window, so cost depends on the filters. Each is measured
//! alone and in combinations, with a common and a rare value, because an index
//! choice that helps one routinely hurts the other.
//!
//! Filter values are the busiest and quietest domain, token and query type in
//! `BENCH_DB` itself. `BENCH_NOW` (unix seconds) pins the clock for the domain
//! suggestions, the one windowed reading.

use noadd::admin::stats::domain_suggestions;
use noadd::db::Database;
use noadd::now_unix;
use rusqlite::{Connection, OpenFlags, OptionalExtension};

/// `LOGS_PAGE_SIZE` in `src/admin/pages.rs`.
const PAGE_SIZE: i64 = 50;

/// How deep the second list reading goes: `OFFSET` still reads every skipped
/// row.
const DEEP_PAGE: i64 = 20;

/// Pages `f` reads with the pool's page cache dropped first.
async fn page_misses<F, Fut, T>(db: &Database, f: F) -> i64
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    db.reset_read_page_accounting().await.unwrap();
    let before = db.read_page_cache_stats().await.unwrap();
    f().await;
    let after = db.read_page_cache_stats().await.unwrap();
    after.misses - before.misses
}

/// The value of `column` with the most (`DESC`) or fewest (`ASC`) rows, ties
/// broken by value. Values with a search metacharacter are skipped, since they
/// would turn the prefix match into a `LIKE`.
fn pick(conn: &Connection, column: &str, order: &str) -> Option<String> {
    conn.query_row(
        &format!(
            "SELECT {column} FROM query_logs \
             WHERE {column} IS NOT NULL AND {column} NOT GLOB '*[%_*?]*' \
             GROUP BY {column} ORDER BY COUNT(*) {order}, {column} LIMIT 1"
        ),
        [],
        |row| row.get(0),
    )
    .optional()
    .unwrap()
}

/// The filters one load of `/logs` passes to `query_logs` and `count_logs`.
struct Filter {
    label: String,
    search: Option<String>,
    blocked: Option<bool>,
    token: Option<String>,
    query_type: Option<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "benchmark; run manually with --ignored"]
async fn logs_page_miss_bench() {
    let db_path = std::env::var("BENCH_DB").unwrap_or_else(|_| "/tmp/noadd-bench.db".into());
    assert!(
        std::path::Path::new(&db_path).exists(),
        "BENCH_DB={db_path} not found — copy a production database to a scratch path before running"
    );
    let now = std::env::var("BENCH_NOW").ok().map_or_else(now_unix, |v| {
        v.parse::<i64>().expect("BENCH_NOW must be unix seconds")
    });

    // Opened first so the migrations have run before anything reads the schema.
    let db = Database::open(&db_path).await.unwrap();
    let storage = db.db_storage_stats().await.unwrap();

    // Outside the read pool, so these scans are not counted below.
    let (busy_domain, quiet_domain, busy_token, quiet_token, busy_type, quiet_type) = {
        let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        (
            pick(&conn, "domain", "DESC"),
            pick(&conn, "domain", "ASC"),
            pick(&conn, "doh_token", "DESC"),
            pick(&conn, "doh_token", "ASC"),
            pick(&conn, "query_type", "DESC"),
            pick(&conn, "query_type", "ASC"),
        )
    };
    let busy_domain = busy_domain.expect("BENCH_DB has no query logs");
    // A plain term is a GLOB prefix search; a wildcard makes it a LIKE.
    let prefix = busy_domain
        .split('.')
        .next()
        .unwrap_or(&busy_domain)
        .to_string();
    let labels: Vec<&str> = busy_domain.split('.').collect();
    let contains = format!("*{}*", labels[labels.len().saturating_sub(2)]);
    eprintln!(
        "logs_page_miss_bench: db={db_path} now={now}\n  prefix={prefix:?} rare={quiet_domain:?} \
         contains={contains:?}\n  token busy={busy_token:?} quiet={quiet_token:?}\n  \
         type busy={busy_type:?} quiet={quiet_type:?}"
    );

    let f = |label: &str,
             search: Option<&str>,
             blocked: Option<bool>,
             token: Option<&Option<String>>,
             query_type: Option<&Option<String>>| {
        // No such value (e.g. no DoH traffic): skip the row.
        let token = match token {
            Some(None) => return None,
            Some(Some(t)) => Some(t.clone()),
            None => None,
        };
        let query_type = match query_type {
            Some(None) => return None,
            Some(Some(t)) => Some(t.clone()),
            None => None,
        };
        Some(Filter {
            label: label.to_string(),
            search: search.map(str::to_string),
            blocked,
            token,
            query_type,
        })
    };
    let filters: Vec<Filter> = [
        f("no filter", None, None, None, None),
        f("search prefix (busy)", Some(&prefix), None, None, None),
        f(
            "search prefix (rare)",
            quiet_domain.as_deref(),
            None,
            None,
            None,
        ),
        f("search contains", Some(&contains), None, None, None),
        f("blocked", None, Some(true), None, None),
        f("allowed", None, Some(false), None, None),
        f("token (busy)", None, None, Some(&busy_token), None),
        f("token (quiet)", None, None, Some(&quiet_token), None),
        f("type (busy)", None, None, None, Some(&busy_type)),
        f("type (quiet)", None, None, None, Some(&quiet_type)),
        f(
            "blocked + type (busy)",
            None,
            Some(true),
            None,
            Some(&busy_type),
        ),
        f(
            "search prefix + allowed",
            Some(&prefix),
            Some(false),
            None,
            None,
        ),
        f(
            "token (busy) + blocked",
            None,
            Some(true),
            Some(&busy_token),
            None,
        ),
        f(
            "token + type (both quiet)",
            None,
            None,
            Some(&quiet_token),
            Some(&quiet_type),
        ),
    ]
    .into_iter()
    .flatten()
    .collect();

    let mut rows: Vec<(String, i64)> = Vec::new();
    for filter in &filters {
        let (search, token, query_type) = (
            filter.search.as_deref(),
            filter.token.as_deref(),
            filter.query_type.as_deref(),
        );
        for (page_label, page) in [("page 1", 1), ("page 20", DEEP_PAGE)] {
            let offset = (page - 1) * PAGE_SIZE;
            let n = page_misses(&db, || {
                db.query_logs(PAGE_SIZE, offset, search, filter.blocked, token, query_type)
            })
            .await;
            rows.push((format!("{} — list {page_label}", filter.label), n));
        }
        let n = page_misses(&db, || {
            db.count_logs(search, filter.blocked, token, query_type)
        })
        .await;
        rows.push((format!("{} — count", filter.label), n));
    }
    rows.push((
        "domain suggestions".to_string(),
        page_misses(&db, || domain_suggestions(&db, now)).await,
    ));
    let total: i64 = rows.iter().map(|(_, n)| *n).sum();

    let mib = |pages: i64| (pages * 4096) as f64 / (1024.0 * 1024.0);
    eprintln!();
    eprintln!("  {:<50} {:>9}  {:>9}", "reading", "pages", "MiB");
    for (label, n) in &rows {
        eprintln!("  {label:<50} {n:>9}  {:>9.1}", mib(*n));
    }
    eprintln!(
        "  {:<50} {total:>9}  {:>9.1}",
        "SUM OF ALL READINGS",
        mib(total)
    );
    eprintln!(
        "  database is {:.1} MiB",
        storage.main_bytes as f64 / (1024.0 * 1024.0)
    );

    // Zero means the cache was not dropped and every number is meaningless.
    assert!(
        total > 0,
        "no page misses recorded — is BENCH_DB an empty database?"
    );
}
