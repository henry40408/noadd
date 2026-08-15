//! The runner for the eight tests that were never Gherkin.
//!
//! `harness = false`, for the same reason the Cucumber runner uses it: every
//! file here owns a noadd instance that has to be started, sometimes seeded
//! between two boots, and stopped around its cases. A `#[test]` function has
//! nowhere to keep that — a `static` holding the server never drops, so the
//! process would exit leaving eight orphans holding ports.
//!
//! Files run concurrently up to a small cap; cases *within* a file run in the
//! order they are written, as they did under `workers: 1`. Every file has its
//! own ports and its own database, which is what makes the first half safe —
//! and several files depend on the second: the query log's last case empties
//! the log the earlier ones page through.

mod account_sensitive_actions;
mod chart_touch;
mod filters_no_js;
mod logs_no_js;
mod pages_no_js;
mod password_change_session_list;
mod settings_autosave;
mod stats_no_js;

use std::sync::Arc;

use anyhow::Result;
use noadd_e2e::browser::Browser;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Schedules one spec file behind the concurrency permit.
macro_rules! spawn_spec {
    ($set:expr, $permits:expr, $module:ident) => {{
        let permits = Arc::clone(&$permits);
        $set.spawn(async move {
            let _permit = permits.acquire().await;
            println!("\n=== {} ===", stringify!($module));
            $module::run().await
        });
    }};
}

#[tokio::main]
async fn main() -> Result<()> {
    // Before anything runs in parallel — see `Browser::prepare`. On a cold
    // driver cache several sessions opening at once contend on the same
    // download and the run wedges rather than slows, and CI is cold every run.
    Browser::prepare().await?;

    let permits = Arc::new(Semaphore::new(noadd_e2e::max_concurrency()));
    let mut set = JoinSet::new();
    spawn_spec!(set, permits, account_sensitive_actions);
    spawn_spec!(set, permits, chart_touch);
    spawn_spec!(set, permits, filters_no_js);
    spawn_spec!(set, permits, logs_no_js);
    spawn_spec!(set, permits, pages_no_js);
    spawn_spec!(set, permits, password_change_session_list);
    spawn_spec!(set, permits, settings_autosave);
    spawn_spec!(set, permits, stats_no_js);

    // Every file runs before any of them can fail the process: which cases
    // failed is the whole report, not which file failed first.
    let mut failures = Vec::new();
    while let Some(joined) = set.join_next().await {
        failures.extend(joined??);
    }

    if failures.is_empty() {
        println!("\nall spec cases passed");
        return Ok(());
    }
    println!("\n{} failing case(s):", failures.len());
    for failure in &failures {
        println!("  - {failure}");
    }
    anyhow::bail!("{} spec case(s) failed", failures.len())
}
