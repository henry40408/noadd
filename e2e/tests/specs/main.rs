//! The runner for the non-Gherkin specs (`harness = false`; see
//! [`noadd_e2e::Suite`] for why not libtest).
//!
//! Files run concurrently up to [`noadd_e2e::max_concurrency`], safe because
//! each has its own ports and database; cases within a file run in order.

mod account_sensitive_actions;
mod chart_touch;
mod filters_no_js;
mod logs_live_tail;
mod logs_no_js;
mod pages_no_js;
mod password_change_session_list;
mod settings_autosave;
mod stats_charts;
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
    // Before anything runs in parallel — see `Browser::prepare`.
    Browser::prepare().await?;

    let permits = Arc::new(Semaphore::new(noadd_e2e::max_concurrency()));
    let mut set = JoinSet::new();
    spawn_spec!(set, permits, account_sensitive_actions);
    spawn_spec!(set, permits, chart_touch);
    spawn_spec!(set, permits, filters_no_js);
    spawn_spec!(set, permits, logs_live_tail);
    spawn_spec!(set, permits, logs_no_js);
    spawn_spec!(set, permits, pages_no_js);
    spawn_spec!(set, permits, password_change_session_list);
    spawn_spec!(set, permits, settings_autosave);
    spawn_spec!(set, permits, stats_charts);
    spawn_spec!(set, permits, stats_no_js);

    // Collect every file's failing cases before failing the process. (A file
    // whose setup errors still aborts the run via `??`.)
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
