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

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use noadd_e2e::browser::Browser;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Schedules one spec file behind the concurrency permit, recording its name by
/// task id so a file that panics can still be reported by name.
macro_rules! spawn_spec {
    ($set:expr, $names:expr, $permits:expr, $module:ident) => {{
        let permits = Arc::clone(&$permits);
        let handle = $set.spawn(async move {
            let _permit = permits.acquire().await;
            println!("\n=== {} ===", stringify!($module));
            $module::run().await
        });
        $names.insert(handle.id(), stringify!($module));
    }};
}

#[tokio::main]
async fn main() -> Result<()> {
    // Before anything runs in parallel — see `Browser::prepare`.
    Browser::prepare().await?;

    let permits = Arc::new(Semaphore::new(noadd_e2e::max_concurrency()));
    let mut set = JoinSet::new();
    let mut names = HashMap::new();
    spawn_spec!(set, names, permits, account_sensitive_actions);
    spawn_spec!(set, names, permits, chart_touch);
    spawn_spec!(set, names, permits, filters_no_js);
    spawn_spec!(set, names, permits, logs_live_tail);
    spawn_spec!(set, names, permits, logs_no_js);
    spawn_spec!(set, names, permits, pages_no_js);
    spawn_spec!(set, names, permits, password_change_session_list);
    spawn_spec!(set, names, permits, settings_autosave);
    spawn_spec!(set, names, permits, stats_charts);
    spawn_spec!(set, names, permits, stats_no_js);

    // Every file runs to the end before the process fails: a file that errors
    // or panics (a server that will not start, say) is one more failure, not a
    // reason to abort the others mid-run.
    let mut failures = Vec::new();
    while let Some(joined) = set.join_next_with_id().await {
        match joined {
            Ok((_, Ok(cases))) => failures.extend(cases),
            Ok((id, Err(e))) => failures.push(format!("{} :: did not finish: {e:#}", names[&id])),
            Err(e) => failures.push(format!("{} :: panicked: {e}", names[&e.id()])),
        }
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
