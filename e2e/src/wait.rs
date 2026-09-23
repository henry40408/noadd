//! Retrying assertions. `WebDriver` does not retry: a `find` that runs before
//! `app.js` has swapped a class reports the old state. Every assertion in
//! [`crate::dom`] is built on these two.

use std::fmt::Debug;
use std::future::Future;
use std::time::Instant;

use anyhow::{Result, bail};

use crate::browser::{WAIT_INTERVAL, WAIT_TIMEOUT};

/// Polls `probe` until it reports the expected value.
///
/// On timeout the failure names the last value seen. An error from `probe` means
/// "not yet", as in [`eventually`]: reading an element is two round trips, and a
/// page re-drawn from server pushes can replace the node between them, so a
/// stale element is ordinary on a live page, not a verdict.
///
/// # Errors
///
/// Fails when the value has still not matched by [`WAIT_TIMEOUT`], reporting
/// the last value seen or, if `probe` never returned one, its last error.
pub async fn eventually_eq<T, E, F, Fut>(what: &str, expected: E, mut probe: F) -> Result<()>
where
    T: Debug,
    E: Debug + PartialEq<T>,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let deadline = Instant::now() + WAIT_TIMEOUT;
    let mut last: Option<T> = None;
    let mut last_error: Option<String> = None;

    loop {
        match probe().await {
            Ok(value) => {
                if expected == value {
                    return Ok(());
                }
                last = Some(value);
            }
            Err(e) => last_error = Some(e.to_string()),
        }

        if Instant::now() >= deadline {
            match (last, last_error) {
                (Some(value), _) => bail!(
                    "{what}: expected {expected:?}, last saw {value:?} after {WAIT_TIMEOUT:?}"
                ),
                (None, Some(error)) => bail!(
                    "{what}: expected {expected:?}, never read a value after {WAIT_TIMEOUT:?} (last error: {error})"
                ),
                (None, None) => bail!(
                    "{what}: expected {expected:?}, never read a value after {WAIT_TIMEOUT:?}"
                ),
            };
        }

        tokio::time::sleep(WAIT_INTERVAL).await;
    }
}

/// Polls `probe` until it reports `Ok(true)`, describing the last state it saw.
///
/// `probe` returns the value it judged alongside the verdict so a failure can
/// print it. An error means "not yet": a `find` mid-navigation legitimately fails.
///
/// # Errors
///
/// Fails when the condition has still not held by [`WAIT_TIMEOUT`], reporting
/// the last value or error seen.
pub async fn eventually<F, Fut>(what: &str, mut probe: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(bool, String)>>,
{
    let deadline = Instant::now() + WAIT_TIMEOUT;
    // Assigned on every path through the loop before the timeout can read it.
    let mut last;
    loop {
        match probe().await {
            Ok((true, _)) => return Ok(()),
            Ok((false, seen)) => last = seen,
            Err(e) => last = format!("error: {e}"),
        }
        if Instant::now() >= deadline {
            bail!("{what}: last saw {last} after {WAIT_TIMEOUT:?}");
        }
        tokio::time::sleep(WAIT_INTERVAL).await;
    }
}
