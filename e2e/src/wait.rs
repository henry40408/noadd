//! Retrying assertions.
//!
//! Playwright's `expect(...)` polls until the assertion holds or a timeout
//! expires, which is what let the old tests write `await expect(page).toHaveURL('/')`
//! straight after a click. `WebDriver` has no such layer: a `find` that runs
//! before `app.js` has finished swapping a class simply reports the old state.
//!
//! There were 208 `await expect(...)` calls in the suite this replaces, so the
//! polling is not an occasional convenience — it is the substrate. Every
//! assertion in [`crate::dom`] is built on these two.

use std::fmt::Debug;
use std::future::Future;
use std::time::Instant;

use anyhow::{Result, bail};

use crate::browser::{WAIT_INTERVAL, WAIT_TIMEOUT};

/// Polls `probe` until it reports the expected value.
///
/// On timeout the failure names the last value seen, not merely that a wait
/// expired — that is the difference between "the row count never reached 2" and
/// a message you have to reproduce by hand to understand.
///
/// An error from `probe` is "not yet", the same as a value that does not match
/// — matching [`eventually`], which always read them that way. Reading an
/// element is two round trips (find it, then ask it for the value), and on a
/// page that re-draws itself from server pushes the node can be replaced
/// between them: `Element is stale` is the ordinary state of a live page, not
/// a verdict. Treating it as fatal made every such assertion a race against
/// the next push, which is how a dashboard poll interval ended up deciding
/// whether a test passed.
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
/// print it. An error from `probe` is treated as "not yet" rather than fatal:
/// a `find` against a page mid-navigation legitimately fails, and the timeout
/// is what decides whether that was transient.
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
