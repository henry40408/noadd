//! The runner for the non-Gherkin regression specs in `tests/specs`.
//!
//! Not libtest: each file owns a noadd instance started, seeded and stopped
//! around its cases, and a `static` holding a server never drops, so `#[test]`
//! functions would leave orphans holding ports.
//!
//! Cases run in the order written, and several files depend on it — the query
//! log's last case empties the log the earlier ones page through.

use anyhow::Result;

use crate::browser::{Browser, Profile};
use crate::dom::Page;

/// A named group of cases sharing one instance and one browser profile.
pub struct Suite {
    title: &'static str,
    base: String,
    profile: Profile,
    passed: usize,
    failures: Vec<String>,
}

impl Suite {
    /// Opens a suite against an already-running instance.
    pub fn new(title: &'static str, base: impl Into<String>, profile: Profile) -> Self {
        Self {
            title,
            base: base.into(),
            profile,
            passed: 0,
            failures: Vec::new(),
        }
    }

    /// Runs one case in a session of its own.
    ///
    /// Per-case sessions are required: `Emulation.setScriptExecutionDisabled`
    /// applies to the next document, so a no-JS case cannot inherit a session
    /// that has already navigated. A failure is recorded and later cases still run.
    pub async fn case<F>(&mut self, name: &str, body: F)
    where
        F: AsyncFnOnce(&Browser, &Page) -> Result<()>,
    {
        match self.run_case(body).await {
            Ok(()) => {
                self.passed += 1;
                println!("  ok   {name}");
            }
            Err(e) => {
                println!("  FAIL {name}");
                for cause in e.chain() {
                    println!("         {cause}");
                }
                self.failures.push(format!("{} :: {name}", self.title));
            }
        }
    }

    async fn run_case<F>(&self, body: F) -> Result<()>
    where
        F: AsyncFnOnce(&Browser, &Page) -> Result<()>,
    {
        let browser = Browser::open(&self.profile).await?;
        let page = Page::new(browser.driver(), &self.base);
        // Close the session even on failure, or a red run leaks a browser per case.
        let outcome = body(&browser, &page).await;
        let closed = browser.quit().await;
        outcome?;
        closed
    }

    /// Reports the suite and hands back the names of what failed.
    pub fn finish(self) -> Vec<String> {
        println!(
            "{}: {} passed, {} failed",
            self.title,
            self.passed,
            self.failures.len()
        );
        self.failures
    }
}
