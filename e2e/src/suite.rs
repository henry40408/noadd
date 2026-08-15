//! The runner for the tests that were never Gherkin.
//!
//! Eight of the twelve Playwright projects were plain `test()` blocks rather
//! than features — the touch, auto-save, account and four no-JS files. They are
//! regressions with a paragraph of reasoning each, not user journeys, and
//! rewriting them as scenarios would have invented a vocabulary nobody speaks.
//! So they stay tests, and this is the `describe` / `test` they need.
//!
//! It is not libtest. Each file owns a noadd instance that has to be started,
//! seeded and stopped around its cases, and `#[test]` functions have nowhere to
//! put that: a `static` holding the server never drops, so the process would
//! exit leaving eight orphans holding ports. A [`Suite`] owns the server for as
//! long as its cases run and takes it down on the way out.
//!
//! Cases run in the order they are written, as they did under `workers: 1`.
//! Several files depend on it — the query log's last case empties the log the
//! earlier ones page through.

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
    /// A fresh session per case is what Playwright's per-test context gave, and
    /// here it is also a requirement: `Emulation.setScriptExecutionDisabled`
    /// applies to the next document, so a no-JS case cannot inherit a session
    /// that has already navigated.
    ///
    /// A failure is recorded and the remaining cases still run — the whole
    /// point of a suite is to learn more than which test failed first.
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
        // The session is closed either way: a case that failed has already
        // reported, and leaking a browser per failure is how a red run becomes
        // an unusable machine.
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
