//! Browser E2E support for noadd: the instances under test, the browser
//! session, the page and locator layer the tests speak, and the fixture SQL
//! behind the seeded suites.
//!
//! This replaces the `playwright-bdd` project that lived here. The five
//! `.feature` files are reused verbatim — the `cucumber` crate reads the same
//! Gherkin — and what was rewritten is everything underneath them, plus the
//! eight plain Playwright specs and the screenshot pipeline.

pub mod api;
pub mod browser;
pub mod dns;
pub mod dom;
pub mod seed;
pub mod server;
pub mod suite;
pub mod wait;
pub mod world;

pub use api::{ADMIN_PASSWORD, ADMIN_USERNAME, Api};
pub use browser::{Browser, Profile, Scripting, Viewport};
pub use dom::{Locator, Page, StepError, StepResult, ensure};
pub use server::Server;
pub use suite::Suite;

/// The ports every instance listens on, unchanged from `playwright.config.js`.
///
/// They are spelled out in one place now rather than once per spec file, which
/// also settles the note the old onboarding steps carried: the DNS port the
/// "noadd resolves a real DNS query" step sends to was a literal in the step
/// file that had to be kept in sync with the config by hand.
pub mod ports {
    /// The shared, pre-authenticated instance the `@app` features read.
    pub const APP: (u16, u16) = (14100, 15100);
    /// The fresh instance the `@auth` lifecycle configures for itself.
    pub const AUTH: (u16, u16) = (14101, 15101);
    /// The pristine instance the `@onboarding` guidance runs against.
    pub const ONBOARDING: (u16, u16) = (14102, 15102);

    /// Statistics charts under touch.
    pub const CHART_TOUCH: (u16, u16) = (14103, 15103);
    /// The settings page's save model.
    pub const SETTINGS: (u16, u16) = (14104, 15104);
    /// The account page's session list after a password change.
    pub const PASSWORD_CHANGE: (u16, u16) = (14105, 15105);
    /// The account page's password-proofed actions.
    pub const ACCOUNT: (u16, u16) = (14106, 15106);
    /// Filters with scripting off.
    pub const FILTERS_NO_JS: (u16, u16) = (14107, 15107);
    /// The query log with scripting off.
    pub const LOGS_NO_JS: (u16, u16) = (14108, 15108);
    /// Statistics with scripting off.
    pub const STATS_NO_JS: (u16, u16) = (14109, 15109);
    /// The dashboard, settings and account with scripting off.
    pub const PAGES_NO_JS: (u16, u16) = (14110, 15110);

    /// The screenshot pipeline, which is not part of a test run.
    pub const SCREENSHOTS: (u16, u16) = (14150, 15150);
}

/// The most instances — and so browsers — to drive at once, whatever the
/// machine.
///
/// A fixed four is fine on a developer's machine and too many for a two-core CI
/// runner, where browsers contend until pages take longer to settle than the
/// assertions wait for.
pub fn max_concurrency() -> usize {
    std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(4)
}
