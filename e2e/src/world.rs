//! The Cucumber world: one browser session per scenario, against the instance
//! the feature's tag names.
//!
//! `playwright.config.js` expressed the split as three BDD projects, each with
//! its own `baseURL` and its own `webServer` entry. The features already carry
//! the same information as a tag on the feature — `@app`, `@auth`,
//! `@onboarding` — so the runner starts three instances, registers them here,
//! and a `before` hook picks one by tag. Nothing about the Gherkin changed.
//!
//! The session cannot be opened in `new`, because `World::new` never sees the
//! scenario and so cannot know which instance it belongs to. A `before` hook
//! opens it instead.

use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use cucumber::World;

use crate::api::Api;
use crate::browser::{Browser, Profile};
use crate::dom::Page;

/// One running instance, as the steps need to address it.
#[derive(Debug, Clone)]
pub struct Instance {
    /// Where its admin UI is.
    pub base: String,
    /// The UDP port its DNS listener answers on.
    pub dns_port: u16,
    /// A session minted by the runner, replayed into the browser instead of a
    /// UI sign-in. `None` for the instances a feature is meant to configure
    /// itself — the first-run setup scenarios would have nothing to prove
    /// against an instance somebody else had already set up.
    pub session: Option<String>,
}

/// The instances the runner started, keyed by the tag that selects them.
static INSTANCES: OnceLock<HashMap<String, Instance>> = OnceLock::new();

/// Publishes the running instances. Called once, before any scenario.
///
/// # Errors
///
/// Fails when called twice.
pub fn register(instances: impl IntoIterator<Item = (String, Instance)>) -> Result<()> {
    let instances: HashMap<String, Instance> = instances.into_iter().collect();
    INSTANCES
        .set(instances)
        .map_err(|_already_set| anyhow::anyhow!("the instances were registered twice"))
}

/// The instance a feature's tags select.
///
/// # Errors
///
/// Fails when no tag matches — a new feature that forgot its tag, which is
/// better caught here than as a scenario that quietly ran against the wrong
/// database.
pub fn instance_for(tags: &[String]) -> Result<Instance> {
    let registry = INSTANCES.get().context("no instances registered")?;
    tags.iter()
        .find_map(|tag| registry.get(tag))
        .cloned()
        .with_context(|| format!("no instance for tags {tags:?}"))
}

/// State shared by the steps of one scenario.
#[derive(Debug, World)]
#[world(init = Self::new)]
pub struct NoaddWorld {
    browser: Option<Browser>,
    page: Option<Page>,
    instance: Option<Instance>,
    /// Filled by the sweep that visits every tab looking for markup rendered as
    /// visible text, and read by the assertion that follows it.
    pub leaked_markup: Vec<String>,
}

impl NoaddWorld {
    fn new() -> Self {
        Self {
            browser: None,
            page: None,
            instance: None,
            leaked_markup: Vec::new(),
        }
    }

    /// Opens the session for a scenario and points it at `instance`.
    ///
    /// # Errors
    ///
    /// Fails when no browser session can be started, or when a session token
    /// cannot be replayed into it.
    pub async fn open(&mut self, instance: Instance, profile: &Profile) -> Result<()> {
        let browser = Browser::open(profile).await?;
        let page = Page::new(browser.driver(), &instance.base);
        if let Some(token) = &instance.session {
            page.adopt_session(token).await?;
        }
        self.browser = Some(browser);
        self.page = Some(page);
        self.instance = Some(instance);
        Ok(())
    }

    /// Ends the session, if one was opened.
    ///
    /// # Errors
    ///
    /// Fails when the driver refuses to close.
    pub async fn close(&mut self) -> Result<()> {
        self.page = None;
        self.instance = None;
        if let Some(browser) = self.browser.take() {
            browser.quit().await?;
        }
        Ok(())
    }

    /// The scenario's page.
    ///
    /// # Errors
    ///
    /// Fails when no session was opened — a `before` hook that did not run.
    pub fn page(&self) -> Result<&Page> {
        self.page
            .as_ref()
            .context("no browser session: the `before` hook did not open one")
    }

    /// The scenario's browser, for the emulations a step reaches for directly.
    ///
    /// # Errors
    ///
    /// Fails when no session was opened.
    pub fn browser(&self) -> Result<&Browser> {
        self.browser
            .as_ref()
            .context("no browser session: the `before` hook did not open one")
    }

    /// The instance this scenario runs against.
    ///
    /// # Errors
    ///
    /// Fails when no session was opened.
    pub fn instance(&self) -> Result<&Instance> {
        self.instance
            .as_ref()
            .context("no instance for this scenario")
    }

    /// An HTTP client for this scenario's instance.
    ///
    /// # Errors
    ///
    /// Fails when no session was opened.
    pub fn api(&self) -> Result<Api> {
        Ok(Api::new(&self.instance()?.base))
    }
}
