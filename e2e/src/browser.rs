//! The browser session, and every emulation the suite depends on.
//!
//! `WebDriver::managed` downloads and supervises a matching chromedriver
//! itself, so nothing has to be installed alongside the tests — but it does
//! *not* download the browser, unlike the Playwright setup this replaces. A
//! Chrome or Chromium in one of the well-known locations is a prerequisite now;
//! [`Browser::open`] says so in as many words when it is missing, because the
//! raw driver error does not.
//!
//! Everything `playwright.config.js` expressed as a `use:` block is a CDP call
//! here:
//!
//! * `viewport` / `deviceScaleFactor` / `isMobile` — `Emulation.setDeviceMetricsOverride`,
//!   for every profile rather than only the mobile ones. A `--window-size`
//!   argument sets the *outer* window and leaves the viewport a function of the
//!   browser's own chrome; the no-JS specs pin 1024×600 precisely because the
//!   fixed status bar overlaps what sits at the foot of a short window, so an
//!   approximate viewport would quietly stop testing that.
//! * `hasTouch` — `Emulation.setTouchEmulationEnabled`, plus
//!   `Input.dispatchTouchEvent` for the taps themselves.
//! * `reducedMotion` / `colorScheme` — `Emulation.setEmulatedMedia`.
//! * `javaScriptEnabled: false` — `Emulation.setScriptExecutionDisabled`, which
//!   is what Playwright used underneath. It applies to the *next* document, so
//!   sessions are per-case and the flag is set before the first navigation.
//! * `addInitScript` — `Page.addScriptToEvaluateOnNewDocument`. Two of the
//!   ported tests need it: one rewrites a JSON response the dashboard reads,
//!   the other records what the settings page sends. Both are `window.fetch`
//!   wrappers, because `app.js` makes every call through `fetch`.
//!
//! `BiDi` is deliberately not enabled. `Emulation.setEmulatedMedia` is the only
//! route to `prefers-color-scheme` at all, and the rest is a WebSocket stack
//! for things CDP already does over the connection we have.

use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use thirtyfour::prelude::*;

/// How long a query waits for a condition before giving up.
///
/// Only ever paid in full by a genuine failure, so it is set for the slowest
/// machine that runs this rather than the fastest: locally every wait settles
/// in well under a second, while a two-core CI runner driving several browsers
/// took longer than Playwright's 10 s `expect` timeout to land a navigation.
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a query re-checks while waiting.
pub const WAIT_INTERVAL: Duration = Duration::from_millis(100);

/// Whether the page's own scripts run — the `javaScriptEnabled` split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scripting {
    /// The scripted path: `app.js` runs and enhances the server-rendered body.
    Enabled,
    /// The no-JS path: the page's own scripts never execute.
    Disabled,
}

/// A viewport, matching a Playwright `devices[...]` entry.
#[derive(Debug, Clone, Copy)]
pub struct Viewport {
    pub width: u32,
    pub height: u32,
    pub scale: f64,
    pub mobile: bool,
    pub touch: bool,
}

impl Viewport {
    /// `devices['Desktop Chrome']`.
    pub const DESKTOP: Self = Self {
        width: 1280,
        height: 720,
        scale: 1.0,
        mobile: false,
        touch: false,
    };

    /// The short window the no-JS specs pin, so the fixed status bar really
    /// does overlap the foot of the page.
    pub const SHORT: Self = Self {
        width: 1024,
        height: 600,
        scale: 1.0,
        mobile: false,
        touch: false,
    };

    /// `devices['Pixel 5']`.
    pub const PIXEL_5: Self = Self {
        width: 393,
        height: 851,
        scale: 2.75,
        mobile: true,
        touch: true,
    };
}

/// Everything a Playwright project's `use:` block used to carry.
#[derive(Debug, Clone)]
pub struct Profile {
    pub scripting: Scripting,
    pub viewport: Viewport,
    pub reduced_motion: bool,
    /// `prefers-color-scheme`, when the case cares which one it gets.
    pub color_scheme: Option<&'static str>,
    /// IANA zone the page's clock reports. The screenshots pin UTC so the
    /// heatmap keeps the seed's diurnal curve instead of smearing it across
    /// whatever zone the machine capturing them is in.
    pub timezone: Option<&'static str>,
    /// BCP 47 tag the page formats numbers and dates with.
    pub locale: Option<&'static str>,
    /// Scripts run before the page's own, in document order.
    pub init_scripts: Vec<String>,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            scripting: Scripting::Enabled,
            viewport: Viewport::DESKTOP,
            reduced_motion: false,
            color_scheme: None,
            timezone: None,
            locale: None,
            init_scripts: Vec::new(),
        }
    }
}

impl Profile {
    /// The scripted desktop default.
    pub fn desktop() -> Self {
        Self::default()
    }

    /// The `javaScriptEnabled: false, reducedMotion: 'reduce'` profile the four
    /// no-JS specs share, in the 1024×600 window they pin.
    pub fn no_js() -> Self {
        Self {
            scripting: Scripting::Disabled,
            viewport: Viewport::SHORT,
            reduced_motion: true,
            ..Self::default()
        }
    }

    /// A touch-enabled Pixel 5, for the chart tap tests.
    pub fn mobile() -> Self {
        Self {
            viewport: Viewport::PIXEL_5,
            ..Self::default()
        }
    }

    pub fn with_viewport(mut self, viewport: Viewport) -> Self {
        self.viewport = viewport;
        self
    }

    pub fn with_reduced_motion(mut self) -> Self {
        self.reduced_motion = true;
        self
    }

    pub fn with_color_scheme(mut self, scheme: &'static str) -> Self {
        self.color_scheme = Some(scheme);
        self
    }

    pub fn with_clock(mut self, timezone: &'static str, locale: &'static str) -> Self {
        self.timezone = Some(timezone);
        self.locale = Some(locale);
        self
    }

    pub fn with_init_script(mut self, source: impl Into<String>) -> Self {
        self.init_scripts.push(source.into());
        self
    }
}

/// A browser session, scoped to one scenario or one spec case.
#[derive(Debug)]
pub struct Browser {
    driver: WebDriver,
}

impl Browser {
    /// Starts a headless session configured by `profile`.
    ///
    /// # Errors
    ///
    /// Fails when no local browser is installed, when the driver cannot be
    /// downloaded, or when the session cannot be created.
    pub async fn open(profile: &Profile) -> Result<Self> {
        let mut caps = DesiredCapabilities::chrome();
        caps.set_headless()?;
        // Containers get a 64 MB /dev/shm by default, which Chrome outgrows.
        caps.add_arg("--disable-dev-shm-usage")?;
        // A `confirm()` is a real control here — the account page's "log out
        // other sessions" is one — and the W3C default of "dismiss and notify"
        // would answer Cancel before the test ever saw it. `ignore` leaves the
        // dialog standing so `accept_alert` can answer it.
        caps.as_mut().set("unhandledPromptBehavior", "ignore")?;

        let driver = WebDriver::managed(caps).await.context(
            "could not start a browser session — a local Chrome or Chromium is required \
             (`brew install --cask ungoogled-chromium`, or the Chrome that CI's runner \
             image ships); unlike Playwright, the driver manager downloads only the driver",
        )?;

        let browser = Self { driver };
        browser.apply(profile).await?;
        Ok(browser)
    }

    /// Downloads and starts the driver once, before any case asks for it.
    ///
    /// `WebDriver::managed` builds a *new* manager per call, so each session
    /// prepares the driver for itself. That is harmless when it is already
    /// cached and pathological when it is not: several sessions opening at once
    /// on a cold cache all try to download the same driver and contend on its
    /// lock file, which is a stall, not a slowdown. CI has a cold cache every
    /// run, which is exactly where the specs run in parallel.
    ///
    /// # Errors
    ///
    /// Fails for the same reasons [`Browser::open`] does.
    pub async fn prepare() -> Result<()> {
        Self::open(&Profile::desktop()).await?.quit().await
    }

    /// The underlying session.
    pub fn driver(&self) -> &WebDriver {
        &self.driver
    }

    /// Ends the session.
    ///
    /// # Errors
    ///
    /// Fails when the driver refuses to close.
    pub async fn quit(self) -> Result<()> {
        self.driver.quit().await?;
        Ok(())
    }

    /// Taps at a viewport point, as a finger would.
    ///
    /// `Input.dispatchTouchEvent` is a plain CDP command, so this needs no
    /// event stream — which is the whole reason the touch spec ports without
    /// `BiDi`. Chrome turns the touch points into `pointerdown` / `pointerup`
    /// with `pointerType: 'touch'`, which is exactly what `addChartTouch` in
    /// `app.js` keys on.
    ///
    /// # Errors
    ///
    /// Fails when either CDP command is refused.
    pub async fn tap(&self, x: f64, y: f64) -> Result<()> {
        let point = json!([{ "x": x, "y": y, "id": 1 }]);
        self.cdp(
            "Input.dispatchTouchEvent",
            json!({
                "type": "touchStart",
                "touchPoints": point,
            }),
        )
        .await?;
        self.cdp(
            "Input.dispatchTouchEvent",
            json!({
                "type": "touchEnd",
                "touchPoints": json!([]),
            }),
        )
        .await?;
        Ok(())
    }

    /// Moves the mouse to a viewport point.
    ///
    /// # Errors
    ///
    /// Fails when the CDP command is refused.
    pub async fn mouse_move(&self, x: f64, y: f64) -> Result<()> {
        self.cdp(
            "Input.dispatchMouseEvent",
            json!({
                "type": "mouseMoved",
                "x": x,
                "y": y,
                "button": "none",
                "buttons": 0,
                "pointerType": "mouse",
            }),
        )
        .await?;
        Ok(())
    }

    /// Grows the emulated viewport to `height`, so a screenshot catches more of
    /// the page than the window shows.
    ///
    /// # Errors
    ///
    /// Fails when the CDP command is refused.
    pub async fn resize(&self, viewport: Viewport) -> Result<()> {
        self.driver
            .cdp()
            .emulation()
            .set_device_metrics_override(
                viewport.width,
                viewport.height,
                viewport.scale,
                viewport.mobile,
            )
            .await?;
        Ok(())
    }

    /// A PNG of the viewport, at the emulated device scale factor.
    ///
    /// `Page.captureScreenshot` rather than `WebDriver`'s "Take Screenshot":
    /// the latter is defined in CSS pixels, so the 2× shots the README uses
    /// would come back at 1×.
    ///
    /// # Errors
    ///
    /// Fails when the capture is refused or comes back as something other than
    /// base64.
    pub async fn screenshot_png(&self) -> Result<Vec<u8>> {
        use base64::Engine as _;
        let encoded = self.driver.cdp().page().capture_screenshot_base64().await?;
        Ok(base64::engine::general_purpose::STANDARD.decode(encoded)?)
    }

    /// Installs a script to run before the *next* document's own scripts.
    ///
    /// A profile carries the ones a whole suite needs; this is for the one
    /// scenario that installs its own mid-run — the dashboard's Throughput
    /// card, whose `Given` sets up the response override and whose `When`
    /// then navigates.
    ///
    /// # Errors
    ///
    /// Fails when the CDP command is refused.
    pub async fn add_init_script(&self, source: impl Into<String>) -> Result<()> {
        self.driver
            .cdp()
            .page()
            .add_script_to_evaluate_on_new_document(source.into())
            .await?;
        Ok(())
    }

    /// Sends a raw CDP command.
    ///
    /// # Errors
    ///
    /// Fails when the command is refused.
    pub async fn cdp(&self, method: &str, params: Value) -> Result<Value> {
        Ok(self.driver.cdp().send_raw(method, params).await?)
    }

    async fn apply(&self, profile: &Profile) -> Result<()> {
        let vp = profile.viewport;
        self.resize(vp).await?;
        if vp.touch {
            self.cdp(
                "Emulation.setTouchEmulationEnabled",
                json!({
                    "enabled": true,
                    "maxTouchPoints": 5,
                }),
            )
            .await?;
        }

        let mut features = Vec::new();
        if profile.reduced_motion {
            features.push(json!({ "name": "prefers-reduced-motion", "value": "reduce" }));
        }
        if let Some(scheme) = profile.color_scheme {
            features.push(json!({ "name": "prefers-color-scheme", "value": scheme }));
        }
        if !features.is_empty() {
            self.cdp(
                "Emulation.setEmulatedMedia",
                json!({
                    "media": "screen",
                    "features": features,
                }),
            )
            .await?;
        }

        if let Some(timezone) = profile.timezone {
            self.driver
                .cdp()
                .emulation()
                .set_timezone_override(timezone)
                .await?;
        }
        if let Some(locale) = profile.locale {
            self.driver
                .cdp()
                .emulation()
                .set_locale_override(locale)
                .await?;
        }

        for source in &profile.init_scripts {
            self.driver
                .cdp()
                .page()
                .add_script_to_evaluate_on_new_document(source.clone())
                .await?;
        }

        if profile.scripting == Scripting::Disabled {
            self.cdp(
                "Emulation.setScriptExecutionDisabled",
                json!({ "value": true }),
            )
            .await?;
        }
        Ok(())
    }
}

/// An init script that records every `fetch` the page makes, so a test can ask
/// what was sent without a request-interception stream.
///
/// Replaces `page.on('request', …)` and `page.waitForResponse(…)`: both of the
/// settings-page assertions are about *whether* a PUT went out and when, which
/// a wrapper answers exactly. `app.js` routes everything through `fetch`
/// (`api.request`), so nothing escapes this.
pub const RECORD_REQUESTS: &str = r"
    window.__requests = [];
    const __fetch = window.fetch;
    window.fetch = function (input, init) {
        const url = typeof input === 'string' ? input : input.url;
        const method = (init && init.method) || (input && input.method) || 'GET';
        window.__requests.push({ url: String(url), method: String(method).toUpperCase() });
        return __fetch.apply(this, arguments);
    };
";

/// An init script that rewrites the two rates on `/api/stats/summary`.
///
/// Replaces `page.route('**/api/stats/summary', …)`. Driving the real
/// 60-second window from a browser would mean generating live DNS traffic and
/// racing the logger's flush, so the figures are injected instead — see the
/// scenario in `dashboard.feature` for why they are chosen to differ.
pub fn override_summary(queries_1m: i64, total_today: i64) -> String {
    format!(
        r"
        const __fetch = window.fetch;
        window.fetch = async function (input, init) {{
            const url = typeof input === 'string' ? input : input.url;
            const res = await __fetch.apply(this, arguments);
            if (!String(url).includes('/api/stats/summary')) return res;
            const body = await res.clone().json();
            body.queries_1m = {queries_1m};
            body.total_today = {total_today};
            return new Response(JSON.stringify(body), {{
                status: res.status,
                headers: {{ 'content-type': 'application/json' }},
            }});
        }};
        "
    )
}
