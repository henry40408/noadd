//! The browser session, and every emulation the suite depends on.
//!
//! `WebDriver::managed` fetches and supervises chromedriver but *not* the
//! browser: a local Chrome or Chromium is a prerequisite, and [`Browser::open`]
//! says so when it is missing because the raw driver error does not.
//!
//! Emulation is CDP:
//!
//! * Viewport — `Emulation.setDeviceMetricsOverride` for every profile, since
//!   `--window-size` sets the *outer* window. The no-JS specs need an exact
//!   1024×600 so the fixed status bar really overlaps the foot of the page.
//! * Touch — `Emulation.setTouchEmulationEnabled` plus `Input.dispatchTouchEvent`.
//! * Reduced motion / colour scheme — `Emulation.setEmulatedMedia`.
//! * No JS — `Emulation.setScriptExecutionDisabled`. It applies to the *next*
//!   document, so sessions are per-case and it is set before the first navigation.
//! * Init scripts — `Page.addScriptToEvaluateOnNewDocument` ([`RECORD_REQUESTS`],
//!   [`override_summary`]).
//!
//! `BiDi` is not enabled: CDP already covers all of this over the one connection.

use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use thirtyfour::prelude::*;

/// How long a query waits for a condition before giving up.
///
/// Paid in full only on a genuine failure, so it is sized for a two-core CI
/// runner driving several browsers, where 10 s was too short for a navigation.
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a query re-checks while waiting.
pub const WAIT_INTERVAL: Duration = Duration::from_millis(100);

/// Whether the page's own scripts run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scripting {
    /// The scripted path: `app.js` runs and enhances the server-rendered body.
    Enabled,
    /// The no-JS path: the page's own scripts never execute.
    Disabled,
}

/// An emulated viewport.
#[derive(Debug, Clone, Copy)]
pub struct Viewport {
    pub width: u32,
    pub height: u32,
    pub scale: f64,
    pub mobile: bool,
    pub touch: bool,
}

impl Viewport {
    /// Desktop Chrome.
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

    /// Pixel 5.
    pub const PIXEL_5: Self = Self {
        width: 393,
        height: 851,
        scale: 2.75,
        mobile: true,
        touch: true,
    };
}

/// How a browser session is emulated.
#[derive(Debug, Clone)]
pub struct Profile {
    pub scripting: Scripting,
    pub viewport: Viewport,
    pub reduced_motion: bool,
    /// `prefers-color-scheme`, when the case cares which one it gets.
    pub color_scheme: Option<&'static str>,
    /// IANA zone the page's clock reports (the screenshots pin UTC to match the seed).
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

    /// Scripts off, reduced motion, 1024×600: the four no-JS specs' profile.
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
        // The W3C default "dismiss and notify" would answer a `confirm()` (e.g.
        // the account page's "log out other sessions") with Cancel; `ignore`
        // leaves it for `accept_alert`.
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
    /// `WebDriver::managed` builds a new manager per call, so parallel sessions
    /// on a cold cache (every CI run) all download the driver and stall on its
    /// lock file.
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
    /// Chrome turns the touch points into `pointerdown` / `pointerup` with
    /// `pointerType: 'touch'`, which `addChartTouch` in `app.js` keys on.
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

    /// Re-emulates the viewport, e.g. taller so a screenshot catches more of the page.
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
    /// `Page.captureScreenshot`, because `WebDriver`'s "Take Screenshot" is in
    /// CSS pixels and would return the README's 2× shots at 1×.
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
    /// For a scenario that installs one mid-run (the dashboard's Throughput
    /// card); suite-wide scripts belong on the [`Profile`].
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
/// `app.js` routes every call through `fetch` (`api.request`), so nothing escapes it.
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

/// An init script that rewrites `queries_1m` and `total_today` in the summary
/// of every pushed `stats` event, rather than generating live DNS traffic and
/// racing the logger's flush.
pub fn override_summary(queries_1m: i64, total_today: i64) -> String {
    // Patches `EventSource`, not `fetch`: the dashboard's readings arrive on the
    // event stream. `MessageEvent.data` is read-only, so the listener gets a
    // reconstructed event.
    format!(
        r"
        const __add = EventSource.prototype.addEventListener;
        EventSource.prototype.addEventListener = function (type, fn, opts) {{
            if (type !== 'stats' || typeof fn !== 'function') {{
                return __add.call(this, type, fn, opts);
            }}
            return __add.call(this, type, function (e) {{
                let data;
                try {{ data = JSON.parse(e.data); }} catch (_) {{ return fn(e); }}
                if (data && data.summary) {{
                    data.summary.queries_1m = {queries_1m};
                    data.summary.total_today = {total_today};
                }}
                fn(new MessageEvent(e.type, {{ data: JSON.stringify(data) }}));
            }}, opts);
        }};
        "
    )
}
