//! The HTTP calls the suite makes on its own behalf, outside a browser.
//!
//! Replaces Playwright's `page.request` / `APIRequestContext`: the fixtures
//! that create the operator account, mint a second session, or ask whether a
//! filter rebuild has settled are ordinary requests, not things a user does.
//!
//! The CSRF guard (`src/admin/csrf.rs`) classifies a request with neither
//! `Sec-Fetch-Site` nor `Origin` as a non-browser caller and lets it through,
//! which is what makes these POSTs work without a token — the same reason
//! `page.request.post` worked before.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// The operator these tests create and sign in as.
pub const ADMIN_USERNAME: &str = "testuser";

/// Its password. Long enough to clear `MIN_PASSWORD_LENGTH`, and the same
/// string the setup-and-auth scenarios spell out in their Gherkin.
pub const ADMIN_PASSWORD: &str = "correct horse battery staple";

/// The name of the session cookie noadd sets.
pub const SESSION_COOKIE: &str = "session";

/// An HTTP client bound to one instance.
#[derive(Debug, Clone)]
pub struct Api {
    base: String,
    client: reqwest::Client,
}

impl Api {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            client: reqwest::Client::new(),
        }
    }

    /// `GET /api/health`, which also reports whether the instance is
    /// unconfigured (`needs_setup`).
    ///
    /// # Errors
    ///
    /// Fails when the instance is unreachable or answers something other than
    /// JSON.
    pub async fn health(&self) -> Result<Value> {
        let res = self
            .client
            .get(format!("{}/api/health", self.base))
            .send()
            .await
            .context("GET /api/health")?;
        Ok(res.json().await?)
    }

    /// Is this instance still waiting for its first operator account?
    ///
    /// # Errors
    ///
    /// Fails when `/api/health` cannot be read.
    pub async fn needs_setup(&self) -> Result<bool> {
        Ok(self.health().await?["needs_setup"]
            .as_bool()
            .unwrap_or(false))
    }

    /// Creates the first operator. Idempotent: a 409 means one already exists,
    /// which every caller here is happy with.
    ///
    /// # Errors
    ///
    /// Fails on any status other than 200 or 409.
    pub async fn setup(&self, username: &str, password: &str) -> Result<()> {
        let res = self
            .client
            .post(format!("{}/api/auth/setup", self.base))
            .json(&json!({ "username": username, "password": password }))
            .send()
            .await
            .context("POST /api/auth/setup")?;
        let status = res.status();
        if status.is_success() || status == reqwest::StatusCode::CONFLICT {
            return Ok(());
        }
        bail!("POST /api/auth/setup answered {status}");
    }

    /// Signs in and returns the session cookie's value.
    ///
    /// Handing the raw token back rather than a cookie jar is deliberate: it is
    /// replayed into the *browser* with `add_cookie`, which is how a spec skips
    /// a UI sign-in it is not there to test — and, more to the point, how it
    /// avoids spending the five-per-minute login budget on setup.
    ///
    /// # Errors
    ///
    /// Fails when the sign-in is refused or carries no session cookie.
    pub async fn login(&self, username: &str, password: &str) -> Result<String> {
        let res = self
            .client
            .post(format!("{}/api/auth/login", self.base))
            .json(&json!({ "username": username, "password": password }))
            .send()
            .await
            .context("POST /api/auth/login")?;
        anyhow::ensure!(res.status().is_success(), "login answered {}", res.status());

        for value in res.headers().get_all(reqwest::header::SET_COOKIE) {
            let raw = value.to_str().unwrap_or_default();
            if let Some(rest) = raw.strip_prefix(&format!("{SESSION_COOKIE}="))
                && let Some(token) = rest.split(';').next()
            {
                return Ok(token.to_string());
            }
        }
        bail!("no `{SESSION_COOKIE}` cookie in the login response")
    }

    /// Creates the operator and signs in, returning the session token.
    ///
    /// # Errors
    ///
    /// Fails when either half does.
    pub async fn provision(&self) -> Result<String> {
        self.setup(ADMIN_USERNAME, ADMIN_PASSWORD).await?;
        self.login(ADMIN_USERNAME, ADMIN_PASSWORD).await
    }

    /// Blocks until no filter rebuild is in flight.
    ///
    /// The appliance publishes rebuild state only on `GET /api/events`, so this
    /// reads the stream rather than polling a status endpoint. What makes that
    /// safe for a caller that may have arrived late is the opening `rebuild`
    /// event every connection is handed: a rebuild that finished before this
    /// call is reported as settled immediately, instead of leaving it waiting
    /// for an edge that has already passed.
    ///
    /// # Errors
    ///
    /// Fails when the stream is unreachable, closes early, or does not report a
    /// settled rebuild within `timeout`.
    pub async fn wait_until_rebuilt(&self, session: &str, timeout: Duration) -> Result<()> {
        tokio::time::timeout(timeout, self.read_until_rebuilt(session))
            .await
            .with_context(|| {
                format!("no settled `rebuild` event on /api/events within {timeout:?}")
            })?
    }

    async fn read_until_rebuilt(&self, session: &str) -> Result<()> {
        let mut res = self
            .client
            .get(format!("{}/api/events", self.base))
            .header(
                reqwest::header::COOKIE,
                format!("{SESSION_COOKIE}={session}"),
            )
            .send()
            .await
            .context("GET /api/events")?;
        if !res.status().is_success() {
            bail!("GET /api/events answered {}", res.status());
        }

        // Frames are separated by a blank line and can split across chunks, so
        // they are reassembled here rather than parsed a chunk at a time.
        let mut buf = String::new();
        while let Some(chunk) = res.chunk().await.context("reading /api/events")? {
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(end) = buf.find("\n\n") {
                let frame = buf[..end].to_string();
                buf.drain(..end + 2);
                if rebuild_settled(&frame) {
                    return Ok(());
                }
            }
        }
        bail!("/api/events closed before reporting a settled rebuild")
    }
}

/// Is this SSE frame a `rebuild` event saying nothing is in flight?
fn rebuild_settled(frame: &str) -> bool {
    let mut is_rebuild = false;
    let mut settled = false;
    for line in frame.lines() {
        if let Some(name) = line.strip_prefix("event:") {
            is_rebuild = name.trim() == "rebuild";
        } else if let Some(data) = line.strip_prefix("data:") {
            settled = serde_json::from_str::<Value>(data.trim())
                .ok()
                .and_then(|v| v["rebuilding"].as_bool())
                .is_some_and(|rebuilding| !rebuilding);
        }
    }
    is_rebuild && settled
}
