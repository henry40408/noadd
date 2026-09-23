//! The HTTP calls the suite makes on its own behalf, outside a browser: creating
//! the operator, minting sessions, waiting for a filter rebuild.
//!
//! These POSTs pass the CSRF guard (`src/admin/csrf.rs`) because a request with
//! neither `Sec-Fetch-Site` nor `Origin` counts as a non-browser caller.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// The operator these tests create and sign in as.
pub const ADMIN_USERNAME: &str = "testuser";

/// Its password: clears `MIN_PASSWORD_LENGTH`, and matches the Gherkin.
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

    /// Creates the first operator. Idempotent: a 409 (one exists) is success.
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
    /// The raw token is replayed into the browser with `add_cookie`, so a spec
    /// skips the UI sign-in without spending the five-per-minute login budget.
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

    /// `GET` a JSON endpoint as the operator `session` belongs to.
    ///
    /// # Errors
    ///
    /// Fails when the instance is unreachable, answers a non-success status, or
    /// answers something other than JSON.
    pub async fn get_json(&self, session: &str, path: &str) -> Result<Value> {
        let res = self
            .client
            .get(format!("{}{path}", self.base))
            .header(
                reqwest::header::COOKIE,
                format!("{SESSION_COOKIE}={session}"),
            )
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        anyhow::ensure!(
            res.status().is_success(),
            "GET {path} answered {}",
            res.status()
        );
        Ok(res.json().await?)
    }

    /// Blocks until no filter rebuild is in flight.
    ///
    /// Rebuild state is published only on `GET /api/events`. Every connection
    /// opens with a `rebuild` event, so a rebuild that already finished is
    /// reported as settled at once rather than waited for.
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

        // Frames end at a blank line and can split across chunks.
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
