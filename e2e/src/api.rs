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

    /// Is a filter rebuild still in flight?
    ///
    /// # Errors
    ///
    /// Fails when the endpoint is unreachable or answers something other than
    /// the expected JSON.
    pub async fn rebuilding(&self, session: &str) -> Result<bool> {
        let res = self
            .client
            .get(format!("{}/api/filter/rebuild-status", self.base))
            .header(
                reqwest::header::COOKIE,
                format!("{SESSION_COOKIE}={session}"),
            )
            .send()
            .await
            .context("GET /api/filter/rebuild-status")?;
        let body: Value = res.json().await?;
        Ok(body["rebuilding"].as_bool().unwrap_or(false))
    }
}
