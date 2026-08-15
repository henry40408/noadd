//! A page and a locator, in the shape the ported tests already spoke.
//!
//! Playwright's locator is lazy and its `expect` retries; `WebDriver`'s
//! `WebElement` is a handle to one element found once, and nothing retries. The
//! suite this replaces leaned on that behaviour 208 times, so rebuilding it is
//! not optional — [`Locator`] resolves its selector on every call and every
//! `expect_*` polls through [`crate::wait`].
//!
//! Two Playwright conveniences are rebuilt rather than imitated:
//!
//! * `locator.filter({ hasText })` — [`Locator::having_text`], applied after
//!   the selector because CSS cannot express it. The filter-list rows keyed by
//!   a name carrying a double quote are exactly why: `[data-name="q\" …"]` is
//!   not a selector anyone should have to write.
//! * `click({ force: true })` — [`Locator::click_js`]. Playwright's `force`
//!   skips the actionability checks; the equivalent here is to activate the
//!   element directly instead of aiming a synthetic pointer at its centre.
//!   Both no-JS suites need it for the same reason they needed it before: the
//!   status bar is `position: fixed` at the foot of the viewport and swallows a
//!   click aimed at what sits under it, and a card still running its fade-in is
//!   a moving target.

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use thirtyfour::prelude::*;
use thirtyfour::{Key, session::handle::SessionHandle};

use crate::wait::{eventually, eventually_eq};

/// One instance's admin UI, in one browser session.
#[derive(Debug, Clone)]
pub struct Page {
    handle: Arc<SessionHandle>,
    base: String,
}

impl Page {
    /// Binds a session to an origin.
    pub fn new(driver: &WebDriver, base: impl Into<String>) -> Self {
        Self {
            handle: Arc::clone(driver),
            base: base.into(),
        }
    }

    /// The origin this page navigates against.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Navigates to a path on this instance, or to an absolute URL.
    ///
    /// # Errors
    ///
    /// Fails when the navigation does not complete.
    pub async fn goto(&self, path: &str) -> Result<()> {
        let url = if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}{path}", self.base)
        };
        self.handle.goto(url).await?;
        Ok(())
    }

    /// Reloads the current document.
    ///
    /// # Errors
    ///
    /// Fails when the reload does not complete.
    pub async fn reload(&self) -> Result<()> {
        self.handle.refresh().await?;
        Ok(())
    }

    /// The current URL, as a string.
    ///
    /// # Errors
    ///
    /// Fails when the driver cannot report one.
    pub async fn url(&self) -> Result<String> {
        Ok(self.handle.current_url().await?.to_string())
    }

    /// Replays an API session into the browser.
    ///
    /// A cookie can only be set for the document's own origin, so this lands on
    /// the instance first. That first request is the sign-in page, which is
    /// cheap and — unlike a UI sign-in — spends none of the five-per-minute
    /// login budget the tests that follow are there to exercise.
    ///
    /// # Errors
    ///
    /// Fails when the navigation or the cookie is refused.
    pub async fn adopt_session(&self, token: &str) -> Result<()> {
        self.goto("/").await?;
        let mut cookie = Cookie::new(crate::api::SESSION_COOKIE, token);
        cookie.set_path("/");
        cookie.set_domain("127.0.0.1");
        self.handle.add_cookie(cookie).await?;
        Ok(())
    }

    /// A locator for a CSS selector.
    pub fn loc(&self, css: impl Into<String>) -> Locator {
        Locator {
            handle: Arc::clone(&self.handle),
            css: css.into(),
            has_text: None,
            index: None,
            within: None,
        }
    }

    /// A locator for a `data-testid`, which is how most of this UI is addressed.
    pub fn testid(&self, id: &str) -> Locator {
        self.loc(format!("[data-testid=\"{id}\"]"))
    }

    /// Runs a script in the page and returns its value.
    ///
    /// The driver can inject script into a page whose *own* scripts are
    /// disabled — `Emulation.setScriptExecutionDisabled` stops the document's
    /// scripts, not `Execute Script` — so this works in the no-JS suites too,
    /// which is what makes the "is any of this text on screen" checks portable
    /// across both.
    ///
    /// # Errors
    ///
    /// Fails when the script throws.
    pub async fn eval(&self, script: &str) -> Result<Value> {
        Ok(self
            .handle
            .execute(script, Vec::new())
            .await?
            .json()
            .clone())
    }

    /// Is this string among the page's text?
    ///
    /// Replaces `page.getByText(name, { exact: false }).first()` followed by
    /// `toBeVisible`. It walks the document's text nodes rather than reading
    /// `innerText`, for the reason set out on [`Locator::text`]: `innerText` is
    /// the *rendered* form, and this UI puts `text-transform: uppercase` on
    /// section headings — so "Database Health" would never be found by a check
    /// that only sees "DATABASE HEALTH".
    ///
    /// `<script>` and `<style>` are skipped, which is the difference between
    /// this and a bare `document.body.textContent`.
    ///
    /// ⚠️ It walks the elements itself rather than using a `TreeWalker`,
    /// because a `TreeWalker`'s `acceptNode` filter is *page* script: with
    /// `Emulation.setScriptExecutionDisabled` in force the DOM refuses to call
    /// it, and the whole script fails with "the provided callback is no longer
    /// runnable". `Execute Script` still runs — it is the document's own
    /// scripting that is off — so anything callback-free is fine.
    ///
    /// # Errors
    ///
    /// Fails when the script cannot run.
    pub async fn has_text(&self, needle: &str) -> Result<bool> {
        let found = self
            .handle
            .execute(
                r"
                let text = '';
                for (const el of document.body.querySelectorAll('*')) {
                    if (el.tagName === 'SCRIPT' || el.tagName === 'STYLE') { continue; }
                    for (const child of el.childNodes) {
                        if (child.nodeType === Node.TEXT_NODE) { text += child.nodeValue + '\n'; }
                    }
                }
                return text.includes(arguments[0]);
                ",
                vec![json!(needle)],
            )
            .await?
            .json()
            .as_bool()
            .unwrap_or(false);
        Ok(found)
    }

    /// Waits until the page shows this text.
    ///
    /// # Errors
    ///
    /// Fails when it never does.
    pub async fn expect_text(&self, needle: &str) -> Result<()> {
        eventually(&format!("page shows {needle:?}"), || async {
            Ok((
                self.has_text(needle).await?,
                format!("no {needle:?} on screen"),
            ))
        })
        .await
    }

    /// Waits until the URL contains `needle`.
    ///
    /// # Errors
    ///
    /// Fails when it never does.
    pub async fn expect_url_contains(&self, needle: &str) -> Result<()> {
        eventually(&format!("url contains {needle:?}"), || async {
            let url = self.url().await?;
            Ok((url.contains(needle), url))
        })
        .await
    }

    /// Waits until the URL ends with `suffix` — the `toHaveURL(/…$/)` shape.
    ///
    /// # Errors
    ///
    /// Fails when it never does.
    pub async fn expect_url_ends_with(&self, suffix: &str) -> Result<()> {
        eventually(&format!("url ends with {suffix:?}"), || async {
            let url = self.url().await?;
            Ok((url.ends_with(suffix), url))
        })
        .await
    }

    /// Answers a `confirm()` with OK.
    ///
    /// The session runs with `unhandledPromptBehavior: "ignore"`, so the dialog
    /// is still standing when this is called — the W3C default would have
    /// answered Cancel before the test got a say.
    ///
    /// # Errors
    ///
    /// Fails when no dialog appears within the wait.
    pub async fn accept_dialog(&self) -> Result<()> {
        eventually("a confirm() to answer", || async {
            match self.handle.accept_alert().await {
                Ok(()) => Ok((true, String::new())),
                Err(e) => Ok((false, format!("no dialog yet ({e})"))),
            }
        })
        .await
    }

    /// Waits until the page has made no new network request for a beat.
    ///
    /// Replaces `waitForLoadState('networkidle')`, which only one step used —
    /// the sweep that visits every tab and looks for markup rendered as text.
    /// The resource timeline is the same signal, read from the page rather than
    /// from the driver.
    ///
    /// # Errors
    ///
    /// Fails when the page never goes quiet.
    pub async fn wait_for_network_idle(&self) -> Result<()> {
        let count = || async {
            Ok::<_, anyhow::Error>(
                self.eval("return performance.getEntriesByType('resource').length;")
                    .await?
                    .as_u64()
                    .unwrap_or(0),
            )
        };
        // Written as a plain loop rather than through `eventually`: the
        // previous reading has to survive between polls, and a `FnMut` closure
        // cannot lend a captured variable to the future it returns.
        let deadline = std::time::Instant::now() + crate::browser::WAIT_TIMEOUT;
        let mut last = count().await?;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let now = count().await?;
            if now == last {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("the page never went quiet: {now} resources and still counting");
            }
            last = now;
        }
    }

    /// Every `fetch` the page has made, as `(method, url)` pairs.
    ///
    /// Only meaningful with [`crate::browser::RECORD_REQUESTS`] installed;
    /// without it the page has no `__requests` and this reports none.
    ///
    /// # Errors
    ///
    /// Fails when the script cannot run.
    pub async fn requests(&self) -> Result<Vec<(String, String)>> {
        let raw = self.eval("return window.__requests || [];").await?;
        Ok(raw
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| {
                        (
                            entry["method"].as_str().unwrap_or_default().to_string(),
                            entry["url"].as_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// How many recorded requests were `method` against a URL containing `path`.
    ///
    /// # Errors
    ///
    /// Fails when the recorded requests cannot be read.
    pub async fn request_count(&self, method: &str, path: &str) -> Result<usize> {
        Ok(self
            .requests()
            .await?
            .iter()
            .filter(|(m, url)| m == method && url.contains(path))
            .count())
    }

    /// Waits for one more `method` request to `path` than there were before.
    ///
    /// Replaces `page.waitForResponse(...)`, whose only job in these tests was
    /// to keep a reload from racing the save it was checking.
    ///
    /// # Errors
    ///
    /// Fails when no such request is made in time.
    pub async fn expect_request(&self, method: &str, path: &str, before: usize) -> Result<()> {
        eventually(&format!("a {method} to {path}"), || async {
            let now = self.request_count(method, path).await?;
            Ok((now > before, format!("{now} seen, was {before}")))
        })
        .await
    }
}

/// A lazily-resolved selector, with the filters the ported tests used.
#[derive(Debug, Clone)]
pub struct Locator {
    handle: Arc<SessionHandle>,
    css: String,
    has_text: Option<String>,
    index: Option<usize>,
    within: Option<Arc<Locator>>,
}

impl Locator {
    /// Narrows to the elements whose rendered text contains `text`.
    pub fn having_text(mut self, text: impl Into<String>) -> Self {
        self.has_text = Some(text.into());
        self
    }

    /// The nth match, zero-based.
    pub fn nth(mut self, index: usize) -> Self {
        self.index = Some(index);
        self
    }

    /// The first match.
    pub fn first(self) -> Self {
        self.nth(0)
    }

    /// A locator scoped to this one's first match — `row.getByTestId(…)`.
    pub fn loc(&self, css: impl Into<String>) -> Self {
        Self {
            handle: Arc::clone(&self.handle),
            css: css.into(),
            has_text: None,
            index: None,
            within: Some(Arc::new(self.clone())),
        }
    }

    /// A `data-testid` scoped to this one's first match.
    pub fn testid(&self, id: &str) -> Self {
        self.loc(format!("[data-testid=\"{id}\"]"))
    }

    /// Every element this locator currently matches.
    ///
    /// # Errors
    ///
    /// Fails on a driver error; matching nothing is an empty `Vec`.
    pub async fn all(&self) -> Result<Vec<WebElement>> {
        let found = match &self.within {
            Some(parent) => {
                let Some(scope) = Box::pin(parent.opt()).await? else {
                    return Ok(Vec::new());
                };
                scope.find_all(By::Css(self.css.as_str())).await?
            }
            None => self.handle.find_all(By::Css(self.css.as_str())).await?,
        };

        let mut matched = Vec::new();
        for element in found {
            if let Some(text) = &self.has_text
                && !text_content(&self.handle, &element)
                    .await
                    .unwrap_or_default()
                    .contains(text.as_str())
            {
                continue;
            }
            matched.push(element);
        }
        match self.index {
            Some(i) => Ok(matched.into_iter().skip(i).take(1).collect()),
            None => Ok(matched),
        }
    }

    /// The first match, or `None`.
    ///
    /// # Errors
    ///
    /// Fails on a driver error.
    pub async fn opt(&self) -> Result<Option<WebElement>> {
        Ok(self.all().await?.into_iter().next())
    }

    /// The first match, waiting for it to appear.
    ///
    /// # Errors
    ///
    /// Fails when nothing matches within the wait.
    pub async fn get(&self) -> Result<WebElement> {
        self.expect_count_at_least(1).await?;
        self.opt()
            .await?
            .with_context(|| format!("no element matches {}", self.describe()))
    }

    /// How many elements match right now.
    ///
    /// # Errors
    ///
    /// Fails on a driver error.
    pub async fn count(&self) -> Result<usize> {
        Ok(self.all().await?.len())
    }

    /// The first match's text, with whitespace normalised.
    ///
    /// `textContent`, not `WebElement::text`. `WebDriver`'s "Get Element Text" is
    /// the *rendered* form, which applies `text-transform` — and this UI
    /// uppercases badges and section headings in CSS, so a verdict written
    /// `Blocked` comes back as `BLOCKED`. Playwright's text assertions read
    /// `textContent`, so every ported assertion is phrased against the markup's
    /// casing; reading the rendered form would have meant rewriting all of them
    /// to match a stylesheet.
    ///
    /// # Errors
    ///
    /// Fails when nothing matches.
    pub async fn text(&self) -> Result<String> {
        Ok(normalize(&self.text_raw().await?))
    }

    /// The first match's `textContent`, untouched.
    ///
    /// For the one caller that needs the line breaks: a query-log row's domain
    /// cell carries the domain on its first line and metadata under it.
    ///
    /// # Errors
    ///
    /// Fails when nothing matches.
    pub async fn text_raw(&self) -> Result<String> {
        let element = self.get().await?;
        text_content(&self.handle, &element).await
    }

    /// The first match's `value` property.
    ///
    /// # Errors
    ///
    /// Fails when nothing matches.
    pub async fn value(&self) -> Result<String> {
        Ok(self.get().await?.prop("value").await?.unwrap_or_default())
    }

    /// An attribute of the first match.
    ///
    /// # Errors
    ///
    /// Fails when nothing matches.
    pub async fn attr(&self, name: &str) -> Result<Option<String>> {
        Ok(self.get().await?.attr(name).await?)
    }

    /// Is the first match a ticked checkbox?
    ///
    /// # Errors
    ///
    /// Fails when nothing matches.
    pub async fn is_checked(&self) -> Result<bool> {
        Ok(self.get().await?.is_selected().await?)
    }

    /// Is any match displayed?
    ///
    /// # Errors
    ///
    /// Fails on a driver error.
    pub async fn is_visible(&self) -> Result<bool> {
        for element in self.all().await? {
            if element.is_displayed().await.unwrap_or(false) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // --- actions ---------------------------------------------------------

    /// Clears the field and types `text` into it.
    ///
    /// Real key events rather than an assigned `value`, which matters: the
    /// settings page fires on `change`, not `input`, and the whole point of one
    /// of its tests is that typing mid-value sends nothing.
    ///
    /// # Errors
    ///
    /// Fails when the field is missing.
    pub async fn fill(&self, text: &str) -> Result<()> {
        let element = self.get().await?;
        element.clear().await?;
        if !text.is_empty() {
            element.send_keys(text).await?;
        }
        Ok(())
    }

    /// Types into the field without clearing it first.
    ///
    /// # Errors
    ///
    /// Fails when the field is missing.
    pub async fn type_text(&self, text: &str) -> Result<()> {
        self.get().await?.send_keys(text).await?;
        Ok(())
    }

    /// Presses Enter in the field, which is how a browser submits a form that
    /// has a submit button in it — a real path, and the one a keyboard user
    /// takes. It is also independent of where the button ended up, which the
    /// fixed status bar makes a live concern on a short viewport.
    ///
    /// # Errors
    ///
    /// Fails when the field is missing.
    pub async fn press_enter(&self) -> Result<()> {
        self.get().await?.send_keys(Key::Enter).await?;
        Ok(())
    }

    /// Clicks the element, scrolling it into view first.
    ///
    /// # Errors
    ///
    /// Fails when the element is missing or refuses the click.
    pub async fn click(&self) -> Result<()> {
        let element = self.get().await?;
        element.scroll_into_view().await?;
        element.click().await?;
        Ok(())
    }

    /// Activates the element directly — the stand-in for `click({force:true})`.
    ///
    /// # Errors
    ///
    /// Fails when the element is missing.
    pub async fn click_js(&self) -> Result<()> {
        let element = self.get().await?;
        self.handle
            .execute("arguments[0].click();", vec![element.to_json()?])
            .await?;
        Ok(())
    }

    /// Selects an `<option>` by value, firing the `change` the page listens for.
    ///
    /// # Errors
    ///
    /// Fails when the select or the option is missing.
    pub async fn select_value(&self, value: &str) -> Result<()> {
        use thirtyfour::components::SelectElement;
        let element = self.get().await?;
        SelectElement::new(&element)
            .await?
            .select_by_value(value)
            .await?;
        Ok(())
    }

    /// Blurs the field, which is what commits a value on the settings page.
    ///
    /// # Errors
    ///
    /// Fails when the field is missing.
    pub async fn blur(&self) -> Result<()> {
        let element = self.get().await?;
        self.handle
            .execute("arguments[0].blur();", vec![element.to_json()?])
            .await?;
        Ok(())
    }

    /// The centre of the first match, in viewport coordinates.
    ///
    /// `WebElement::rect` reports document coordinates, which is the wrong
    /// frame for `Input.dispatchTouchEvent`.
    ///
    /// # Errors
    ///
    /// Fails when the element is missing.
    pub async fn viewport_center(&self) -> Result<(f64, f64)> {
        let (x, y, width, height) = self.viewport_rect().await?;
        Ok((x + width / 2.0, y + height / 2.0))
    }

    /// The first match's `getBoundingClientRect`, as `(x, y, width, height)` —
    /// Playwright's `boundingBox()`.
    ///
    /// # Errors
    ///
    /// Fails when the element is missing.
    pub async fn viewport_rect(&self) -> Result<(f64, f64, f64, f64)> {
        let element = self.get().await?;
        element.scroll_into_view().await?;
        let rect = self
            .handle
            .execute(
                "const r = arguments[0].getBoundingClientRect();
                 return [r.left, r.top, r.width, r.height];",
                vec![element.to_json()?],
            )
            .await?
            .json()
            .clone();
        let at = |i: usize| rect[i].as_f64().context("incomplete element rect");
        Ok((at(0)?, at(1)?, at(2)?, at(3)?))
    }

    // --- assertions ------------------------------------------------------

    /// `toBeVisible`.
    ///
    /// # Errors
    ///
    /// Fails when nothing matching is displayed within the wait.
    pub async fn expect_visible(&self) -> Result<()> {
        eventually(&format!("{} is visible", self.describe()), || async {
            let count = self.count().await?;
            Ok((
                self.is_visible().await?,
                format!("{count} match(es), none displayed"),
            ))
        })
        .await
    }

    /// `toBeHidden` / `not.toBeVisible` — absent counts as hidden, as in
    /// Playwright.
    ///
    /// # Errors
    ///
    /// Fails when it stays visible.
    pub async fn expect_hidden(&self) -> Result<()> {
        eventually(&format!("{} is hidden", self.describe()), || async {
            Ok((!self.is_visible().await?, "still displayed".into()))
        })
        .await
    }

    /// `toHaveCount`.
    ///
    /// # Errors
    ///
    /// Fails when the count never settles on `expected`.
    pub async fn expect_count(&self, expected: usize) -> Result<()> {
        eventually_eq(&format!("{} count", self.describe()), expected, || async {
            self.count().await
        })
        .await
    }

    /// `expect(count).toBeGreaterThan(n - 1)`.
    ///
    /// # Errors
    ///
    /// Fails when fewer than `least` ever match.
    pub async fn expect_count_at_least(&self, least: usize) -> Result<()> {
        eventually(
            &format!("{} matches at least {least}", self.describe()),
            || async {
                let count = self.count().await?;
                Ok((count >= least, format!("{count} match(es)")))
            },
        )
        .await
    }

    /// `toContainText`.
    ///
    /// # Errors
    ///
    /// Fails when the text never appears.
    pub async fn expect_text_contains(&self, needle: &str) -> Result<()> {
        eventually(
            &format!("{} contains {needle:?}", self.describe()),
            || async {
                let text = self.text().await?;
                Ok((text.contains(needle), format!("{text:?}")))
            },
        )
        .await
    }

    /// The negative of [`Locator::expect_text_contains`], checked once the
    /// element is there — an absence that is only true because the page has not
    /// rendered yet is not the absence these tests mean.
    ///
    /// # Errors
    ///
    /// Fails when the text is present.
    pub async fn expect_text_excludes(&self, needle: &str) -> Result<()> {
        let text = self.text().await?;
        anyhow::ensure!(
            !text.contains(needle),
            "{} should not contain {needle:?}, but reads {text:?}",
            self.describe()
        );
        Ok(())
    }

    /// `toHaveText` — the whole rendered text, with whitespace normalised the
    /// way Playwright normalised it, so a line break in the markup does not
    /// decide whether an assertion holds.
    ///
    /// # Errors
    ///
    /// Fails when it never matches.
    pub async fn expect_text_eq(&self, expected: &str) -> Result<()> {
        eventually_eq(
            &format!("{} text", self.describe()),
            normalize(expected),
            || async { self.text().await },
        )
        .await
    }

    /// `toHaveValue`.
    ///
    /// # Errors
    ///
    /// Fails when the value never matches.
    pub async fn expect_value(&self, expected: &str) -> Result<()> {
        eventually_eq(
            &format!("{} value", self.describe()),
            expected.to_string(),
            || async { self.value().await },
        )
        .await
    }

    /// `toHaveValue(/^prefix/)`.
    ///
    /// # Errors
    ///
    /// Fails when the value never starts with `prefix`.
    pub async fn expect_value_starts_with(&self, prefix: &str) -> Result<()> {
        eventually(
            &format!("{} value starts with {prefix:?}", self.describe()),
            || async {
                let value = self.value().await?;
                Ok((value.starts_with(prefix), format!("{value:?}")))
            },
        )
        .await
    }

    /// `not.toBeEmpty()` on a field.
    ///
    /// # Errors
    ///
    /// Fails when the value stays empty.
    pub async fn expect_value_not_empty(&self) -> Result<()> {
        eventually(&format!("{} has a value", self.describe()), || async {
            let value = self.value().await?;
            Ok((!value.is_empty(), format!("{value:?}")))
        })
        .await
    }

    /// `toHaveClass(/name/)`.
    ///
    /// # Errors
    ///
    /// Fails when the class never appears.
    pub async fn expect_class(&self, name: &str) -> Result<()> {
        eventually(
            &format!("{} carries the {name:?} class", self.describe()),
            || async {
                let classes = self.get().await?.class_name().await?.unwrap_or_default();
                Ok((
                    classes.split_whitespace().any(|c| c == name),
                    format!("{classes:?}"),
                ))
            },
        )
        .await
    }

    /// `not.toHaveClass(/name/)`.
    ///
    /// # Errors
    ///
    /// Fails when the class stays.
    pub async fn expect_not_class(&self, name: &str) -> Result<()> {
        eventually(
            &format!("{} drops the {name:?} class", self.describe()),
            || async {
                let classes = self.get().await?.class_name().await?.unwrap_or_default();
                Ok((
                    !classes.split_whitespace().any(|c| c == name),
                    format!("{classes:?}"),
                ))
            },
        )
        .await
    }

    /// `toBeChecked({ checked })`.
    ///
    /// # Errors
    ///
    /// Fails when the box never settles into that state.
    pub async fn expect_checked(&self, checked: bool) -> Result<()> {
        eventually_eq(&format!("{} checked", self.describe()), checked, || async {
            self.is_checked().await
        })
        .await
    }

    /// `toHaveAttribute`.
    ///
    /// # Errors
    ///
    /// Fails when the attribute never has that value.
    pub async fn expect_attr(&self, name: &str, expected: &str) -> Result<()> {
        eventually_eq(
            &format!("{} @{name}", self.describe()),
            Some(expected.to_string()),
            || async { self.attr(name).await },
        )
        .await
    }

    fn describe(&self) -> String {
        let mut description = match &self.within {
            Some(parent) => format!("{} within {}", self.css, parent.describe()),
            None => self.css.clone(),
        };
        if let Some(text) = &self.has_text {
            let _ = write!(description, " having text {text:?}");
        }
        if let Some(index) = self.index {
            let _ = write!(description, " [{index}]");
        }
        description
    }
}

/// Fails with `message` — the shape a ported `expect(x).toBe(y)` takes when
/// there is nothing to poll for.
///
/// # Errors
///
/// Always, when `condition` is false.
pub fn ensure(condition: bool, message: impl std::fmt::Display) -> Result<()> {
    if condition {
        Ok(())
    } else {
        bail!("{message}")
    }
}

/// Trims and collapses runs of whitespace, as Playwright's text assertions did.
fn normalize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// An element's `textContent` — see [`Locator::text`] for why not its rendered
/// text.
async fn text_content(handle: &Arc<SessionHandle>, element: &WebElement) -> Result<String> {
    Ok(handle
        .execute("return arguments[0].textContent;", vec![element.to_json()?])
        .await?
        .json()
        .as_str()
        .unwrap_or_default()
        .to_string())
}

/// A step failure that prints its whole context chain.
///
/// `cucumber`'s codegen turns a non-unit return into
/// `unwrap_or_else(|e| panic!("{}", e))`, and `anyhow`'s `Display` prints only
/// the outermost message — so "no element matches …" would arrive without the
/// "while signing in" that explains where it came from. This prints `{:#}`
/// instead, which is the whole chain on one line.
#[derive(Debug)]
pub struct StepError(anyhow::Error);

impl std::fmt::Display for StepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.0)
    }
}

impl<E: Into<anyhow::Error>> From<E> for StepError {
    fn from(error: E) -> Self {
        Self(error.into())
    }
}

/// What every step function returns.
pub type StepResult = Result<(), StepError>;
