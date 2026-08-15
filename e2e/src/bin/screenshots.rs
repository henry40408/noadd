//! The README screenshot pipeline, re-runnable end to end:
//!
//! ```text
//! wipe DB -> boot #1 (schema + defaults) -> POST /api/auth/setup -> stop
//!   -> sqlite3 seed (backdated 90d traffic) -> boot #2 -> login -> capture
//! ```
//!
//! Run it from `e2e/` with `cargo run --bin screenshots`. It writes the same
//! seven PNGs into `docs/screenshots/` that `npm run screenshots` did, at the
//! same sizes and in the same order.
//!
//! Two things changed in the port, both deliberate:
//!
//! * **The routes are paths.** The JavaScript version still asked for
//!   `#dashboard`, `#stats`, `#logs` and `#filters` — fragments from the
//!   client-routed era, which arrived at the right page only because `app.js`
//!   opens with a `LEGACY_HASH_ROUTES` rewrite for exactly those bookmarks.
//!   Asking for the real path skips the redirect, and stops these shots being
//!   the reason that shim cannot be retired.
//! * **`networkidle` and `document.fonts.ready` are gone**, because neither was
//!   the signal. What each page is waited for is its own rendered content,
//!   which is what the `WAITS` table already spelled out. The fonts wait in
//!   particular could never have done anything: `app.css` declares no
//!   `@font-face` at all — the whole UI is `--font-mono` and `--font-sans`
//!   resolved to system faces — so there is nothing to load and nothing to
//!   await. Reimplemented faithfully, it timed out on every capture.

use std::path::Path;

use anyhow::{Context, Result};
use noadd_e2e::browser::{Browser, Profile, Viewport};
use noadd_e2e::dom::Page;
use noadd_e2e::{ADMIN_PASSWORD, ADMIN_USERNAME, Api, Server, ports, seed, server};

/// Desktop captures: a 1280×800 viewport at 2×, as the README shows them.
const DESKTOP: Viewport = Viewport {
    width: 1280,
    height: 800,
    scale: 2.0,
    mobile: false,
    touch: false,
};

/// Mobile captures: a 375×812 viewport at 2×, with touch.
const MOBILE: Viewport = Viewport {
    width: 375,
    height: 812,
    scale: 2.0,
    mobile: true,
    touch: true,
};

/// Freezes fade-in animations and carets so re-runs are pixel-stable.
///
/// Both `animation-duration` *and* `animation-delay` collapse to zero: the
/// staggered `.fade-in` cards would otherwise be caught mid-delay at their
/// `opacity: 0` start rather than at the end state the shot is meant to show.
const FREEZE: &str = "*{animation-duration:0s !important;animation-delay:0s !important;\
                      transition:none !important;caret-color:transparent !important}";

/// Which page's content a shot waits for before the shutter.
#[derive(Debug, Clone, Copy)]
enum Wait {
    Dashboard,
    Stats,
    Logs,
    LogsMobile,
    Filters,
}

/// One capture: where to go, what to wait for, and how to render it.
struct Shot {
    file: &'static str,
    route: &'static str,
    wait: Wait,
    scheme: &'static str,
    viewport: Viewport,
}

/// Viewport-only captures: each shot is exactly the visible viewport (a clean
/// "above the fold" single-screen composition), not the entire scrolling page.
/// The `position: fixed` status bar legitimately sits at the bottom edge — it
/// is part of the aesthetic and exactly how the live app renders — so it stays
/// visible.
const SHOTS: &[Shot] = &[
    Shot {
        file: "dashboard-dark.png",
        route: "/",
        wait: Wait::Dashboard,
        scheme: "dark",
        viewport: DESKTOP,
    },
    Shot {
        file: "statistics-dark.png",
        route: "/stats",
        wait: Wait::Stats,
        scheme: "dark",
        viewport: DESKTOP,
    },
    Shot {
        file: "query-log-dark.png",
        route: "/logs",
        wait: Wait::Logs,
        scheme: "dark",
        viewport: DESKTOP,
    },
    Shot {
        file: "filters-dark.png",
        route: "/filters",
        wait: Wait::Filters,
        scheme: "dark",
        viewport: DESKTOP,
    },
    Shot {
        file: "statistics-light.png",
        route: "/stats",
        wait: Wait::Stats,
        scheme: "light",
        viewport: DESKTOP,
    },
    Shot {
        file: "dashboard-mobile.png",
        route: "/",
        wait: Wait::Dashboard,
        scheme: "dark",
        viewport: MOBILE,
    },
    Shot {
        file: "query-log-mobile.png",
        route: "/logs",
        wait: Wait::LogsMobile,
        scheme: "dark",
        viewport: MOBILE,
    },
];

#[tokio::main]
async fn main() -> Result<()> {
    let out = server::repo_root().join("docs/screenshots");
    tokio::fs::create_dir_all(&out).await?;

    // Phase 1: boot fresh, create the operator through the product's own setup
    // flow, stop.
    let mut noadd =
        Server::fresh("screenshots", ports::SCREENSHOTS.0, ports::SCREENSHOTS.1).await?;
    let api = Api::new(noadd.base_url());
    api.setup(ADMIN_USERNAME, ADMIN_PASSWORD).await?;
    noadd.stop().await?;

    // Phase 2: backdated seed against the stopped database.
    noadd.seed(&seed::screenshots(seed::now_ms())).await?;

    // Phase 3: boot with the seeded data. Retention is 180 days in the fixture,
    // which is what protects the backdate from the prune that fires at boot,
    // and the seeded list content is what lets the rebuild yield a live engine
    // without touching the network.
    noadd.start().await?;
    let session = api.login(ADMIN_USERNAME, ADMIN_PASSWORD).await?;

    for shot in SHOTS {
        capture(&noadd.base_url(), &session, shot, &out).await?;
        println!("captured {}", shot.file);
    }

    noadd.stop().await?;
    println!("done — PNGs in {}", out.display());
    Ok(())
}

async fn capture(base: &str, session: &str, shot: &Shot, out: &Path) -> Result<()> {
    let profile = Profile::desktop()
        .with_viewport(shot.viewport)
        .with_color_scheme(shot.scheme)
        .with_reduced_motion()
        // UTC keeps the heatmap on the seed's diurnal curve; the locale keeps
        // number and date formatting stable wherever this is run.
        .with_clock("UTC", "en-US");
    let browser = Browser::open(&profile).await?;
    let page = Page::new(browser.driver(), base);

    page.adopt_session(session).await?;
    page.goto(shot.route).await?;
    page.testid("app-shell").expect_visible().await?;
    page.eval(&format!(
        "const s = document.createElement('style'); s.textContent = {}; \
         document.head.appendChild(s); return true;",
        serde_json::to_string(FREEZE)?
    ))
    .await?;

    wait_for(&page, shot.wait).await?;

    let png = browser.screenshot_png().await?;
    tokio::fs::write(out.join(shot.file), png)
        .await
        .with_context(|| format!("writing {}", shot.file))?;
    browser.quit().await
}

/// Per-page readiness: data rendered, not spinners or empty states.
async fn wait_for(page: &Page, wait: Wait) -> Result<()> {
    match wait {
        Wait::Dashboard => {
            page.testid("stat-blocked-today").expect_visible().await?;
            page.loc("#chart .tl-svg").expect_visible().await?;
            page.loc("#top-domains table tbody tr")
                .first()
                .expect_visible()
                .await?;
            page.loc("#top-upstreams table tbody tr")
                .first()
                .expect_visible()
                .await
        }
        Wait::Stats => {
            page.loc("#timeline-chart .tl-svg").expect_visible().await?;
            page.loc("#rate-trend-chart svg").expect_visible().await?;
            page.loc("#heatmap-container .heatmap-cell")
                .first()
                .expect_visible()
                .await?;
            page.loc("#qtypes-chart .bar-row")
                .first()
                .expect_visible()
                .await?;
            page.loc("#outcomes-chart .bar-row")
                .first()
                .expect_visible()
                .await?;
            page.loc("#highlights-grid .stat-card")
                .first()
                .expect_visible()
                .await?;
            page.loc("#health-grid .stat-card")
                .first()
                .expect_visible()
                .await
        }
        // At least ten rows on page 1.
        Wait::Logs => page.loc("#log-body tr").nth(9).expect_visible().await,
        // The mobile card layout, which replaces the table at narrow widths.
        Wait::LogsMobile => {
            page.loc("#log-cards .log-card")
                .nth(5)
                .expect_visible()
                .await
        }
        Wait::Filters => {
            // Three lists and three custom rules, from the fixture.
            page.testid("filter-list-row")
                .nth(2)
                .expect_visible()
                .await?;
            page.testid("rule-row").nth(2).expect_visible().await?;
            // Populate the domain-test card so the shot shows a live verdict.
            page.testid("domain-test-input")
                .fill("doubleclick.net")
                .await?;
            page.testid("domain-test-submit").click().await?;
            page.loc("[data-testid=\"domain-test-result\"] .badge-blocked")
                .expect_visible()
                .await
        }
    }
}
