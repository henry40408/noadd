//! The Cucumber runner.
//!
//! `harness = false`: cucumber drives the scenarios itself, so there is no
//! libtest harness collecting `#[test]` functions. Run it from `e2e/` with
//! `cargo test --test e2e`.
//!
//! What `playwright.config.js` expressed as three BDD projects plus three
//! `webServer` entries is expressed here as three instances and three passes,
//! selected by the tag each feature already carries:
//!
//! * `@auth` — first-run setup and the session lifecycle. A database can only
//!   be set up once and revoking sessions is destructive, so it gets an
//!   instance of its own that starts unconfigured.
//! * `@onboarding` — the new-install guidance. Every scenario depends on an
//!   appliance that has served *no* DNS queries, and the last one sends a real
//!   query to prove the banner clears itself, so there is no going back.
//! * `@app` — the read-mostly features, against a shared instance the runner
//!   configures up front. That is the old `setup-app` project: a session minted
//!   over the API and replayed as a cookie, which is what `storageState` was.
//!
//! Scenarios run one at a time, as they did under `workers: 1`. That is not
//! conservatism: the `@auth` and `@onboarding` features are each one deliberate
//! narrative in file order, and the `@app` features share mutable filter state.
//! What *is* parallel is nothing here — the parallelism in this suite lives in
//! `tests/specs`, where every file owns its own instance.

mod steps;

use std::collections::HashMap;

use anyhow::Result;
use cucumber::World as _;
use cucumber::gherkin;
use cucumber::writer::Stats as _;
use noadd_e2e::browser::{Browser, Profile};
use noadd_e2e::world::{Instance, NoaddWorld, register};
use noadd_e2e::{Api, Server, ports};

const FEATURES: &str = "features";

#[tokio::main]
async fn main() -> Result<()> {
    // Killed when these bindings drop at the end of `main`.
    let app = Server::fresh("app", ports::APP.0, ports::APP.1).await?;
    let auth = Server::fresh("auth", ports::AUTH.0, ports::AUTH.1).await?;
    let onboarding = Server::fresh("onboarding", ports::ONBOARDING.0, ports::ONBOARDING.1).await?;

    // The `setup-app` project, in one line: configure the shared instance and
    // keep the session it hands back.
    let app_session = Api::new(app.base_url()).provision().await?;

    register(HashMap::from([
        (
            "app".to_string(),
            Instance {
                base: app.base_url(),
                dns_port: app.dns_port(),
                session: Some(app_session),
            },
        ),
        // No session for these two: the scenarios are about configuring an
        // appliance and signing in to it, which an already-authenticated
        // browser would have skipped past.
        (
            "auth".to_string(),
            Instance {
                base: auth.base_url(),
                dns_port: auth.dns_port(),
                session: None,
            },
        ),
        (
            "onboarding".to_string(),
            Instance {
                base: onboarding.base_url(),
                dns_port: onboarding.dns_port(),
                session: None,
            },
        ),
    ]))?;

    // Before anything opens a session for real — see `Browser::prepare`.
    Browser::prepare().await?;

    let mut failures = 0;
    for tag in ["auth", "onboarding", "app"] {
        println!("\n=== @{tag} ===");
        failures += run(tag).await;
    }

    // Every pass runs before any of them can fail the process: a broken
    // onboarding flow is worth seeing on the same run that showed the rest
    // passing.
    anyhow::ensure!(failures == 0, "{failures} cucumber failure(s)");
    Ok(())
}

/// Runs the features carrying `tag`, reporting how many ways they failed.
async fn run(tag: &'static str) -> usize {
    let writer = NoaddWorld::cucumber()
        .max_concurrent_scenarios(1)
        .fail_on_skipped()
        .before(move |feature, _rule, _scenario, world| {
            Box::pin(async move {
                let instance = noadd_e2e::world::instance_for(&feature.tags)
                    .expect("every feature carries a tag naming its instance");
                world
                    .open(instance, &Profile::desktop())
                    .await
                    .expect("could not open a browser session");
            })
        })
        .after(|_feature, _rule, _scenario, _finished, world| {
            Box::pin(async move {
                if let Some(world) = world {
                    world.close().await.expect("could not close the session");
                }
            })
        })
        .filter_run(FEATURES, move |feature: &gherkin::Feature, _, _| {
            feature.tags.iter().any(|candidate| candidate == tag)
        })
        .await;

    writer.failed_steps() + writer.parsing_errors() + writer.hook_errors()
}
