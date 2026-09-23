//! The Cucumber runner (`cargo test --test e2e` from `e2e/`). One instance and
//! one pass per feature tag:
//!
//! * `@auth` — first-run setup and the session lifecycle. Setup happens once and
//!   revoking sessions is destructive, so it starts unconfigured on its own.
//! * `@onboarding` — needs an appliance that has served no DNS queries, and its
//!   last scenario sends one, so it too gets its own.
//! * `@app` — the read-mostly features, on a shared instance provisioned up
//!   front with a session minted over the API and replayed as a cookie.
//!
//! Scenarios run one at a time: `@auth` and `@onboarding` are each one narrative
//! in file order, and the `@app` features share mutable filter state. Parallelism
//! lives in `tests/specs`, where every file owns its instance.

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

    // Configure the shared instance and keep the session it hands back.
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
        // No session: these scenarios configure the appliance and sign in themselves.
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

    // Run every pass before failing, so one broken tag does not hide the others.
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
