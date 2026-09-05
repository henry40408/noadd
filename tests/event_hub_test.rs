//! The heartbeat's `traffic` bit: how the onboarding notice learns that the
//! appliance has started answering queries without anything polling for it.

use std::sync::Arc;
use std::time::Duration;

use noadd::admin::events::{EventHub, run};
use noadd::db::{Database, QueryLogEntry};
use tempfile::tempdir;

const TICK: Duration = Duration::from_millis(50);

async fn test_db() -> Database {
    let dir = tempdir().unwrap();
    let path = dir.keep().join("test.db");
    Database::open(path.to_str().unwrap()).await.unwrap()
}

fn a_query(timestamp: i64) -> QueryLogEntry {
    QueryLogEntry {
        timestamp,
        domain: "example.com".to_string(),
        query_type: "A".to_string(),
        client_ip: "192.168.1.1".to_string(),
        blocked: false,
        cached: false,
        upstream: None,
        doh_token: None,
        result: None,
        response_ms: 5,
        authenticated_data: false,
    }
}

/// Waits for a tick, failing rather than hanging if the ticker has stopped.
async fn next_tick(
    rx: &mut tokio::sync::broadcast::Receiver<Arc<noadd::admin::events::Tick>>,
) -> Arc<noadd::admin::events::Tick> {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("no tick within 5s")
        .expect("the ticker stopped")
}

/// The notice asks one question — has this machine ever answered anything — and
/// the answer rides the heartbeat every connection already receives, rather
/// than a page polling an endpoint to find out.
#[tokio::test]
async fn the_tick_reports_traffic_once_the_appliance_has_answered_something() {
    let db = test_db().await;
    let hub = Arc::new(EventHub::new(8));
    // Subscribing is also what makes the ticker run: it skips the whole cycle
    // while nothing is connected.
    let mut rx = hub.subscribe();
    let ticker = tokio::spawn(run(db.clone(), hub.clone(), TICK));

    let tick = next_tick(&mut rx).await;
    assert!(!tick.traffic, "a fresh appliance has answered nothing");

    db.insert_query_logs(&[a_query(1_000_000)]).await.unwrap();

    let mut latched = false;
    for _ in 0..20 {
        if next_tick(&mut rx).await.traffic {
            latched = true;
            break;
        }
    }
    assert!(
        latched,
        "the tick never reported the appliance's first query"
    );

    ticker.abort();
}

/// The latch is one-way, and deliberately so: it exists to stop an appliance
/// that is plainly working from paying for the question on every tick.
#[tokio::test]
async fn the_traffic_latch_does_not_clear_when_the_logs_are_emptied() {
    let db = test_db().await;
    let hub = Arc::new(EventHub::new(8));

    assert!(!hub.has_traffic());
    hub.note_traffic();
    assert!(hub.has_traffic());

    db.delete_all_logs().await.unwrap();
    assert!(
        hub.has_traffic(),
        "an appliance that has served traffic is not a fresh one again"
    );
}
