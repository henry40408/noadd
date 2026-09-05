use std::sync::atomic::Ordering;
use std::time::Duration;

use noadd::filter::rebuild::RebuildCoordinator;

#[tokio::test]
async fn rebuild_state_transitions() {
    let coord = RebuildCoordinator::new();
    let state = coord.state();
    assert!(!state.rebuilding.load(Ordering::Relaxed));
    assert_eq!(state.started_at.load(Ordering::Relaxed), 0);
    assert_eq!(state.last_duration_ms.load(Ordering::Relaxed), 0);

    let handle = coord.clone().spawn_raw(|| async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        Ok::<_, std::io::Error>(())
    });

    // Give the spawn a tick to start.
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(state.rebuilding.load(Ordering::Relaxed));
    assert!(state.started_at.load(Ordering::Relaxed) > 0);

    handle.await.unwrap();
    assert!(!state.rebuilding.load(Ordering::Relaxed));
    assert!(state.last_duration_ms.load(Ordering::Relaxed) >= 30);
}

#[tokio::test]
async fn concurrent_spawns_serialised() {
    let coord = RebuildCoordinator::new();
    let h1 = coord.clone().spawn_raw(|| async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok::<_, std::io::Error>(())
    });
    let h2 = coord.clone().spawn_raw(|| async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok::<_, std::io::Error>(())
    });
    let t = std::time::Instant::now();
    h1.await.unwrap();
    h2.await.unwrap();
    assert!(t.elapsed() >= Duration::from_millis(95));
}

/// Both edges reach a subscriber, and the completion carries the numbers that
/// go with it: a banner that read `last_duration_ms` from a message published
/// before the duration landed would report the *previous* rebuild's time.
#[tokio::test]
async fn subscribers_see_both_edges_of_a_rebuild() {
    let coord = RebuildCoordinator::new();
    let mut rx = coord.subscribe();

    coord
        .clone()
        .spawn_raw(|| async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            Ok::<_, std::io::Error>(())
        })
        .await
        .unwrap();

    let started = rx.try_recv().expect("no message for the rebuild starting");
    assert!(started.rebuilding);
    assert!(started.started_at > 0);

    let finished = rx.try_recv().expect("no message for the rebuild finishing");
    assert!(!finished.rebuilding);
    assert!(finished.last_duration_ms >= 30);
    assert_eq!(finished.started_at, started.started_at);

    assert!(
        rx.try_recv().is_err(),
        "a rebuild published more than its two edges"
    );
}

/// The state a late subscriber is handed, which is what the event stream sends
/// as a connection opens. Without it a client that connects between two
/// rebuilds cannot tell an idle appliance from one it has simply not heard
/// from yet.
#[tokio::test]
async fn status_reports_the_current_state_to_a_caller_that_missed_the_edges() {
    let coord = RebuildCoordinator::new();
    let idle = coord.status();
    assert!(!idle.rebuilding);
    assert_eq!(idle.started_at, 0);

    coord
        .clone()
        .spawn_raw(|| async { Ok::<_, std::io::Error>(()) })
        .await
        .unwrap();

    let after = coord.status();
    assert!(!after.rebuilding);
    assert!(after.started_at > 0);
}

#[tokio::test]
async fn failed_rebuild_clears_flag() {
    let coord = RebuildCoordinator::new();
    let state = coord.state();
    coord
        .clone()
        .spawn_raw(|| async { Err::<(), _>(std::io::Error::other("boom")) })
        .await
        .unwrap();
    // The flag is what this guards: a failed rebuild must not leave the
    // coordinator wedged as permanently "rebuilding".
    assert!(!state.rebuilding.load(Ordering::Relaxed));
}
