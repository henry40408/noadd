use std::sync::atomic::Ordering;
use std::time::Duration;

use noadd::filter::rebuild::RebuildCoordinator;

#[tokio::test]
async fn rebuild_state_transitions() {
    let coord = RebuildCoordinator::new();
    let state = coord.state();
    assert!(!state.rebuilding.load(Ordering::Relaxed));
    assert_eq!(state.started_at.load(Ordering::Relaxed), 0);
    assert_eq!(state.last_completed_at.load(Ordering::Relaxed), 0);

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
    assert!(state.last_completed_at.load(Ordering::Relaxed) > 0);
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

#[tokio::test]
async fn failed_rebuild_clears_flag() {
    let coord = RebuildCoordinator::new();
    let state = coord.state();
    coord
        .clone()
        .spawn_raw(|| async { Err::<(), _>(std::io::Error::other("boom")) })
        .await
        .unwrap();
    assert!(!state.rebuilding.load(Ordering::Relaxed));
    assert!(state.last_completed_at.load(Ordering::Relaxed) > 0);
}
