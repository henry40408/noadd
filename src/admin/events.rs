//! The tick source behind the admin UI's one SSE stream (`stream_events` in
//! `api.rs`): the `ping` heartbeat and the dashboard's `stats` snapshot.
//!
//! One connection per page, because the status indicator is in the shell and
//! so on every page; a stream per feature would eat into the browser's six
//! HTTP/1.1 connections per origin.
//!
//! - `ping` goes out every tick. It must be a real event: SSE keep-alive
//!   comments never reach `EventSource`, so a dead socket would look idle.
//! - `stats` goes only to connections that asked, so an idle settings page
//!   costs no aggregate queries.
//!
//! The snapshot is computed once per tick and shared across connections.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use serde::Serialize;
use tokio::sync::broadcast;

use crate::admin::stats;
use crate::db::{Database, DbError, TimelinePoint, TopClient, TopDomain, TopUpstream};

/// How often a tick fires.
pub const TICK_INTERVAL_SECS: u64 = 10;

/// Rows behind each dashboard table; both the client and the server render ten.
const TOP_N: i64 = 10;

/// Hours of history behind the dashboard chart.
const TIMELINE_HOURS: i64 = 24;

/// Everything the dashboard draws, in one payload.
///
/// Each field has the shape of the matching `/api/stats/*` response, so the
/// renderers in `app.js` read the same shapes either way.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardSnapshot {
    pub summary: stats::Summary,
    pub timeline: Vec<TimelinePoint>,
    pub top_domains: Vec<TopDomain>,
    pub top_clients: Vec<TopClient>,
    pub top_upstreams: Vec<TopUpstream>,
}

/// One tick of the stream.
///
/// `snapshot` is `None` when no connected client asked for stats.
#[derive(Debug, Clone)]
pub struct Tick {
    pub seq: u64,
    pub at: i64,
    /// Whether the appliance has ever answered a query — a state bit for the
    /// onboarding notice, so it rides the heartbeat rather than its own event.
    pub traffic: bool,
    pub snapshot: Option<Arc<DashboardSnapshot>>,
}

/// Broadcast hub for [`Tick`]s, plus the count of connections that want a
/// snapshot in them.
pub struct EventHub {
    tx: broadcast::Sender<Arc<Tick>>,
    stats_subscribers: AtomicUsize,
    /// One-way latch: set on the first answered query seen, never cleared. A
    /// machine that has served traffic is not a fresh one again.
    traffic_seen: AtomicBool,
}

impl EventHub {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self {
            tx,
            stats_subscribers: AtomicUsize::new(0),
            traffic_seen: AtomicBool::new(false),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Tick>> {
        self.tx.subscribe()
    }

    /// Number of live SSE connections, stats-wanting or not.
    pub fn connection_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Has the appliance answered a query, as far as anything has looked?
    pub fn has_traffic(&self) -> bool {
        self.traffic_seen.load(Ordering::Relaxed)
    }

    /// Records that it has. The ticker probes for it; a page render that learns
    /// the same fact sets it too.
    pub fn note_traffic(&self) {
        self.traffic_seen.store(true, Ordering::Relaxed);
    }

    pub fn wants_stats(&self) -> bool {
        self.stats_subscribers.load(Ordering::Relaxed) > 0
    }

    /// Register interest in snapshots for as long as the returned guard lives.
    /// A guard, because an SSE connection normally ends by being dropped.
    pub fn stats_guard(self: &Arc<Self>) -> StatsGuard {
        self.stats_subscribers.fetch_add(1, Ordering::Relaxed);
        StatsGuard { hub: self.clone() }
    }

    fn send(&self, tick: Tick) {
        // No receivers just means every client left since the tick fired.
        let _ = self.tx.send(Arc::new(tick));
    }
}

/// Drops a connection's claim on snapshot computation.
pub struct StatsGuard {
    hub: Arc<EventHub>,
}

impl Drop for StatsGuard {
    fn drop(&mut self) {
        self.hub.stats_subscribers.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Read everything the dashboard shows, in the shapes `app.js` renders.
pub async fn compute_snapshot(db: &Database, now: i64) -> Result<DashboardSnapshot, DbError> {
    let (summary, timeline, (top_domains, top_clients), top_upstreams) = tokio::try_join!(
        stats::compute_summary(db, now),
        stats::compute_timeline(db, now, TIMELINE_HOURS),
        stats::compute_top_domains_and_clients(db, now, TOP_N),
        stats::compute_top_upstreams(db, now, TOP_N),
    )?;

    Ok(DashboardSnapshot {
        summary,
        timeline,
        top_domains,
        top_clients,
        top_upstreams,
    })
}

/// Drive the stream: one tick every `interval` ([`TICK_INTERVAL_SECS`] in
/// production; a parameter so tests run the real loop without a mocked clock).
/// The whole cycle is skipped while no connection is open.
pub async fn run(db: Database, hub: Arc<EventHub>, interval: std::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut seq: u64 = 0;

    loop {
        ticker.tick().await;

        if hub.connection_count() == 0 {
            continue;
        }

        seq = seq.wrapping_add(1);
        let now = crate::now_unix();

        // One `EXISTS` per tick, only until the one-way latch is set.
        if !hub.has_traffic() {
            match db.has_any_query_logs().await {
                Ok(true) => hub.note_traffic(),
                Ok(false) => {}
                Err(e) => tracing::warn!(
                    event = "events.traffic_probe_failed",
                    error = %e,
                    "failed to check whether the appliance has served any queries"
                ),
            }
        }

        let snapshot = if hub.wants_stats() {
            match compute_snapshot(&db, now).await {
                Ok(snap) => Some(Arc::new(snap)),
                Err(e) => {
                    // The heartbeat still goes out: the server is still up.
                    tracing::warn!(
                        event = "events.snapshot_failed",
                        error = %e,
                        "failed to compute the dashboard snapshot for the event stream"
                    );
                    None
                }
            }
        } else {
            None
        };

        hub.send(Tick {
            seq,
            at: now,
            traffic: hub.has_traffic(),
            snapshot,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Database {
        let dir = tempfile::tempdir().unwrap();
        // Persist the tempdir (no Drop cleanup) so the file outlives it.
        let path = dir.keep().join("events.db");
        Database::open(path.to_str().unwrap()).await.unwrap()
    }

    #[test]
    fn a_hub_with_no_connections_reports_none() {
        let hub = Arc::new(EventHub::new(8));
        assert_eq!(hub.connection_count(), 0);
        assert!(!hub.wants_stats());
    }

    #[test]
    fn a_dropped_stats_guard_releases_its_claim() {
        // A client vanishing mid-stream never makes an explicit call.
        let hub = Arc::new(EventHub::new(8));
        {
            let _guard = hub.stats_guard();
            assert!(hub.wants_stats());
            {
                let _second = hub.stats_guard();
                assert!(hub.wants_stats());
            }
            assert!(
                hub.wants_stats(),
                "one connection leaving must not cancel another's snapshots"
            );
        }
        assert!(!hub.wants_stats());
    }

    /// A fast tick, so the real loop runs without a mocked clock.
    const FAST: std::time::Duration = std::time::Duration::from_millis(20);

    /// Long enough for several `FAST` ticks; a hang fails the test, not the suite.
    const WAIT: std::time::Duration = std::time::Duration::from_secs(5);

    async fn next_tick(rx: &mut broadcast::Receiver<Arc<Tick>>) -> Arc<Tick> {
        tokio::time::timeout(WAIT, rx.recv())
            .await
            .expect("no tick arrived")
            .unwrap()
    }

    /// The whole cycle is skipped while nobody is connected.
    #[tokio::test]
    async fn the_ticker_does_nothing_while_nobody_is_connected() {
        let db = test_db().await;
        let hub = Arc::new(EventHub::new(8));
        let task = tokio::spawn(run(db, hub.clone(), FAST));

        // Several intervals pass with no subscriber; a first seen seq of 1
        // proves none of them ran.
        tokio::time::sleep(FAST * 5).await;
        let mut rx = hub.subscribe();

        let tick = next_tick(&mut rx).await;
        assert_eq!(
            tick.seq, 1,
            "ticks were numbered while no one was connected, so the cycle ran anyway"
        );

        task.abort();
    }

    /// A connection that did not ask for stats must not cost aggregate queries.
    #[tokio::test]
    async fn a_tick_carries_a_snapshot_only_when_one_was_asked_for() {
        let db = test_db().await;
        let hub = Arc::new(EventHub::new(64));
        let task = tokio::spawn(run(db, hub.clone(), FAST));

        let mut rx = hub.subscribe();
        assert!(
            next_tick(&mut rx).await.snapshot.is_none(),
            "a stats-free connection was sent a snapshot"
        );

        let guard = hub.stats_guard();
        // The tick in flight may predate the guard; wait for one reflecting it.
        let got_snapshot = tokio::time::timeout(WAIT, async {
            loop {
                if next_tick(&mut rx).await.snapshot.is_some() {
                    return true;
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            got_snapshot,
            "a connection holding a stats guard was never sent one"
        );

        drop(guard);
        let stopped = tokio::time::timeout(WAIT, async {
            loop {
                if next_tick(&mut rx).await.snapshot.is_none() {
                    return true;
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            stopped,
            "snapshots kept being computed after the last dashboard left"
        );

        task.abort();
    }

    #[tokio::test]
    async fn a_tick_reaches_every_subscriber() {
        let hub = Arc::new(EventHub::new(8));
        let mut a = hub.subscribe();
        let mut b = hub.subscribe();
        assert_eq!(hub.connection_count(), 2);

        hub.send(Tick {
            seq: 7,
            at: 1234,
            traffic: false,
            snapshot: None,
        });

        for rx in [&mut a, &mut b] {
            let tick = rx.recv().await.unwrap();
            assert_eq!(tick.seq, 7);
            assert_eq!(tick.at, 1234);
            assert!(tick.snapshot.is_none());
        }
    }
}
