//! The multiplexed event stream behind the shell's status indicator and the
//! dashboard's readings.
//!
//! One SSE connection per page carries every push the admin UI needs, because
//! the status indicator lives in the shell and therefore on *every* page: a
//! stream per feature would hold two or three connections per tab, and a
//! browser talking HTTP/1.1 to a plain-HTTP appliance only gets six per origin
//! before ordinary navigation starts queueing behind them.
//!
//! Two event names ride it:
//!
//! - `ping` — emitted on every tick whether or not anything changed. It is the
//!   status indicator's heartbeat, and it has to be a real event rather than
//!   the SSE keep-alive comment: comments never surface to `EventSource`, so a
//!   connection whose TCP socket died silently would look identical to an idle
//!   one. Missing pings are what the client times out on.
//! - `stats` — the dashboard snapshot, sent only to connections that asked for
//!   it. A settings page holding the stream open must not make the appliance
//!   run five aggregate queries every ten seconds for a page that shows none
//!   of them.
//!
//! The snapshot is computed once per tick and shared, not once per connection.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use serde::Serialize;
use tokio::sync::broadcast;

use crate::admin::stats;
use crate::db::{Database, DbError, TimelinePoint, TopClient, TopDomain, TopUpstream};

/// How often a tick fires. Matches the cadence the dashboard used to poll at,
/// so the readings move exactly as often as they did before.
pub const TICK_INTERVAL_SECS: u64 = 10;

/// Rows behind each dashboard table. The client renders ten and the server
/// renders ten; asking for more only moved bytes the page threw away.
const TOP_N: i64 = 10;

/// Hours of history behind the dashboard chart.
const TIMELINE_HOURS: i64 = 24;

/// Everything the dashboard draws, in one payload.
///
/// The field names are the five `/api/stats/*` responses the page used to
/// fetch separately, unchanged — the renderers in `app.js` read the same
/// shapes whether they arrived by poll or by push.
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
/// `snapshot` is `None` when no connected client asked for stats, which is the
/// common case for an appliance sitting on the settings page.
#[derive(Debug, Clone)]
pub struct Tick {
    pub seq: u64,
    pub at: i64,
    /// Whether the appliance has ever answered a query. Rides the heartbeat
    /// rather than taking an event name of its own: it is a state bit, not
    /// something that happened, and the onboarding notice it hides is the only
    /// thing that reads it.
    pub traffic: bool,
    pub snapshot: Option<Arc<DashboardSnapshot>>,
}

/// Broadcast hub for [`Tick`]s, plus the count of connections that want a
/// snapshot in them.
pub struct EventHub {
    tx: broadcast::Sender<Arc<Tick>>,
    stats_subscribers: AtomicUsize,
    /// Latches on the first query this appliance is seen to have answered, and
    /// never clears. The onboarding notice it hides is about a machine that has
    /// never served traffic, and a machine that has served some is not that
    /// machine again — so once the answer is yes, nothing needs to ask again.
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

    /// Records that it has. Callable from anywhere that happens to learn it —
    /// the ticker probes for it, and a page render that reads the same fact
    /// keeps the latch warm on an appliance nobody is watching.
    pub fn note_traffic(&self) {
        self.traffic_seen.store(true, Ordering::Relaxed);
    }

    pub fn wants_stats(&self) -> bool {
        self.stats_subscribers.load(Ordering::Relaxed) > 0
    }

    /// Register interest in snapshots for as long as the returned guard lives.
    /// A guard rather than a pair of calls because the decrement has to survive
    /// the connection being dropped mid-stream, which is the normal way an SSE
    /// connection ends.
    pub fn stats_guard(self: &Arc<Self>) -> StatsGuard {
        self.stats_subscribers.fetch_add(1, Ordering::Relaxed);
        StatsGuard { hub: self.clone() }
    }

    fn send(&self, tick: Tick) {
        // A send with no receivers is not an error here: it means every client
        // disconnected between the tick firing and this call.
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
    let (summary, timeline, top_domains, top_clients, top_upstreams) = tokio::try_join!(
        stats::compute_summary(db, now),
        stats::compute_timeline(db, now, TIMELINE_HOURS),
        stats::compute_top_domains(db, now, TOP_N),
        stats::compute_top_clients(db, now, TOP_N),
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

/// Drive the stream: one tick every `interval` for as long as anyone is
/// listening. Production passes [`TICK_INTERVAL_SECS`]; the interval is a
/// parameter so a test can run the real loop in milliseconds rather than
/// mock the clock.
///
/// Nothing is computed and nothing is sent while no connection is open, so an
/// appliance nobody is looking at does no work for this at all.
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

        // Asked only while the answer can still be no. The latch is one-way, so
        // an appliance that has served traffic pays for this once and a fresh
        // one pays a single `EXISTS` per tick until its first query lands.
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
                    // The heartbeat still goes out: the server answering at all
                    // is the fact the status indicator reports, and a failed
                    // stats read does not make it untrue.
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
        // The decrement has to happen on drop rather than on an explicit call,
        // because a client vanishing mid-stream never reaches one.
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

    /// A tick every few milliseconds, so the real loop is exercised without a
    /// mocked clock.
    const FAST: std::time::Duration = std::time::Duration::from_millis(20);

    /// Long enough for several `FAST` ticks, short enough that a hang fails the
    /// test rather than the suite.
    const WAIT: std::time::Duration = std::time::Duration::from_secs(5);

    async fn next_tick(rx: &mut broadcast::Receiver<Arc<Tick>>) -> Arc<Tick> {
        tokio::time::timeout(WAIT, rx.recv())
            .await
            .expect("no tick arrived")
            .unwrap()
    }

    /// The whole cycle is skipped while nobody is connected, so an appliance
    /// nobody is looking at does no work for this at all.
    #[tokio::test]
    async fn the_ticker_does_nothing_while_nobody_is_connected() {
        let db = test_db().await;
        let hub = Arc::new(EventHub::new(8));
        let task = tokio::spawn(run(db, hub.clone(), FAST));

        // Let several intervals pass with no subscriber, then join. The first
        // tick this receiver sees being seq 1 is what proves none of them ran.
        tokio::time::sleep(FAST * 5).await;
        let mut rx = hub.subscribe();

        let tick = next_tick(&mut rx).await;
        assert_eq!(
            tick.seq, 1,
            "ticks were numbered while no one was connected, so the cycle ran anyway"
        );

        task.abort();
    }

    /// A connection that did not ask for stats must not make the appliance run
    /// five aggregate queries every tick.
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
        // The tick in flight when the guard was taken may already have been
        // built without one, so this waits for the first that reflects it.
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
