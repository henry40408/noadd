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
use std::sync::atomic::{AtomicUsize, Ordering};

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
    pub snapshot: Option<Arc<DashboardSnapshot>>,
}

/// Broadcast hub for [`Tick`]s, plus the count of connections that want a
/// snapshot in them.
pub struct EventHub {
    tx: broadcast::Sender<Arc<Tick>>,
    stats_subscribers: AtomicUsize,
}

impl EventHub {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self {
            tx,
            stats_subscribers: AtomicUsize::new(0),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Tick>> {
        self.tx.subscribe()
    }

    /// Number of live SSE connections, stats-wanting or not.
    pub fn connection_count(&self) -> usize {
        self.tx.receiver_count()
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

/// Drive the stream: one tick every [`TICK_INTERVAL_SECS`] for as long as
/// anyone is listening.
///
/// Nothing is computed and nothing is sent while no connection is open, so an
/// appliance nobody is looking at does no work for this at all.
pub async fn run(db: Database, hub: Arc<EventHub>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(TICK_INTERVAL_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut seq: u64 = 0;

    loop {
        ticker.tick().await;

        if hub.connection_count() == 0 {
            continue;
        }

        seq = seq.wrapping_add(1);
        let now = crate::now_unix();

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
            snapshot,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn a_tick_reaches_every_subscriber() {
        let hub = Arc::new(EventHub::new(8));
        let mut a = hub.subscribe();
        let mut b = hub.subscribe();
        assert_eq!(hub.connection_count(), 2);

        hub.send(Tick {
            seq: 7,
            at: 1234,
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
