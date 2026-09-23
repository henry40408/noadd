use hickory_proto::rr::RecordType;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::db::{Database, QueryLogEntry};
use crate::dns::handler::{QueryAction, QueryContext};

/// Async query logger that buffers log entries and flushes them to the database
/// in batches, either when the buffer reaches a threshold or on a timer.
pub struct QueryLogger {
    db: Database,
    rx: mpsc::Receiver<QueryContext>,
    flush_threshold: usize,
    flush_interval_secs: u64,
    events: Option<tokio::sync::broadcast::Sender<std::sync::Arc<QueryLogEntry>>>,
}

impl QueryLogger {
    /// Create a `QueryLogger` and its sender (channel capacity 10,000).
    pub fn new(
        db: Database,
        flush_threshold: usize,
        flush_interval_secs: u64,
    ) -> (Self, mpsc::Sender<QueryContext>) {
        let (tx, rx) = mpsc::channel(10_000);
        let logger = Self {
            db,
            rx,
            flush_threshold,
            flush_interval_secs,
            events: None,
        };
        (logger, tx)
    }

    /// Also publish each entry live, before the DB flush (the admin UI tail).
    pub fn with_event_sender(
        mut self,
        tx: tokio::sync::broadcast::Sender<std::sync::Arc<QueryLogEntry>>,
    ) -> Self {
        self.events = Some(tx);
        self
    }

    /// Run the logger loop: flush at `flush_threshold` entries or on the
    /// interval, and flush the remainder once every sender is dropped.
    pub async fn run(mut self) {
        let mut buffer: Vec<QueryLogEntry> = Vec::new();
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(self.flush_interval_secs));
        // Skip the immediate first tick.
        interval.tick().await;

        loop {
            tokio::select! {
                maybe_ctx = self.rx.recv() => {
                    if let Some(ctx) = maybe_ctx {
                        let entry = query_context_to_entry(ctx);
                        // Gated on receiver_count: no clone when nobody is watching.
                        if let Some(events) = &self.events
                            && events.receiver_count() > 0
                        {
                            let _ = events.send(std::sync::Arc::new(entry.clone()));
                        }
                        buffer.push(entry);
                        if buffer.len() >= self.flush_threshold {
                            flush(&self.db, &mut buffer).await;
                        }
                    } else {
                        if !buffer.is_empty() {
                            flush(&self.db, &mut buffer).await;
                        }
                        info!(event = "querylog.worker_stopped", "query logger shutting down");
                        return;
                    }
                }
                _ = interval.tick() => {
                    if !buffer.is_empty() {
                        flush(&self.db, &mut buffer).await;
                    }
                }
            }
        }
    }
}

/// Convert a `QueryContext` to a `QueryLogEntry` for database storage.
///
/// Stringifying here keeps it off the query hot path.
fn query_context_to_entry(ctx: QueryContext) -> QueryLogEntry {
    QueryLogEntry {
        timestamp: ctx.timestamp,
        domain: ctx.domain,
        query_type: RecordType::from(ctx.query_type).to_string(),
        client_ip: ctx.client_ip.to_string(),
        blocked: matches!(ctx.action, QueryAction::Blocked),
        cached: ctx.cached,
        response_ms: ctx.response_time_ms,
        upstream: ctx.upstream,
        doh_token: ctx.doh_token,
        result: ctx.result,
        authenticated_data: ctx.authenticated_data,
    }
}

/// Flush all buffered entries to the database.
async fn flush(db: &Database, buffer: &mut Vec<QueryLogEntry>) {
    if let Err(e) = db.insert_query_logs(buffer).await {
        warn!(
            event = "querylog.flush_failed",
            entries = buffer.len(),
            error = %e,
            "failed to flush query logs to database"
        );
    }
    buffer.clear();
}
