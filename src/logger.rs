use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::db::{Database, QueryLogEntry};
use crate::dns::handler::QueryContext;

/// Async query logger that buffers log entries and flushes them to the database
/// in batches, either when the buffer reaches a threshold or on a timer.
pub struct QueryLogger {
    db: Database,
    rx: mpsc::Receiver<QueryContext>,
    flush_threshold: usize,
    flush_interval_secs: u64,
}

impl QueryLogger {
    /// Create a new QueryLogger and its corresponding sender.
    ///
    /// The channel has a capacity of 10,000 entries.
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
        };
        (logger, tx)
    }

    /// Run the logger loop. Consumes self. Call in a `tokio::spawn`.
    ///
    /// Buffers incoming `QueryContext` entries and flushes to the database when:
    /// - The buffer reaches `flush_threshold`, or
    /// - The flush interval timer fires
    ///
    /// On channel close (all senders dropped), flushes remaining entries and exits.
    pub async fn run(mut self) {
        let mut buffer: Vec<QueryLogEntry> = Vec::new();
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(self.flush_interval_secs));
        // The first tick completes immediately; consume it so we don't flush an empty buffer.
        interval.tick().await;

        loop {
            tokio::select! {
                maybe_ctx = self.rx.recv() => {
                    match maybe_ctx {
                        Some(ctx) => {
                            buffer.push(query_context_to_entry(ctx));
                            if buffer.len() >= self.flush_threshold {
                                flush(&self.db, &mut buffer).await;
                            }
                        }
                        None => {
                            // Channel closed, flush remaining and exit
                            if !buffer.is_empty() {
                                flush(&self.db, &mut buffer).await;
                            }
                            info!("query logger shutting down");
                            return;
                        }
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
fn query_context_to_entry(ctx: QueryContext) -> QueryLogEntry {
    QueryLogEntry {
        timestamp: ctx.timestamp,
        domain: ctx.domain,
        query_type: ctx.query_type,
        client_ip: ctx.client_ip,
        blocked: ctx.action == "blocked",
        cached: ctx.cached,
        response_ms: ctx.response_time_ms,
        upstream: ctx.upstream,
        doh_token: ctx.doh_token,
        result: ctx.result,
    }
}

/// Flush all buffered entries to the database.
async fn flush(db: &Database, buffer: &mut Vec<QueryLogEntry>) {
    if let Err(e) = db.insert_query_logs(buffer).await {
        warn!("failed to flush query logs to database: {e}");
    }
    buffer.clear();
}
