use serde::Serialize;

use crate::db::{Database, DbError, TimelinePoint, TopClient, TopDomain};

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub total_today: i64,
    pub blocked_today: i64,
    pub total_7d: i64,
    pub blocked_7d: i64,
    pub total_30d: i64,
    pub blocked_30d: i64,
    pub block_ratio_today: f64,
    pub cache_hit_rate_today: f64,
    pub avg_response_ms_today: f64,
}

pub async fn compute_summary(db: &Database, now: i64) -> Result<Summary, DbError> {
    let one_day = 86400;
    let since_today = now - one_day;
    let since_7d = now - 7 * one_day;
    let since_30d = now - 30 * one_day;

    let (total_today, blocked_today) = db.count_queries_since(since_today).await?;
    let (total_7d, blocked_7d) = db.count_queries_since(since_7d).await?;
    let (total_30d, blocked_30d) = db.count_queries_since(since_30d).await?;
    let (cache_hits, allowed_total, avg_response_ms) =
        db.cache_stats_since(since_today).await?;

    let block_ratio_today = if total_today > 0 {
        blocked_today as f64 / total_today as f64
    } else {
        0.0
    };

    let cache_hit_rate_today = if allowed_total > 0 {
        cache_hits as f64 / allowed_total as f64
    } else {
        0.0
    };

    Ok(Summary {
        total_today,
        blocked_today,
        total_7d,
        blocked_7d,
        total_30d,
        blocked_30d,
        block_ratio_today,
        cache_hit_rate_today,
        avg_response_ms_today: avg_response_ms,
    })
}

pub async fn compute_top_domains(
    db: &Database,
    now: i64,
    limit: i64,
) -> Result<Vec<TopDomain>, DbError> {
    let since = now - 86400;
    db.top_domains_since(since, limit).await
}

pub async fn compute_top_clients(
    db: &Database,
    now: i64,
    limit: i64,
) -> Result<Vec<TopClient>, DbError> {
    let since = now - 86400;
    db.top_clients_since(since, limit).await
}

const TARGET_BARS: i64 = 48;

pub async fn compute_timeline(
    db: &Database,
    now: i64,
    hours: i64,
) -> Result<Vec<TimelinePoint>, DbError> {
    let max_since = now - hours * 3600;

    // Find the earliest log timestamp to determine actual data range
    let earliest = db.earliest_log_timestamp().await?;
    let since = match earliest {
        Some(ts_ms) => {
            let ts_secs = ts_ms / 1000;
            // Use the later of: earliest log or max lookback
            ts_secs.max(max_since)
        }
        None => max_since,
    };

    // Dynamic bucket: divide actual range by target bar count
    let range = (now - since).max(1);
    // Round bucket to a clean interval (minimum 60s)
    let raw_bucket = range / TARGET_BARS;
    let bucket_secs = if raw_bucket <= 60 {
        60
    } else if raw_bucket <= 300 {
        300 // 5 min
    } else if raw_bucket <= 600 {
        600 // 10 min
    } else if raw_bucket <= 1800 {
        1800 // 30 min
    } else {
        3600 // 1 hour
    };

    db.timeline_since(since, bucket_secs).await
}
