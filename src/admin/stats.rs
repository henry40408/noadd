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
}

pub async fn compute_summary(db: &Database, now: i64) -> Result<Summary, DbError> {
    let one_day = 86400;
    let since_today = now - one_day;
    let since_7d = now - 7 * one_day;
    let since_30d = now - 30 * one_day;

    let (total_today, blocked_today) = db.count_queries_since(since_today).await?;
    let (total_7d, blocked_7d) = db.count_queries_since(since_7d).await?;
    let (total_30d, blocked_30d) = db.count_queries_since(since_30d).await?;

    let block_ratio_today = if total_today > 0 {
        blocked_today as f64 / total_today as f64
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

pub async fn compute_timeline(
    db: &Database,
    now: i64,
    hours: i64,
) -> Result<Vec<TimelinePoint>, DbError> {
    let since = now - hours * 3600;
    // Use 10-minute buckets
    let bucket_secs = 600;
    db.timeline_since(since, bucket_secs).await
}
