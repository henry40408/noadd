use serde::Serialize;

use crate::db::{
    Database, DbError, HeatmapCell, TimelineMultiPoint, TimelinePoint, TopClient, TopDomain,
    TopUpstream,
};

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
    pub queries_1m: i64,
}

pub async fn compute_summary(db: &Database, now: i64) -> Result<Summary, DbError> {
    let one_day = 86400;
    let since_today = now - one_day;
    let since_7d = now - 7 * one_day;
    let since_30d = now - 30 * one_day;

    let since_1m = now - 60;
    let (queries_1m, _) = db.count_queries_since(since_1m).await?;
    let (total_today, blocked_today) = db.count_queries_since(since_today).await?;
    let (total_7d, blocked_7d) = db.count_queries_since(since_7d).await?;
    let (total_30d, blocked_30d) = db.count_queries_since(since_30d).await?;
    let (cache_hits, allowed_total, avg_response_ms) = db.cache_stats_since(since_today).await?;

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
        queries_1m,
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

pub async fn compute_top_upstreams(
    db: &Database,
    now: i64,
    limit: i64,
) -> Result<Vec<TopUpstream>, DbError> {
    let since = now - 86400;
    db.top_upstreams_since(since, limit).await
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

#[derive(Debug, Clone, Copy)]
pub enum StatsRange {
    Days7,
    Days30,
    Days90,
}

impl StatsRange {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "7d" => Some(Self::Days7),
            "30d" => Some(Self::Days30),
            "90d" => Some(Self::Days90),
            _ => None,
        }
    }

    /// (since_seconds_offset, bucket_secs)
    fn window(self) -> (i64, i64) {
        match self {
            Self::Days7 => (7 * 86400, 3600),
            Self::Days30 => (30 * 86400, 6 * 3600),
            Self::Days90 => (90 * 86400, 86400),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Breakdowns {
    pub query_types: Vec<(String, i64)>,
    pub outcomes: Vec<(String, i64)>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DbHealth {
    pub db_size_bytes: i64,
    pub total_log_count: i64,
    pub oldest_log_timestamp: Option<i64>, // unix seconds
    pub log_retention_days: Option<i64>,
    pub avg_new_rows_per_day: f64,
}

pub async fn compute_stats_timeline(
    db: &Database,
    now: i64,
    range: StatsRange,
) -> Result<Vec<TimelineMultiPoint>, DbError> {
    let (window_secs, bucket_secs) = range.window();
    db.timeline_multi_since(now - window_secs, bucket_secs)
        .await
}

pub async fn compute_heatmap(db: &Database, now: i64) -> Result<Vec<HeatmapCell>, DbError> {
    db.hourly_heatmap_since(now - 30 * 86400).await
}

pub async fn compute_breakdowns(
    db: &Database,
    now: i64,
    range: StatsRange,
) -> Result<Breakdowns, DbError> {
    let (window_secs, _) = range.window();
    let since = now - window_secs;
    let query_types = db.query_type_breakdown_since(since).await?;
    let outcomes = db.outcome_breakdown_since(since).await?;
    Ok(Breakdowns {
        query_types,
        outcomes,
    })
}

pub async fn compute_db_health(db: &Database, now: i64) -> Result<DbHealth, DbError> {
    let db_size_bytes = db.db_file_size().await?;
    let total_log_count = db.total_log_count().await?;
    let earliest_ms = db.earliest_log_timestamp().await?;
    let oldest_log_timestamp = earliest_ms.map(|ms| ms / 1000);
    let log_retention_days = db
        .get_setting("log_retention_days")
        .await?
        .and_then(|s| s.parse::<i64>().ok());

    let avg_new_rows_per_day = match oldest_log_timestamp {
        Some(oldest) if now > oldest => {
            let span_days = ((now - oldest) as f64 / 86400.0).max(1.0);
            total_log_count as f64 / span_days
        }
        _ => 0.0,
    };

    Ok(DbHealth {
        db_size_bytes,
        total_log_count,
        oldest_log_timestamp,
        log_retention_days,
        avg_new_rows_per_day,
    })
}
