use serde::Serialize;

use crate::db::{
    Database, DbError, HeatmapCell, TimelineMultiPoint, TimelinePoint, TopClient, TopDomain,
    TopUpstream,
};

/// Days of query-log history kept when `log_retention_days` is unset or
/// unparseable. The hourly prune task and the DB health report both fall back
/// to this, so the admin UI shows the retention that is actually in effect.
pub const DEFAULT_LOG_RETENTION_DAYS: i64 = 7;

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub total_today: i64,
    pub blocked_today: i64,
    pub total_7d: i64,
    pub blocked_7d: i64,
    pub total_30d: i64,
    pub blocked_30d: i64,
    pub block_ratio_today: f64,
    pub block_ratio_7d: f64,
    pub block_ratio_30d: f64,
    pub cache_hit_rate_today: f64,
    pub cache_hit_rate_7d: f64,
    pub cache_hit_rate_30d: f64,
    pub avg_response_ms_today: f64,
    pub avg_response_ms_7d: f64,
    pub avg_response_ms_30d: f64,
    pub queries_1m: i64,
}

pub async fn compute_summary(db: &Database, now: i64) -> Result<Summary, DbError> {
    let one_day: i64 = 86_400;
    let since_today = now - one_day;
    let since_7d = now - 7 * one_day;
    let since_30d = now - 30 * one_day;
    let since_1m = now - 60;

    let (queries_1m, _) = db.count_queries_since(since_1m).await?;
    let ((total_today, blocked_today), (total_7d, blocked_7d), (total_30d, blocked_30d)) = db
        .count_queries_multi_since(since_today, since_7d, since_30d)
        .await?;
    let (
        (cache_hits_today, allowed_total_today, avg_response_ms_today),
        (cache_hits_7d, allowed_total_7d, avg_response_ms_7d),
        (cache_hits_30d, allowed_total_30d, avg_response_ms_30d),
    ) = db
        .cache_stats_multi_since(since_today, since_7d, since_30d)
        .await?;

    let ratio = |blocked: i64, total: i64| -> f64 {
        if total > 0 {
            blocked as f64 / total as f64
        } else {
            0.0
        }
    };
    let hit_rate = |hits: i64, allowed: i64| -> f64 {
        if allowed > 0 {
            hits as f64 / allowed as f64
        } else {
            0.0
        }
    };

    Ok(Summary {
        total_today,
        blocked_today,
        total_7d,
        blocked_7d,
        total_30d,
        blocked_30d,
        block_ratio_today: ratio(blocked_today, total_today),
        block_ratio_7d: ratio(blocked_7d, total_7d),
        block_ratio_30d: ratio(blocked_30d, total_30d),
        cache_hit_rate_today: hit_rate(cache_hits_today, allowed_total_today),
        cache_hit_rate_7d: hit_rate(cache_hits_7d, allowed_total_7d),
        cache_hit_rate_30d: hit_rate(cache_hits_30d, allowed_total_30d),
        avg_response_ms_today,
        avg_response_ms_7d,
        avg_response_ms_30d,
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

    /// (`since_seconds_offset`, `bucket_secs`)
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
    /// Main database file size (`page_count * page_size`).
    pub db_size_bytes: i64,
    /// Free pages a `VACUUM` would return to the OS (subset of the main file).
    pub reclaimable_bytes: i64,
    /// Reclaimable share of the main file, 0.0–1.0. Mirrors the freelist ratio
    /// that gates the background `VACUUM`.
    pub fragmentation_ratio: f64,
    pub total_log_count: i64,
    pub oldest_log_timestamp: Option<i64>, // unix seconds
    pub log_retention_days: Option<i64>,
    pub avg_new_rows_per_day: f64,
    /// Average on-disk bytes per log row (`db_size_bytes / total_log_count`),
    /// 0.0 when there are no logs.
    pub bytes_per_log: f64,
    /// Actual span of retained data in days (newest − oldest log), 0.0 when
    /// fewer than two logs exist.
    pub log_coverage_days: f64,
    /// Projected steady-state main-file size once retention is full:
    /// `bytes_per_log × avg_new_rows_per_day × log_retention_days`. 0 when any
    /// input is unavailable.
    pub projected_full_bytes: i64,
}

pub async fn compute_stats_timeline(
    db: &Database,
    now: i64,
    range: StatsRange,
    tz_offset_secs: i64,
) -> Result<Vec<TimelineMultiPoint>, DbError> {
    let (window_secs, bucket_secs) = range.window();
    db.timeline_multi_since(now - window_secs, bucket_secs, tz_offset_secs)
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
    let (query_types, outcomes) = tokio::try_join!(
        db.query_type_breakdown_since(since),
        db.outcome_breakdown_since(since),
    )?;
    Ok(Breakdowns {
        query_types,
        outcomes,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StatsHighlights {
    pub unique_domains: i64,
    pub latency: crate::db::LatencySummary,
}

pub async fn compute_highlights(
    db: &Database,
    now: i64,
    range: StatsRange,
) -> Result<StatsHighlights, DbError> {
    let (window_secs, _) = range.window();
    let since = now - window_secs;
    let (unique_domains, latency) = tokio::try_join!(
        db.unique_domains_since(since),
        db.latency_summary_since(since),
    )?;
    Ok(StatsHighlights {
        unique_domains,
        latency,
    })
}

pub async fn compute_top_domains_ranged(
    db: &Database,
    now: i64,
    range: StatsRange,
    limit: i64,
) -> Result<Vec<crate::db::TopDomain>, DbError> {
    let (window_secs, _) = range.window();
    db.top_domains_since(now - window_secs, limit).await
}

pub async fn compute_top_clients_ranged(
    db: &Database,
    now: i64,
    range: StatsRange,
    limit: i64,
) -> Result<Vec<crate::db::TopClient>, DbError> {
    let (window_secs, _) = range.window();
    db.top_clients_since(now - window_secs, limit).await
}

pub async fn compute_db_health(db: &Database, now: i64) -> Result<DbHealth, DbError> {
    let (storage, total_log_count, earliest_ms, latest_ms, retention_setting) = tokio::try_join!(
        db.db_storage_stats(),
        db.total_log_count(),
        db.earliest_log_timestamp(),
        db.latest_log_timestamp(),
        db.get_setting("log_retention_days"),
    )?;
    let db_size_bytes = storage.main_bytes;
    let fragmentation_ratio = if storage.main_bytes > 0 {
        storage.reclaimable_bytes as f64 / storage.main_bytes as f64
    } else {
        0.0
    };
    let oldest_log_timestamp = earliest_ms.map(|ms| ms / 1000);
    let log_retention_days = Some(
        retention_setting
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(DEFAULT_LOG_RETENTION_DAYS),
    );

    let avg_new_rows_per_day = match oldest_log_timestamp {
        Some(oldest) if now > oldest => {
            let span_days = ((now - oldest) as f64 / 86400.0).max(1.0);
            total_log_count as f64 / span_days
        }
        _ => 0.0,
    };

    let bytes_per_log = if total_log_count > 0 {
        db_size_bytes as f64 / total_log_count as f64
    } else {
        0.0
    };

    // Actual span of retained data (newest − oldest). Reported in days.
    let log_coverage_days = match (earliest_ms, latest_ms) {
        (Some(min_ms), Some(max_ms)) if max_ms > min_ms => (max_ms - min_ms) as f64 / 86_400_000.0,
        _ => 0.0,
    };

    // Steady-state estimate: per-row cost × expected rows held at full retention.
    let projected_full_bytes = match log_retention_days {
        Some(days) if days > 0 && avg_new_rows_per_day > 0.0 && bytes_per_log > 0.0 => {
            (bytes_per_log * avg_new_rows_per_day * days as f64) as i64
        }
        _ => 0,
    };

    Ok(DbHealth {
        db_size_bytes,
        reclaimable_bytes: storage.reclaimable_bytes,
        fragmentation_ratio,
        total_log_count,
        oldest_log_timestamp,
        log_retention_days,
        avg_new_rows_per_day,
        bytes_per_log,
        log_coverage_days,
        projected_full_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn db_health_retention_defaults_when_setting_absent() {
        let db = Database::open(":memory:").await.unwrap();
        let h = compute_db_health(&db, 0).await.unwrap();
        assert_eq!(h.log_retention_days, Some(DEFAULT_LOG_RETENTION_DAYS));
    }

    #[tokio::test]
    async fn db_health_retention_reflects_configured_setting() {
        let db = Database::open(":memory:").await.unwrap();
        db.set_setting("log_retention_days", "30").await.unwrap();
        let h = compute_db_health(&db, 0).await.unwrap();
        assert_eq!(h.log_retention_days, Some(30));
    }

    #[tokio::test]
    async fn db_health_retention_defaults_when_setting_unparseable() {
        let db = Database::open(":memory:").await.unwrap();
        db.set_setting("log_retention_days", "not-a-number")
            .await
            .unwrap();
        let h = compute_db_health(&db, 0).await.unwrap();
        assert_eq!(h.log_retention_days, Some(DEFAULT_LOG_RETENTION_DAYS));
    }

    fn log_at(ms: i64) -> crate::db::QueryLogEntry {
        crate::db::QueryLogEntry {
            timestamp: ms,
            domain: "example.com".into(),
            query_type: "A".into(),
            client_ip: "127.0.0.1".into(),
            blocked: false,
            cached: false,
            response_ms: 1,
            upstream: None,
            doh_token: None,
            result: None,
            authenticated_data: false,
        }
    }

    #[tokio::test]
    async fn db_health_derived_fields_zero_on_empty_db() {
        let db = Database::open(":memory:").await.unwrap();
        let h = compute_db_health(&db, 1_000_000).await.unwrap();
        assert_eq!(h.bytes_per_log, 0.0);
        assert_eq!(h.log_coverage_days, 0.0);
        assert_eq!(h.projected_full_bytes, 0);
    }

    #[tokio::test]
    async fn db_health_derived_fields_reflect_logged_span() {
        let db = Database::open(":memory:").await.unwrap();
        let day_ms = 86_400_000;
        // Two logs three days apart (timestamps stored in ms).
        db.insert_query_logs(&[log_at(day_ms), log_at(4 * day_ms)])
            .await
            .unwrap();
        let now = 5 * 86_400; // seconds
        let h = compute_db_health(&db, now).await.unwrap();

        assert!(h.bytes_per_log > 0.0);
        // Span is exactly three days.
        assert!((h.log_coverage_days - 3.0).abs() < 1e-6);
        // Projection requires positive avg/day, retention, and bytes/log.
        assert!(h.projected_full_bytes > 0);
    }
}
