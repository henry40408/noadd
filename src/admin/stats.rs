use serde::Serialize;

use crate::db::{
    Database, DbError, HeatmapCell, TimelineMultiPoint, TimelinePoint, TopClient, TopDomain,
    TopUpstream,
};

/// Days of query-log history kept when `log_retention_days` is unset or
/// unparseable. The hourly prune task and the DB health report both fall back
/// to this, so the admin UI shows the retention that is actually in effect.
pub const DEFAULT_LOG_RETENTION_DAYS: i64 = 7;

/// Retention spans the settings form suggests, ascending, from a day of
/// debugging up to a year. [`DEFAULT_LOG_RETENTION_DAYS`] is among them so the
/// list can restore the default the operator started from.
///
/// Unlike the block-mode addresses, `apply_settings` does not validate this
/// field — an unparseable value is stored and every reader falls back to the
/// default. The suggestions are therefore held to the stricter bar the readers
/// actually need: each must parse as a positive `i64`. Enforced by
/// `log_retention_suggestions_are_usable`.
pub const LOG_RETENTION_DAYS_SUGGESTIONS: &[i64] = &[1, 7, 14, 30, 90, 365];

/// `Default` is all zeroes, which is what the dashboard renders when the read
/// fails: a page of zeroes is more useful than one that will not load, and it
/// is the same shape an appliance that has answered nothing yet reports.
#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct Summary {
    /// Total queries handled since local midnight today.
    pub total_today: i64,
    /// Queries blocked by the filter engine since local midnight today.
    pub blocked_today: i64,
    /// Total queries handled in the trailing 7 days.
    pub total_7d: i64,
    /// Queries blocked in the trailing 7 days.
    pub blocked_7d: i64,
    /// Total queries handled in the trailing 30 days.
    pub total_30d: i64,
    /// Queries blocked in the trailing 30 days.
    pub blocked_30d: i64,
    /// `blocked_today / total_today`, or `0` if there were no queries today.
    pub block_ratio_today: f64,
    /// `blocked_7d / total_7d`, or `0` if there were no queries in the window.
    pub block_ratio_7d: f64,
    /// `blocked_30d / total_30d`, or `0` if there were no queries in the window.
    pub block_ratio_30d: f64,
    /// Fraction of today's queries answered from the DNS cache.
    pub cache_hit_rate_today: f64,
    /// Fraction of the trailing-7-day queries answered from the DNS cache.
    pub cache_hit_rate_7d: f64,
    /// Fraction of the trailing-30-day queries answered from the DNS cache.
    pub cache_hit_rate_30d: f64,
    /// Average response time in milliseconds for today's queries.
    pub avg_response_ms_today: f64,
    /// Average response time in milliseconds over the trailing 7 days.
    pub avg_response_ms_7d: f64,
    /// Average response time in milliseconds over the trailing 30 days.
    pub avg_response_ms_30d: f64,
    /// Queries handled in the last 60 seconds (a rough current-rate indicator).
    pub queries_1m: i64,
}

pub async fn compute_summary(db: &Database, now: i64) -> Result<Summary, DbError> {
    let one_day: i64 = 86_400;
    let since_today = now - one_day;
    let since_7d = now - 7 * one_day;
    let since_30d = now - 30 * one_day;
    let since_1m = now - 60;

    let queries_1m = db.count_queries_since(since_1m).await?;
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

/// How far back the domain suggestions look. A week rather than the
/// dashboard's day: those two boxes are used to chase something already
/// noticed, and "it was misbehaving on Friday" has to still be offered on
/// Monday. It also matches [`DEFAULT_LOG_RETENTION_DAYS`], so the window is
/// the log itself on a default install.
const DOMAIN_SUGGESTION_WINDOW_SECS: i64 = DEFAULT_LOG_RETENTION_DAYS * 86400;

/// How many domains those boxes offer. Long enough to cover a home network's
/// regulars, short enough that the dropdown stays a shortlist — past a screenful
/// scrolling it is slower than typing.
const DOMAIN_SUGGESTION_LIMIT: i64 = 20;

/// The domains to suggest in a box the operator types a domain into: the
/// `/filters` tester and the `/logs` search.
///
/// Ordered by how often each was queried, not alphabetically — the whole point
/// is that the domain being chased is near the top, and a browser renders a
/// datalist in document order. Empty on a read failure or an empty log, which
/// the pages turn into no `<datalist>` at all rather than an empty one.
pub async fn domain_suggestions(db: &Database, now: i64) -> Vec<String> {
    db.top_domains_since(now - DOMAIN_SUGGESTION_WINDOW_SECS, DOMAIN_SUGGESTION_LIMIT)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.domain)
        .collect()
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

    let earliest = db.earliest_log_timestamp().await?;
    let since = match earliest {
        Some(ts_ms) => {
            let ts_secs = ts_ms / 1000;
            ts_secs.max(max_since)
        }
        None => max_since,
    };

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

    /// The spelling `parse` accepts, which is also what the range switcher puts
    /// in the URL and every card title says. One source for all three, so a
    /// title cannot disagree with the link that produced it.
    pub fn label(self) -> &'static str {
        match self {
            Self::Days7 => "7d",
            Self::Days30 => "30d",
            Self::Days90 => "90d",
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

pub async fn compute_heatmap(
    db: &Database,
    now: i64,
    tz_offset_secs: i64,
) -> Result<Vec<HeatmapCell>, DbError> {
    db.hourly_heatmap_since(now - 30 * 86400, tz_offset_secs)
        .await
}

pub async fn compute_breakdowns(
    db: &Database,
    now: i64,
    range: StatsRange,
) -> Result<Breakdowns, DbError> {
    let (window_secs, _) = range.window();
    let since = now - window_secs;
    // Both breakdowns fold out of one statement; asking for them separately is
    // two scans of the index that answers either.
    let metrics = db.window_metrics_since(since).await?;
    Ok(Breakdowns {
        query_types: metrics.query_types,
        outcomes: metrics.outcomes,
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

/// Everything the Statistics page reads out of `query_logs` for its window, in
/// the fewest scans the indexes allow.
///
/// The page used to ask for the five readings separately — a query-type
/// breakdown, an outcome breakdown, a latency summary, a unique-domain count,
/// a top-domain list — and every one of them re-scanned an index another had
/// just walked. Three of them share
/// [`crate::db::Database::window_metrics_since`] and two share
/// [`crate::db::Database::domain_stats_since`], which is two index scans
/// instead of six.
pub struct RangeStats {
    pub metrics: crate::db::WindowMetrics,
    pub domains: crate::db::DomainStats,
}

pub async fn compute_range_stats(
    db: &Database,
    now: i64,
    range: StatsRange,
    top_n: i64,
) -> Result<RangeStats, DbError> {
    let (window_secs, _) = range.window();
    let since = now - window_secs;
    let (metrics, domains) = tokio::try_join!(
        db.window_metrics_since(since),
        db.domain_stats_since(since, top_n),
    )?;
    Ok(RangeStats { metrics, domains })
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

    /// The retention field takes anything the save is given, so the guarantee
    /// the suggestions have to meet is the readers': each must come back as a
    /// positive count rather than silently collapsing to the default.
    #[tokio::test]
    async fn log_retention_suggestions_are_usable() {
        assert!(LOG_RETENTION_DAYS_SUGGESTIONS.contains(&DEFAULT_LOG_RETENTION_DAYS));

        // A browser renders a datalist in document order, so an unsorted list
        // reads as arbitrary.
        assert!(
            LOG_RETENTION_DAYS_SUGGESTIONS
                .windows(2)
                .all(|w| w[0] < w[1])
        );

        let db = Database::open(":memory:").await.unwrap();
        for days in LOG_RETENTION_DAYS_SUGGESTIONS {
            assert!(*days > 0, "retention of {days} days would keep nothing");
            db.set_setting("log_retention_days", &days.to_string())
                .await
                .unwrap();
            let h = compute_db_health(&db, 0).await.unwrap();
            assert_eq!(
                h.log_retention_days,
                Some(*days),
                "suggestion {days} did not survive the read back"
            );
        }
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
    #[allow(clippy::float_cmp, reason = "exact-value test assertion")]
    async fn db_health_derived_fields_zero_on_empty_db() {
        let db = Database::open(":memory:").await.unwrap();
        let h = compute_db_health(&db, 1_000_000).await.unwrap();
        assert_eq!(h.bytes_per_log, 0.0);
        assert_eq!(h.log_coverage_days, 0.0);
        assert_eq!(h.projected_full_bytes, 0);
    }

    fn log_for(domain: &str, ms: i64) -> crate::db::QueryLogEntry {
        crate::db::QueryLogEntry {
            domain: domain.into(),
            ..log_at(ms)
        }
    }

    /// The suggestions are a shortlist of what the resolver has actually seen,
    /// most-queried first — the domain being chased should be near the top,
    /// and a browser renders a datalist in document order.
    #[tokio::test]
    async fn domain_suggestions_are_ordered_by_how_often_each_was_queried() {
        let db = Database::open(":memory:").await.unwrap();
        let now = 10 * 86_400;
        let recent_ms = (now - 3600) * 1000;

        let mut logs = vec![log_for("rare.example", recent_ms)];
        logs.extend((0..5).map(|_| log_for("common.example", recent_ms)));
        logs.extend((0..3).map(|_| log_for("middling.example", recent_ms)));
        db.insert_query_logs(&logs).await.unwrap();

        assert_eq!(
            domain_suggestions(&db, now).await,
            vec![
                "common.example".to_string(),
                "middling.example".to_string(),
                "rare.example".to_string(),
            ]
        );
    }

    /// The window is a week, not the dashboard's day: chasing something first
    /// noticed on Friday has to still work on Monday.
    #[tokio::test]
    async fn domain_suggestions_span_a_week_but_no_further() {
        let db = Database::open(":memory:").await.unwrap();
        let now = 30 * 86_400;

        db.insert_query_logs(&[
            log_for("within.example", (now - 6 * 86_400) * 1000),
            log_for("expired.example", (now - 8 * 86_400) * 1000),
        ])
        .await
        .unwrap();

        assert_eq!(
            domain_suggestions(&db, now).await,
            vec!["within.example".to_string()]
        );
    }

    /// A fresh install has nothing to suggest, and says so with an empty list
    /// rather than an error — the pages turn that into no `<datalist>` at all.
    #[tokio::test]
    async fn domain_suggestions_are_empty_when_nothing_has_been_queried() {
        let db = Database::open(":memory:").await.unwrap();
        assert!(domain_suggestions(&db, 10 * 86_400).await.is_empty());
    }

    #[tokio::test]
    async fn domain_suggestions_stay_a_shortlist() {
        let db = Database::open(":memory:").await.unwrap();
        let now = 10 * 86_400;
        let recent_ms = (now - 3600) * 1000;

        let logs: Vec<_> = (0..DOMAIN_SUGGESTION_LIMIT + 10)
            .map(|i| log_for(&format!("d{i}.example"), recent_ms))
            .collect();
        db.insert_query_logs(&logs).await.unwrap();

        assert_eq!(
            domain_suggestions(&db, now).await.len(),
            usize::try_from(DOMAIN_SUGGESTION_LIMIT).unwrap()
        );
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
