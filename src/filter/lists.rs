use std::sync::Arc;

use arc_swap::ArcSwap;
use thiserror::Error;

use crate::db::Database;
use crate::filter::engine::FilterEngine;
use crate::filter::parser::{RuleAction, parse_list, parse_rule};

#[derive(Debug, Error)]
pub enum ListError {
    #[error("db error: {0}")]
    Db(#[from] crate::db::DbError),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

pub const DEFAULT_LISTS: &[(&str, &str, bool)] = &[
    (
        "AdGuard DNS filter",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        true,
    ),
    (
        "AdAway Default Blocklist",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",
        false,
    ),
];

#[derive(Clone)]
pub struct ListManager {
    db: Database,
    filter: Arc<ArcSwap<FilterEngine>>,
}

impl ListManager {
    pub fn new(db: Database, filter: Arc<ArcSwap<FilterEngine>>) -> Self {
        Self { db, filter }
    }

    /// Rebuild the filter engine from all enabled lists + custom rules in DB.
    pub async fn rebuild_filter(&self) -> Result<(), ListError> {
        let start = std::time::Instant::now();
        tracing::info!("rebuilding filter engine");

        let lists = self.db.get_filter_lists().await?;

        let mut block_rules = Vec::new();
        let mut allow_rules = Vec::new();

        // Load rules from enabled filter lists
        for list in &lists {
            if !list.enabled {
                continue;
            }
            if let Some(content) = self.db.get_filter_list_content(list.id).await? {
                let parsed = parse_list(&content);
                for rule in parsed {
                    match rule.action {
                        RuleAction::Block => {
                            block_rules.push((rule, list.name.clone()));
                        }
                        RuleAction::Allow => {
                            allow_rules.push(rule);
                        }
                    }
                }
            }
        }

        // Load custom block rules
        let custom_blocks = self.db.get_custom_rules_by_type("block").await?;
        for cr in &custom_blocks {
            if let Some(rule) = parse_rule(&cr.rule) {
                block_rules.push((rule, "Custom".to_string()));
            }
        }

        // Load custom allow rules
        let custom_allows = self.db.get_custom_rules_by_type("allow").await?;
        for cr in &custom_allows {
            if let Some(rule) = parse_rule(&cr.rule) {
                allow_rules.push(rule);
            }
        }

        let block_count = block_rules.len();
        let allow_count = allow_rules.len();
        let engine = FilterEngine::new(block_rules, allow_rules);
        self.filter.store(Arc::new(engine));

        tracing::info!(
            block_count,
            allow_count,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "filter engine rebuilt"
        );

        Ok(())
    }

    /// Download a single list by ID and store its content in DB.
    /// Returns the number of parsed rules.
    pub async fn download_and_update_list(&self, list_id: i64) -> Result<usize, ListError> {
        let lists = self.db.get_filter_lists().await?;
        let list = lists.iter().find(|l| l.id == list_id);
        let list = match list {
            Some(l) => l,
            None => return Ok(0),
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .user_agent(crate::user_agent())
            .build()?;

        let content = client.get(&list.url).send().await?.text().await?;

        self.db.set_filter_list_content(list_id, &content).await?;

        let parsed = parse_list(&content);
        let rule_count = parsed.len();

        let now = crate::now_unix();

        self.db
            .update_filter_list_stats(list_id, now, rule_count as i64)
            .await?;

        Ok(rule_count)
    }

    /// Download all enabled lists. Does **not** rebuild the filter engine.
    ///
    /// Downloads run concurrently (bounded) — serial downloads were the
    /// dominant cost of the 24h update cycle on hosts running many lists.
    pub async fn update_all_lists_no_rebuild(&self) -> Result<(), ListError> {
        let lists = self.db.get_filter_lists().await?;

        let sem = Arc::new(tokio::sync::Semaphore::new(4));
        let mut set = tokio::task::JoinSet::new();
        for list in lists.into_iter().filter(|l| l.enabled) {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let this = self.clone();
            set.spawn(async move {
                let _permit = permit;
                let result = this.download_and_update_list(list.id).await;
                (list.id, list.name, result)
            });
        }
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((list_id, name, Ok(rule_count))) => {
                    tracing::info!(list_id, name = %name, rule_count, "updated filter list");
                }
                Ok((list_id, name, Err(e))) => {
                    tracing::error!(list_id, name = %name, error = %e, "failed to download list");
                }
                Err(e) => {
                    tracing::error!(error = %e, "list download task join failed");
                }
            }
        }

        Ok(())
    }

    /// Download all enabled lists and rebuild the filter.
    pub async fn update_all_lists(&self) -> Result<(), ListError> {
        self.update_all_lists_no_rebuild().await?;
        self.rebuild_filter().await?;
        Ok(())
    }

    /// On first run, seed default lists into the DB.
    pub async fn seed_default_lists(&self) -> Result<(), ListError> {
        let existing = self.db.get_filter_lists().await?;
        if !existing.is_empty() {
            return Ok(());
        }

        for (name, url, enabled) in DEFAULT_LISTS {
            self.db.add_filter_list(name, url, *enabled).await?;
        }

        Ok(())
    }
}
