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

pub const DEFAULT_LISTS: &[(&str, &str)] = &[
    (
        "AdGuard DNS Filter",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    ),
    ("EasyList", "https://easylist.to/easylist/easylist.txt"),
    (
        "Peter Lowe's List",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    ),
    ("OISD Small", "https://small.oisd.nl/"),
    (
        "Steven Black Unified Hosts",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    (
        "URLhaus Malware Filter",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
    ),
];

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

        tracing::info!(block_count, allow_count, "filter engine rebuilt");

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

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.db
            .update_filter_list_stats(list_id, now, rule_count as i64)
            .await?;

        Ok(rule_count)
    }

    /// Download all enabled lists and rebuild the filter.
    pub async fn update_all_lists(&self) -> Result<(), ListError> {
        let lists = self.db.get_filter_lists().await?;

        for list in &lists {
            if !list.enabled {
                continue;
            }
            match self.download_and_update_list(list.id).await {
                Ok(rule_count) => {
                    tracing::info!(list_id = list.id, name = %list.name, rule_count, "updated filter list");
                }
                Err(e) => {
                    tracing::error!(list_id = list.id, name = %list.name, error = %e, "failed to download list");
                }
            }
        }

        self.rebuild_filter().await?;

        Ok(())
    }

    /// On first run, seed default lists into the DB.
    pub async fn seed_default_lists(&self) -> Result<(), ListError> {
        let existing = self.db.get_filter_lists().await?;
        if !existing.is_empty() {
            return Ok(());
        }

        for (name, url) in DEFAULT_LISTS {
            self.db.add_filter_list(name, url, true).await?;
        }

        Ok(())
    }
}
