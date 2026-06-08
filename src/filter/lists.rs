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
    #[error("filter rebuild task panicked: {0}")]
    Join(#[from] tokio::task::JoinError),
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

        // Read each enabled list's content sequentially (a single SQLite
        // connection serializes the calls anyway) into a `(name, content)`
        // vector. Parse + trie build then run on the blocking pool.
        let mut list_payloads: Vec<(String, String)> = Vec::new();
        for list in lists.iter().filter(|l| l.enabled) {
            if let Some(content) = self.db.get_filter_list_content(list.id).await? {
                list_payloads.push((list.name.clone(), content));
            }
        }

        let custom_blocks = self.db.get_custom_rules_by_type("block").await?;
        let custom_block_rules: Vec<String> = custom_blocks.into_iter().map(|cr| cr.rule).collect();

        let custom_allows = self.db.get_custom_rules_by_type("allow").await?;
        let custom_allow_rules: Vec<String> = custom_allows.into_iter().map(|cr| cr.rule).collect();

        // Parse each list on its own blocking worker so the parse cost (line
        // tokenising + per-rule `to_lowercase`) is shared across cores.
        let parse_start = std::time::Instant::now();
        let mut set: tokio::task::JoinSet<(usize, String, Vec<crate::filter::parser::ParsedRule>)> =
            tokio::task::JoinSet::new();
        for (idx, (name, content)) in list_payloads.into_iter().enumerate() {
            set.spawn_blocking(move || (idx, name, parse_list(&content)));
        }
        let mut parsed_lists: Vec<Option<(String, Vec<crate::filter::parser::ParsedRule>)>> =
            (0..set.len()).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            let (idx, name, parsed) = joined?;
            parsed_lists[idx] = Some((name, parsed));
        }
        let parse_ms = parse_start.elapsed().as_millis() as u64;

        // Finalise rule tables on the blocking pool so FilterEngine::new
        // (FST + flat trie build) doesn't pin a runtime worker. DNS queries
        // served from other listener tasks keep moving while we rebuild.
        let engine = tokio::task::spawn_blocking(move || {
            let mut list_names: Vec<Box<str>> = Vec::new();
            let mut block_rules: Vec<(crate::filter::parser::ParsedRule, u16)> = Vec::new();
            let mut allow_rules: Vec<crate::filter::parser::ParsedRule> = Vec::new();

            for slot in parsed_lists.into_iter() {
                let (name, parsed) = match slot {
                    Some(v) => v,
                    None => continue,
                };
                let list_idx = list_names.len() as u16;
                let mut used = false;
                for rule in parsed {
                    match rule.action {
                        RuleAction::Block => {
                            block_rules.push((rule, list_idx));
                            used = true;
                        }
                        RuleAction::Allow => {
                            allow_rules.push(rule);
                        }
                    }
                }
                if used {
                    list_names.push(Box::from(name.as_str()));
                }
            }

            // Custom rules sit under a synthetic "Custom" list. Only allocate
            // the slot if at least one custom block rule lands in it.
            let mut custom_idx: Option<u16> = None;
            for rule_text in custom_block_rules {
                if let Some(rule) = parse_rule(&rule_text) {
                    let idx = *custom_idx.get_or_insert_with(|| {
                        let i = list_names.len() as u16;
                        list_names.push(Box::from("Custom"));
                        i
                    });
                    block_rules.push((rule, idx));
                }
            }
            for rule_text in custom_allow_rules {
                if let Some(rule) = parse_rule(&rule_text) {
                    allow_rules.push(rule);
                }
            }

            let block_count = block_rules.len();
            let allow_count = allow_rules.len();
            let engine = FilterEngine::new(list_names, block_rules, allow_rules);
            (engine, block_count, allow_count)
        })
        .await?;
        let (engine, block_count, allow_count) = engine;
        self.filter.store(Arc::new(engine));

        // The build dropped its large transient trees on the blocking worker;
        // return those freed pages to the OS now instead of waiting for the
        // allocator's lazy purge, so the resident spike doesn't linger.
        crate::reclaim_memory();

        tracing::info!(
            block_count,
            allow_count,
            parse_ms,
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
        // Per-list download failures are expected (transient network issues,
        // upstream 5xx, list removed). Aggregate them into a single warn instead
        // of one error per list so a flaky update does not flood the logs.
        let mut failures: Vec<String> = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((list_id, name, Ok(rule_count))) => {
                    tracing::info!(list_id, name = %name, rule_count, "updated filter list");
                }
                Ok((_list_id, name, Err(e))) => {
                    failures.push(format!("{name} ({e})"));
                }
                Err(e) => {
                    failures.push(format!("<join failed> ({e})"));
                }
            }
        }
        if !failures.is_empty() {
            tracing::warn!(
                failed = failures.len(),
                lists = %failures.join(", "),
                "some filter lists failed to update; keeping previous data for those"
            );
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
