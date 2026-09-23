use std::sync::Arc;

use arc_swap::ArcSwap;
use thiserror::Error;

use crate::db::Database;
use crate::filter::engine::{CUSTOM_LIST_ID, FilterEngine, ListMeta};
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
        tracing::info!(event = "filter.rebuild_started", "rebuilding filter engine");

        let lists = self.db.get_filter_lists().await?;

        // Sequential reads: SQLite serialises them anyway.
        let mut list_payloads: Vec<(i64, String, String)> = Vec::new();
        for list in lists.iter().filter(|l| l.enabled) {
            if let Some(content) = self.db.get_filter_list_content(list.id).await? {
                list_payloads.push((list.id, list.name.clone(), content));
            }
        }

        let custom_blocks = self.db.get_custom_rules_by_type("block").await?;
        let custom_block_rules: Vec<String> = custom_blocks.into_iter().map(|cr| cr.rule).collect();

        let custom_allows = self.db.get_custom_rules_by_type("allow").await?;
        let custom_allow_rules: Vec<String> = custom_allows.into_iter().map(|cr| cr.rule).collect();

        // One blocking worker per list, so parsing spreads across cores.
        let parse_start = std::time::Instant::now();
        let mut set: tokio::task::JoinSet<(
            usize,
            ListMeta,
            Vec<crate::filter::parser::ParsedRule>,
        )> = tokio::task::JoinSet::new();
        for (idx, (id, name, content)) in list_payloads.into_iter().enumerate() {
            set.spawn_blocking(move || (idx, ListMeta::new(&name, id), parse_list(&content)));
        }
        let mut parsed_lists: Vec<Option<(ListMeta, Vec<crate::filter::parser::ParsedRule>)>> =
            (0..set.len()).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            let (idx, meta, parsed) = joined?;
            parsed_lists[idx] = Some((meta, parsed));
        }
        let parse_ms = parse_start.elapsed().as_millis() as u64;

        // `FilterEngine::new` on the blocking pool so it does not pin a runtime
        // worker that DNS queries need.
        let engine = tokio::task::spawn_blocking(move || {
            let mut lists: Vec<ListMeta> = Vec::new();
            let mut block_rules: Vec<(crate::filter::parser::ParsedRule, u16)> = Vec::new();
            let mut allow_rules: Vec<crate::filter::parser::ParsedRule> = Vec::new();

            for slot in parsed_lists {
                let Some((meta, parsed)) = slot else {
                    continue;
                };
                let list_idx = lists.len() as u16;
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
                    lists.push(meta);
                }
            }

            // Synthetic "Custom" list, allocated only if a custom block rule exists.
            let mut custom_idx: Option<u16> = None;
            for rule_text in custom_block_rules {
                if let Some(rule) = parse_rule(&rule_text) {
                    let idx = *custom_idx.get_or_insert_with(|| {
                        let i = lists.len() as u16;
                        lists.push(ListMeta::new("Custom", CUSTOM_LIST_ID));
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
            let engine = FilterEngine::new(lists, block_rules, allow_rules);
            (engine, block_count, allow_count)
        })
        .await?;
        let (engine, block_count, allow_count) = engine;
        self.filter.store(Arc::new(engine));

        // Return the build's freed transient trees to the OS now.
        crate::reclaim_memory();

        tracing::info!(
            event = "filter.rebuild_completed",
            block_count,
            allow_count,
            parse_ms,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "filter engine rebuilt"
        );

        Ok(())
    }

    /// Download a list by ID and store it; returns the number of parsed rules.
    pub async fn download_and_update_list(&self, list_id: i64) -> Result<usize, ListError> {
        let lists = self.db.get_filter_lists().await?;
        let list = lists.iter().find(|l| l.id == list_id);
        let Some(list) = list else {
            return Ok(0);
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
    /// Downloads run concurrently, at most four at a time.
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
        // Per-list failures are expected; aggregate them into one warn.
        let mut failures: Vec<String> = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((list_id, name, Ok(rule_count))) => {
                    tracing::info!(
                        event = "filter.list_updated",
                        list_id,
                        name = %name,
                        rule_count,
                        "updated filter list"
                    );
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
                event = "filter.list_update_failed",
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
