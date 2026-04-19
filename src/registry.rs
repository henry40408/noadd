use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("parse error: {0}")]
    Parse(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegistryFilter {
    pub filter_id: i64,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub homepage: Option<String>,
    pub download_url: String,
    pub group_id: i64,
    pub deprecated: bool,
    pub time_updated: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegistryGroup {
    pub group_id: i64,
    pub group_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegistryData {
    pub filters: Vec<RegistryFilter>,
    pub groups: Vec<RegistryGroup>,
}

struct CachedEntry {
    fetched_at: Instant,
    data: RegistryData,
}

pub struct RegistryClient {
    http: reqwest::Client,
    cache: RwLock<Option<CachedEntry>>,
    ttl: Duration,
    url: String,
}

pub const DEFAULT_REGISTRY_URL: &str =
    "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json";

impl RegistryClient {
    pub fn new(url: impl Into<String>, ttl: Duration) -> Arc<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(crate::user_agent())
            .build()
            .expect("reqwest client build");
        Arc::new(Self {
            http,
            cache: RwLock::new(None),
            ttl,
            url: url.into(),
        })
    }

    pub async fn list(&self) -> Result<RegistryData, RegistryError> {
        {
            let guard = self.cache.read().await;
            if let Some(ref entry) = *guard
                && entry.fetched_at.elapsed() < self.ttl
            {
                return Ok(entry.data.clone());
            }
        }

        let body = self
            .http
            .get(&self.url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let data: RegistryData = serde_json::from_str(&body)?;

        let mut guard = self.cache.write().await;
        *guard = Some(CachedEntry {
            fetched_at: Instant::now(),
            data: data.clone(),
        });
        Ok(data)
    }
}
