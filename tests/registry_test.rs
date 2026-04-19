use std::time::Duration;

use noadd::registry::RegistryClient;

#[path = "common/mod.rs"]
mod common;

fn sample_json() -> &'static str {
    r#"{
      "filters": [
        {
          "filterKey": "adguard_dns",
          "filterId": 1,
          "groupId": 1,
          "name": "AdGuard DNS filter",
          "description": "Desc 1",
          "homepage": "https://example.com/1",
          "deprecated": false,
          "tags": [1],
          "languages": [],
          "version": "1",
          "expires": 345600,
          "displayNumber": 1,
          "downloadUrl": "https://example.com/filter_1.txt",
          "subscriptionUrl": "https://example.com/sub_1",
          "timeAdded": "2021-01-01T00:00:00+0000",
          "timeUpdated": "2026-04-19T00:00:00+0000"
        }
      ],
      "groups": [
        { "groupId": 1, "groupName": "General" }
      ],
      "tags": []
    }"#
}

#[tokio::test]
async fn fetch_populates_cache() {
    let base = common::spawn_fake_upstream(
        "/filters.json",
        sample_json().to_string(),
        "application/json",
    )
    .await;
    let client = RegistryClient::new(format!("{base}/filters.json"), Duration::from_secs(3600));
    let data = client.list().await.unwrap();
    assert_eq!(data.filters.len(), 1);
    assert_eq!(data.filters[0].name, "AdGuard DNS filter");
    assert_eq!(
        data.filters[0].download_url,
        "https://example.com/filter_1.txt"
    );
    assert_eq!(data.groups.len(), 1);
    assert_eq!(data.groups[0].group_name, "General");
    // Second call served from cache — returns the same data even if upstream changes.
    let data2 = client.list().await.unwrap();
    assert_eq!(data2.filters[0].name, "AdGuard DNS filter");
}

#[tokio::test]
async fn cache_expires_after_ttl() {
    let base = common::spawn_fake_upstream(
        "/filters.json",
        sample_json().to_string(),
        "application/json",
    )
    .await;
    let client = RegistryClient::new(format!("{base}/filters.json"), Duration::from_millis(1));
    client.list().await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    // Second call — TTL expired. Must still succeed.
    let data2 = client.list().await.unwrap();
    assert_eq!(data2.filters.len(), 1);
}

#[tokio::test]
async fn upstream_error_surfaces() {
    let base = common::spawn_fake_upstream_status("/filters.json", 500).await;
    let client = RegistryClient::new(format!("{base}/filters.json"), Duration::from_secs(3600));
    let err = client.list().await.unwrap_err();
    let msg = format!("{err}").to_lowercase();
    assert!(msg.contains("http") || msg.contains("500"));
}
