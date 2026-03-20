use std::sync::Arc;

use arc_swap::ArcSwap;

use noadd::db::Database;
use noadd::filter::engine::{FilterEngine, FilterResult};
use noadd::filter::lists::{ListManager, DEFAULT_LISTS};

async fn setup() -> (Database, ListManager) {
    let db = Database::open(":memory:").await.unwrap();
    let engine = FilterEngine::new(vec![], vec![]);
    let filter = Arc::new(ArcSwap::new(Arc::new(engine)));
    let manager = ListManager::new(db.clone(), filter.clone());
    (db, manager)
}

async fn setup_with_filter() -> (Database, ListManager, Arc<ArcSwap<FilterEngine>>) {
    let db = Database::open(":memory:").await.unwrap();
    let engine = FilterEngine::new(vec![], vec![]);
    let filter = Arc::new(ArcSwap::new(Arc::new(engine)));
    let manager = ListManager::new(db.clone(), filter.clone());
    (db, manager, filter)
}

#[tokio::test]
async fn test_seed_default_lists() {
    let (db, manager) = setup().await;

    manager.seed_default_lists().await.unwrap();

    let lists = db.get_filter_lists().await.unwrap();
    assert_eq!(lists.len(), DEFAULT_LISTS.len());

    for (i, list) in lists.iter().enumerate() {
        assert_eq!(list.name, DEFAULT_LISTS[i].0);
        assert_eq!(list.url, DEFAULT_LISTS[i].1);
        assert!(list.enabled);
    }
}

#[tokio::test]
async fn test_seed_default_lists_idempotent() {
    let (db, manager) = setup().await;

    manager.seed_default_lists().await.unwrap();
    manager.seed_default_lists().await.unwrap();

    let lists = db.get_filter_lists().await.unwrap();
    assert_eq!(lists.len(), DEFAULT_LISTS.len());
}

#[tokio::test]
async fn test_rebuild_filter_from_custom_rules() {
    let (db, manager, filter) = setup_with_filter().await;

    // Add a custom block rule
    db.add_custom_rule("||ads.example.com^", "block")
        .await
        .unwrap();

    // Add a custom allow rule
    db.add_custom_rule("@@||safe.ads.example.com^", "allow")
        .await
        .unwrap();

    // Rebuild the filter engine
    manager.rebuild_filter().await.unwrap();

    let engine = filter.load();

    // ads.example.com should be blocked (subdomain rule)
    assert!(matches!(
        engine.check("ads.example.com"),
        FilterResult::Blocked { .. }
    ));

    // sub.ads.example.com should also be blocked (subdomain match)
    assert!(matches!(
        engine.check("sub.ads.example.com"),
        FilterResult::Blocked { .. }
    ));

    // safe.ads.example.com should be allowed (allow rule takes precedence)
    assert!(matches!(
        engine.check("safe.ads.example.com"),
        FilterResult::Allowed
    ));

    // unrelated domain should be allowed
    assert!(matches!(
        engine.check("example.org"),
        FilterResult::Allowed
    ));
}
