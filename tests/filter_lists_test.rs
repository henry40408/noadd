use std::sync::Arc;

use arc_swap::ArcSwap;

use noadd::db::Database;
use noadd::filter::engine::{FilterEngine, FilterResult};
use noadd::filter::lists::{DEFAULT_LISTS, ListManager};

async fn setup() -> (Database, ListManager) {
    let db = Database::open(":memory:").await.unwrap();
    let engine = FilterEngine::new(vec![], vec![], vec![]);
    let filter = Arc::new(ArcSwap::new(Arc::new(engine)));
    let manager = ListManager::new(db.clone(), filter.clone());
    (db, manager)
}

async fn setup_with_filter() -> (Database, ListManager, Arc<ArcSwap<FilterEngine>>) {
    let db = Database::open(":memory:").await.unwrap();
    let engine = FilterEngine::new(vec![], vec![], vec![]);
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
        assert_eq!(list.enabled, DEFAULT_LISTS[i].2);
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

    db.add_custom_rule("||ads.example.com^", "block")
        .await
        .unwrap();

    db.add_custom_rule("@@||safe.ads.example.com^", "allow")
        .await
        .unwrap();

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
        FilterResult::Allowed { .. }
    ));

    // unrelated domain should be allowed
    assert!(matches!(
        engine.check("example.org"),
        FilterResult::Allowed { .. }
    ));
}

#[tokio::test]
async fn test_update_all_lists_no_rebuild_does_not_rebuild() {
    let (db, manager, filter) = setup_with_filter().await;

    // Insert a custom block rule so rebuild would notice it.
    db.add_custom_rule("||ads.example.com^", "block")
        .await
        .unwrap();

    // Sanity: before any rebuild, engine does not know the rule.
    assert!(matches!(
        filter.load().check("ads.example.com"),
        noadd::filter::engine::FilterResult::Allowed { .. }
    ));

    // update_all_lists_no_rebuild must leave engine untouched.
    manager.update_all_lists_no_rebuild().await.unwrap();
    assert!(matches!(
        filter.load().check("ads.example.com"),
        noadd::filter::engine::FilterResult::Allowed { .. }
    ));

    // A direct rebuild_filter call still works.
    manager.rebuild_filter().await.unwrap();
    assert!(matches!(
        filter.load().check("ads.example.com"),
        noadd::filter::engine::FilterResult::Blocked { .. }
    ));
}

#[tokio::test]
async fn test_store_list_content_reports_whether_content_changed() {
    let (db, manager) = setup().await;
    let id = db
        .add_filter_list("test", "https://example.invalid/list.txt", true)
        .await
        .unwrap();
    let current_row = || async {
        db.get_filter_lists()
            .await
            .unwrap()
            .into_iter()
            .find(|l| l.id == id)
            .unwrap()
    };

    let one_rule = "||ads.example.com^\n";
    let first = manager
        .store_list_content(&current_row().await, one_rule)
        .await
        .unwrap();
    assert!(first.changed);
    assert_eq!(first.rule_count, 1);

    let same = manager
        .store_list_content(&current_row().await, one_rule)
        .await
        .unwrap();
    assert!(!same.changed);
    assert_eq!(same.rule_count, 1);

    let edited = manager
        .store_list_content(
            &current_row().await,
            "||ads.example.com^\n||b.example.com^\n",
        )
        .await
        .unwrap();
    assert!(edited.changed);
    assert_eq!(edited.rule_count, 2);
}
