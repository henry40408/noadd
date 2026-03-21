use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::{Name, RecordType};
use tokio::sync::mpsc;
use tower::ServiceExt;

use noadd::cache::DnsCache;
use noadd::db::Database;
use noadd::dns::doh::doh_router;
use noadd::dns::handler::{DnsHandler, QueryContext};
use noadd::filter::engine::FilterEngine;
use noadd::filter::parser::{ParsedRule, RuleAction};
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

fn make_query_bytes(domain: &str, record_type: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut query = hickory_proto::op::Query::new();
    query.set_name(Name::from_str(domain).unwrap());
    query.set_query_type(record_type);
    msg.add_query(query);
    msg.to_vec().unwrap()
}

fn make_handler() -> Arc<DnsHandler> {
    let block_rules = vec![(
        ParsedRule {
            domain: "blocked.example.com".to_string(),
            action: RuleAction::Block,
            is_subdomain: true,
        },
        "test-list".to_string(),
    )];
    let engine = FilterEngine::new(block_rules, vec![]);
    let filter = Arc::new(ArcSwap::from_pointee(engine));
    let cache = DnsCache::new(100);
    let config = UpstreamConfig::default();
    let forwarder = Arc::new(UpstreamForwarder::new(config));
    let (tx, _rx) = mpsc::channel::<QueryContext>(64);
    Arc::new(DnsHandler::new(filter, cache, forwarder, tx))
}

async fn test_db() -> Database {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    // Leak the tempdir so it lives for the test duration
    let path_str = path.to_str().unwrap().to_string();
    std::mem::forget(dir);
    Database::open(&path_str).await.unwrap()
}

#[tokio::test]
async fn test_doh_get_no_token() {
    let handler = make_handler();
    let db = test_db().await;
    let app = doh_router(handler, db);

    let query_bytes = make_query_bytes("blocked.example.com", RecordType::A);
    let encoded = URL_SAFE_NO_PAD.encode(&query_bytes);

    let request = Request::builder()
        .method("GET")
        .uri(format!("/dns-query?dns={encoded}"))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // No tokens configured — should allow open access
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap().to_str().unwrap(),
        "application/dns-message"
    );
}

#[tokio::test]
async fn test_doh_post_no_token() {
    let handler = make_handler();
    let db = test_db().await;
    let app = doh_router(handler, db);

    let query_bytes = make_query_bytes("blocked.example.com", RecordType::A);

    let request = Request::builder()
        .method("POST")
        .uri("/dns-query")
        .header("content-type", "application/dns-message")
        .body(Body::from(query_bytes))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_doh_token_required_when_configured() {
    let handler = make_handler();
    let db = test_db().await;
    // Configure a token and set policy to deny
    db.add_doh_token("my-secret-token").await.unwrap();
    db.set_setting("doh_access_policy", "deny").await.unwrap();
    let app = doh_router(handler, db);

    let query_bytes = make_query_bytes("blocked.example.com", RecordType::A);
    let encoded = URL_SAFE_NO_PAD.encode(&query_bytes);

    // Without token — should be 403
    let request = Request::builder()
        .method("GET")
        .uri(format!("/dns-query?dns={encoded}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // With wrong token — should be 403
    let request = Request::builder()
        .method("GET")
        .uri(format!("/dns-query/wrong-token?dns={encoded}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // With correct token — should be 200
    let request = Request::builder()
        .method("GET")
        .uri(format!("/dns-query/my-secret-token?dns={encoded}"))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
