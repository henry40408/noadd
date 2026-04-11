use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use tempfile::NamedTempFile;

use noadd::cache::DnsCache;
use noadd::db::Database;
use noadd::dns::handler::DnsHandler;
use noadd::filter::engine::FilterEngine;
use noadd::filter::lists::ListManager;
use noadd::logger::QueryLogger;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

fn make_query_bytes(domain: &str, record_type: RecordType) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(1234);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    let mut query = Query::new();
    query.set_name(Name::from_str(domain).unwrap());
    query.set_query_type(record_type);
    msg.add_query(query);
    msg.to_vec().unwrap()
}

/// End-to-end test: a blocked domain flows through the full pipeline and
/// produces the correct DNS response and a query log entry in the database.
#[tokio::test]
async fn test_full_query_pipeline_block() {
    // 1. Create a temp DB
    let tmp = NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    let db = Database::open(&db_path).await.unwrap();

    // 2. Add a custom block rule
    db.add_custom_rule("||ads.blocked.com^", "block")
        .await
        .unwrap();

    // 3. Create FilterEngine + ListManager and rebuild filter
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![])));
    let manager = ListManager::new(db.clone(), filter.clone());
    manager.rebuild_filter().await.unwrap();

    // 4. Create DnsCache, UpstreamForwarder, DnsHandler with logger
    let cache = DnsCache::new(1000);
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);
    let (logger, log_tx) = QueryLogger::new(db.clone(), 500, 1);
    let logger_handle = tokio::spawn(logger.run());
    let handler = Arc::new(DnsHandler::new(filter, cache, forwarder, log_tx));

    // 5. Build DNS query bytes for ads.blocked.com A record
    let query_bytes = make_query_bytes("ads.blocked.com", RecordType::A);
    let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

    // 6. Handle the query
    let response_bytes = handler.handle(&query_bytes, client_ip, None).await.unwrap();

    // 7. Parse response and verify answer is 0.0.0.0
    let response = Message::from_bytes(&response_bytes).unwrap();
    assert_eq!(response.message_type(), MessageType::Response);
    assert!(!response.answers().is_empty(), "should have an answer");
    let answer = &response.answers()[0];
    match answer.data() {
        RData::A(a) => {
            assert_eq!(a.0, Ipv4Addr::UNSPECIFIED, "blocked A should be 0.0.0.0");
        }
        other => panic!("expected A record, got {other:?}"),
    }

    // 8. Drop the handler (and its log sender) to flush the logger
    drop(handler);
    logger_handle.await.unwrap();

    // 9. Verify query log in DB has blocked=true and domain="ads.blocked.com"
    let logs = db.query_logs(10, 0, None, None, None, None).await.unwrap();
    assert!(!logs.is_empty(), "should have at least one log entry");
    let log = &logs[0];
    assert_eq!(log.domain, "ads.blocked.com");
    assert!(log.blocked, "log entry should be marked as blocked");
}

/// End-to-end test: an allowed domain is forwarded upstream and returns a real
/// DNS response. Requires network access to upstream resolvers.
#[tokio::test]
async fn test_full_query_pipeline_allow() {
    // 1. Create a temp DB with empty filter (no block rules)
    let tmp = NamedTempFile::new().unwrap();
    let db_path = tmp.path().to_str().unwrap().to_string();
    let db = Database::open(&db_path).await.unwrap();

    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![])));
    let manager = ListManager::new(db.clone(), filter.clone());
    manager.rebuild_filter().await.unwrap();

    let cache = DnsCache::new(1000);
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);
    let (logger, log_tx) = QueryLogger::new(db.clone(), 500, 1);
    let logger_handle = tokio::spawn(logger.run());
    let handler = Arc::new(DnsHandler::new(filter, cache, forwarder, log_tx));

    // 2. Query example.com A record
    let query_bytes = make_query_bytes("example.com", RecordType::A);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let response_bytes = handler.handle(&query_bytes, client_ip, None).await.unwrap();

    // 3. Verify response has non-empty answers (requires network to upstream)
    let response = Message::from_bytes(&response_bytes).unwrap();
    assert_eq!(response.message_type(), MessageType::Response);
    assert!(
        !response.answers().is_empty(),
        "allowed domain should have answers from upstream"
    );

    // Verify the log entry is marked as allowed
    drop(handler);
    logger_handle.await.unwrap();

    let logs = db.query_logs(10, 0, None, None, None, None).await.unwrap();
    assert!(!logs.is_empty(), "should have at least one log entry");
    let log = &logs[0];
    assert_eq!(log.domain, "example.com");
    assert!(!log.blocked, "log entry should be marked as allowed");
}
