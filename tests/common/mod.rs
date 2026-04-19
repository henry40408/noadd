use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use tokio::net::TcpListener;

/// Spawn an ephemeral HTTP server that serves a fixed response body at `path`
/// with the given content-type. Returns the `http://127.0.0.1:PORT` base URL.
#[allow(dead_code)]
pub async fn spawn_fake_upstream(
    path: &'static str,
    body: String,
    content_type: &'static str,
) -> String {
    let body = Arc::new(body);
    let handler = {
        let body = body.clone();
        move || {
            let body = body.clone();
            async move {
                (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, content_type)],
                    (*body).clone(),
                )
            }
        }
    };
    let app = Router::new().route(path, get(handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}

/// Variant that serves a given HTTP status code (for 404/500 tests).
#[allow(dead_code)]
pub async fn spawn_fake_upstream_status(path: &'static str, status: u16) -> String {
    let app = Router::new().route(
        path,
        get(move || async move { axum::http::StatusCode::from_u16(status).unwrap() }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}
