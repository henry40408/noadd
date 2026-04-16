use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use clap::Parser;

use noadd::admin::api::{AppState, ServerInfo, admin_router};
use noadd::admin::auth::{RateLimiter, load_sessions_from_db, new_session_store};
use noadd::cache::DnsCache;
use noadd::config::CliArgs;
use noadd::db::Database;
use noadd::dns::doh::doh_router;
use noadd::dns::handler::DnsHandler;
use noadd::dns::ratelimit::IpRateLimiter;
use noadd::dns::tcp::run_tcp_listener;
use noadd::dns::udp::run_udp_listener;
use noadd::filter::engine::FilterEngine;
use noadd::filter::lists::ListManager;
use noadd::logger::QueryLogger;
use noadd::shutdown::shutdown_signal;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Parse CLI args (before tracing init so we can pick the log format)
    let args = CliArgs::parse();

    // 2. Init tracing
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "noadd=info".into());

    match args.log_format {
        noadd::config::LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .init();
        }
        noadd::config::LogFormat::Text => {
            let use_color = std::env::var_os("NO_COLOR").is_none();
            tracing_subscriber::fmt()
                .with_ansi(use_color)
                .with_env_filter(env_filter)
                .init();
        }
    }

    // 3. Open database
    let db_path = args.db_path.to_str().unwrap_or("noadd.db");
    let db = Database::open(db_path).await?;

    // Auto-set public_url from ACME domain if not already configured
    if !args.acme_domain.is_empty() && db.get_setting("public_url").await?.is_none() {
        let url = format!("https://{}", args.acme_domain[0]);
        db.set_setting("public_url", &url).await?;
        tracing::info!(%url, "auto-set public_url from ACME domain");
    }

    // 4. Create filter engine (empty initially)
    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(vec![], vec![])));

    // 5. Seed default lists + rebuild filter
    let list_manager = ListManager::new(db.clone(), filter.clone());
    list_manager.seed_default_lists().await?;
    list_manager.rebuild_filter().await?;

    // 6. Create upstream forwarder
    let forwarder = Arc::new(UpstreamForwarder::new(UpstreamConfig::default()).await);

    // Load upstream strategy from DB
    if let Ok(Some(strategy_str)) = db.get_setting("upstream_strategy").await
        && let Ok(strategy) = strategy_str.parse::<noadd::upstream::strategy::UpstreamStrategy>()
    {
        forwarder.set_strategy(strategy);
        tracing::info!(%strategy_str, "loaded upstream strategy from DB");
    }

    // 7. Create DNS cache
    let cache = DnsCache::new(10_000);

    // 8. Create query logger
    let (logger, log_tx) = QueryLogger::new(db.clone(), 500, 1);
    let logger_handle = tokio::spawn(logger.run());

    // 9. Create DNS handler
    let ip_rate_limiter = Arc::new(IpRateLimiter::new(
        args.rate_limit_qps,
        args.rate_limit_burst,
    ));
    let handler = Arc::new(
        DnsHandler::with_max_inflight(
            filter.clone(),
            cache.clone(),
            forwarder.clone(),
            log_tx,
            args.max_inflight_queries,
        )
        .with_rate_limiter(ip_rate_limiter.clone()),
    );
    tracing::info!(
        max_inflight = args.max_inflight_queries,
        rate_limit_qps = args.rate_limit_qps,
        rate_limit_burst = args.rate_limit_burst,
        "DNS handler limits configured"
    );

    // 10. Setup shutdown signal
    let (shutdown_tx, shutdown_signal) = shutdown_signal();

    // 11. Start UDP listener
    let dns_addr: SocketAddr = args.dns_addr.parse()?;
    let udp_handler = handler.clone();
    let udp_handle = tokio::spawn(async move {
        if let Err(e) = run_udp_listener(dns_addr, udp_handler).await {
            tracing::error!(error = %e, "UDP listener failed");
        }
    });

    // 12. Start TCP listener
    let tcp_handler = handler.clone();
    let tcp_handle = tokio::spawn(async move {
        if let Err(e) = run_tcp_listener(dns_addr, tcp_handler).await {
            tracing::error!(error = %e, "TCP listener failed");
        }
    });

    // 13. Build HTTP app (DoH + Admin)
    let doh_routes = doh_router(handler.clone(), db.clone());
    let session_store = new_session_store();
    load_sessions_from_db(&session_store, &db).await?;
    let rate_limiter = Arc::new(RateLimiter::new(5, 60));
    let server_info = ServerInfo {
        dns_addr: args.dns_addr.clone(),
        http_addr: args.http_addr.clone(),
        tls_enabled: args.tls_cert.is_some() && args.tls_key.is_some(),
    };
    let admin_routes = admin_router(AppState {
        db: db.clone(),
        sessions: session_store,
        filter: filter.clone(),
        cache: cache.clone(),
        rate_limiter,
        forwarder: forwarder.clone(),
        handler: handler.clone(),
        server_info,
    });
    let app = doh_routes.merge(admin_routes);

    // 14. Start HTTP server
    let http_addr: SocketAddr = args.http_addr.parse()?;

    // 15. Background list update scheduler (every 24h)
    let update_db = db.clone();
    let update_filter = filter.clone();
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
        interval.tick().await; // skip first immediate tick
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let manager = ListManager::new(update_db.clone(), update_filter.clone());
                    if let Err(e) = manager.update_all_lists().await {
                        tracing::error!(error = %e, "failed to update filter lists");
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    });

    // 16. Background log pruning (every hour)
    let prune_db = db.clone();
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let retention_days: i64 = prune_db
                        .get_setting("log_retention_days")
                        .await
                        .ok()
                        .flatten()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(7);
                    let cutoff = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64
                        - retention_days * 86400;
                    match prune_db.prune_logs_before(cutoff).await {
                        Ok(count) if count > 0 => tracing::info!(count, "pruned old query logs"),
                        Err(e) => tracing::error!(error = %e, "failed to prune logs"),
                        _ => {}
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    });

    // 17a. Background rate-limiter bucket pruning. IPs unseen for 10 min are
    // evicted so the map cannot grow without bound if clients roam or a
    // scanner cycles through source addresses.
    let prune_limiter = ip_rate_limiter.clone();
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        interval.tick().await; // skip immediate tick
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let removed = prune_limiter.prune(std::time::Duration::from_secs(600));
                    if removed > 0 {
                        tracing::debug!(removed, "pruned inactive rate-limit buckets");
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    });

    // 17. Background upstream latency probe (every 60s, only for lowest-latency strategy)
    let probe_forwarder = forwarder.clone();
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.tick().await; // skip first immediate tick
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if probe_forwarder.strategy()
                        == noadd::upstream::strategy::UpstreamStrategy::LowestLatency
                    {
                        probe_forwarder.probe_all().await;
                        tracing::debug!("upstream latency probe complete");
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    });

    // 18. Serve HTTP with graceful shutdown
    let use_tls = args.tls_cert.is_some() && args.tls_key.is_some();
    let use_acme = !args.acme_domain.is_empty();

    if use_acme {
        // Let's Encrypt automatic TLS via rustls-acme
        use rustls_acme::AcmeConfig;
        use rustls_acme::caches::DirCache;
        use tokio_stream::StreamExt;

        let acme_cache = args.acme_cache.clone();
        let mut acme_config = AcmeConfig::new(args.acme_domain)
            .cache(DirCache::new(acme_cache))
            .directory_lets_encrypt(args.acme_prod);

        if let Some(ref email) = args.acme_email {
            acme_config = acme_config.contact([format!("mailto:{email}")]);
        }

        let mut state = acme_config.state();
        let acceptor = state.axum_acceptor(state.default_rustls_config());

        tokio::spawn(async move {
            loop {
                match state.next().await {
                    Some(Ok(ok)) => tracing::info!("ACME event: {:?}", ok),
                    Some(Err(err)) => tracing::error!("ACME error: {:?}", err),
                    None => break,
                }
            }
        });

        tracing::info!(%http_addr, "HTTPS server started with Let's Encrypt (DoH + Admin)");
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal.await;
            server_handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
        });
        axum_server::bind(http_addr)
            .acceptor(acceptor)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else if use_tls {
        // Manual TLS with provided cert/key
        let tls_config = noadd::tls::load_tls_config(
            args.tls_cert.as_ref().unwrap(),
            args.tls_key.as_ref().unwrap(),
        )?;
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(tls_config);
        tracing::info!(%http_addr, "HTTPS server started (DoH + Admin)");
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal.await;
            server_handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
        });
        axum_server::bind_rustls(http_addr, rustls_config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        // Plain HTTP
        let listener = tokio::net::TcpListener::bind(http_addr).await?;
        tracing::info!(%http_addr, "HTTP server started (DoH + Admin)");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal)
        .await?;
    }

    // 19. Cleanup
    tracing::info!("shutting down...");
    udp_handle.abort();
    tcp_handle.abort();
    drop(handler); // drops log_tx
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), logger_handle).await;
    tracing::info!("goodbye");

    Ok(())
}
