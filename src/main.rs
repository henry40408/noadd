use std::net::SocketAddr;
use std::sync::Arc;

// Use mimalloc to keep resident memory low: the filter rebuild allocates a
// large transient BuildNode tree, and the system glibc allocator tends to
// retain those pages as RSS afterwards. mimalloc returns freed pages to the
// OS far more aggressively.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
use noadd::net::TrustedProxies;
use noadd::shutdown::shutdown_signal;
use noadd::upstream::forwarder::{UpstreamConfig, UpstreamForwarder};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    noadd::config::init_tracing(args.log_format);

    let db_path = noadd::config::resolve_db_path(args.db_path);
    let db = Database::open(db_path.to_str().unwrap_or(noadd::config::DEFAULT_DB_PATH)).await?;

    // Auto-set public_url from ACME domain if not already configured
    if !args.acme_domain.is_empty() && db.get_setting("public_url").await?.is_none() {
        let url = format!("https://{}", args.acme_domain[0]);
        db.set_setting("public_url", &url).await?;
        tracing::info!(%url, "auto-set public_url from ACME domain");
    }

    let filter = Arc::new(ArcSwap::from_pointee(FilterEngine::new(
        vec![],
        vec![],
        vec![],
    )));

    let list_manager = Arc::new(ListManager::new(db.clone(), filter.clone()));
    list_manager.seed_default_lists().await?;
    list_manager.rebuild_filter().await?;
    let rebuild = noadd::filter::rebuild::RebuildCoordinator::new();
    let registry = noadd::registry::RegistryClient::new(
        noadd::registry::DEFAULT_REGISTRY_URL,
        std::time::Duration::from_secs(3600),
    );

    let upstream_config = match db.get_setting("upstream_servers").await {
        Ok(Some(v)) if !v.trim().is_empty() => {
            match noadd::upstream::forwarder::parse_upstreams(&v) {
                Ok(servers) => UpstreamConfig {
                    servers,
                    ..UpstreamConfig::default()
                },
                Err(e) => {
                    tracing::warn!(error = %e, "invalid upstream_servers setting; using defaults");
                    UpstreamConfig::default()
                }
            }
        }
        _ => UpstreamConfig::default(),
    };
    let forwarder = Arc::new(UpstreamForwarder::new(upstream_config).await);

    if let Ok(Some(strategy_str)) = db.get_setting("upstream_strategy").await
        && let Ok(strategy) = strategy_str.parse::<noadd::upstream::strategy::UpstreamStrategy>()
    {
        forwarder.set_strategy(strategy);
        tracing::info!(%strategy_str, "loaded upstream strategy from DB");
    }

    if let Ok(Some(v)) = db.get_setting("dnssec_disabled").await {
        forwarder.set_dnssec_enabled(v.trim() != "true");
        tracing::info!(dnssec_disabled = %v, "loaded DNSSEC transparency setting");
    }

    let block_config = {
        let mode = db.get_setting("block_mode").await.ok().flatten();
        let v4 = db.get_setting("block_custom_ipv4").await.ok().flatten();
        let v6 = db.get_setting("block_custom_ipv6").await.ok().flatten();
        noadd::dns::block::from_settings(mode.as_deref(), v4.as_deref(), v6.as_deref())
    };
    tracing::info!(
        block_mode = block_config.mode.as_str(),
        "loaded block-response mode"
    );

    let cache = DnsCache::new(10_000);

    let (logger, log_tx) = QueryLogger::new(db.clone(), 500, 1);
    let logger_handle = tokio::spawn(logger.run());

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
        .with_rate_limiter(ip_rate_limiter.clone())
        .with_log_query_results(args.log_query_results)
        .with_block_config(block_config),
    );
    tracing::info!(
        max_inflight = args.max_inflight_queries,
        rate_limit_qps = args.rate_limit_qps,
        rate_limit_burst = args.rate_limit_burst,
        "DNS handler limits configured"
    );

    let (shutdown_tx, shutdown_signal) = shutdown_signal();
    // Convert the OS signal into the broadcast so the HTTP server, DNS
    // listeners and background tasks all observe one shutdown event. A fatal
    // DNS listener failure broadcasts on the same channel (see
    // supervise_listener) so the whole process winds down instead of silently
    // serving HTTP/DoH with dead plain-DNS.
    tokio::spawn(shutdown_signal);
    let listener_failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Subscribe the HTTP server to the shutdown broadcast *before* spawning the
    // DNS listeners. A listener can fail (and broadcast) within microseconds of
    // being spawned; subscribing afterwards would race and miss that message,
    // leaving HTTP serving until an OS signal arrives.
    let mut http_shutdown = shutdown_tx.subscribe();

    let dns_addr: SocketAddr = args.dns_addr.parse()?;
    let udp_handle = tokio::spawn(noadd::shutdown::supervise_listener(
        "UDP",
        run_udp_listener(dns_addr, handler.clone()),
        shutdown_tx.clone(),
        listener_failed.clone(),
    ));
    let tcp_handle = tokio::spawn(noadd::shutdown::supervise_listener(
        "TCP",
        run_tcp_listener(dns_addr, handler.clone()),
        shutdown_tx.clone(),
        listener_failed.clone(),
    ));

    let trusted_proxies = Arc::new(TrustedProxies::parse(&args.trusted_proxies).map_err(|e| {
        anyhow::anyhow!("failed to parse --trusted-proxies / NOADD_TRUSTED_PROXIES: {e}")
    })?);
    if !trusted_proxies.is_empty() {
        tracing::info!(
            count = trusted_proxies.len(),
            "trusted proxy CIDRs configured — X-Forwarded-For / X-Real-IP will be honoured for matching peers"
        );
    }

    let doh_routes = doh_router(handler.clone(), db.clone(), trusted_proxies.clone());
    let session_store = new_session_store();
    load_sessions_from_db(&session_store, &db).await?;
    let session_store_for_flush = session_store.clone();
    let db_for_flush = db.clone();
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
        list_manager: list_manager.clone(),
        rebuild: rebuild.clone(),
        registry: registry.clone(),
        trusted_proxies: trusted_proxies.clone(),
    });

    // Periodically persist session last_seen so it survives restarts.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        tick.tick().await; // skip immediate fire
        loop {
            tick.tick().await;
            let _ =
                noadd::admin::auth::flush_last_seen(&session_store_for_flush, &db_for_flush).await;
        }
    });

    let app = doh_routes.merge(admin_routes);

    let http_addr: SocketAddr = args.http_addr.parse()?;

    // Background list update scheduler (every 24h)
    let update_manager = list_manager.clone();
    let update_rebuild = rebuild.clone();
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
        interval.tick().await; // skip first immediate tick
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = update_manager.update_all_lists_no_rebuild().await {
                        tracing::warn!(error = %e, "failed to update filter lists; keeping previous lists");
                    }
                    let mgr = update_manager.clone();
                    update_rebuild.clone().spawn_raw(move || async move {
                        mgr.rebuild_filter().await
                    });
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    });

    // Background log pruning (every hour)
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
                        .unwrap_or(noadd::admin::stats::DEFAULT_LOG_RETENTION_DAYS);
                    let cutoff = noadd::now_unix() - retention_days * 86400;
                    match prune_db.prune_logs_before(cutoff).await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!(count, "pruned old query logs");
                            }
                            if let Err(e) = prune_db.run_maintenance().await {
                                tracing::warn!(error = %e, "database maintenance failed; will retry next cycle");
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "failed to prune logs; will retry next cycle"),
                    }
                }
                _ = shutdown_rx.recv() => break,
            }
        }
    });

    // Rate-limiter bucket pruning — IPs unseen for 10 min are evicted so
    // the map cannot grow without bound under clients that roam or scanners
    // that cycle through source addresses.
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

    // Upstream latency probe (every 60s, only for the lowest-latency strategy)
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
            let _ = http_shutdown.recv().await;
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
            let _ = http_shutdown.recv().await;
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
        .with_graceful_shutdown(async move {
            let _ = http_shutdown.recv().await;
        })
        .await?;
    }

    tracing::info!("shutting down...");
    udp_handle.abort();
    tcp_handle.abort();
    drop(handler); // drops log_tx
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), logger_handle).await;
    db.close().await; // checkpoint WAL and close connections so -wal/-shm are removed
    tracing::info!("goodbye");

    // If a DNS listener brought us down (rather than an OS signal), exit
    // non-zero so orchestrators and health checks see the failure instead of a
    // clean shutdown.
    if listener_failed.load(std::sync::atomic::Ordering::Relaxed) {
        anyhow::bail!("DNS listener failed; exiting with non-zero status");
    }

    Ok(())
}
