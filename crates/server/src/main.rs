use salvo::prelude::*;
use server::ingest::divergence_worker::DivergenceWorker;
use server::ingest::freshness_worker::{DEFAULT_FRESHNESS_TICK, FreshnessWorker};
use server::ingest::pull_worker::PullWorker;
use server::workers::expiry::ExpiryWorker;
use server::workers::takedown_notifier::TakedownNotifier;
use server::{AppConfig, AppState, Db, metrics_service, profile, service};
use tokio::signal;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Anti-drift guard: panic at startup if the wire surface declared in
    // `server::kinds` no longer matches the embedded baseline profile
    // (`cx.profile.directory_service.v1`). This is a hard precondition for
    // running teabay — see crates/server/src/profile/mod.rs.
    profile::verify_or_panic();

    let config = AppConfig::from_env()?;

    // Push the parsed DATABASE_URL into the env so any downstream Diesel
    // tooling that reads it directly (e.g. `diesel print-schema`) sees the
    // same value our pool used.
    //
    // SAFETY: invoked once, before any worker thread starts touching env.
    unsafe {
        std::env::set_var("DATABASE_URL", &config.database_url);
    }

    let db = Db::connect_with(&config.database_url, &config.db_pool)?;
    db.run_migrations(&config.database_url).await?;
    let state = AppState::new(config.clone(), db);

    if let Some(period) = config.pull_interval {
        let _worker = PullWorker::new(state.clone(), period).spawn();
    }
    if let Some(period) = config.divergence_interval {
        let _worker = DivergenceWorker::new(state.clone(), period).spawn();
    }
    // P2E.5 follow-up — freshness sweep marks `stale=true` for rows
    // whose heartbeat-driven `expires_at` lapsed. Always-on with a
    // 10-minute tick; cheap (single UPDATE, partial index).
    let _freshness_worker = FreshnessWorker::new(state.clone(), DEFAULT_FRESHNESS_TICK).spawn();

    // P5 HIGH — background expiry purge (24h+grace beyond stale).
    if let Some(period) = config.expiry_interval {
        let _expiry_worker = ExpiryWorker::new(state.clone(), period).spawn();
        info!(
            period_seconds = period.as_secs(),
            "teabay expiry worker scheduled"
        );
    }
    // P5 HIGH — pending-takedown HMAC-signed webhook fanout.
    if let Some(period) = config.takedown_notifier_interval {
        match TakedownNotifier::new(state.clone(), period) {
            Ok(notifier) => {
                let _takedown_worker = notifier.spawn();
                info!(
                    period_seconds = period.as_secs(),
                    "teabay takedown notifier scheduled"
                );
            }
            Err(e) => warn!(%e, "failed to build takedown notifier; webhook fanout disabled"),
        }
    }

    let metrics_acceptor = TcpListener::new(config.metrics_bind.to_string())
        .bind()
        .await;
    let metrics_server = Server::new(metrics_acceptor);
    let metrics_handle = metrics_server.handle();
    let _metrics_task = tokio::spawn(metrics_server.serve(metrics_service(state.clone())));
    info!(bind = %config.metrics_bind, "teabay metrics listener starting");

    let acceptor = TcpListener::new(config.bind.to_string()).bind().await;
    info!(
        bind = %config.bind,
        public_base_url = %config.public_base_url,
        service_did = %config.service_did,
        accept_policy = ?config.accept_policy_kind,
        development_mode = config.development_mode,
        "teabay starting"
    );

    let server = Server::new(acceptor);
    let handle = server.handle();
    tokio::spawn(async move {
        shutdown_signal().await;
        handle.stop_graceful(None);
        metrics_handle.stop_graceful(None);
    });
    server.serve(service(state)).await;
    info!("teabay stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!(%e, "failed to install Ctrl-C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(e) => tracing::error!(%e, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received SIGINT"),
        _ = terminate => info!("received SIGTERM"),
    }
}
