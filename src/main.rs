use salvo::prelude::*;
use teabay::{
    AppConfig, AppState, Db,
    ingest::{divergence_worker::DivergenceWorker, pull_worker::PullWorker},
    service,
};
use tokio::signal;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = AppConfig::from_env()?;

    // Push the parsed DATABASE_URL into the env so any downstream Diesel
    // tooling that reads it directly (e.g. `diesel print-schema`) sees the
    // same value our pool used.
    //
    // SAFETY: invoked once, before any worker thread starts touching env.
    unsafe {
        std::env::set_var("DATABASE_URL", &config.database_url);
    }

    let db = Db::connect(&config.database_url)?;
    db.run_migrations()?;
    let state = AppState::new(config.clone(), db);

    if let Some(period) = config.pull_interval {
        let _worker = PullWorker::new(state.clone(), period).spawn();
    }
    if let Some(period) = config.divergence_interval {
        let _worker = DivergenceWorker::new(state.clone(), period).spawn();
    }

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
