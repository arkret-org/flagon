use salvo::prelude::*;
use server::{AppConfig, AppState, Db, metrics_service, service};
use tokio::signal;
use tracing::info;

fn main() -> anyhow::Result<()> {
    server::config::prepare_process_environment()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = AppConfig::from_env()?;

    // `database_url` is threaded explicitly to everything that needs it
    // (`Db::connect_with` / `run_migrations`); we do NOT write it back into the
    // process environment. Offline Diesel tooling (`diesel print-schema`) reads
    // `DATABASE_URL` from `.env` / the shell, not from this runtime process, so
    // an `unsafe std::env::set_var` here bought nothing and was unsound under
    // the multi-threaded tokio runtime.
    let db = Db::connect_with(&config.database_url, &config.db_pool)?;
    db.run_migrations(&config.database_url).await?;
    let state = AppState::new(config.clone(), db)?;

    let metrics_acceptor = TcpListener::new(config.metrics_bind.to_string())
        .bind()
        .await;
    let metrics_server = Server::new(metrics_acceptor);
    let metrics_handle = metrics_server.handle();
    let _metrics_task = tokio::spawn(metrics_server.serve(metrics_service(state.clone())));
    info!(bind = %config.metrics_bind, "flagon metrics listener starting");

    let acceptor = TcpListener::new(config.bind.to_string()).bind().await;
    info!(
        bind = %config.bind,
        public_base_url = %config.public_base_url,
        service_id = %config.service_id,
        development_mode = config.development_mode,
        "flagon starting"
    );

    let server = Server::new(acceptor);
    let handle = server.handle();
    tokio::spawn(async move {
        shutdown_signal().await;
        handle.stop_graceful(None);
        metrics_handle.stop_graceful(None);
    });
    server.serve(service(state)).await;
    info!("flagon stopped");
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
