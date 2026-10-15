//! diesel-async + deadpool connection pool, and the boot-time migration runner.

use diesel_async::async_connection_wrapper::AsyncConnectionWrapper;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::{Object, Pool};
use diesel_async::{AsyncPgConnection, SimpleAsyncConnection};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

use crate::config::DbPoolConfig;

pub type PgPool = Pool<AsyncPgConnection>;
pub type PgPooledConnection = Object<AsyncPgConnection>;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

#[derive(Clone)]
pub struct Db {
    pool: PgPool,
}

impl Db {
    /// Build a connection pool against `database_url` using the default
    /// pool sizing. Prefer [`Db::connect_with`] in production paths so
    /// the operator's [`DbPoolConfig`] env overrides land on the pool.
    pub fn connect(database_url: &str) -> anyhow::Result<Self> {
        Self::connect_with(database_url, &DbPoolConfig::default())
    }

    /// Build a connection pool against `database_url` with explicit
    /// pool tunables (P2E.6). Honours `max_size` and `connection_timeout`
    /// from the config; see `docs/scaling.md` for sizing guidance.
    pub fn connect_with(database_url: &str, pool: &DbPoolConfig) -> anyhow::Result<Self> {
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
        let pool = Pool::builder(manager)
            .max_size(pool.max_size as usize)
            .timeouts(deadpool::managed::Timeouts {
                wait: Some(pool.connection_timeout),
                create: Some(pool.connection_timeout),
                recycle: Some(pool.connection_timeout),
            })
            .runtime(deadpool::Runtime::Tokio1)
            .post_create(diesel_async::pooled_connection::deadpool::Hook::async_fn(|conn: &mut AsyncPgConnection, _| Box::pin(async move {
                tokio::time::timeout(std::time::Duration::from_secs(5), conn.batch_execute("SET statement_timeout = '30s'; SET lock_timeout = '5s'; SET idle_in_transaction_session_timeout = '60s';"))
                    .await.map_err(|_| diesel_async::pooled_connection::deadpool::HookError::Message("database session setup timed out".into()))?
                    .map_err(|error| diesel_async::pooled_connection::deadpool::HookError::Backend(diesel_async::pooled_connection::PoolError::QueryError(error)))?;
                Ok(())
            })))
            .build()
            .map_err(|e| anyhow::anyhow!("connect to {database_url}: {e}"))?;
        Ok(Self { pool })
    }

    /// Apply all pending embedded migrations. Called once at boot in main.
    ///
    /// `diesel_migrations` requires a synchronous `MigrationHarness`, so we
    /// drive it through [`AsyncConnectionWrapper`] on a blocking thread
    /// rather than the async pool connection.
    pub async fn run_migrations(&self, database_url: &str) -> anyhow::Result<()> {
        let url = database_url.to_owned();
        tokio::task::spawn_blocking(move || {
            use diesel::Connection;
            let mut wrapper = AsyncConnectionWrapper::<AsyncPgConnection>::establish(&url)
                .map_err(|e| anyhow::anyhow!("establish migration connection: {e}"))?;
            wrapper
                .run_pending_migrations(MIGRATIONS)
                .map_err(|e| anyhow::anyhow!("run pending migrations: {e}"))?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(|e| anyhow::anyhow!("migration task panicked: {e}"))?
    }

    pub async fn get(&self) -> anyhow::Result<PgPooledConnection> {
        tokio::time::timeout(
            self.pool
                .timeouts()
                .wait
                .unwrap_or(std::time::Duration::from_secs(5)),
            self.pool.get(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("database checkout timed out"))?
        .map_err(|e| anyhow::anyhow!("acquire pg conn: {e}"))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// P2E.6 — snapshot live deadpool pool stats for the Prometheus
    /// scrape. deadpool's `status()` is cheap so it is safe to call from
    /// the metrics scrape hot path.
    pub fn pool_stats(&self) -> DbPoolStats {
        let status = self.pool.status();
        DbPoolStats {
            connections: status.size as u32,
            idle: status.available as u32,
            in_use: status.size.saturating_sub(status.available) as u32,
            max_size: status.max_size as u32,
        }
    }
}

/// Snapshot of deadpool pool occupancy at the moment of capture. All
/// counts are u32 to match the Prometheus gauge surface.
#[derive(Clone, Copy, Debug)]
pub struct DbPoolStats {
    pub connections: u32,
    pub idle: u32,
    pub in_use: u32,
    pub max_size: u32,
}

#[cfg(test)]
mod wait_bound_tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn pool_exhaustion_and_unanswered_handshake_finish() {
        let url =
            std::env::var("FLAGON_TEST_DATABASE_URL").expect("isolated test database required");
        let config = DbPoolConfig {
            max_size: 1,
            connection_timeout: Duration::from_millis(200),
        };
        let db = Db::connect_with(&url, &config).unwrap();
        let held = db.get().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), db.get())
                .await
                .unwrap()
                .is_err()
        );
        drop(held);
        assert!(db.get().await.is_ok());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let blackhole = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let db = Db::connect_with(
            &format!("postgres://postgres@{address}/test?sslmode=disable"),
            &config,
        )
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), db.get())
                .await
                .unwrap()
                .is_err()
        );
        blackhole.abort();
    }
}
