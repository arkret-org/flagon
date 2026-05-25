//! Diesel + r2d2 connection pool, and the boot-time migration runner.

use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

use crate::config::DbPoolConfig;

pub type PgPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type PgPooledConnection = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

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
    /// pool tunables (P2E.6). Honours `max_size`, `min_idle`,
    /// `connection_timeout`, and `idle_timeout` from the config; see
    /// `docs/scaling.md` for sizing guidance.
    pub fn connect_with(database_url: &str, pool: &DbPoolConfig) -> anyhow::Result<Self> {
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let mut builder = r2d2::Pool::builder()
            .max_size(pool.max_size)
            .connection_timeout(pool.connection_timeout);
        if let Some(min_idle) = pool.min_idle {
            builder = builder.min_idle(Some(min_idle));
        }
        if let Some(idle_timeout) = pool.idle_timeout {
            builder = builder.idle_timeout(Some(idle_timeout));
        }
        let pool = builder
            .build(manager)
            .map_err(|e| anyhow::anyhow!("connect to {database_url}: {e}"))?;
        Ok(Self { pool })
    }

    /// Apply all pending embedded migrations. Called once at boot in main.
    pub fn run_migrations(&self) -> anyhow::Result<()> {
        let mut conn = self.pool.get()?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| anyhow::anyhow!("run pending migrations: {e}"))?;
        Ok(())
    }

    pub fn get(&self) -> anyhow::Result<PgPooledConnection> {
        self.pool
            .get()
            .map_err(|e| anyhow::anyhow!("acquire pg conn: {e}"))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// P2E.6 — snapshot live r2d2 pool stats for the Prometheus
    /// scrape. r2d2's `state()` is cheap (Mutex-guarded reads) so it
    /// is safe to call from the metrics scrape hot path.
    pub fn pool_stats(&self) -> DbPoolStats {
        let state = self.pool.state();
        DbPoolStats {
            connections: state.connections,
            idle: state.idle_connections,
            in_use: state.connections.saturating_sub(state.idle_connections),
            max_size: self.pool.max_size(),
        }
    }
}

/// Snapshot of r2d2 pool occupancy at the moment of capture. All
/// counts are u32 to match r2d2's public API.
#[derive(Clone, Copy, Debug)]
pub struct DbPoolStats {
    pub connections: u32,
    pub idle: u32,
    pub in_use: u32,
    pub max_size: u32,
}
