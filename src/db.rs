//! Diesel + r2d2 connection pool, and the boot-time migration runner.

use diesel::pg::PgConnection;
use diesel::r2d2::{self, ConnectionManager};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

pub type PgPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type PgPooledConnection = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

#[derive(Clone)]
pub struct Db {
    pool: PgPool,
}

impl Db {
    /// Build a connection pool against `database_url`. Caller is responsible
    /// for ensuring `DATABASE_URL` is set if Diesel CLI tooling is used.
    pub fn connect(database_url: &str) -> anyhow::Result<Self> {
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let pool = r2d2::Pool::builder()
            .max_size(16)
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
}
