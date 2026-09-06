//! Shared bring-up for the Docker-backed integration tests.
//!
//! Every suite that needs a real PostgreSQL gates on the same environment
//! switch and starts the same container. Keeping one copy stops the image tag
//! and the credentials from drifting between suites: `pcd_http` had already
//! been left behind on a hard-coded tag after the other two gained the
//! `TEABAY_TEST_POSTGRES_TAG` override.

use testcontainers_modules::postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// Whether the Docker-backed suites are enabled for this run.
///
/// They stay off by default so a checkout without a Docker daemon still runs
/// the rest of the suite green instead of failing on container bring-up.
pub fn docker_tests_enabled() -> bool {
    std::env::var("TEABAY_RUN_DOCKER_TESTS").ok().as_deref() == Some("1")
}

/// Start a throwaway PostgreSQL container and return it with its URL.
///
/// The container handle must stay alive for as long as the URL is used;
/// dropping it stops the database.
pub async fn boot_postgres() -> anyhow::Result<(
    testcontainers_modules::testcontainers::ContainerAsync<postgres::Postgres>,
    String,
)> {
    let postgres_tag =
        std::env::var("TEABAY_TEST_POSTGRES_TAG").unwrap_or_else(|_| "16-alpine".to_string());
    let container = postgres::Postgres::default()
        .with_password("1amTester!")
        .with_tag(postgres_tag)
        .start()
        .await?;
    let database_url = format!(
        "postgres://postgres:1amTester!@{}:{}/postgres",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    Ok((container, database_url))
}
