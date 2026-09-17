//! Shared bring-up for the Docker-backed integration tests.
//!
//! Every suite that needs a real PostgreSQL starts the same container.
//! Keeping one copy stops the image tag and the credentials from drifting
//! between suites: `pcd_http` had already been left behind on a hard-coded tag
//! after the other two gained the `TEABAY_TEST_POSTGRES_TAG` override.
//!
//! # Why these tests are `#[ignore]` and not `if !enabled { return Ok(()) }`
//!
//! They used to gate on a `TEABAY_RUN_DOCKER_TESTS=1` environment variable and
//! `return Ok(())` when it was absent. libtest has no notion of "the body
//! decided not to run", so it counted all seven of them as **passed**. A
//! default `cargo test` therefore reported green for
//! `conformance::postgres_query_conformance_smoke` — the only end-to-end
//! coverage this repository has for `announce`, `withdraw`, every
//! `search-*` / `resolve-*` route and the admin surface — having executed
//! nothing at all.
//!
//! `#[ignore]` is the mechanism libtest actually has for this, and it reports
//! separately: a default run says `N passed; 7 ignored`, and "ignored" is not
//! "passed" in any counter, summary line, or machine-readable output. Run them
//! with `-- --include-ignored`.
//!
//! There is deliberately no environment switch left. A second way to skip is a
//! second way to be silently green: when an ignored test is included it runs,
//! and if Docker is not reachable [`boot_postgres`] fails the test loudly
//! instead of reporting success for work it did not do.

use testcontainers_modules::postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// Start a throwaway PostgreSQL container and return it with its URL.
///
/// The container handle must stay alive for as long as the URL is used;
/// dropping it stops the database.
///
/// An unreachable Docker daemon is an error, never a skip. The caller is
/// already inside a test that was explicitly included with
/// `--include-ignored`, so "Docker is missing" is a failed run of a test the
/// operator asked for, not an absent one.
pub async fn boot_postgres() -> anyhow::Result<(
    testcontainers_modules::testcontainers::ContainerAsync<postgres::Postgres>,
    String,
)> {
    let postgres_tag =
        std::env::var("TEABAY_TEST_POSTGRES_TAG").unwrap_or_else(|_| "16-alpine".to_string());
    let container = postgres::Postgres::default()
        .with_password("1amTester!")
        .with_tag(&postgres_tag)
        .start()
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "Docker-backed test could not start PostgreSQL ({postgres_tag} image): {error}. \
                 This test was included explicitly, so a missing Docker daemon is a failure, \
                 not a skip."
            )
        })?;
    let database_url = format!(
        "postgres://postgres:1amTester!@{}:{}/postgres",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    Ok((container, database_url))
}
