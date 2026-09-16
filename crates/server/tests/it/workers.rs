#![allow(
    unsafe_code,
    reason = "integration tests mutate process environment before server startup and restore it"
)]

//! P5 — integration tests for the background workers (expiry +
//! takedown notifier). All Postgres tests are gated on the
//! `TEABAY_RUN_DOCKER_TESTS=1` env so the test suite remains green on
//! hosts without Docker.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use diesel_async::RunQueryDsl;

use crate::common::{boot_postgres, docker_tests_enabled};

async fn test_app_state(
    database_url: &str,
) -> anyhow::Result<(server::AppConfig, server::AppState)> {
    unsafe {
        std::env::set_var("TEABAY_BIND", "127.0.0.1:0");
        std::env::set_var("TEABAY_PUBLIC_BASE_URL", "http://directory.test");
        std::env::set_var("TEABAY_SERVICE_DID", "did:web:directory.test");
        std::env::set_var(
            "TEABAY_SERVICE_METHOD_HISTORY_HEAD",
            "did-web-document-etag-fixture",
        );
        std::env::set_var(
            "TEABAY_SERVICE_VERSION_ID",
            "did-web-document-version-fixture",
        );
        std::env::set_var("DATABASE_URL", database_url);
        std::env::set_var("TEABAY_DEVELOPMENT_MODE", "true");
        std::env::set_var("TEABAY_REQUIRE_HTTP_SIG", "false");
    }
    let config = server::AppConfig::from_env()?;
    let db = server::Db::connect(database_url)?;
    db.run_migrations(database_url).await?;
    let state = server::AppState::new(config.clone(), db)?;
    Ok((config, state))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_worker_purges_rows_past_grace() -> anyhow::Result<()> {
    if !docker_tests_enabled() {
        eprintln!("skipping expiry_worker_purges_rows_past_grace; set TEABAY_RUN_DOCKER_TESTS=1");
        return Ok(());
    }
    let (_pg, database_url) = boot_postgres().await?;
    let (_config, state) = test_app_state(&database_url).await?;

    {
        let mut conn = state.db().get().await?;
        // Insert a row whose expires_at is 48h in the past, far past
        // the default 24-hour grace window.
        diesel::sql_query(
            "INSERT INTO directory_resources (\
                 resource_kind, resource_id, station_id, discovery_state, \
                 public_projection, discoverability, as_of, source_refs, policy_revision, indexed_at, \
                 effective_ttl_seconds, next_revalidation_after, stale, divergent, \
                 via_services, last_refreshed_at, expires_at) \
             VALUES (\
                 'realm'::resource_kind, 'ak.realm:expired', 'ak:did_core:web:expired.test', \
                 '{}'::jsonb, '{}'::jsonb, 'public'::discoverability, now() - interval '50 hours', \
                 '[]'::jsonb, 'rev-expired', now() - interval '50 hours', 60, now() + interval '1 minute', \
                 true, false, ARRAY[]::text[], now() - interval '50 hours', now() - interval '48 hours')",
        )
        .execute(&mut conn)
        .await?;
    }

    let worker = server::workers::expiry::ExpiryWorker::new(state.clone(), Duration::from_secs(60));
    let purged = worker.run_once().await?;
    assert!(
        purged >= 1,
        "expected to purge at least one row, got {purged}"
    );

    let mut conn = state.db().get().await?;
    let count: i64 = diesel::sql_query(
        "SELECT count(*)::BIGINT AS count FROM directory_resources \
         WHERE resource_id = 'ak.realm:expired'",
    )
    .get_result::<CountRow>(&mut conn)
    .await?
    .count;
    assert_eq!(count, 0, "expired row was not purged");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn freshness_worker_waits_until_revalidation_grace_elapsed() -> anyhow::Result<()> {
    if !docker_tests_enabled() {
        eprintln!(
            "skipping freshness_worker_waits_until_revalidation_grace_elapsed; set TEABAY_RUN_DOCKER_TESTS=1"
        );
        return Ok(());
    }
    let (_pg, database_url) = boot_postgres().await?;
    let (_config, state) = test_app_state(&database_url).await?;

    {
        let mut conn = state.db().get().await?;
        diesel::sql_query(
            "INSERT INTO directory_resources (\
                 resource_kind, resource_id, station_id, discovery_state, \
                 public_projection, discoverability, as_of, source_refs, policy_revision, indexed_at, \
                 effective_ttl_seconds, next_revalidation_after, stale, divergent, \
                 via_services, last_refreshed_at, expires_at) \
             VALUES \
                 ('realm'::resource_kind, 'ak.realm:within-grace', 'ak:did_core:web:fresh.test', \
                  '{}'::jsonb, '{}'::jsonb, 'public'::discoverability, now() - interval '2 hours', \
                  '[]'::jsonb, 'rev-within-grace', now() - interval '2 hours', 60, now() - interval '30 minutes', \
                  false, false, ARRAY[]::text[], now() - interval '2 hours', now() - interval '30 minutes'), \
                 ('realm'::resource_kind, 'ak.realm:past-grace', 'ak:did_core:web:stale.test', \
                  '{}'::jsonb, '{}'::jsonb, 'public'::discoverability, now() - interval '3 hours', \
                  '[]'::jsonb, 'rev-past-grace', now() - interval '3 hours', 60, now() - interval '2 hours', \
                  false, false, ARRAY[]::text[], now() - interval '3 hours', now() - interval '2 hours')",
        )
        .execute(&mut conn)
        .await?;
    }

    let worker = server::ingest::freshness_worker::FreshnessWorker::new(
        state.clone(),
        Duration::from_secs(60),
    );
    let flipped = worker.run_once().await?;
    assert_eq!(flipped, 1, "only the row past grace should flip stale");

    let mut conn = state.db().get().await?;
    let stale_count: i64 = diesel::sql_query(
        "SELECT count(*)::BIGINT AS count FROM directory_resources WHERE stale = true",
    )
    .get_result::<CountRow>(&mut conn)
    .await?
    .count;
    assert_eq!(stale_count, 1);
    let within_grace_count: i64 = diesel::sql_query(
        "SELECT count(*)::BIGINT AS count FROM directory_resources \
         WHERE resource_id = 'ak.realm:within-grace' AND stale = false",
    )
    .get_result::<CountRow>(&mut conn)
    .await?
    .count;
    assert_eq!(within_grace_count, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn takedown_notifier_dlqs_after_three_retries() -> anyhow::Result<()> {
    if !docker_tests_enabled() {
        eprintln!(
            "skipping takedown_notifier_dlqs_after_three_retries; set TEABAY_RUN_DOCKER_TESTS=1"
        );
        return Ok(());
    }
    let (_pg, database_url) = boot_postgres().await?;
    let (_config, state) = test_app_state(&database_url).await?;

    // Start a tiny TCP server that returns HTTP 500 to every request.
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let endpoint = format!("http://127.0.0.1:{port}/sink");
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_count_thread = hit_count.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = stop.clone();
    let server_handle = std::thread::spawn(move || {
        use std::io::{Read, Write};
        while !stop_thread.as_ref().load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut sock, _peer)) => {
                    sock.set_read_timeout(Some(Duration::from_millis(250))).ok();
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf);
                    let _ = sock.write_all(
                        b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n",
                    );
                    hit_count_thread.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    {
        let mut conn = state.db().get().await?;
        diesel::sql_query(
            "INSERT INTO pending_takedown_webhooks (webhook_id, endpoint, secret) \
             VALUES ('wh-test', $1, decode('00112233445566778899aabbccddeeff', 'hex'))",
        )
        .bind::<diesel::sql_types::Text, _>(&endpoint)
        .execute(&mut conn)
        .await?;

        diesel::sql_query(
            "INSERT INTO pending_takedowns (\
                 pending_id, resource_kind, resource_id, reason, proposed_by, \
                 status, expires_at) \
             VALUES (\
                 'pt-test', 'realm'::resource_kind, 'ak.realm:dlq', 'spam', \
                 'ak:did_core:web:operator.test', 'pending', now() + interval '1 day')",
        )
        .execute(&mut conn)
        .await?;
    }

    let notifier = server::workers::takedown_notifier::TakedownNotifier::new(
        state.clone(),
        Duration::from_secs(60),
    )?;

    assert_eq!(notifier.run_once().await?, 1);
    assert_eq!(
        notifier.run_once().await?,
        0,
        "retry backoff should block immediate redelivery"
    );

    for _ in 0..2 {
        force_takedown_notification_due(&state, "pt-test").await?;
        assert_eq!(notifier.run_once().await?, 1);
    }

    let mut conn = state.db().get().await?;
    let status_row: StatusRow = diesel::sql_query(
        "SELECT notification_status \
         FROM pending_takedowns WHERE pending_id = 'pt-test'",
    )
    .get_result::<StatusRow>(&mut conn)
    .await?;
    let status = status_row.notification_status.unwrap_or_default();
    assert!(
        status.starts_with("dlq:"),
        "expected DLQ status, got `{status}`"
    );
    assert!(
        hit_count.as_ref().load(Ordering::SeqCst) >= 3,
        "expected at least 3 outbound hits, got {}",
        hit_count.as_ref().load(Ordering::SeqCst)
    );

    stop.store(true, Ordering::SeqCst);
    let _ = server_handle.join();
    Ok(())
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

#[derive(diesel::QueryableByName)]
struct StatusRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    notification_status: Option<String>,
}

async fn force_takedown_notification_due(
    state: &server::AppState,
    pending_id: &str,
) -> anyhow::Result<()> {
    let mut conn = state.db().get().await?;
    diesel::sql_query(
        "UPDATE pending_takedowns \
         SET next_notification_after = now() - interval '1 second' \
         WHERE pending_id = $1",
    )
    .bind::<diesel::sql_types::Text, _>(pending_id)
    .execute(&mut conn)
    .await?;
    Ok(())
}
