//! PostgreSQL contracts for the deliberately unreachable PCD durable core.

use chrono::{DateTime, Duration, Utc};
use diesel_async::RunQueryDsl;
use server::pcd_dark::{
    BlindAdmissionRequest, DeviceCredentialDigest, MatchAdmissionRequest, OpaqueExactBucketBytes,
    OutcomeWrite, PcdAdmission, PcdBatchId, PcdError, PcdLimits, PcdReject, PcdRequestDigest,
    PostgresPcdStore,
};
use testcontainers_modules::postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

fn docker_tests_enabled() -> bool {
    std::env::var("TEABAY_RUN_DOCKER_TESTS").ok().as_deref() == Some("1")
}

async fn boot_postgres() -> anyhow::Result<(
    testcontainers_modules::testcontainers::ContainerAsync<postgres::Postgres>,
    String,
)> {
    let postgres_tag =
        std::env::var("TEABAY_TEST_POSTGRES_TAG").unwrap_or_else(|_| "16-alpine".to_string());
    let container = postgres::Postgres::default()
        .with_tag(postgres_tag)
        .start()
        .await?;
    let database_url = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    Ok((container, database_url))
}

fn limits() -> PcdLimits {
    PcdLimits {
        batch_item_count: 4,
        max_queries_per_window: 1,
        quota_window_seconds: 86_400,
        batch_completion_ttl_seconds: 3_600,
        evaluation_lease_seconds: 30,
    }
}

fn now() -> DateTime<Utc> {
    "2026-08-29T00:00:00Z".parse().expect("timestamp")
}

fn batch_id(index: u8) -> PcdBatchId {
    PcdBatchId::parse(format!("ak:batch:0196429a-0000-7000-8000-{index:012x}")).expect("batch id")
}

fn padded(label: &[u8]) -> OpaqueExactBucketBytes {
    let mut bytes = vec![b' '; 4096];
    bytes[..label.len()].copy_from_slice(label);
    OpaqueExactBucketBytes::for_advertised_bucket(bytes, 4096)
        .expect("test bytes occupy one exact current-v1 bucket")
}

fn blind(device: u8, batch: u8, digest: u8, owner: u8) -> BlindAdmissionRequest {
    BlindAdmissionRequest {
        device_credential_digest: DeviceCredentialDigest::new([device; 32]),
        batch_id: batch_id(batch),
        request_digest: PcdRequestDigest::from_closed_body_sha256([digest; 32]),
        key_epoch: 14,
        item_count: 4,
        lease_owner: [owner; 32],
    }
}

fn matching(blind: &BlindAdmissionRequest, digest: u8, owner: u8) -> MatchAdmissionRequest {
    MatchAdmissionRequest {
        device_credential_digest: blind.device_credential_digest,
        batch_id: blind.batch_id.clone(),
        request_digest: PcdRequestDigest::from_closed_body_sha256([digest; 32]),
        key_epoch: blind.key_epoch,
        item_count: blind.item_count,
        lease_owner: [owner; 32],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pcd_state_survives_pool_restart_and_retains_epoch_fk() -> anyhow::Result<()> {
    if !docker_tests_enabled() {
        eprintln!(
            "skipping pcd_state_survives_pool_restart_and_retains_epoch_fk; set TEABAY_RUN_DOCKER_TESTS=1"
        );
        return Ok(());
    }
    let (_postgres, database_url) = boot_postgres().await?;
    let db = server::Db::connect(&database_url)?;
    db.run_migrations(&database_url).await?;
    let store = PostgresPcdStore::new(db.clone());
    store
        .register_key_epoch(
            14,
            [3; 32],
            "kms://teabay/pcd/epoch/14",
            now() - Duration::days(1),
        )
        .await?;
    store
        .register_key_epoch(
            14,
            [3; 32],
            "kms://teabay/pcd/epoch/14",
            now() - Duration::days(1),
        )
        .await?;
    assert_eq!(
        store
            .register_key_epoch(
                14,
                [4; 32],
                "kms://teabay/pcd/epoch/14",
                now() - Duration::days(1),
            )
            .await,
        Err(PcdError::Rejected(PcdReject::DuplicateConflict))
    );

    // Admission uses this same row-lock shape inside its quota+batch
    // transaction. Hold it explicitly here to prove a retirement update
    // cannot interleave between active-epoch validation and the pinned FK.
    let mut epoch_reader = db.get().await?;
    diesel::sql_query("BEGIN")
        .execute(&mut epoch_reader)
        .await?;
    diesel::sql_query("SELECT key_epoch FROM pcd_key_epochs WHERE key_epoch = 14 FOR SHARE")
        .execute(&mut epoch_reader)
        .await?;
    let mut retirement_writer = db.get().await?;
    diesel::sql_query("SET lock_timeout = '100ms'")
        .execute(&mut retirement_writer)
        .await?;
    let retirement_while_shared =
        diesel::sql_query("UPDATE pcd_key_epochs SET retired_at = now() WHERE key_epoch = 14")
            .execute(&mut retirement_writer)
            .await;
    assert!(
        retirement_while_shared.is_err(),
        "retirement must not pass an admission-held epoch share lock"
    );
    diesel::sql_query("ROLLBACK")
        .execute(&mut epoch_reader)
        .await?;
    drop(retirement_writer);
    drop(epoch_reader);

    let blind_request = blind(1, 1, 1, 7);
    assert!(matches!(
        store
            .admit_blind(limits(), now(), blind_request.clone())
            .await?,
        PcdAdmission::Evaluate {
            lease_version: 1,
            ..
        }
    ));
    let mut changed_limits = limits();
    changed_limits.batch_item_count = 8;
    assert!(matches!(
        store
            .admit_blind(changed_limits, now(), blind_request.clone())
            .await?,
        PcdAdmission::PendingRetry {
            lease_version: 1,
            retry_after_seconds: 30,
            ..
        }
    ));
    assert_eq!(
        store
            .record_blind_outcome(now(), &blind_request, 1, padded(b"canonical-blind-body"))
            .await?,
        OutcomeWrite::Recorded
    );
    assert!(matches!(
        store
            .admit_blind(changed_limits, now(), blind_request.clone())
            .await?,
        PcdAdmission::Cached { ref outcome, .. } if outcome == &padded(b"canonical-blind-body")
    ));
    assert!(matches!(
        store.admit_blind(limits(), now(), blind(1, 2, 2, 7)).await,
        Err(PcdError::Rejected(PcdReject::QuotaExhausted { .. }))
    ));

    // A fresh pool simulates process restart; cached bytes and pinned epoch
    // remain the source of truth.
    drop(store);
    drop(db);
    let restarted = server::Db::connect(&database_url)?;
    let restarted_store = PostgresPcdStore::new(restarted.clone());
    let matching = matching(&blind_request, 2, 8);
    assert!(matches!(
        restarted_store
            .admit_match(changed_limits, now(), matching.clone())
            .await?,
        PcdAdmission::Evaluate {
            lease_version: 1,
            ..
        }
    ));
    restarted_store
        .record_match_outcome(now(), &matching, 1, padded(b"canonical-match-body"))
        .await?;
    assert!(matches!(
        restarted_store
            .admit_match(changed_limits, now(), matching)
            .await?,
        PcdAdmission::Cached { ref outcome, .. } if outcome == &padded(b"canonical-match-body")
    ));

    let mut conn = restarted.get().await?;
    let delete_result = diesel::sql_query("DELETE FROM pcd_key_epochs WHERE key_epoch = 14")
        .execute(&mut conn)
        .await;
    assert!(
        delete_result.is_err(),
        "live batch must retain its pinned epoch FK"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_pending_lease_is_taken_over_with_versioned_cas() -> anyhow::Result<()> {
    if !docker_tests_enabled() {
        eprintln!(
            "skipping expired_pending_lease_is_taken_over_with_versioned_cas; set TEABAY_RUN_DOCKER_TESTS=1"
        );
        return Ok(());
    }
    let (_postgres, database_url) = boot_postgres().await?;
    let db = server::Db::connect(&database_url)?;
    db.run_migrations(&database_url).await?;
    let store = PostgresPcdStore::new(db);
    store
        .register_key_epoch(
            14,
            [3; 32],
            "kms://teabay/pcd/epoch/14",
            now() - Duration::days(1),
        )
        .await?;

    let first_owner = blind(2, 2, 2, 7);
    store
        .admit_blind(limits(), now(), first_owner.clone())
        .await?;
    let mut takeover = first_owner.clone();
    takeover.lease_owner = [9; 32];
    assert!(matches!(
        store
            .admit_blind(limits(), now() + Duration::seconds(31), takeover.clone())
            .await?,
        PcdAdmission::Evaluate {
            lease_version: 2,
            ..
        }
    ));
    assert_eq!(
        store
            .record_blind_outcome(
                now() + Duration::seconds(31),
                &first_owner,
                1,
                padded(b"stale-worker-body"),
            )
            .await,
        Err(PcdError::Rejected(PcdReject::LeaseLost))
    );
    assert_eq!(
        store
            .record_blind_outcome(
                now() + Duration::seconds(31),
                &takeover,
                2,
                padded(b"takeover-body"),
            )
            .await?,
        OutcomeWrite::Recorded
    );

    let batch_expires_at = now() + Duration::seconds(3_600);
    let near_expiry = batch_expires_at - Duration::seconds(1);

    let first_near_ttl_owner = blind(3, 3, 3, 7);
    store
        .admit_blind(limits(), now(), first_near_ttl_owner.clone())
        .await?;
    let mut blind_near_ttl_takeover = first_near_ttl_owner.clone();
    blind_near_ttl_takeover.lease_owner = [9; 32];
    assert!(matches!(
        store
            .admit_blind(limits(), near_expiry, blind_near_ttl_takeover.clone())
            .await?,
        PcdAdmission::Evaluate {
            lease_version: 2,
            lease_expires_at,
            ..
        } if lease_expires_at == batch_expires_at
    ));
    store
        .record_blind_outcome(
            near_expiry,
            &blind_near_ttl_takeover,
            2,
            padded(b"near-ttl-blind"),
        )
        .await?;
    let first_match_near_ttl = matching(&blind_near_ttl_takeover, 4, 8);
    assert!(matches!(
        store
            .admit_match(limits(), near_expiry, first_match_near_ttl.clone())
            .await?,
        PcdAdmission::Evaluate {
            lease_version: 1,
            lease_expires_at,
            ..
        } if lease_expires_at == batch_expires_at
    ));
    assert_eq!(
        store
            .admit_match(limits(), batch_expires_at, first_match_near_ttl)
            .await,
        Err(PcdError::Rejected(PcdReject::BatchUnavailable))
    );

    let second_near_ttl_blind = blind(4, 4, 5, 7);
    store
        .admit_blind(limits(), now(), second_near_ttl_blind.clone())
        .await?;
    store
        .record_blind_outcome(now(), &second_near_ttl_blind, 1, padded(b"blind"))
        .await?;
    let first_match_owner = matching(&second_near_ttl_blind, 6, 8);
    store
        .admit_match(limits(), now(), first_match_owner.clone())
        .await?;
    let mut match_near_ttl_takeover = first_match_owner;
    match_near_ttl_takeover.lease_owner = [10; 32];
    assert!(matches!(
        store
            .admit_match(limits(), near_expiry, match_near_ttl_takeover.clone())
            .await?,
        PcdAdmission::Evaluate {
            lease_version: 2,
            lease_expires_at,
            ..
        } if lease_expires_at == batch_expires_at
    ));
    assert_eq!(
        store
            .record_match_outcome(
                batch_expires_at,
                &match_near_ttl_takeover,
                2,
                padded(b"too-late"),
            )
            .await,
        Err(PcdError::Rejected(PcdReject::BatchUnavailable))
    );
    Ok(())
}
