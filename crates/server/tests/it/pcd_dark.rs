//! PostgreSQL contracts for the deliberately unreachable PCD durable core.

use chrono::{DateTime, Duration, Utc};
use diesel::QueryableByName;
use diesel::sql_types::BigInt;
use diesel_async::RunQueryDsl;
use server::pcd_dark::{
    BlindAdmissionRequest, DeviceCredentialDigest, MatchAdmissionRequest, OpaqueExactBucketBytes,
    OutcomeWrite, PcdAdmission, PcdBatchId, PcdError, PcdOperationalLimits, PcdReject,
    PcdRequestDigest, PostgresPcdStore,
};
use testcontainers_modules::postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

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

const PUBLIC_KEY: &str = "yAPizGsF_BUGRUm1kgZZykp3ssym8E9rNXAJM1R2rU4";

fn config(key_epoch: u64, batch_item_count: u16) -> arkret_sdk::PrivateContactDiscovery {
    let config = arkret_sdk::PrivateContactDiscovery::new(
        PUBLIC_KEY,
        key_epoch,
        batch_item_count,
        arkret_sdk::PrivateContactDiscoveryHandoffStubsMode::Never,
        4096,
        4096,
        3_600,
        1,
        86_400,
        arkret_sdk::AntiEnumerationDelay {
            minimum_ms: 100,
            jitter_ms: 50,
            distribution: arkret_sdk::AntiEnumerationDelayDistribution::Uniform,
        },
    );
    config.validate().expect("valid test PCD config");
    config
}

fn changed_config() -> arkret_sdk::PrivateContactDiscovery {
    let mut config = config(14, 8);
    config.handoff_stubs_mode = arkret_sdk::PrivateContactDiscoveryHandoffStubsMode::Always;
    config.anti_enumeration_delay.minimum_ms = 200;
    config.validate().expect("valid changed test PCD config");
    config
}

fn operational() -> PcdOperationalLimits {
    PcdOperationalLimits {
        evaluation_lease_seconds: 30,
    }
}

fn public_key() -> [u8; 32] {
    arkret_sdk::canonical::base64url_decode(PUBLIC_KEY)
        .expect("valid public key")
        .try_into()
        .expect("32-byte public key")
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
            public_key(),
            "kms://teabay/pcd/epoch/14",
            now() - Duration::days(1),
        )
        .await?;
    store
        .register_key_epoch(
            14,
            public_key(),
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
    let original_config = config(14, 4);
    assert!(matches!(
        store
            .admit_blind(&original_config, operational(), now(), blind_request.clone())
            .await?,
        PcdAdmission::Evaluate { ref pinned_config,
            lease_version: 1,
            ..
        } if pinned_config.config() == &original_config
    ));
    let mut changed_config = config(14, 8);
    changed_config.handoff_stubs_mode = arkret_sdk::PrivateContactDiscoveryHandoffStubsMode::Always;
    changed_config.anti_enumeration_delay.minimum_ms = 200;
    changed_config.validate()?;
    assert!(matches!(
        store
            .admit_blind(&changed_config, operational(), now(), blind_request.clone())
            .await?,
        PcdAdmission::PendingRetry {
            ref pinned_config,
            lease_version: 1,
            retry_after_seconds: 30,
            ..
        } if pinned_config.config() == &original_config
    ));
    let mut temporarily_invalid_current = changed_config.clone();
    temporarily_invalid_current.batch_item_count = 0;
    assert!(matches!(
        store
            .admit_blind(
                &temporarily_invalid_current,
                operational(),
                now(),
                blind_request.clone(),
            )
            .await?,
        PcdAdmission::PendingRetry { ref pinned_config, .. }
            if pinned_config.config() == &original_config
    ));
    assert_eq!(
        store
            .record_blind_outcome(now(), &blind_request, 1, padded(b"canonical-blind-body"))
            .await?,
        OutcomeWrite::Recorded
    );
    assert!(matches!(
        store
            .admit_blind(&changed_config, operational(), now(), blind_request.clone())
            .await?,
        PcdAdmission::Cached { ref pinned_config, ref outcome, .. }
            if pinned_config.config() == &original_config
                && outcome == &padded(b"canonical-blind-body")
    ));
    assert!(matches!(
        store
            .admit_blind(&original_config, operational(), now(), blind(1, 2, 2, 7))
            .await,
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
            .admit_match(operational(), now(), matching.clone())
            .await?,
        PcdAdmission::Evaluate { ref pinned_config,
            lease_version: 1,
            ..
        } if pinned_config.config() == &original_config
    ));
    restarted_store
        .record_match_outcome(now(), &matching, 1, padded(b"canonical-match-body"))
        .await?;
    assert!(matches!(
        restarted_store
            .admit_match(operational(), now(), matching)
            .await?,
        PcdAdmission::Cached { ref pinned_config, ref outcome, .. }
            if pinned_config.config() == &original_config
                && outcome == &padded(b"canonical-match-body")
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
            public_key(),
            "kms://teabay/pcd/epoch/14",
            now() - Duration::days(1),
        )
        .await?;

    let first_owner = blind(2, 2, 2, 7);
    store
        .admit_blind(&config(14, 4), operational(), now(), first_owner.clone())
        .await?;
    let mut takeover = first_owner.clone();
    takeover.lease_owner = [9; 32];
    assert!(matches!(
        store
            .admit_blind(
                &config(14, 4),
                operational(),
                now() + Duration::seconds(31),
                takeover.clone(),
            )
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
        .admit_blind(
            &config(14, 4),
            operational(),
            now(),
            first_near_ttl_owner.clone(),
        )
        .await?;
    let mut blind_near_ttl_takeover = first_near_ttl_owner.clone();
    blind_near_ttl_takeover.lease_owner = [9; 32];
    assert!(matches!(
        store
            .admit_blind(
                &config(14, 4),
                operational(),
                near_expiry,
                blind_near_ttl_takeover.clone(),
            )
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
            .admit_match(operational(), near_expiry, first_match_near_ttl.clone())
            .await?,
        PcdAdmission::Evaluate {
            lease_version: 1,
            lease_expires_at,
            ..
        } if lease_expires_at == batch_expires_at
    ));
    assert_eq!(
        store
            .admit_match(operational(), batch_expires_at, first_match_near_ttl)
            .await,
        Err(PcdError::Rejected(PcdReject::BatchUnavailable))
    );

    let second_near_ttl_blind = blind(4, 4, 5, 7);
    store
        .admit_blind(
            &config(14, 4),
            operational(),
            now(),
            second_near_ttl_blind.clone(),
        )
        .await?;
    store
        .record_blind_outcome(now(), &second_near_ttl_blind, 1, padded(b"blind"))
        .await?;
    let first_match_owner = matching(&second_near_ttl_blind, 6, 8);
    store
        .admit_match(operational(), now(), first_match_owner.clone())
        .await?;
    let mut match_near_ttl_takeover = first_match_owner;
    match_near_ttl_takeover.lease_owner = [10; 32];
    assert!(matches!(
        store
            .admit_match(operational(), near_expiry, match_near_ttl_takeover.clone())
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_gc_preserves_current_and_live_bindings_then_reclaims_history()
-> anyhow::Result<()> {
    if !docker_tests_enabled() {
        eprintln!(
            "skipping explicit_gc_preserves_current_and_live_bindings_then_reclaims_history; set TEABAY_RUN_DOCKER_TESTS=1"
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
            public_key(),
            "kms://teabay/pcd/epoch/14",
            now() - Duration::days(1),
        )
        .await?;
    store
        .register_key_epoch(
            15,
            public_key(),
            "kms://teabay/pcd/epoch/15",
            now() + Duration::seconds(3_599),
        )
        .await?;

    let old_digest = match store
        .admit_blind(&config(14, 4), operational(), now(), blind(10, 10, 10, 7))
        .await?
    {
        PcdAdmission::Evaluate { pinned_config, .. } => pinned_config.digest(),
        other => anyhow::bail!("unexpected old admission: {other:?}"),
    };
    let mut changed_request = blind(11, 11, 11, 7);
    changed_request.item_count = 8;
    let current_epoch_digest = match store
        .admit_blind(&changed_config(), operational(), now(), changed_request)
        .await?
    {
        PcdAdmission::Evaluate { pinned_config, .. } => pinned_config.digest(),
        other => anyhow::bail!("unexpected changed admission: {other:?}"),
    };
    assert_ne!(old_digest, current_epoch_digest);

    // Epoch 15 exists, so only the composite snapshot binding can reject this
    // split-brain operator write.
    let mut conn = db.get().await?;
    let split_binding = diesel::sql_query(
        "UPDATE pcd_batches SET pinned_key_epoch = 15 \
         WHERE batch_id = 'ak:batch:0196429a-0000-7000-8000-00000000000a'",
    )
    .execute(&mut conn)
    .await;
    assert!(
        split_binding.is_err(),
        "composite config-digest/epoch FK must reject split binding"
    );
    drop(conn);

    store
        .retire_key_epoch(14, now() + Duration::seconds(3_599))
        .await?;
    assert_eq!(
        store
            .register_key_epoch(
                14,
                public_key(),
                "kms://teabay/pcd/epoch/14",
                now() - Duration::days(1),
            )
            .await,
        Err(PcdError::Rejected(PcdReject::DuplicateConflict))
    );
    store
        .retire_key_epoch(14, now() + Duration::seconds(3_599))
        .await?;
    let live_gc = store
        .garbage_collect(now() + Duration::seconds(3_599), current_epoch_digest)
        .await?;
    assert_eq!(live_gc, Default::default());
    let first_gc = store
        .garbage_collect(now() + Duration::seconds(3_600), current_epoch_digest)
        .await?;
    assert_eq!(first_gc.expired_batches, 2);
    assert_eq!(first_gc.unreferenced_config_snapshots, 1);
    assert_eq!(first_gc.retired_key_epochs, 0);

    let mut replacement_request = blind(12, 12, 12, 7);
    replacement_request.key_epoch = 15;
    let replacement_digest = match store
        .admit_blind(
            &config(15, 4),
            operational(),
            now() + Duration::seconds(3_600),
            replacement_request,
        )
        .await?
    {
        PcdAdmission::Evaluate { pinned_config, .. } => pinned_config.digest(),
        other => anyhow::bail!("unexpected replacement admission: {other:?}"),
    };
    let second_gc = store
        .garbage_collect(now() + Duration::seconds(7_200), replacement_digest)
        .await?;
    assert_eq!(second_gc.expired_batches, 1);
    assert_eq!(second_gc.unreferenced_config_snapshots, 1);
    assert_eq!(second_gc.retired_key_epochs, 1);

    let mut conn = db.get().await?;
    let epochs = diesel::sql_query("SELECT COUNT(*)::BIGINT AS count FROM pcd_key_epochs")
        .get_result::<CountRow>(&mut conn)
        .await?;
    let snapshots = diesel::sql_query("SELECT COUNT(*)::BIGINT AS count FROM pcd_config_snapshots")
        .get_result::<CountRow>(&mut conn)
        .await?;
    let batches = diesel::sql_query("SELECT COUNT(*)::BIGINT AS count FROM pcd_batches")
        .get_result::<CountRow>(&mut conn)
        .await?;
    assert_eq!((epochs.count, snapshots.count, batches.count), (1, 1, 0));
    drop(conn);

    let quota_gc = store
        .garbage_collect(now() + Duration::seconds(90_000), replacement_digest)
        .await?;
    assert_eq!(quota_gc.expired_quota_windows, 3);
    Ok(())
}
