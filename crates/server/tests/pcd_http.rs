use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use arkret_sdk::{
    AntiEnumerationDelay, DirectoryPrivateContactDiscoveryOutcome,
    DirectoryPrivateContactDiscoveryRequestBody, PrivateContactDiscovery,
    PrivateContactDiscoveryHandoffStubsMode, PsiPaddedProblem,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration as ChronoDuration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt as _;
use salvo::Service;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use server::config::{
    AcceptPolicyKind, DbPoolConfig, IngestModeAdvert, PrivateContactDiscoveryRuntimeConfig,
};
use sha2::Sha256;
mod common;

use common::{boot_postgres, docker_tests_enabled};
use voprf::{Group, Ristretto255, VoprfClient, VoprfServer};

const OPERATION: &str = "ak.find.directory.read.private_contact_discovery.v1";

struct EpochFixture {
    runtime: PrivateContactDiscoveryRuntimeConfig,
    private_key_file: PathBuf,
    custody_key_ref: String,
    matching_prefix: String,
}

fn epoch_fixture(directory: &Path, epoch: u64, scalar_byte: u8) -> anyhow::Result<EpochFixture> {
    let mut private_key = [0_u8; 32];
    private_key[0] = scalar_byte;
    let server = VoprfServer::<Ristretto255>::new_with_key(&private_key)?;
    let public_key = URL_SAFE_NO_PAD.encode(Ristretto255::serialize_elem(server.get_public_key()));
    let evaluated = server.evaluate(b"alice@example.com")?;
    let matching_prefix = URL_SAFE_NO_PAD.encode(&evaluated[..16]);
    let configuration = PrivateContactDiscovery::new(
        public_key,
        epoch,
        2,
        PrivateContactDiscoveryHandoffStubsMode::Never,
        4096,
        4096,
        3_600,
        1,
        86_400,
        AntiEnumerationDelay {
            minimum_ms: 0,
            jitter_ms: 1,
        },
    );
    configuration.validate()?;

    let private_key_file = directory.join(format!("epoch-{epoch}.key"));
    std::fs::write(&private_key_file, URL_SAFE_NO_PAD.encode(private_key))?;
    let index_manifest_path = directory.join(format!("epoch-{epoch}-index.json"));
    std::fs::write(
        &index_manifest_path,
        serde_json::to_vec(&json!({
            "key_epoch": epoch,
            "generation": format!("generation-{epoch}"),
            "entries": [{ "derived_prefix": matching_prefix }],
        }))?,
    )?;
    let custody_key_ref = format!("kms://teabay/pcd/epoch/{epoch}");
    let device_authentication_key_path = directory.join("device-authentication.key");
    if !device_authentication_key_path.exists() {
        std::fs::write(
            &device_authentication_key_path,
            URL_SAFE_NO_PAD.encode([9_u8; 32]),
        )?;
    }
    Ok(EpochFixture {
        runtime: PrivateContactDiscoveryRuntimeConfig {
            describe: configuration,
            custody_key_ref: custody_key_ref.clone(),
            custody_manifest_path: directory.join("custody.json"),
            index_manifest_path,
            device_authentication_key_path,
            key_activated_at: Utc::now() - ChronoDuration::seconds(1),
            evaluation_lease_seconds: 5,
            garbage_collection_interval: Duration::from_secs(60),
        },
        private_key_file,
        custody_key_ref,
        matching_prefix,
    })
}

fn write_custody_manifest(directory: &Path, epochs: &[&EpochFixture]) -> anyhow::Result<()> {
    let keys = epochs
        .iter()
        .map(|epoch| {
            json!({
                "custody_key_ref": epoch.custody_key_ref,
                "private_key_file": epoch
                    .private_key_file
                    .file_name()
                    .unwrap()
                    .to_string_lossy(),
            })
        })
        .collect::<Vec<_>>();
    std::fs::write(
        directory.join("custody.json"),
        serde_json::to_vec(&json!({ "keys": keys }))?,
    )?;
    Ok(())
}

fn app_config(
    database_url: &str,
    runtime: PrivateContactDiscoveryRuntimeConfig,
) -> server::AppConfig {
    server::AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "http://directory.test".to_owned(),
        service_id: arkret_sdk::DidCoreId::new("ak:did_core:web:directory.test").unwrap(),
        service_did: arkret_sdk::Did::new("did:web:directory.test").unwrap(),
        service_resolution: arkret_sdk::ResolutionCommitment {
            did: arkret_sdk::Did::new("did:web:directory.test").unwrap(),
            method_history_head: "pcd-test-history".to_owned(),
            version_id: "pcd-test-version".to_owned(),
        },
        trust_domain: "ak:trust_domain:local.test".to_owned(),
        database_url: database_url.to_owned(),
        cors_allow_origin: None,
        admin_csrf_token: None,
        admin_token: None,
        admin_token_rotation_window: Duration::from_secs(1_800),
        development_mode: true,
        accept_policy_kind: AcceptPolicyKind::Open,
        accept_policy_ref: None,
        takedown_contact: None,
        accepted_resource_kinds: arkret_sdk::DirectoryResourceKind::ALL.to_vec(),
        accepted_did_methods: vec!["did:web".to_owned()],
        default_ttl: Duration::from_secs(3_600),
        max_ttl: Duration::from_secs(86_400),
        revalidation_grace: Duration::from_secs(300),
        as_of_skew: Duration::from_secs(60),
        ingest_modes: vec![IngestModeAdvert::Push],
        rate_limit_per_resource_per_min: 60,
        query_max_queries_per_ip_per_min: 0,
        query_max_resolves_per_resource_per_min: 0,
        query_latency_floor: Duration::ZERO,
        query_latency_jitter: Duration::ZERO,
        require_http_sig: false,
        http_sig_pubkeys: HashMap::new(),
        receipt_signing_key: None,
        db_pool: DbPoolConfig::default(),
        expiry_interval: None,
        takedown_notifier_interval: None,
        trusted_proxy: None,
        private_contact_discovery: Some(runtime),
    }
}

async fn build_service(
    database_url: &str,
    runtime: PrivateContactDiscoveryRuntimeConfig,
) -> anyhow::Result<Service> {
    let config = app_config(database_url, runtime.clone());
    let db = server::Db::connect(database_url)?;
    db.run_migrations(database_url).await?;
    let pcd = server::pcd::PrivateContactDiscoveryService::bootstrap(&runtime, &db).await?;
    let state = server::AppState::new_with_private_contact_discovery(config, db, Some(pcd))?;
    Ok(server::service(state))
}

fn device_token() -> String {
    let device_id = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let signed = format!("pcd1.{device_id}");
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[9_u8; 32]).unwrap();
    mac.update(signed.as_bytes());
    format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn batch_id(value: u8) -> String {
    format!("ak:batch:0196429a-0000-7000-8000-{value:012x}")
}

async fn post(service: &Service, body: &Value) -> salvo::Response {
    TestClient::post("http://local/_arkret/find/directory/private-contact-discovery")
        .add_header("Arkret-Operation", OPERATION, true)
        .add_header("Authorization", format!("Bearer {}", device_token()), true)
        .json(body)
        .send(service)
        .await
}

fn assert_bucket_headers(response: &salvo::Response, content_type: &str) {
    assert_eq!(
        response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok()),
        Some("4096")
    );
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store, no-transform")
    );
    assert!(response.headers().get("content-encoding").is_none());
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some(content_type)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pcd_http_closes_proof_padding_retry_quota_restart_and_rotation() -> anyhow::Result<()> {
    if !docker_tests_enabled() {
        eprintln!(
            "skipping pcd_http_closes_proof_padding_retry_quota_restart_and_rotation; set TEABAY_RUN_DOCKER_TESTS=1"
        );
        return Ok(());
    }
    let (_postgres, database_url) = boot_postgres().await?;
    let mut random = [0_u8; 8];
    rand::rng().fill(&mut random);
    let directory = std::env::temp_dir().join(format!("teabay-pcd-{}", u64::from_le_bytes(random)));
    std::fs::create_dir_all(&directory)?;

    let epoch14 = epoch_fixture(&directory, 14, 1)?;
    write_custody_manifest(&directory, &[&epoch14])?;
    let service14 = build_service(&database_url, epoch14.runtime.clone())
        .await
        .context("bootstrap epoch 14")?;

    let inputs = [
        b"alice@example.com".as_slice(),
        b"dummy-private-input".as_slice(),
    ];
    let mut blinded_elements = Vec::new();
    for input in inputs {
        let blind = VoprfClient::<Ristretto255>::blind(input, &mut rand_09::rng())?;
        blinded_elements.push(URL_SAFE_NO_PAD.encode(blind.message.serialize()));
    }
    let blind_body = json!({
        "profile": "ak.private_contact_discovery.v1",
        "phase": "blind",
        "batch_id": batch_id(1),
        "ciphersuite": "ristretto255-SHA512",
        "key_epoch": 14,
        "blinded_elements": blinded_elements,
    });
    let typed_blind: DirectoryPrivateContactDiscoveryRequestBody =
        serde_json::from_value(blind_body.clone())?;
    let mut blind_response = post(&service14, &blind_body).await;
    assert_eq!(blind_response.status_code, Some(StatusCode::OK));
    assert_bucket_headers(&blind_response, "application/json");
    let blind_bytes = blind_response.take_bytes(None).await?.to_vec();
    assert_eq!(blind_bytes.len(), 4096);
    let blind_outcome: DirectoryPrivateContactDiscoveryOutcome =
        arkret_sdk::canonical::from_canonical_json_slice(&blind_bytes)?;
    blind_outcome.validate_against_request(&typed_blind, &epoch14.runtime.describe)?;

    let mut exact_retry = post(&service14, &blind_body).await;
    assert_eq!(exact_retry.status_code, Some(StatusCode::OK));
    assert_eq!(exact_retry.take_bytes(None).await?.as_ref(), blind_bytes);

    let epoch15 = epoch_fixture(&directory, 15, 2)?;
    write_custody_manifest(&directory, &[&epoch14, &epoch15])?;
    let service15 = build_service(&database_url, epoch15.runtime.clone())
        .await
        .context("bootstrap epoch 15")?;

    let mut old_retry_after_rotation = post(&service15, &blind_body).await;
    assert_eq!(old_retry_after_rotation.status_code, Some(StatusCode::OK));
    assert_eq!(
        old_retry_after_rotation.take_bytes(None).await?.as_ref(),
        blind_bytes
    );

    let match_body = json!({
        "profile": "ak.private_contact_discovery.v1",
        "phase": "match",
        "batch_id": batch_id(1),
        "key_epoch": 14,
        "derived_prefixes": [epoch14.matching_prefix, URL_SAFE_NO_PAD.encode([0_u8; 16])],
    });
    let typed_match: DirectoryPrivateContactDiscoveryRequestBody =
        serde_json::from_value(match_body.clone())?;
    let mut match_response = post(&service15, &match_body).await;
    assert_eq!(match_response.status_code, Some(StatusCode::OK));
    assert_bucket_headers(&match_response, "application/json");
    let match_bytes = match_response.take_bytes(None).await?.to_vec();
    let match_outcome: DirectoryPrivateContactDiscoveryOutcome =
        arkret_sdk::canonical::from_canonical_json_slice(&match_bytes)?;
    match_outcome.validate_against_request(&typed_match, &epoch14.runtime.describe)?;
    assert!(matches!(
        match_outcome,
        DirectoryPrivateContactDiscoveryOutcome::Match { hit_bitmap, .. }
            if hit_bitmap == vec![true, false]
    ));

    let restarted15 = build_service(&database_url, epoch15.runtime.clone())
        .await
        .context("restart epoch 15")?;
    let mut match_retry = post(&restarted15, &match_body).await;
    assert_eq!(match_retry.status_code, Some(StatusCode::OK));
    assert_eq!(match_retry.take_bytes(None).await?.as_ref(), match_bytes);

    let quota_body = json!({
        "profile": "ak.private_contact_discovery.v1",
        "phase": "blind",
        "batch_id": batch_id(2),
        "ciphersuite": "ristretto255-SHA512",
        "key_epoch": 15,
        "blinded_elements": blind_body["blinded_elements"],
    });
    let mut quota_response = post(&restarted15, &quota_body).await;
    assert_eq!(
        quota_response.status_code,
        Some(StatusCode::TOO_MANY_REQUESTS)
    );
    assert_bucket_headers(&quota_response, "application/problem+json");
    let retry_after = quota_response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .parse::<u64>()?;
    assert!(retry_after >= 300 && retry_after % 300 == 0);
    let quota_bytes = quota_response.take_bytes(None).await?;
    let quota_problem: PsiPaddedProblem =
        arkret_sdk::canonical::from_canonical_json_slice(&quota_bytes)?;
    quota_problem.validate_for_phase_and_bucket(
        arkret_sdk::PsiResponsePhase::Blind,
        &epoch15.runtime.describe,
    )?;

    let mut conflict_body = match_body;
    conflict_body["derived_prefixes"][1] = json!(URL_SAFE_NO_PAD.encode([1_u8; 16]));
    let mut conflict_response = post(&restarted15, &conflict_body).await;
    assert_eq!(conflict_response.status_code, Some(StatusCode::CONFLICT));
    assert_bucket_headers(&conflict_response, "application/problem+json");
    assert_eq!(conflict_response.take_bytes(None).await?.len(), 4096);

    std::fs::remove_dir_all(&directory)?;
    Ok(())
}
