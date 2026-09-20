#![allow(
    unsafe_code,
    reason = "integration tests mutate process environment before server startup and restore it"
)]

use arkret_sdk::{
    DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND, Did, DidCoreId, DirectoryPresentedClaim,
    DirectoryRestrictedClaimPresentation, Hash, ProducerEventProof, RealmId, ScopeRef, canonical,
};
use arkret_signatures::EventProofBuilder;
use arkret_signatures::jws::sign_jws_ed25519;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration as ChronoDuration, Utc};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::RunQueryDsl;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::prelude::Service;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value as JsonValue, json};

use crate::common::boot_postgres;

#[derive(diesel::QueryableByName)]
struct WithdrawalProofRow {
    #[diesel(sql_type = Text)]
    withdraw_id: String,
    #[diesel(sql_type = Jsonb)]
    proof: JsonValue,
}

#[ignore = "Docker-backed: this test starts a real PostgreSQL container. Run it with `-- --include-ignored`; a default run reports it as ignored, never as passed."]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_query_conformance_smoke() -> anyhow::Result<()> {
    let (_container, database_url) = boot_postgres().await?;

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
        std::env::set_var("DATABASE_URL", &database_url);
        std::env::set_var("TEABAY_ADMIN_TOKEN", "cotest-admin");
        std::env::set_var(
            "TEABAY_RECEIPT_SIGNING_KEY_B64",
            URL_SAFE_NO_PAD.encode([13_u8; 32]),
        );
        std::env::set_var(
            "TEABAY_RECEIPT_KEY_ID",
            "did:web:directory.test#receipt-conformance",
        );
        std::env::set_var("TEABAY_DEVELOPMENT_MODE", "true");
        // This harness explicitly uses self-contained governance and claim
        // keys, outside the production default allowlist.
        std::env::set_var("TEABAY_ACCEPTED_DID_METHODS", "did:key,did:web");
        std::env::set_var("TEABAY_QUERY_LATENCY_FLOOR_MS", "0");
        std::env::set_var("TEABAY_QUERY_LATENCY_JITTER_MS", "0");
        // The conformance harness posts unsigned envelopes against the
        // ingest surface to exercise the 5-step verify chain in isolation.
        // The TB-1 HTTP signature middleware would otherwise reject them
        // at the transport layer before they reach `VerifyContext::verify`,
        // so explicitly run the middleware in passthrough mode here. The
        // dedicated `http_sig` unit tests cover the enforcement behavior.
        std::env::set_var("TEABAY_REQUIRE_HTTP_SIG", "false");
    }

    let config = server::AppConfig::from_env()?;
    let db = server::Db::connect(&database_url)?;
    db.run_migrations(&database_url).await?;
    seed_directory_fixture(&db).await?;

    let service = server::service(server::AppState::new(config.clone(), db.clone())?);
    assert_describe_advertises_core(&service).await?;
    assert_query_surface_matrix(&db, &service).await?;
    assert_search_realms_finds_seeded_realm(&service).await?;
    assert_official_badge_is_verified_relationship_driven(&db, &service).await?;
    assert_first_ingest_rejects_unresolvable_station_then_refreshes_seeded_resource(&db, &service)
        .await?;
    assert_freshness_flags_are_exposed(&db, &service).await?;
    assert_three_path_takedown_strand(&db, &service).await?;
    assert_admin_operator_surface(&service).await?;
    // Last: this one indexes a new resource, and running it here keeps every
    // assertion above it looking at exactly the fixture set it was written
    // against.
    crate::first_ingest::assert_first_ingest_admits_a_did_web_station(&db, &service).await?;
    Ok(())
}

const DIRECTORY_FIXTURE_SQL: &str = include_str!("fixtures/directory_resources.sql");

/// TBY-ORG-04 — verified `ak.realm.organization` relationship fixtures. Seeded
/// after [`DIRECTORY_FIXTURE_SQL`] (it references those realm rows).
const VERIFIED_REALM_ORGANIZATIONS_FIXTURE_SQL: &str =
    include_str!("fixtures/verified_realm_organizations.sql");

async fn seed_directory_fixture(db: &server::Db) -> anyhow::Result<()> {
    let mut conn = db.get().await?;
    diesel::sql_query(DIRECTORY_FIXTURE_SQL)
        .execute(&mut conn)
        .await?;
    // TBY-ORG-04 — verified relationship index rows reference the realm rows
    // seeded above, so they must be applied after the directory fixture.
    diesel::sql_query(VERIFIED_REALM_ORGANIZATIONS_FIXTURE_SQL)
        .execute(&mut conn)
        .await?;
    Ok(())
}

async fn install_restricted_realm_claim_selector(
    db: &server::Db,
    issuer_id: &str,
    organization: &str,
) -> anyhow::Result<()> {
    let mut conn = db.get().await?;
    let discoverers = json!([{
        "type": "claim",
        "claim_kind": "organization_membership",
        "issuer_id": issuer_id,
        "organization_id": organization
    }]);
    diesel::sql_query(
        "UPDATE directory_resources \
         SET public_projection = jsonb_set(public_projection, '{allowed_discoverers}', $1::jsonb, true) \
         WHERE resource_kind = 'realm'::resource_kind AND resource_id = 'ak:realm:AdaQzevAO2VnYKLw4DxSt_OKfNQnb8F2PBgVHfF5A6yt'",
    )
    .bind::<Jsonb, _>(discoverers)
    .execute(&mut conn)
    .await?;
    Ok(())
}

async fn assert_describe_advertises_core(service: &Service) -> anyhow::Result<()> {
    let mut res = TestClient::get("http://local/_arkret/find/directory/describe")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_DESCRIBE_V1,
            true,
        )
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    let profiles = body["supported_profiles"].as_array().unwrap();
    assert!(profiles.is_empty());
    assert_eq!(body["service_id"], "ak:did_core:web:directory.test");
    assert_eq!(body["service_resolution"]["did"], "did:web:directory.test");
    assert_eq!(
        body["service_resolution"]["method_history_head"],
        "did-web-document-etag-fixture"
    );
    assert_eq!(body["service_kind"], "directory_service");
    assert!(
        body["accepted_resource_kinds"]
            .as_array()
            .unwrap()
            .contains(&json!("realm"))
    );
    assert!(body.get("ingest_modes").is_none());
    assert!(
        body["supported_operation_bundles"]
            .as_array()
            .unwrap()
            .contains(&json!("ak.operation_bundle.directory_service.http_core.v1"))
    );
    assert!(
        body["x_teabay_limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|limitation| limitation["feature"] == "pull_mode_ingest"
                && limitation["status"] == "unsupported")
    );
    assert!(
        body["x_teabay_limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|limitation| limitation["feature"] == "operator_takedown_notification")
    );
    Ok(())
}

async fn assert_search_realms_finds_seeded_realm(service: &Service) -> anyhow::Result<()> {
    let mut res = TestClient::post("http://local/_arkret/find/directory/search-realms")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
            true,
        )
        .json(&json!({ "query": "tea", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert!(body["realms"].as_array().unwrap().iter().any(
        |result| result["realm_id"] == "ak:realm:ASsKHIftKaTemZcyvFWmoYnCtQNN_4deE04hdIPA0PPu"
    ));
    Ok(())
}

/// TBY-ORG-02/03/04 — the official verified badge / owning-organization surface
/// is driven exclusively by the verified `ak.realm.organization` index, never by
/// a declared projection hint. Covers: active owner ⇒ badge; declared-only ⇒ no
/// badge; relationship mismatch (sponsor ≠ owner) ⇒ no badge; revoke removes
/// badge; expiry removes badge.
async fn assert_official_badge_is_verified_relationship_driven(
    db: &server::Db,
    service: &Service,
) -> anyhow::Result<()> {
    async fn resolve_owning_orgs(service: &Service, realm_id: &str) -> Vec<String> {
        let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
            .add_header(
                "Arkret-Operation",
                arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
                true,
            )
            .json(&json!({ "realm_id": realm_id }))
            .send(service)
            .await;
        assert_eq!(
            res.status_code.unwrap_or(StatusCode::OK),
            StatusCode::OK,
            "{}",
            res.take_string().await.unwrap_or_default()
        );
        let body: JsonValue = res.take_json().await.expect("resolve-realm body");
        body["realm_preview"]["owning_organization_ids"]
            .as_array()
            .map(|orgs| {
                orgs.iter()
                    .filter_map(|o| o.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    // (1) active owner relationship ⇒ verified owning organization surfaces.
    let verified = resolve_owning_orgs(
        service,
        "ak:realm:AZ0Vyo6cesGriGAh_ea-7SD_Hy3GDnSxDMTrErh0Ki2C",
    )
    .await;
    assert_eq!(
        verified,
        vec!["ak:did_core:web:tea-org.example".to_owned()],
        "active owner ak.realm.organization MUST surface verified owning org"
    );

    // (2) declared-only org hint (no statement) ⇒ no verified owning org.
    let declared_only = resolve_owning_orgs(
        service,
        "ak:realm:Ab7H4uKENRIBMz-0WnjlHdtN9c-vVHQwqtKu6O3MOfYa",
    )
    .await;
    assert!(
        declared_only.is_empty(),
        "declared owning_organization_ids / organization_id hint MUST NOT yield a verified badge"
    );

    // (3) relationship mismatch: sponsor is NOT owner/governance ⇒ no owning org.
    let sponsor_only = resolve_owning_orgs(
        service,
        "ak:realm:ASsKHIftKaTemZcyvFWmoYnCtQNN_4deE04hdIPA0PPu",
    )
    .await;
    assert!(
        sponsor_only.is_empty(),
        "sponsor relationship MUST NOT be usable as a verified owner/governance badge"
    );

    // (4) revoke (delete the verified row) ⇒ badge disappears after refresh.
    {
        let mut conn = db.get().await?;
        diesel::sql_query(
            "DELETE FROM verified_realm_organizations \
             WHERE realm_id = 'ak:realm:AZ0Vyo6cesGriGAh_ea-7SD_Hy3GDnSxDMTrErh0Ki2C'",
        )
        .execute(&mut conn)
        .await?;
    }
    let after_revoke = resolve_owning_orgs(
        service,
        "ak:realm:AZ0Vyo6cesGriGAh_ea-7SD_Hy3GDnSxDMTrErh0Ki2C",
    )
    .await;
    assert!(
        after_revoke.is_empty(),
        "revoking the ak.realm.organization statement MUST remove the verified badge"
    );

    // (5) expired relationship ⇒ not surfaced even before purge.
    {
        let mut conn = db.get().await?;
        diesel::sql_query(
            "INSERT INTO verified_realm_organizations \
               (realm_id, organization_id, relationship, control_scopes, statement_id, \
                statement_issued_at, not_before, expires_at, realm_commit_ref, stale, \
                verified_at, source_announce_id) \
             VALUES ('ak:realm:AZ0Vyo6cesGriGAh_ea-7SD_Hy3GDnSxDMTrErh0Ki2C', 'ak:did_core:web:tea-org.example', 'owner', \
                     ARRAY['official_badge'], 'org-stmt-expired', now() - interval '2 hours', \
                     NULL, now() - interval '1 hour', NULL, false, now(), 'ak.announce:expired')",
        )
        .execute(&mut conn)
        .await?;
    }
    let after_expiry = resolve_owning_orgs(
        service,
        "ak:realm:AZ0Vyo6cesGriGAh_ea-7SD_Hy3GDnSxDMTrErh0Ki2C",
    )
    .await;
    assert!(
        after_expiry.is_empty(),
        "expired ak.realm.organization statement MUST NOT surface a verified badge"
    );

    Ok(())
}

async fn assert_query_surface_matrix(db: &server::Db, service: &Service) -> anyhow::Result<()> {
    let mut res = TestClient::post("http://local/_arkret/find/directory/search-realms")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
            true,
        )
        .json(&json!({ "query": "tea", "limit": 1 }))
        .send(service)
        .await;
    let status = res.status_code.unwrap_or(StatusCode::OK);
    if status != StatusCode::OK {
        let body = res.take_string().await.unwrap_or_default();
        panic!("search-realms first page failed with {status}: {body}");
    }
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["realms"].as_array().unwrap().len(), 1);
    let first = &body["realms"][0];
    assert!(first.get("as_of").is_some());
    assert!(
        first["source_refs"]
            .as_array()
            .is_some_and(|refs| !refs.is_empty())
    );
    assert!(
        first
            .get("join_candidates")
            .is_none_or(|candidates| { candidates.as_array().is_some_and(Vec::is_empty) })
    );
    let cursor = body["next_cursor"]
        .as_str()
        .unwrap_or_else(|| panic!("expected next_cursor for first search page: {body}"));
    assert!(cursor.starts_with("ak:cursor:"));

    let mut cross_filter = TestClient::post("http://local/_arkret/find/directory/search-realms")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
            true,
        )
        .json(&json!({ "query": "other", "limit": 1, "cursor": cursor }))
        .send(service)
        .await;
    assert_eq!(
        cross_filter.status_code.unwrap_or(StatusCode::OK),
        StatusCode::BAD_REQUEST
    );
    let cross_filter_body: JsonValue = cross_filter.take_json().await?;
    assert_eq!(
        cross_filter_body["type"],
        "https://arkret.org/problems/cursor_integrity_invalid"
    );

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-realms")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
            true,
        )
        .json(&json!({ "query": "tea", "limit": 1, "cursor": cursor }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["realms"].as_array().unwrap().len(), 1);

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-realms")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
            true,
        )
        .json(&json!({ "cursor": "not-base64" }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::BAD_REQUEST
    );
    let invalid_body: JsonValue = res.take_json().await?;
    assert_eq!(
        invalid_body["type"],
        "https://arkret.org/problems/param_invalid"
    );

    assert_resolve_realm_status(
        service,
        "ak:realm:ASsKHIftKaTemZcyvFWmoYnCtQNN_4deE04hdIPA0PPu",
        StatusCode::OK,
        json!({}),
    )
    .await?;
    assert_resolve_realm_status(
        service,
        "ak:realm:AbIyba6ZVhEj1TBUAIooJ17_OctiUGV4uhJIVViNysT0",
        StatusCode::NOT_FOUND,
        json!({}),
    )
    .await?;
    assert_resolve_realm_status(
        service,
        "ak:realm:AdaQzevAO2VnYKLw4DxSt_OKfNQnb8F2PBgVHfF5A6yt",
        StatusCode::NOT_FOUND,
        json!({}),
    )
    .await?;

    let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        signing_key.verifying_key().as_bytes(),
    );
    // The signing identity is a resolvable `did:key` DID; the claim
    // identity it asserts is that DID's stable adapter projection.
    let issuer_did = Did::new(format!("did:key:{multibase}"))?;
    let verification_method =
        arkret_wire::DidUrl::new(format!("{}#{multibase}", issuer_did.as_str()))
            .map_err(anyhow::Error::msg)?;
    let issuer_id = arkret_sdk::project_did_to_core_id(&issuer_did)?;
    let subject_id = DidCoreId::new("ak:did_core:web:alice.example".to_owned())?;
    let organization = DidCoreId::new("ak:did_core:web:tea-org.example".to_owned())?;
    install_restricted_realm_claim_selector(db, issuer_id.as_str(), organization.as_str()).await?;
    let proof_challenge = "realm-restricted-proof-challenge-1";
    let claim = DirectoryPresentedClaim {
        claim_id: "claim-realm-restricted".to_owned(),
        subject_id: subject_id.clone(),
        issuer_id: issuer_id.clone(),
        claim_kind: "organization_membership".to_owned(),
        value: serde_json::from_value(json!({
            "organization_id": organization,
            "roles": ["member"],
        }))?,
        issued_at: Utc::now(),
        refreshed_at: None,
        expires_at: None,
        revoked_at: None,
        disclosed_fields: Default::default(),
    };
    let presentation = signed_restricted_claim_presentation(
        &signing_key,
        issuer_id,
        verification_method,
        "ak:did_core:web:directory.test",
        proof_challenge,
        claim,
    )?;
    let presentation_json = serde_json::to_value(&presentation)?;

    assert_resolve_realm_status(
        service,
        "ak:realm:AdaQzevAO2VnYKLw4DxSt_OKfNQnb8F2PBgVHfF5A6yt",
        StatusCode::NOT_FOUND,
        json!({
            "requester_id": subject_id.as_str(),
            "proof_challenge": "wrong-challenge",
            "claim_presentations": [presentation_json.clone()]
        }),
    )
    .await?;
    assert_resolve_realm_status(
        service,
        "ak:realm:AdaQzevAO2VnYKLw4DxSt_OKfNQnb8F2PBgVHfF5A6yt",
        StatusCode::OK,
        json!({
            "requester_id": subject_id.as_str(),
            "proof_challenge": proof_challenge,
            "claim_presentations": [presentation_json.clone()]
        }),
    )
    .await?;

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-realms")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
            true,
        )
        .json(&json!({
            "query": "Restricted",
            "requester_id": subject_id.as_str(),
            "proof_challenge": proof_challenge,
            "claim_presentations": [presentation_json],
            "limit": 10
        }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert!(body["realms"].as_array().unwrap().iter().any(
        |result| result["realm_id"] == "ak:realm:AdaQzevAO2VnYKLw4DxSt_OKfNQnb8F2PBgVHfF5A6yt"
    ));

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-organizations")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ORGANIZATIONS_V1,
            true,
        )
        .json(&json!({ "query": "tea", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(
        body["organizations"][0]["organization_id"],
        "ak:did_core:web:tea-org.example"
    );

    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-organization")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_ORGANIZATION_V1,
            true,
        )
        .json(&json!({ "organization_id": "ak:did_core:web:tea-org.example" }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(
        body["organization_preview"]["organization_id"],
        "ak:did_core:web:tea-org.example"
    );

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-actors")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ACTORS_V1,
            true,
        )
        .json(&json!({ "query": "alice", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(
        body["actors"][0]["actor_id"],
        json!(arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example")?,
            DidCoreId::new("ak:did_core:web:principal.test")?,
        )))
    );

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-users")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_USERS_V1,
            true,
        )
        .json(&json!({
            "query": "alice",
            "realm_id": "ak:realm:ASsKHIftKaTemZcyvFWmoYnCtQNN_4deE04hdIPA0PPu",
            "limit": 10
        }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["users"][0]["display_name"], "Alice Tea");
    assert!(body["users"][0].get("account_id").is_none());
    assert!(body["users"][0].get("actor_id").is_none());

    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-handle")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_HANDLE_V1,
            true,
        )
        .json(&json!({ "handle": "alice:example.com" }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    // Handle resolution is the closed SDK outcome, not a directory result
    // envelope. Its identity is the complete principal/Station account pair.
    let outcome: arkret_sdk::DirectoryHandleResolutionOutcome = res.take_json().await?;
    assert_eq!(
        outcome.account_id,
        arkret_sdk::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example".to_owned())?,
            DidCoreId::new("ak:did_core:web:principal.test".to_owned())?,
        )
    );
    assert!(!outcome.source_refs.is_empty());
    Ok(())
}

async fn assert_resolve_realm_status(
    service: &Service,
    realm_id: &str,
    expected: StatusCode,
    extra: JsonValue,
) -> anyhow::Result<()> {
    let mut body = json!({ "realm_id": realm_id });
    if let (Some(target), Some(source)) = (body.as_object_mut(), extra.as_object()) {
        target.extend(source.clone());
    }
    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
            true,
        )
        .json(&body)
        .send(service)
        .await;
    let status = res.status_code.unwrap_or(StatusCode::OK);
    let response_body = res.take_string().await.unwrap_or_default();
    assert_eq!(status, expected, "resolve {realm_id}: {response_body}");
    Ok(())
}

// These rows represent previously accepted resources. They do not establish
// first-ingest source verification, which needs a peer resolution carrier.
async fn seed_previously_indexed_realm(
    db: &server::Db,
    realm_id: &str,
    station_id: &str,
) -> anyhow::Result<()> {
    let mut conn = db.get().await?;
    diesel::sql_query(
        "INSERT INTO directory_resources \
         (resource_kind, resource_id, station_id, discovery_state, public_projection, \
          discoverability, as_of, source_refs, policy_revision, indexed_at, \
          effective_ttl_seconds, next_revalidation_after, stale, divergent, via_services, \
          last_announce_id, last_refreshed_at, expires_at) \
         VALUES ('realm'::resource_kind, $1, $2, $3, $3, 'public'::discoverability, \
          now() - interval '1 minute', '[]'::jsonb, 'seeded-accepted-state', now(), \
          3600, now() + interval '1 hour', false, false, ARRAY[$2], \
          'ak:announce:01991000-0000-7000-8000-000000000001', now(), now() + interval '1 hour')",
    )
    .bind::<Text, _>(realm_id)
    .bind::<Text, _>(station_id)
    .bind::<Jsonb, _>(realm_discovery_state("Previously indexed Realm"))
    .execute(&mut conn)
    .await?;
    Ok(())
}

async fn assert_first_ingest_rejects_unresolvable_station_then_refreshes_seeded_resource(
    db: &server::Db,
    service: &Service,
) -> anyhow::Result<()> {
    let policy_ref = "ak:event:ASWGTju1AH5ri82iFC0b-lZTclyFRuOI8TagaYiq5ZD2";
    let realm_id = "ak:realm:ATH75ame6bMfYpXtcoLOVb7FKmgpWVniZZqVBz1dUdQa";
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let mock = FixtureStation::new(&signing_key);
    let verification_method = mock.verification_method();
    let station_id = mock.station_id()?;
    let discovery_event = signed_realm_discovery_event(
        realm_id,
        realm_discovery_state("Pushed Tea"),
        &verification_method,
        &signing_key,
        &station_id,
    )?;

    let source_ref_access = signed_source_ref_access(
        &discovery_event,
        policy_ref,
        &verification_method,
        &signing_key,
        &station_id,
    )?;
    let announce_as_of = canonical::format_timestamp_canonical(source_ref_access.as_of);
    let request = json!({
        "discovery_event": discovery_event,
        "source_ref_access": source_ref_access,
        "as_of": announce_as_of,
        "ttl_seconds": 3600,
    });
    let mut rejected = TestClient::post("http://local/_arkret/find/directory/announce")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE_V1,
            true,
        )
        .json(&request)
        .send(service)
        .await;
    assert_eq!(
        rejected.status_code.unwrap_or(StatusCode::OK),
        StatusCode::BAD_REQUEST
    );
    let rejection: JsonValue = rejected.take_json().await?;
    assert_eq!(
        rejection["type"], "https://arkret.org/problems/source_refs_unverifiable",
        "{rejection}"
    );
    // The fixture Station is a `did:key`, and `identity/identity-did.md`
    // registers `did:key` for device/Agent keys, service *evidence* and the
    // explicit ephemeral pairwise profile — never as a service DID method. A
    // `did:key` Station therefore publishes no DID document and no
    // `ArkretStation` endpoint, so first ingest has nowhere to resolve the
    // carrier `CommittedEventRef` from and MUST fail closed.
    //
    // This assertion used to look for "service-resolution carrier", the
    // wording of a hard `Err` that commit 4f129ff replaced when the source
    // DID started coming from the verified access proof. Nothing caught the
    // drift because this whole suite was being counted as passed while Docker
    // was unavailable.
    assert!(
        rejection
            .to_string()
            .contains("unsupported Station DID method did:key"),
        "{rejection}"
    );
    assert_resolve_realm_status(service, realm_id, StatusCode::NOT_FOUND, json!({})).await?;
    #[derive(diesel::QueryableByName)]
    struct ResourceCount {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }
    let mut conn = db.get().await?;
    let count: ResourceCount = diesel::sql_query(
        "SELECT count(*) AS count FROM directory_resources WHERE resource_id = $1",
    )
    .bind::<Text, _>(realm_id)
    .get_result(&mut conn)
    .await?;
    assert_eq!(
        count.count, 0,
        "rejected first ingest leaves no indexed row"
    );
    drop(conn);

    seed_previously_indexed_realm(db, realm_id, &station_id).await?;
    let mut res = TestClient::post("http://local/_arkret/find/directory/announce")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE_V1,
            true,
        )
        .json(&request)
        .send(service)
        .await;
    let status = res.status_code.unwrap_or(StatusCode::OK);
    if status != StatusCode::OK {
        let body = res.take_string().await.unwrap_or_default();
        panic!("refresh of seeded resource failed with {status}: {body}");
    }
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["announce_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("ak:announce:"))
    );

    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
            true,
        )
        .json(&json!({ "realm_id": realm_id }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["realm_preview"]["realm_id"], realm_id);
    assert_eq!(body["realm_preview"]["member_count_bucket"], "11-50");
    assert!(
        body["realm_preview"]["source_refs"]
            .as_array()
            .is_some_and(|refs| refs
                .iter()
                .any(|reference| reference["event_id"] == discovery_event["event_id"]))
    );
    assert!(
        body.get("join_candidates")
            .is_none_or(|candidates| { candidates.as_array().is_some_and(Vec::is_empty) }),
        "a station core id without a verified resolution carrier must not become a routing candidate"
    );
    Ok(())
}

async fn assert_freshness_flags_are_exposed(
    db: &server::Db,
    service: &Service,
) -> anyhow::Result<()> {
    {
        let mut conn = db.get().await?;
        diesel::sql_query(
            "UPDATE directory_resources \
             SET stale = true \
             WHERE resource_kind = 'realm'::resource_kind AND resource_id = 'ak:realm:ASsKHIftKaTemZcyvFWmoYnCtQNN_4deE04hdIPA0PPu'",
        )
        .execute(&mut conn)
        .await?;
    }
    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
            true,
        )
        .json(&json!({ "realm_id": "ak:realm:ASsKHIftKaTemZcyvFWmoYnCtQNN_4deE04hdIPA0PPu" }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["realm_preview"]["stale"], true);
    Ok(())
}

async fn assert_three_path_takedown_strand(
    db: &server::Db,
    service: &Service,
) -> anyhow::Result<()> {
    let signing_key = SigningKey::from_bytes(&[14; 32]);
    let destroyed_realm_id = "ak:realm:AQpwDm7ZXVTjUWCnaqcmxxZ49Y8CpzFJ-vLzmvCjBXfw";
    let withdrawn_realm_id = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";

    // Path 1: resource state-change (`ak.realm.destroy`) collapses the
    // indexed Realm into a tombstone projection.
    let mut destroyed_state = realm_discovery_state("Destroyable Tea");
    destroyed_state["terminal_state"] = JsonValue::String("destroyed".to_owned());
    destroyed_state["as_of_destroyed"] = json!(canonical::format_timestamp_canonical(Utc::now()));
    let destroy_source_ref = "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM";
    let destroy_mock = FixtureStation::new(&signing_key);
    let verification_method = destroy_mock.verification_method();
    let destroy_station_id = destroy_mock.station_id()?;
    seed_previously_indexed_realm(db, destroyed_realm_id, &destroy_station_id).await?;
    let discovery_event = signed_realm_discovery_event(
        destroyed_realm_id,
        destroyed_state,
        &verification_method,
        &signing_key,
        &destroy_station_id,
    )?;
    let source_ref_access = signed_source_ref_access(
        &discovery_event,
        destroy_source_ref,
        &verification_method,
        &signing_key,
        &destroy_station_id,
    )?;
    let announce_as_of = canonical::format_timestamp_canonical(source_ref_access.as_of);
    let mut res = TestClient::post("http://local/_arkret/find/directory/announce")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE_V1,
            true,
        )
        .json(&json!({
            "discovery_event": discovery_event,
            "source_ref_access": source_ref_access,
            "as_of": announce_as_of,
            "ttl_seconds": 3600,
        }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );

    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
            true,
        )
        .json(&json!({ "realm_id": destroyed_realm_id }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["realm_preview"]["title"], "[erased]");
    assert_eq!(body["realm_preview"]["summary"], "[erased]");
    // The public RealmPreview is closed and does not expose the private
    // tombstone object. Verify its persisted destruction marker directly.
    #[derive(diesel::QueryableByName)]
    struct DestroyedRealmRow {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        destroyed: bool,
    }
    let mut conn = db.get().await?;
    let destroyed: DestroyedRealmRow = diesel::sql_query(
        "SELECT realm_destroyed_at IS NOT NULL AS destroyed FROM directory_resources \
         WHERE resource_kind = 'realm'::resource_kind AND resource_id = $1",
    )
    .bind::<Text, _>(destroyed_realm_id)
    .get_result(&mut conn)
    .await?;
    assert!(destroyed.destroyed);
    drop(conn);

    // Path 2: resource-initiated withdraw stores a verifiable governance
    // proof receipt and blinds subsequent resolves.
    let withdraw_source_ref = "ak:event:AR8bu-n-kOOB3nRUvYuIEglCX5B-JpFaNTex9gxs_cWY";
    let withdraw_mock = FixtureStation::new(&signing_key);
    let verification_method = withdraw_mock.verification_method();
    let withdraw_station_id = withdraw_mock.station_id()?;
    seed_previously_indexed_realm(db, withdrawn_realm_id, &withdraw_station_id).await?;
    let discovery_event = signed_realm_discovery_event(
        withdrawn_realm_id,
        realm_discovery_state("Withdrawable Tea"),
        &verification_method,
        &signing_key,
        &withdraw_station_id,
    )?;
    let source_ref_access = signed_source_ref_access(
        &discovery_event,
        withdraw_source_ref,
        &verification_method,
        &signing_key,
        &withdraw_station_id,
    )?;
    let announce_as_of = canonical::format_timestamp_canonical(source_ref_access.as_of);
    let mut res = TestClient::post("http://local/_arkret/find/directory/announce")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE_V1,
            true,
        )
        .json(&json!({
            "discovery_event": discovery_event,
            "source_ref_access": source_ref_access,
            "as_of": announce_as_of,
            "ttl_seconds": 3600,
        }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );

    let withdraw_body = signed_withdraw_body(
        withdrawn_realm_id,
        &verification_method,
        &signing_key,
        "conformance resource withdraw",
    )?;
    let mut res = TestClient::post("http://local/_arkret/find/directory/withdraw")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW_V1,
            true,
        )
        .json(&withdraw_body)
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["withdrawal_ref"]
            .as_str()
            .is_some_and(|id| id.starts_with("withdrawal:"))
    );

    let res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
            true,
        )
        .json(&json!({ "realm_id": withdrawn_realm_id }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::NOT_FOUND
    );
    let resource_receipt =
        withdrawal_proof(db, "realm", withdrawn_realm_id, "resource_withdraw").await?;
    assert_eq!(
        resource_receipt.proof["receipt_version"],
        "teabay.withdrawal_receipt.v1"
    );
    assert_eq!(resource_receipt.proof["kind"], "resource_withdraw");
    assert_eq!(
        resource_receipt.proof["governance_proof"]["verification_method"],
        verification_method
    );
    assert!(
        resource_receipt.proof["governance_proof"]["jws"]
            .as_str()
            .is_some_and(|jws| !jws.is_empty())
    );
    assert_eq!(
        resource_receipt.proof["signed_payload"]["resource_id"],
        withdrawn_realm_id
    );

    // Path 3: operator takedown signs a service receipt over the full
    // takedown statement and removes the indexed row.
    let operator_resource_id = "ak:did_core:web:takedown-operator.example";
    // Both INSERT and ON CONFLICT UPDATE must advance durable freshness.
    for _ in 0..2 {
        let mut res = TestClient::post("http://local/_teabay/admin/resources")
            .add_header("authorization", "Bearer cotest-admin", true)
            .json(&json!({
                "resource_kind": "organization",
                "resource_id": operator_resource_id,
                "station_id": "ak:did_core:web:directory.test",
                "public_projection": {
                    "organization_id": operator_resource_id,
                    "name": "Operator Takedown Target"
                },
                "discoverability": "listed",
                "as_of": canonical::format_timestamp_canonical(Utc::now()),
                "source_refs": [fixture_committed_ref_json()],
                "policy_revision": "admin-takedown-r1",
                "effective_ttl_seconds": 3600,
                "via_services": ["ak:did_core:web:directory.test"]
            }))
            .send(service)
            .await;
        assert_eq!(
            res.status_code.unwrap_or(StatusCode::OK),
            StatusCode::OK,
            "{}",
            res.take_string().await.unwrap_or_default()
        );
        #[derive(diesel::QueryableByName)]
        struct FreshnessRow {
            #[diesel(sql_type = diesel::sql_types::Bool)]
            fresh: bool,
        }
        let mut conn = db.get().await?;
        let row: FreshnessRow = diesel::sql_query(
            "SELECT last_refreshed_at = indexed_at AND \
         expires_at = last_refreshed_at + effective_ttl_seconds * interval '1 second' \
         AND expires_at > now() AS fresh FROM directory_resources WHERE resource_id = $1",
        )
        .bind::<Text, _>(operator_resource_id)
        .get_result(&mut conn)
        .await?;
        assert!(
            row.fresh,
            "admin writes retain the same durable freshness invariant as accepted announces"
        );
    }

    let mut res = TestClient::post("http://local/_teabay/admin/takedown")
        .add_header("authorization", "Bearer cotest-admin", true)
        .json(&json!({
            "resource_kind": "organization",
            "resource_id": operator_resource_id,
            "reason": "conformance operator receipt",
            "operator": "cotest",
            "evidence": { "case": "three-path" }
        }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    let operator_withdraw_id = body["withdraw_id"].as_str().expect("withdraw_id");

    let res = TestClient::post("http://local/_arkret/find/directory/resolve-organization")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_ORGANIZATION_V1,
            true,
        )
        .json(&json!({ "organization_id": operator_resource_id }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::NOT_FOUND
    );
    let operator_receipt = withdrawal_proof(
        db,
        "organization",
        operator_resource_id,
        "operator_takedown",
    )
    .await?;
    assert_eq!(operator_receipt.withdraw_id, operator_withdraw_id);
    assert_eq!(operator_receipt.proof["kind"], "operator_takedown");
    assert_eq!(
        operator_receipt.proof["receipt_version"],
        "teabay.withdrawal_receipt.v1"
    );
    assert_eq!(
        operator_receipt.proof["statement"]["withdraw_id"],
        operator_withdraw_id
    );
    assert_eq!(
        operator_receipt.proof["receipt_proof"]["verification_method"],
        "did:web:directory.test#receipt-conformance"
    );
    assert!(
        operator_receipt.proof["receipt_proof"]["jws"]
            .as_str()
            .is_some_and(|jws| !jws.is_empty())
    );

    Ok(())
}

async fn withdrawal_proof(
    db: &server::Db,
    resource_kind: &str,
    resource_id: &str,
    withdrawal_kind: &str,
) -> anyhow::Result<WithdrawalProofRow> {
    let mut conn = db.get().await?;
    diesel::sql_query(
        "SELECT withdraw_id, proof FROM withdrawals \
         WHERE resource_kind = $1::resource_kind \
           AND resource_id = $2 \
           AND kind = $3::withdrawal_kind \
         ORDER BY acked_at DESC \
         LIMIT 1",
    )
    .bind::<Text, _>(resource_kind)
    .bind::<Text, _>(resource_id)
    .bind::<Text, _>(withdrawal_kind)
    .get_result(&mut conn)
    .await
    .map_err(Into::into)
}

async fn assert_admin_operator_surface(service: &Service) -> anyhow::Result<()> {
    let managed_resource_id = "ak:did_core:web:admin-managed.example";

    let res = TestClient::get("http://local/_teabay/admin/resources?limit=5")
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::UNAUTHORIZED
    );

    let mut res = TestClient::get("http://local/_teabay/admin/resources?resource_kind=realm&divergent=false&stale=false&limit=10")
        .add_header("authorization", "Bearer cotest-admin", true)
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["items"]
            .as_array()
            .is_some_and(|items| items.len() >= 3)
    );

    let mut res = TestClient::post("http://local/_teabay/admin/allowlist")
        .add_header("authorization", "Bearer cotest-admin", true)
        .json(&json!({
            "resource_did": "did:web:principal.test",
            "added_by": "ak:did_core:web:cotest.example",
            "note": "conformance"
        }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["item"]["resource_did"], "did:web:principal.test");

    let mut res = TestClient::get("http://local/_teabay/admin/allowlist?limit=10")
        .add_header("authorization", "Bearer cotest-admin", true)
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["items"][0]["resource_did"], "did:web:principal.test");

    let mut res = TestClient::post("http://local/_teabay/admin/resources")
        .add_header("authorization", "Bearer cotest-admin", true)
        .json(&json!({
            "resource_kind": "organization",
            "resource_id": managed_resource_id,
            "station_id": "ak:did_core:web:directory.test",
            "public_projection": {
                "organization_id": managed_resource_id,
                "name": "Admin Managed Directory Row",
                "summary": "Inserted through the admin data manager"
            },
            "discoverability": "listed",
            "as_of": canonical::format_timestamp_canonical(Utc::now()),
            "source_refs": [fixture_committed_ref_json()],
            "policy_revision": "admin-r1",
            "effective_ttl_seconds": 3600,
            "via_services": ["ak:did_core:web:directory.test"]
        }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["item"]["resource_id"], managed_resource_id);
    assert_eq!(body["item"]["policy_revision"], "admin-r1");

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-organizations")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ORGANIZATIONS_V1,
            true,
        )
        .json(&json!({ "query": "Admin Managed", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["organizations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["organization_id"] == managed_resource_id)
    );

    let mut res = TestClient::post("http://local/_teabay/admin/takedown")
        .add_header("authorization", "Bearer cotest-admin", true)
        .json(&json!({
            "resource_kind": "handle",
            "resource_id": "alice:example.com",
            "reason": "conformance operator takedown",
            "operator": "cotest",
            "evidence": { "case": "M8" }
        }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["withdraw_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("withdrawal:"))
    );

    let res = TestClient::post("http://local/_arkret/find/directory/resolve-handle")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_HANDLE_V1,
            true,
        )
        .json(&json!({ "handle": "alice:example.com" }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::NOT_FOUND
    );

    let mut res = TestClient::delete(
        "http://local/_teabay/admin/allowlist?resource_did=did:web:principal.test",
    )
    .add_header("authorization", "Bearer cotest-admin", true)
    .send(service)
    .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["deleted"], 1);

    let mut res = TestClient::delete(
        "http://local/_teabay/admin/resources?resource_kind=organization&resource_id=ak:did_core:web:admin-managed.example",
    )
    .add_header("authorization", "Bearer cotest-admin", true)
    .send(service)
    .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["deleted"], 1);

    let mut res = TestClient::get(
        "http://local/_teabay/admin/resources?resource_kind=organization&q=admin-managed&limit=10",
    )
    .add_header("authorization", "Bearer cotest-admin", true)
    .send(service)
    .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);

    let mut res = TestClient::get("http://local/_teabay/admin/audit?limit=50")
        .add_header("authorization", "Bearer cotest-admin", true)
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::OK,
        "{}",
        res.take_string().await.unwrap_or_default()
    );
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == "allowlist_added")
    );
    assert!(
        body["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == "admin_resource_upserted")
    );
    assert!(
        body["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == "admin_resource_deleted")
    );
    assert!(
        body["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == "operator_takedown"
                && event["detail"]["withdraw_id"].as_str().is_some()
                && event["actor_id"].is_null()
                && event["authenticated_credential_id"] == "admin:static-bearer"
                && event["asserted_operator_localpart"] == "cotest"
                && event["authentication_method"] == "static_bearer"),
        "operator audit must separate authenticated credential from an unverified byline: {body}"
    );
    Ok(())
}

// This fixture proves governance-key ownership only. It intentionally has no
// peer ServiceResolutionCarrier or network endpoint, so it cannot prove first ingest.
struct FixtureStation {
    multibase: String,
}

impl FixtureStation {
    fn new(signing_key: &SigningKey) -> Self {
        Self {
            multibase: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                signing_key.verifying_key().as_bytes(),
            ),
        }
    }

    fn station_id(&self) -> anyhow::Result<String> {
        let did = Did::new(format!("did:key:{}", self.multibase))?;
        Ok(arkret_sdk::project_did_to_core_id(&did)?.to_string())
    }

    fn verification_method(&self) -> String {
        format!("did:key:{0}#{0}", self.multibase)
    }
}

pub(crate) fn realm_discovery_state(name: &str) -> JsonValue {
    json!({
        "kind": "ak.realm.discovery",
        "discoverability": "public",
        "directory_ids": ["ak:did_core:web:directory.test"],
        "name": name,
        "summary": "Previously indexed resource refreshed by a verified governance key",
        "member_count": 42,
    })
}

pub(crate) fn signed_realm_discovery_event(
    realm_id: &str,
    discovery_state: JsonValue,
    verification_method: &str,
    signing_key: &SigningKey,
    station_id: &str,
) -> anyhow::Result<JsonValue> {
    let realm_id = RealmId::new(realm_id.to_owned())?;
    let signer_did = Did::new(
        verification_method
            .split_once('#')
            .map_or(verification_method, |(did, _)| did)
            .to_owned(),
    )?;
    let actor_id = arkret_sdk::project_did_to_core_id(&signer_did)?;
    let station_id = DidCoreId::new(station_id.to_owned())?;
    let mut event = arkret_wire::test_support::raw_event(
        "ak.realm.discovery",
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id,
        station_id,
        json!({"value": discovery_state}),
    )?;
    event
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    let builder = EventProofBuilder::new();
    let event_digest = Hash::new(arkret_canonical::canonical::sha256_digest(
        &builder.envelope_bytes(&event)?,
    ))?;
    let mut proof = ProducerEventProof {
        kind: "detached_jws".to_owned(),
        verification_method: arkret_sdk::DidUrl::new(verification_method.to_owned())
            .map_err(anyhow::Error::msg)?,
        event_digest,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    let binding = proof.canonical_binding_bytes(&event.actor_id)?;
    proof.jws = sign_jws_ed25519(&binding, signing_key).map_err(anyhow::Error::msg)?;
    event.producer_proof = Some(proof);
    Ok(serde_json::to_value(event)?)
}

fn committed_ref_for(
    realm_id: arkret_wire::RealmId,
    event_id: arkret_wire::EventId,
    stream_position: u64,
) -> arkret_wire::CommittedEventRef {
    let commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        format!("{}:{stream_position}", event_id.as_str()).as_bytes(),
    ));
    arkret_wire::CommittedEventRef {
        event_id,
        commit_id,
        stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id },
        stream_position,
    }
}

fn signed_source_ref_access(
    discovery_event: &JsonValue,
    additional_event_id: &str,
    verification_method: &str,
    signing_key: &SigningKey,
    station_id: &str,
) -> anyhow::Result<arkret_wire::DirectorySourceRefAccess> {
    let event: arkret_wire::Event = serde_json::from_value(discovery_event.clone())?;
    let mut source_refs = vec![
        committed_ref_for(event.realm_id.clone(), event.event_id.clone(), 0),
        committed_ref_for(
            event.realm_id.clone(),
            arkret_wire::EventId::new(additional_event_id.to_owned())?,
            1,
        ),
    ];
    source_refs.sort();
    source_refs.dedup();
    let as_of = chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
        .expect("current time is representable");
    let mut access = arkret_wire::DirectorySourceRefAccess {
        kind: arkret_wire::DirectorySourceRefAccessKind::DirectoryAnnounce,
        source_id: DidCoreId::new(station_id.to_owned())?,
        directory_id: DidCoreId::new("ak:did_core:web:directory.test")?,
        realm_id: event.realm_id,
        discovery_event_id: event.event_id,
        source_refs,
        as_of,
        expires_at: as_of + ChronoDuration::minutes(5),
        proof: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(verification_method.to_owned())
                .map_err(anyhow::Error::msg)?,
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: as_of,
            domain: Some("arkret-event-v1".to_owned()),
            audience: Some(arkret_wire::Audience::Single(
                "ak:did_core:web:directory.test".to_owned(),
            )),
            proof_purpose: None,
            jws: "e30..c2ln".to_owned(),
        },
    };
    access.proof.payload_digest = access.payload_digest()?;
    access.proof.jws = sign_jws_ed25519(&access.proof_binding_bytes()?, signing_key)
        .map_err(anyhow::Error::msg)?;
    Ok(access)
}

fn fixture_committed_ref_json() -> JsonValue {
    serde_json::to_value(committed_ref_for(
        RealmId::new("ak:realm:ASsKHIftKaTemZcyvFWmoYnCtQNN_4deE04hdIPA0PPu").unwrap(),
        arkret_wire::EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap(),
        0,
    ))
    .expect("fixture committed ref serializes")
}

#[derive(serde::Serialize)]
struct DirectoryRestrictedClaimPresentationSigningPayload<'a> {
    kind: &'a str,
    issuer_id: &'a DidCoreId,
    verification_method: &'a str,
    audience_id: &'a DidCoreId,
    nonce: &'a str,
    claim: &'a DirectoryPresentedClaim,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
}

fn signed_restricted_claim_presentation(
    signing_key: &SigningKey,
    issuer_id: DidCoreId,
    verification_method: arkret_wire::DidUrl,
    audience_id: &str,
    nonce: &str,
    claim: DirectoryPresentedClaim,
) -> anyhow::Result<DirectoryRestrictedClaimPresentation> {
    let audience_id = DidCoreId::new(audience_id.to_owned())?;
    // The SDK serializes this wire timestamp at millisecond precision; sign
    // exactly the value the receiver will deserialize, not hidden nanoseconds.
    let created_at = chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
        .expect("current time is representable");
    let expires_at = Some(created_at + ChronoDuration::minutes(5));
    let payload = DirectoryRestrictedClaimPresentationSigningPayload {
        kind: DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND,
        issuer_id: &issuer_id,
        verification_method: &verification_method,
        audience_id: &audience_id,
        nonce,
        claim: &claim,
        expires_at,
        created_at,
    };
    let canonical = canonical::canonical_json_bytes(&payload)?;
    let jws = sign_jws_ed25519(&canonical, signing_key).map_err(anyhow::Error::msg)?;
    Ok(DirectoryRestrictedClaimPresentation {
        kind: DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND.to_owned(),
        issuer_id,
        verification_method,
        audience_id,
        nonce: nonce.to_owned(),
        claim,
        expires_at,
        created_at,
        jws,
    })
}

/// §8.7.1: the signed transcript is the canonical binding object built by the
/// SDK helper, not the request body. `payload_digest` covers the request
/// without the top-level `governance_proof` member, `audience_id` names this
/// directory's `service_id`, `proof_purpose` is `governance_authorization`,
/// and `created_at` must sit inside the 300-second freshness window.
fn signed_withdraw_body(
    resource_id: &str,
    verification_method: &str,
    signing_key: &SigningKey,
    reason: &str,
) -> anyhow::Result<JsonValue> {
    let mut body = arkret_sdk::DirectoryWithdrawRequestBody {
        resource_id: serde_json::from_value(json!(resource_id))?,
        governance_proof: arkret_sdk::DirectoryGovernanceProof {
            kind: "detached_jws".to_owned(),
            verification_method: arkret_sdk::DidUrl::new(verification_method.to_owned())
                .map_err(|error| anyhow::anyhow!("verification method: {error}"))?,
            payload_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64)))
                .map_err(|error| anyhow::anyhow!("digest: {error}"))?,
            created_at: Utc::now(),
            proof_purpose: arkret_sdk::DirectoryGovernanceProofPurpose::GovernanceAuthorization,
            audience_id: arkret_sdk::DidCoreId::new("ak:did_core:web:directory.test".to_owned())
                .map_err(|error| anyhow::anyhow!("audience: {error}"))?,
            jws: "pending".to_owned(),
        },
        reason: Some(
            arkret_wire::AuditReasonText::new(reason.to_owned()).map_err(anyhow::Error::msg)?,
        ),
        effective_at: None,
    };
    body.governance_proof.payload_digest = body
        .payload_digest()
        .map_err(|error| anyhow::anyhow!("payload digest: {error}"))?;
    let transcript = body
        .proof_binding_bytes()
        .map_err(|error| anyhow::anyhow!("binding bytes: {error}"))?;
    body.governance_proof.jws =
        sign_jws_ed25519(&transcript, signing_key).map_err(anyhow::Error::msg)?;
    Ok(serde_json::to_value(&body)?)
}
