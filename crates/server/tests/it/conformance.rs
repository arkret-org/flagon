use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use arkret_sdk::jws::sign_jws_ed25519;
use arkret_sdk::{
    DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND, Did, DirectoryPresentedClaim,
    DirectoryRestrictedClaimPresentation, PresentedClaim, canonical,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration as ChronoDuration, Utc};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::prelude::Service;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value as JsonValue, json};
use testcontainers_modules::postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::SyncRunner;
use voprf::{EvaluationElement, Group, Proof, Ristretto255, VoprfClient};

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(diesel::QueryableByName)]
struct WithdrawalProofRow {
    #[diesel(sql_type = Text)]
    withdraw_id: String,
    #[diesel(sql_type = Jsonb)]
    proof: JsonValue,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_query_and_psi_conformance_smoke() -> anyhow::Result<()> {
    if std::env::var("TEABAY_RUN_DOCKER_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping docker-backed conformance smoke; set TEABAY_RUN_DOCKER_TESTS=1");
        return Ok(());
    }

    let postgres_tag =
        std::env::var("TEABAY_TEST_POSTGRES_TAG").unwrap_or_else(|_| "16-alpine".to_string());
    let container = postgres::Postgres::default()
        .with_tag(postgres_tag)
        .start()?;
    let database_url = format!(
        "postgres://postgres:postgres@{}:{}/postgres",
        container.get_host()?,
        container.get_host_port_ipv4(5432)?
    );

    unsafe {
        std::env::set_var("TEABAY_BIND", "127.0.0.1:0");
        std::env::set_var("TEABAY_PUBLIC_BASE_URL", "http://directory.test");
        std::env::set_var("TEABAY_SERVICE_ID", "did:web:directory.test");
        std::env::set_var("DATABASE_URL", &database_url);
        std::env::set_var("TEABAY_PRIVATE_CONTACT_DISCOVERY_ENABLED", "true");
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
        std::env::set_var("TEABAY_QUERY_LATENCY_FLOOR_MS", "0");
        std::env::set_var("TEABAY_QUERY_LATENCY_JITTER_MS", "0");
        std::env::set_var("TEABAY_PULL_INTERVAL_SECONDS", "300");
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

    let service = server::service(server::AppState::new(config.clone(), db.clone()));
    assert_describe_advertises_core_and_psi(&service).await?;
    assert_query_surface_matrix(&db, &service).await?;
    assert_search_realms_finds_seeded_realm(&service).await?;
    assert_official_badge_is_verified_relationship_driven(&db, &service).await?;
    assert_pull_subscribe_registers_webhook(&service).await?;
    assert_push_announce_uses_mock_principal_server(&service).await?;
    assert_pull_worker_refreshes_due_entry(&config, &db, &service).await?;
    assert_freshness_flags_are_exposed(&db, &service).await?;
    assert_psi_blind_and_match_finds_seeded_handle(&service).await?;
    assert_three_path_takedown_strand(&db, &service).await?;
    assert_admin_operator_surface(&service).await?;
    Ok(())
}

async fn seed_directory_fixture(db: &server::Db) -> anyhow::Result<()> {
    let mut conn = db.get().await?;
    diesel::sql_query(teabay_testing::DIRECTORY_FIXTURE_SQL)
        .execute(&mut conn)
        .await?;
    // TBY-ORG-04 — verified relationship index rows reference the realm rows
    // seeded above, so they must be applied after the directory fixture.
    diesel::sql_query(teabay_testing::VERIFIED_REALM_ORGANIZATIONS_FIXTURE_SQL)
        .execute(&mut conn)
        .await?;
    Ok(())
}

async fn install_restricted_realm_claim_selector(
    db: &server::Db,
    issuer: &str,
    organization: &str,
) -> anyhow::Result<()> {
    let mut conn = db.get().await?;
    let discoverers = json!([{
        "type": "claim",
        "claim_type": "organization_membership",
        "issuer": issuer,
        "organization": organization
    }]);
    diesel::sql_query(
        "UPDATE directory_resources \
         SET public_projection = jsonb_set(public_projection, '{allowed_discoverers}', $1::jsonb, true) \
         WHERE resource_kind = 'realm'::resource_kind AND resource_id = 'ak.realm:restricted'",
    )
    .bind::<Jsonb, _>(discoverers)
    .execute(&mut conn)
    .await?;
    Ok(())
}

async fn assert_describe_advertises_core_and_psi(service: &Service) -> anyhow::Result<()> {
    let mut res = TestClient::get("http://local/_arkret/find/directory/describe")
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    let profiles = body["supported_profiles"].as_array().unwrap();
    assert!(profiles.contains(&json!("ak.profile.directory_service.v1")));
    assert!(profiles.contains(&json!("ak.private_contact_discovery.v1")));
    let discovery_profiles = body["discovery_profiles"].as_array().unwrap();
    assert!(discovery_profiles.contains(&json!("ak.profile.directory_service.v1")));
    assert!(discovery_profiles.contains(&json!("ak.private_contact_discovery.v1")));
    assert_eq!(body["service_id"], "did:web:directory.test");
    assert_eq!(body["service_type"], "directory_service");
    assert!(
        body["accepted_resource_kinds"]
            .as_array()
            .unwrap()
            .contains(&json!("realm"))
    );
    assert!(
        body["ingest_modes"]
            .as_array()
            .unwrap()
            .contains(&json!("push"))
    );
    assert!(
        body["ingest_modes"]
            .as_array()
            .unwrap()
            .contains(&json!("pull"))
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
        .json(&json!({ "query": "tea", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["realms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["realm_id"] == "ak:realm:tea")
    );
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
            .json(&json!({ "realm_id": realm_id }))
            .send(service)
            .await;
        assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
        let body: JsonValue = res.take_json().await.expect("resolve-realm body");
        body["realm_preview"]["owning_organizations"]
            .as_array()
            .map(|orgs| {
                orgs.iter()
                    .filter_map(|o| o.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    // (1) active owner relationship ⇒ verified owning organization surfaces.
    let verified = resolve_owning_orgs(service, "ak:realm:org-verified").await;
    assert_eq!(
        verified,
        vec!["did:web:tea-org.example".to_owned()],
        "active owner ak.realm.organization MUST surface verified owning org"
    );

    // (2) declared-only org hint (no statement) ⇒ no verified owning org.
    let declared_only = resolve_owning_orgs(service, "ak:realm:org-declared-only").await;
    assert!(
        declared_only.is_empty(),
        "declared owning_organizations / organization_did hint MUST NOT yield a verified badge"
    );

    // (3) relationship mismatch: sponsor is NOT owner/governance ⇒ no owning org.
    let sponsor_only = resolve_owning_orgs(service, "ak:realm:tea").await;
    assert!(
        sponsor_only.is_empty(),
        "sponsor relationship MUST NOT be usable as a verified owner/governance badge"
    );

    // (4) revoke (delete the verified row) ⇒ badge disappears after refresh.
    {
        let mut conn = db.get().await?;
        diesel::sql_query(
            "DELETE FROM verified_realm_organizations \
             WHERE realm_id = 'ak.realm:org-verified'",
        )
        .execute(&mut conn)
        .await?;
    }
    let after_revoke = resolve_owning_orgs(service, "ak:realm:org-verified").await;
    assert!(
        after_revoke.is_empty(),
        "revoking the ak.realm.organization statement MUST remove the verified badge"
    );

    // (5) expired relationship ⇒ not surfaced even before purge.
    {
        let mut conn = db.get().await?;
        diesel::sql_query(
            "INSERT INTO verified_realm_organizations \
               (realm_id, organization_did, relationship, control_scopes, statement_id, \
                statement_issued_at, not_before, expires_at, realm_frontier_digest, stale, \
                verified_at, source_announce_id) \
             VALUES ('ak.realm:org-verified', 'did:web:tea-org.example', 'owner', \
                     ARRAY['official_badge'], 'org-stmt-expired', now() - interval '2 hours', \
                     NULL, now() - interval '1 hour', NULL, false, now(), 'ak.announce:expired')",
        )
        .execute(&mut conn)
        .await?;
    }
    let after_expiry = resolve_owning_orgs(service, "ak:realm:org-verified").await;
    assert!(
        after_expiry.is_empty(),
        "expired ak.realm.organization statement MUST NOT surface a verified badge"
    );

    Ok(())
}

async fn assert_query_surface_matrix(db: &server::Db, service: &Service) -> anyhow::Result<()> {
    let mut res = TestClient::post("http://local/_arkret/find/directory/search-realms")
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
        first["join_candidates"]
            .as_array()
            .is_some_and(|refs| !refs.is_empty())
    );
    let cursor = body["next_cursor"]
        .as_str()
        .unwrap_or_else(|| panic!("expected next_cursor for first search page: {body}"));

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-realms")
        .json(&json!({ "query": "tea", "limit": 1, "cursor": cursor }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["realms"].as_array().unwrap().len(), 1);

    let res = TestClient::post("http://local/_arkret/find/directory/search-realms")
        .json(&json!({ "cursor": "not-base64" }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::BAD_REQUEST
    );

    assert_resolve_realm_status(service, "ak:realm:tea", StatusCode::OK, json!({})).await?;
    assert_resolve_realm_status(service, "ak:realm:secret", StatusCode::NOT_FOUND, json!({}))
        .await?;
    assert_resolve_realm_status(
        service,
        "ak:realm:restricted",
        StatusCode::NOT_FOUND,
        json!({}),
    )
    .await?;

    let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
    let multibase = did_key_multibase(&signing_key);
    let issuer = Did::new(format!("did:key:{multibase}"))?;
    let verification_method = format!("{}#{multibase}", issuer.as_str());
    let subject = Did::new("did:web:alice.example".to_owned())?;
    let organization = Did::new("did:web:tea-org.example".to_owned())?;
    install_restricted_realm_claim_selector(db, issuer.as_str(), organization.as_str()).await?;
    let proof_challenge = "realm-restricted-proof-challenge-1";
    let claim = PresentedClaim::organization_membership(
        "claim-realm-restricted",
        subject.clone(),
        issuer.clone(),
        organization,
        vec!["member".to_owned()],
    );
    let presentation = signed_restricted_claim_presentation(
        &signing_key,
        issuer,
        verification_method,
        "did:web:directory.test",
        proof_challenge,
        claim,
    )?;
    let presentation_json = serde_json::to_value(&presentation)?;

    assert_resolve_realm_status(
        service,
        "ak:realm:restricted",
        StatusCode::NOT_FOUND,
        json!({
            "requester": subject.as_str(),
            "proof_challenge": "wrong-challenge",
            "claim_presentations": [presentation_json.clone()]
        }),
    )
    .await?;
    assert_resolve_realm_status(
        service,
        "ak:realm:restricted",
        StatusCode::OK,
        json!({
            "requester": subject.as_str(),
            "proof_challenge": proof_challenge,
            "claim_presentations": [presentation_json.clone()]
        }),
    )
    .await?;

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-realms")
        .json(&json!({
            "query": "Restricted",
            "requester": subject.as_str(),
            "proof_challenge": proof_challenge,
            "claim_presentations": [presentation_json],
            "limit": 10
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["realms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["realm_id"] == "ak:realm:restricted")
    );

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-organizations")
        .json(&json!({ "query": "tea", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(
        body["organizations"][0]["organization_did"],
        "did:web:tea-org.example"
    );

    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-organization")
        .json(&json!({ "organization_did": "did:web:tea-org.example" }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["organization_did"], "did:web:tea-org.example");

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-actors")
        .json(&json!({ "query": "alice", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["actors"][0]["actor_id"], "did:web:alice.example");

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-users")
        .json(&json!({
            "query": "alice",
            "requester": "did:web:alice.example",
            "realm_id": "ak:realm:tea",
            "limit": 10
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["users"][0]["actor_id"], "did:web:alice.example");

    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-handle")
        .json(&json!({ "handle": "alice.example" }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["did"], "did:web:alice.example");
    assert!(body.get("as_of").is_some());
    assert!(
        body["source_refs"]
            .as_array()
            .is_some_and(|refs| !refs.is_empty())
    );
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
    let res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .json(&body)
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), expected);
    Ok(())
}

async fn assert_psi_blind_and_match_finds_seeded_handle(service: &Service) -> anyhow::Result<()> {
    let mut rng = rand::rngs::OsRng;
    let blind = VoprfClient::<Ristretto255>::blind(b"alice.example", &mut rng)?;
    let blinded_input = URL_SAFE_NO_PAD.encode(blind.message.serialize());

    let mut res = TestClient::post("http://local/_arkret/find/directory/private-contact-discovery")
        .json(&json!({
            "phase": "blind",
            "requester": "did:web:requester.test",
            "blinded_inputs": [blinded_input],
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    let evaluation = decode_evaluation(body["evaluations"][0].as_str().unwrap())?;
    let proof = decode_proof(body["proofs"][0].as_str().unwrap())?;
    let public_key = decode_public_key(body["server_public_key"].as_str().unwrap())?;
    let token = blind
        .state
        .finalize(b"alice.example", &evaluation, &proof, public_key)?;
    let token = URL_SAFE_NO_PAD.encode(token);

    let mut res = TestClient::post("http://local/_arkret/find/directory/private-contact-discovery")
        .json(&json!({
            "phase": "match",
            "requester": "did:web:requester.test",
            "epoch": body["epoch"].as_str().unwrap(),
            "query_id": body["query_id"].as_str().unwrap(),
            "match_tokens": [token],
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["hit_bitmap"].as_array().unwrap().len(), 256);
    assert_eq!(body["hit_bitmap"][0], true);
    Ok(())
}

async fn assert_push_announce_uses_mock_principal_server(service: &Service) -> anyhow::Result<()> {
    let mock = MockPrincipalServer::spawn("evt-announce-realm")?;
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let public_key = did_key_multibase(&signing_key);
    let signer_did = format!("did:key:{public_key}");
    let verification_method = format!("{signer_did}#{public_key}");
    let discovery_state = signed_realm_discovery_state(&verification_method, &signing_key)?;

    let mut res = TestClient::post("http://local/_arkret/find/directory/announce")
        .json(&json!({
            "resource_kind": "realm",
            "resource_id": "ak:realm:pushed",
            "principal_server_did": mock.principal_server_did(),
            "discovery_state": discovery_state,
            "source_refs": ["evt-announce-realm"],
            "as_of": Utc::now(),
            "policy_revision": "rev-pushed-1",
            "ttl_seconds": 3600,
        }))
        .send(service)
        .await;
    let status = res.status_code.unwrap_or(StatusCode::OK);
    if status != StatusCode::OK {
        let body = res.take_string().await.unwrap_or_default();
        panic!("announce with mock Principal Server failed with {status}: {body}");
    }
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["announce_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("ak:announce:"))
    );

    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .json(&json!({ "realm_id": "ak:realm:pushed" }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["realm_id"], "ak:realm:pushed");
    assert_eq!(body["member_count_bucket"], "11-50");
    assert_eq!(body["source_refs"][0], "evt-announce-realm");
    assert_eq!(
        body["join_candidates"][0]["service_id"],
        mock.principal_server_did()
    );
    Ok(())
}

async fn assert_pull_subscribe_registers_webhook(service: &Service) -> anyhow::Result<()> {
    let secret = URL_SAFE_NO_PAD.encode([1_u8; 16]);
    let mut res = TestClient::post("http://local/_arkret/find/directory/push/register")
        .json(&json!({
            "subscriber_did": "did:web:subscriber.example",
            "resource_filter": {
                "resource_kinds": ["realm"],
                "resource_ids": ["ak:realm:pushed"]
            },
            "webhook_endpoint": "http://127.0.0.1:9/teabay-conformance-webhook",
            "secret": secret
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["subscription_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("teabay:subscription:"))
    );
    assert!(body.get("effective_at").is_some());
    assert!(body.get("created_at").is_none());
    assert!(body.get("expires_at").is_none());
    assert!(body.get("webhook_secret").is_none());
    Ok(())
}

async fn assert_pull_worker_refreshes_due_entry(
    config: &server::AppConfig,
    db: &server::Db,
    service: &Service,
) -> anyhow::Result<()> {
    let signing_key = SigningKey::from_bytes(&[9; 32]);
    let public_key = did_key_multibase(&signing_key);
    let signer_did = format!("did:key:{public_key}");
    let verification_method = format!("{signer_did}#{public_key}");
    let pulled_state =
        signed_realm_discovery_state_named(&verification_method, &signing_key, "Pulled Tea")?;
    let mock =
        MockPrincipalServer::spawn_with_discovery_state("evt-pull-realm", pulled_state.clone())?;

    let mut res = TestClient::post("http://local/_arkret/find/directory/announce")
        .json(&json!({
            "resource_kind": "realm",
            "resource_id": "ak:realm:pull",
            "principal_server_did": mock.principal_server_did(),
            "discovery_state": pulled_state,
            "source_refs": ["evt-pull-realm"],
            "as_of": Utc::now(),
            "policy_revision": "rev-pushed-1",
            "ttl_seconds": 3600,
        }))
        .send(service)
        .await;
    let status = res.status_code.unwrap_or(StatusCode::OK);
    if status != StatusCode::OK {
        let body = res.take_string().await.unwrap_or_default();
        panic!("seed pull resource announce failed with {status}: {body}");
    }

    {
        let mut conn = db.get().await?;
        diesel::sql_query(
            "UPDATE directory_resources \
             SET next_revalidation_after = now() - interval '1 second' \
             WHERE resource_kind = 'realm'::resource_kind AND resource_id = 'ak.realm:pull'",
        )
        .execute(&mut conn)
        .await?;
    }

    let worker_state = server::AppState::new(config.clone(), db.clone());
    server::ingest::pull_worker::PullWorker::new(worker_state, Duration::from_millis(1))?
        .run_once_for_tests()
        .await?;

    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .json(&json!({ "realm_id": "ak:realm:pull" }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["name"], "Pulled Tea");

    let mut conn = db.get().await?;
    let pull_count: i64 = diesel::sql_query(
        "SELECT count(*) FROM ingest_announces \
         WHERE resource_kind = 'realm'::resource_kind \
           AND resource_id = 'ak.realm:pull' \
           AND ingest_mode = 'pull'::ingest_mode",
    )
    .get_result::<CountRow>(&mut conn)
    .await?
    .count;
    assert_eq!(pull_count, 1);
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
             WHERE resource_kind = 'realm'::resource_kind AND resource_id = 'ak.realm:tea'",
        )
        .execute(&mut conn)
        .await?;
    }
    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .json(&json!({ "realm_id": "ak:realm:tea" }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["stale"], true);
    Ok(())
}

async fn assert_three_path_takedown_strand(
    db: &server::Db,
    service: &Service,
) -> anyhow::Result<()> {
    let signing_key = SigningKey::from_bytes(&[14; 32]);
    let public_key = did_key_multibase(&signing_key);
    let signer_did = format!("did:key:{public_key}");
    let verification_method = format!("{signer_did}#{public_key}");

    // Path 1: resource state-change (`ak.realm.destroy`) collapses the
    // indexed Realm into a tombstone projection.
    let mut destroyed_state =
        signed_realm_discovery_state_named(&verification_method, &signing_key, "Destroyable Tea")?;
    destroyed_state["terminal_state"] = JsonValue::String("destroyed".to_owned());
    destroyed_state["as_of_destroyed"] = json!(Utc::now());
    destroyed_state["proof"]["jws"] = JsonValue::String(String::new());
    destroyed_state["proof"]["jws"] =
        JsonValue::String(sign_detached_jws(&destroyed_state, &signing_key)?);
    let destroy_mock = MockPrincipalServer::spawn("evt-destroy-realm")?;
    let res = TestClient::post("http://local/_arkret/find/directory/announce")
        .json(&json!({
            "resource_kind": "realm",
            "resource_id": "ak:realm:takedown-state",
            "principal_server_did": destroy_mock.principal_server_did(),
            "discovery_state": destroyed_state,
            "source_refs": ["evt-destroy-realm"],
            "as_of": Utc::now(),
            "policy_revision": "rev-pushed-1",
            "ttl_seconds": 3600,
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);

    let mut res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .json(&json!({ "realm_id": "ak:realm:takedown-state" }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["title"], "[erased]");
    assert_eq!(body["tombstone"]["kind"], "realm_destroyed");

    // Path 2: resource-initiated withdraw stores a verifiable governance
    // proof receipt and blinds subsequent resolves.
    let withdraw_mock = MockPrincipalServer::spawn("evt-withdraw-realm")?;
    let withdraw_state =
        signed_realm_discovery_state_named(&verification_method, &signing_key, "Withdrawable Tea")?;
    let res = TestClient::post("http://local/_arkret/find/directory/announce")
        .json(&json!({
            "resource_kind": "realm",
            "resource_id": "ak:realm:takedown-withdraw",
            "principal_server_did": withdraw_mock.principal_server_did(),
            "discovery_state": withdraw_state,
            "source_refs": ["evt-withdraw-realm"],
            "as_of": Utc::now(),
            "policy_revision": "rev-pushed-1",
            "ttl_seconds": 3600,
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);

    let withdraw_body = signed_withdraw_body(
        "realm",
        "ak:realm:takedown-withdraw",
        &verification_method,
        &signing_key,
        "conformance resource withdraw",
    )?;
    let mut res = TestClient::post("http://local/_arkret/find/directory/withdraw")
        .json(&withdraw_body)
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["withdrawal_ref"]
            .as_str()
            .is_some_and(|id| id.starts_with("teabay:withdraw:"))
    );

    let res = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .json(&json!({ "realm_id": "ak:realm:takedown-withdraw" }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::NOT_FOUND
    );
    let resource_receipt = withdrawal_proof(
        db,
        "realm",
        "ak:realm:takedown-withdraw",
        "resource_withdraw",
    )
    .await?;
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
        "ak:realm:takedown-withdraw"
    );

    // Path 3: operator takedown signs a service receipt over the full
    // takedown statement and removes the indexed row.
    let operator_resource_id = "did:web:takedown-operator.example";
    let res = TestClient::post("http://local/_teabay/admin/resources")
        .add_header("authorization", "Bearer cotest-admin", true)
        .json(&json!({
            "resource_kind": "organization",
            "resource_id": operator_resource_id,
            "principal_server_did": "did:web:directory.test",
            "public_projection": {
                "organization_did": operator_resource_id,
                "name": "Operator Takedown Target"
            },
            "discoverability": "listed",
            "as_of": Utc::now(),
            "source_refs": ["admin:takedown-target"],
            "policy_revision": "admin-takedown-r1",
            "effective_ttl_seconds": 3600,
            "via_services": ["did:web:directory.test"]
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);

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
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    let operator_withdraw_id = body["withdraw_id"].as_str().expect("withdraw_id");

    let res = TestClient::post("http://local/_arkret/find/directory/resolve-organization")
        .json(&json!({ "organization_did": operator_resource_id }))
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
    let managed_resource_id = "did:web:admin-managed.example";

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
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
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
            "added_by": "cotest",
            "note": "conformance"
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["item"]["resource_did"], "did:web:principal.test");

    let mut res = TestClient::get("http://local/_teabay/admin/allowlist?limit=10")
        .add_header("authorization", "Bearer cotest-admin", true)
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["items"][0]["resource_did"], "did:web:principal.test");

    let mut res = TestClient::post("http://local/_teabay/admin/resources")
        .add_header("authorization", "Bearer cotest-admin", true)
        .json(&json!({
            "resource_kind": "organization",
            "resource_id": managed_resource_id,
            "principal_server_did": "did:web:directory.test",
            "public_projection": {
                "organization_did": managed_resource_id,
                "name": "Admin Managed Directory Row",
                "summary": "Inserted through the admin data manager"
            },
            "discoverability": "listed",
            "as_of": Utc::now(),
            "source_refs": ["admin:test"],
            "policy_revision": "admin-r1",
            "effective_ttl_seconds": 3600,
            "via_services": ["did:web:directory.test"]
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["item"]["resource_id"], managed_resource_id);
    assert_eq!(body["item"]["policy_revision"], "admin-r1");

    let mut res = TestClient::post("http://local/_arkret/find/directory/search-organizations")
        .json(&json!({ "query": "Admin Managed", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["organizations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["organization_did"] == managed_resource_id)
    );

    let mut res = TestClient::post("http://local/_teabay/admin/takedown")
        .add_header("authorization", "Bearer cotest-admin", true)
        .json(&json!({
            "resource_kind": "handle",
            "resource_id": "alice.example",
            "reason": "conformance operator takedown",
            "operator": "cotest",
            "evidence": { "case": "M8" }
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["withdraw_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("teabay:withdraw:"))
    );

    let res = TestClient::post("http://local/_arkret/find/directory/resolve-handle")
        .json(&json!({ "handle": "alice.example" }))
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
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["deleted"], 1);

    let mut res = TestClient::delete(
        "http://local/_teabay/admin/resources?resource_kind=organization&resource_id=did:web:admin-managed.example",
    )
    .add_header("authorization", "Bearer cotest-admin", true)
    .send(service)
    .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["deleted"], 1);

    let mut res = TestClient::get(
        "http://local/_teabay/admin/resources?resource_kind=organization&q=admin-managed&limit=10",
    )
    .add_header("authorization", "Bearer cotest-admin", true)
    .send(service)
    .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);

    let mut res = TestClient::get("http://local/_teabay/admin/audit?limit=50")
        .add_header("authorization", "Bearer cotest-admin", true)
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
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
                && event["detail"]["withdraw_id"].as_str().is_some())
    );
    Ok(())
}

fn decode_evaluation(raw: &str) -> anyhow::Result<EvaluationElement<Ristretto255>> {
    let bytes = URL_SAFE_NO_PAD.decode(raw)?;
    EvaluationElement::<Ristretto255>::deserialize(bytes.as_slice()).map_err(Into::into)
}

fn decode_proof(raw: &str) -> anyhow::Result<Proof<Ristretto255>> {
    let bytes = URL_SAFE_NO_PAD.decode(raw)?;
    Proof::<Ristretto255>::deserialize(bytes.as_slice()).map_err(Into::into)
}

fn decode_public_key(
    raw: &str,
) -> anyhow::Result<<<Ristretto255 as voprf::CipherSuite>::Group as Group>::Elem> {
    let bytes = URL_SAFE_NO_PAD.decode(raw)?;
    Ristretto255::deserialize_elem(bytes.as_slice()).map_err(Into::into)
}

struct MockPrincipalServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockPrincipalServer {
    fn spawn(event_id: &str) -> anyhow::Result<Self> {
        Self::spawn_with_optional_discovery_state(event_id, None)
    }

    fn spawn_with_discovery_state(
        event_id: &str,
        discovery_state: JsonValue,
    ) -> anyhow::Result<Self> {
        Self::spawn_with_optional_discovery_state(event_id, Some(discovery_state))
    }

    fn spawn_with_optional_discovery_state(
        event_id: &str,
        discovery_state: Option<JsonValue>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let event_id = event_id.to_owned();
        let principal_server_did = principal_did_for_addr(addr);

        let handle = thread::spawn(move || {
            while !thread_shutdown.as_ref().load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => handle_mock_principal_connection(
                        stream,
                        addr,
                        &principal_server_did,
                        &event_id,
                        discovery_state.as_ref(),
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            shutdown,
            handle: Some(handle),
        })
    }

    fn principal_server_did(&self) -> String {
        principal_did_for_addr(self.addr)
    }
}

impl Drop for MockPrincipalServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn principal_did_for_addr(addr: SocketAddr) -> String {
    format!("did:webvh:teabay-conformance:127.0.0.1%3A{}", addr.port())
}

fn handle_mock_principal_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    principal_server_did: &str,
    event_id: &str,
    discovery_state: Option<&JsonValue>,
) {
    let mut buffer = [0_u8; 2048];
    let Ok(size) = stream.read(&mut buffer) else {
        return;
    };
    let request = String::from_utf8_lossy(&buffer[..size]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let did_doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": principal_server_did,
        "service": [{
            "id": format!("{principal_server_did}#principal"),
            "type": "ArkretPrincipalServer",
            "serviceEndpoint": format!("http://127.0.0.1:{}/_arkret", addr.port()),
        }]
    });
    let (status, body) = if path == "/.well-known/did.json" {
        ("200 OK", did_doc)
    } else if path == format!("/_arkret/self/events/{event_id}") {
        ("200 OK", json!({ "event_id": event_id }))
    } else if path.starts_with("/_arkret/self/events/query?") {
        match discovery_state {
            Some(state) => (
                "200 OK",
                json!({
                    "events": [{
                        "event": {
                            "event_id": event_id,
                            "kind": "ak.realm.discovery",
                            "created_at": Utc::now(),
                            "content": state,
                        }
                    }]
                }),
            ),
            None => ("200 OK", json!({ "events": [] })),
        }
    } else {
        (
            "404 Not Found",
            json!({ "error": "not_found", "path": path }),
        )
    };

    let body = body.to_string();
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn signed_realm_discovery_state(
    verification_method: &str,
    signing_key: &SigningKey,
) -> anyhow::Result<JsonValue> {
    signed_realm_discovery_state_named(verification_method, signing_key, "Pushed Tea")
}

fn signed_realm_discovery_state_named(
    verification_method: &str,
    signing_key: &SigningKey,
    name: &str,
) -> anyhow::Result<JsonValue> {
    let mut state = json!({
        "kind": "ak.realm.discovery",
        "discoverability": "public",
        "directory_services": ["did:web:directory.test"],
        "name": name,
        "summary": "Accepted through push announce against a mock Principal Server",
        "member_count": 42,
        "policy_revision": "rev-pushed-1",
        "proof": {
            "kind": "detached_jws",
            "verification_method": verification_method,
            "jws": "",
        },
    });
    let jws = sign_detached_jws(&state, signing_key)?;
    state["proof"]["jws"] = JsonValue::String(jws);
    Ok(state)
}

#[derive(serde::Serialize)]
struct DirectoryRestrictedClaimPresentationSigningPayload<'a> {
    kind: &'a str,
    iss: &'a Did,
    verification_method: &'a str,
    audience: &'a Did,
    nonce: &'a str,
    claim: &'a DirectoryPresentedClaim,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
}

fn signed_restricted_claim_presentation(
    signing_key: &SigningKey,
    iss: Did,
    verification_method: String,
    audience: &str,
    nonce: &str,
    claim: PresentedClaim,
) -> anyhow::Result<DirectoryRestrictedClaimPresentation> {
    let audience = Did::new(audience.to_owned())?;
    let claim: DirectoryPresentedClaim = claim.into();
    let created_at = Utc::now();
    let expires_at = Some(created_at + ChronoDuration::minutes(5));
    let payload = DirectoryRestrictedClaimPresentationSigningPayload {
        kind: DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND,
        iss: &iss,
        verification_method: &verification_method,
        audience: &audience,
        nonce,
        claim: &claim,
        expires_at,
        created_at,
    };
    let canonical = canonical::canonical_json_bytes(&payload)?;
    let jws = sign_jws_ed25519(&canonical, signing_key).map_err(anyhow::Error::msg)?;
    Ok(DirectoryRestrictedClaimPresentation {
        kind: DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND.to_owned(),
        iss,
        verification_method,
        audience,
        nonce: nonce.to_owned(),
        claim,
        expires_at,
        created_at,
        jws,
    })
}

fn did_key_multibase(signing_key: &SigningKey) -> String {
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

fn sign_detached_jws(payload: &JsonValue, signing_key: &SigningKey) -> anyhow::Result<String> {
    sign_detached_jws_with_proof_key(payload, "proof", signing_key)
}

fn sign_detached_jws_with_proof_key(
    payload: &JsonValue,
    proof_key: &str,
    signing_key: &SigningKey,
) -> anyhow::Result<String> {
    let canonical = canonical_payload_without_jws_at(payload, proof_key)?;
    sign_jws_ed25519(&canonical, signing_key).map_err(anyhow::Error::msg)
}

fn canonical_payload_without_jws_at(
    payload: &JsonValue,
    proof_key: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut unsigned = payload.clone();
    let proof = unsigned
        .get_mut(proof_key)
        .and_then(JsonValue::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("proof object missing"))?;
    proof.remove("jws");
    canonical::canonical_json_bytes(&unsigned).map_err(Into::into)
}

fn signed_withdraw_body(
    resource_kind: &str,
    resource_id: &str,
    verification_method: &str,
    signing_key: &SigningKey,
    reason: &str,
) -> anyhow::Result<JsonValue> {
    let mut body = json!({
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        "governance_proof": {
            "kind": "detached_jws",
            "verification_method": verification_method,
            "jws": "",
        },
        "reason": reason,
        "effective_at": Utc::now(),
    });
    let jws = sign_detached_jws_with_proof_key(&body, "governance_proof", signing_key)?;
    body["governance_proof"]["jws"] = JsonValue::String(jws);
    Ok(body)
}
