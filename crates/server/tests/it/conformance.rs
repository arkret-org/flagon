use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use diesel::RunQueryDsl;
use diesel::sql_types::BigInt;
use ed25519_dalek::{Signer, SigningKey};
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

#[test]
fn postgres_query_and_psi_conformance_smoke() -> anyhow::Result<()> {
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
        std::env::set_var("TEABAY_SERVICE_DID", "did:web:directory.test");
        std::env::set_var("DATABASE_URL", &database_url);
        std::env::set_var("TEABAY_PRIVATE_CONTACT_DISCOVERY_ENABLED", "true");
        std::env::set_var("TEABAY_ADMIN_TOKEN", "cotest-admin");
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
    db.run_migrations()?;
    seed_directory_fixture(&db)?;

    let service = server::service(server::AppState::new(config.clone(), db.clone()));
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            assert_describe_advertises_core_and_psi(&service).await?;
            assert_query_surface_matrix(&service).await?;
            assert_search_spaces_finds_seeded_space(&service).await?;
            assert_pull_subscribe_registers_webhook(&service).await?;
            assert_push_announce_uses_mock_principal_server(&service).await?;
            assert_pull_worker_refreshes_due_entry(&config, &db, &service).await?;
            assert_freshness_flags_are_exposed(&db, &service).await?;
            assert_psi_blind_and_match_finds_seeded_handle(&service).await?;
            assert_admin_operator_surface(&service).await
        })?;
    Ok(())
}

fn seed_directory_fixture(db: &server::Db) -> anyhow::Result<()> {
    let mut conn = db.get()?;
    diesel::sql_query(teabay_testing::DIRECTORY_FIXTURE_SQL).execute(&mut conn)?;
    Ok(())
}

async fn assert_describe_advertises_core_and_psi(service: &Service) -> anyhow::Result<()> {
    let mut res = TestClient::get("http://local/api/v1/directory/describe")
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    let profiles = body["discovery_profiles"].as_array().unwrap();
    assert!(profiles.contains(&json!("cx.profile.directory_service.v1")));
    assert!(profiles.contains(&json!("cx.private_contact_discovery.v1")));
    assert_eq!(body["service_did"], "did:web:directory.test");
    assert!(body["accepted_resource_kinds"].as_array().unwrap().len() >= 5);
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
        body["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|limitation| limitation["feature"] == "operator_takedown_notification")
    );
    Ok(())
}

async fn assert_search_spaces_finds_seeded_space(service: &Service) -> anyhow::Result<()> {
    let mut res = TestClient::post("http://local/api/v1/directory/search-realms")
        .json(&json!({ "query": "tea", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["space_id"] == "cx:space:tea")
    );
    Ok(())
}

async fn assert_query_surface_matrix(service: &Service) -> anyhow::Result<()> {
    let mut res = TestClient::post("http://local/api/v1/directory/search-realms")
        .json(&json!({ "query": "tea", "limit": 1 }))
        .send(service)
        .await;
    let status = res.status_code.unwrap_or(StatusCode::OK);
    if status != StatusCode::OK {
        let body = res.take_string().await.unwrap_or_default();
        panic!("search-realms first page failed with {status}: {body}");
    }
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["results"].as_array().unwrap().len(), 1);
    let first = &body["results"][0];
    assert!(first.get("as_of").is_some());
    assert!(
        first["source_refs"]
            .as_array()
            .is_some_and(|refs| !refs.is_empty())
    );
    assert!(
        first["via_services"]
            .as_array()
            .is_some_and(|refs| !refs.is_empty())
    );
    let cursor = body["next_cursor"]
        .as_str()
        .unwrap_or_else(|| panic!("expected next_cursor for first search page: {body}"));

    let mut res = TestClient::post("http://local/api/v1/directory/search-realms")
        .json(&json!({ "query": "tea", "limit": 1, "cursor": cursor }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["results"].as_array().unwrap().len(), 1);

    let res = TestClient::post("http://local/api/v1/directory/search-realms")
        .json(&json!({ "cursor": "not-base64" }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::BAD_REQUEST
    );

    assert_resolve_space_status(service, "cx:space:tea", StatusCode::OK, json!({})).await?;
    assert_resolve_space_status(service, "cx:space:secret", StatusCode::NOT_FOUND, json!({}))
        .await?;
    assert_resolve_space_status(
        service,
        "cx:space:restricted",
        StatusCode::NOT_FOUND,
        json!({}),
    )
    .await?;
    assert_resolve_space_status(
        service,
        "cx:space:restricted",
        StatusCode::OK,
        json!({ "requester": "did:web:alice.example" }),
    )
    .await?;

    let mut res = TestClient::post("http://local/api/v1/directory/search-organizations")
        .json(&json!({ "query": "tea", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(
        body["results"][0]["organization_did"],
        "did:web:tea-org.example"
    );

    let mut res = TestClient::post("http://local/api/v1/directory/resolve-organization")
        .json(&json!({ "organization_did": "did:web:tea-org.example" }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["organization_did"], "did:web:tea-org.example");

    let mut res = TestClient::post("http://local/api/v1/directory/search-actors")
        .json(&json!({ "query": "alice", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["results"][0]["actor_did"], "did:web:alice.example");

    let mut res = TestClient::post("http://local/api/v1/directory/search-users")
        .json(&json!({
            "q": "alice",
            "requester": "did:web:alice.example",
            "space_id": "cx:space:tea",
            "limit": 10
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["results"][0]["actor_did"], "did:web:alice.example");

    let mut res = TestClient::post("http://local/api/v1/directory/resolve-handle")
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

async fn assert_resolve_space_status(
    service: &Service,
    space_id: &str,
    expected: StatusCode,
    extra: JsonValue,
) -> anyhow::Result<()> {
    let mut body = json!({ "realm_id": space_id });
    if let (Some(target), Some(source)) = (body.as_object_mut(), extra.as_object()) {
        target.extend(source.clone());
    }
    let res = TestClient::post("http://local/api/v1/directory/resolve-realm")
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

    let mut res = TestClient::post("http://local/api/v1/directory/private-contact-discovery")
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

    let mut res = TestClient::post("http://local/api/v1/directory/private-contact-discovery")
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
    let mock = MockPrincipalServer::spawn("evt-announce-space")?;
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let public_key = did_key_multibase(&signing_key);
    let signer_did = format!("did:key:{public_key}");
    let verification_method = format!("{signer_did}#{public_key}");
    let discovery_state = signed_space_discovery_state(&verification_method, &signing_key)?;

    let mut res = TestClient::post("http://local/api/v1/directory/announce")
        .json(&json!({
            "resource_kind": "space",
            "resource_id": "cx:space:pushed",
            "principal_server_did": mock.principal_server_did(),
            "discovery_state": discovery_state,
            "source_refs": ["evt-announce-space"],
            "as_of": Utc::now(),
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
            .is_some_and(|id| id.starts_with("cx:announce:"))
    );

    let mut res = TestClient::post("http://local/api/v1/directory/resolve-realm")
        .json(&json!({ "realm_id": "cx:space:pushed" }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["space_id"], "cx:space:pushed");
    assert_eq!(body["member_count_bucket"], "11-50");
    assert_eq!(body["source_refs"][0], "evt-announce-space");
    assert_eq!(body["via_services"][0], mock.principal_server_did());
    Ok(())
}

async fn assert_pull_subscribe_registers_webhook(service: &Service) -> anyhow::Result<()> {
    let mut res = TestClient::post("http://local/api/v1/directory/subscribe")
        .json(&json!({
            "subscriber_did": "did:web:subscriber.example",
            "resource_filter": {
                "resource_kind": "space",
                "resource_id": "cx:space:pushed"
            },
            "webhook_endpoint": "http://127.0.0.1:9/teabay-conformance-webhook",
            "webhook_secret": "0123456789abcdef"
        }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["subscription_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("cx:subscription:"))
    );
    assert!(body.get("created_at").is_some());
    assert!(body.get("effective_at").is_some());
    assert!(
        body["webhook_secret"]
            .as_str()
            .is_some_and(|secret| !secret.is_empty())
    );
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
        signed_space_discovery_state_named(&verification_method, &signing_key, "Pulled Tea")?;
    let mock =
        MockPrincipalServer::spawn_with_discovery_state("evt-pull-space", pulled_state.clone())?;

    let mut res = TestClient::post("http://local/api/v1/directory/announce")
        .json(&json!({
            "resource_kind": "space",
            "resource_id": "cx:space:pull",
            "principal_server_did": mock.principal_server_did(),
            "discovery_state": pulled_state,
            "source_refs": ["evt-pull-space"],
            "as_of": Utc::now(),
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
        let mut conn = db.get()?;
        diesel::sql_query(
            "UPDATE directory_resources \
             SET next_revalidation_after = now() - interval '1 second' \
             WHERE resource_kind = 'space'::resource_kind AND resource_id = 'cx:space:pull'",
        )
        .execute(&mut conn)?;
    }

    let worker_state = server::AppState::new(config.clone(), db.clone());
    server::ingest::pull_worker::PullWorker::new(worker_state, Duration::from_millis(1))
        .run_once_for_tests()
        .await?;

    let mut res = TestClient::post("http://local/api/v1/directory/resolve-realm")
        .json(&json!({ "realm_id": "cx:space:pull" }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["name"], "Pulled Tea");

    let mut conn = db.get()?;
    let pull_count: i64 = diesel::sql_query(
        "SELECT count(*) FROM ingest_announces \
         WHERE resource_kind = 'space'::resource_kind \
           AND resource_id = 'cx:space:pull' \
           AND ingest_mode = 'pull'::ingest_mode",
    )
    .get_result::<CountRow>(&mut conn)?
    .count;
    assert_eq!(pull_count, 1);
    Ok(())
}

async fn assert_freshness_flags_are_exposed(
    db: &server::Db,
    service: &Service,
) -> anyhow::Result<()> {
    {
        let mut conn = db.get()?;
        diesel::sql_query(
            "UPDATE directory_resources \
             SET stale = true \
             WHERE resource_kind = 'space'::resource_kind AND resource_id = 'cx:space:tea'",
        )
        .execute(&mut conn)?;
    }
    let mut res = TestClient::post("http://local/api/v1/directory/resolve-realm")
        .json(&json!({ "realm_id": "cx:space:tea" }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["stale"], true);
    Ok(())
}

async fn assert_admin_operator_surface(service: &Service) -> anyhow::Result<()> {
    let managed_resource_id = "did:web:admin-managed.example";

    let res = TestClient::get("http://local/api/admin/v1/resources?limit=5")
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::UNAUTHORIZED
    );

    let mut res = TestClient::get("http://local/api/admin/v1/resources?resource_kind=space&divergent=false&stale=false&limit=10")
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

    let mut res = TestClient::post("http://local/api/admin/v1/allowlist")
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

    let mut res = TestClient::get("http://local/api/admin/v1/allowlist?limit=10")
        .add_header("authorization", "Bearer cotest-admin", true)
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["items"][0]["resource_did"], "did:web:principal.test");

    let mut res = TestClient::post("http://local/api/admin/v1/resources")
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

    let mut res = TestClient::post("http://local/api/v1/directory/search-organizations")
        .json(&json!({ "query": "Admin Managed", "limit": 10 }))
        .send(service)
        .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert!(
        body["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["organization_did"] == managed_resource_id)
    );

    let mut res = TestClient::post("http://local/api/admin/v1/takedown")
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
            .is_some_and(|id| id.starts_with("cx:withdraw:"))
    );

    let res = TestClient::post("http://local/api/v1/directory/resolve-handle")
        .json(&json!({ "handle": "alice.example" }))
        .send(service)
        .await;
    assert_eq!(
        res.status_code.unwrap_or(StatusCode::OK),
        StatusCode::NOT_FOUND
    );

    let mut res = TestClient::delete(
        "http://local/api/admin/v1/allowlist?resource_did=did:web:principal.test",
    )
    .add_header("authorization", "Bearer cotest-admin", true)
    .send(service)
    .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["deleted"], 1);

    let mut res = TestClient::delete(
        "http://local/api/admin/v1/resources?resource_kind=organization&resource_id=did:web:admin-managed.example",
    )
    .add_header("authorization", "Bearer cotest-admin", true)
    .send(service)
    .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["deleted"], 1);

    let mut res = TestClient::get(
        "http://local/api/admin/v1/resources?resource_kind=organization&q=admin-managed&limit=10",
    )
    .add_header("authorization", "Bearer cotest-admin", true)
    .send(service)
    .await;
    assert_eq!(res.status_code.unwrap_or(StatusCode::OK), StatusCode::OK);
    let body: JsonValue = res.take_json().await?;
    assert_eq!(body["items"].as_array().unwrap().len(), 0);

    let mut res = TestClient::get("http://local/api/admin/v1/audit?limit=50")
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
            while !thread_shutdown.load(Ordering::SeqCst) {
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
            "type": "ContrixPrincipalServer",
            "serviceEndpoint": format!("http://127.0.0.1:{}/api/v1", addr.port()),
        }]
    });
    let (status, body) = if path == "/.well-known/did.json" {
        ("200 OK", did_doc)
    } else if path == format!("/api/v1/events/{event_id}") {
        ("200 OK", json!({ "event_id": event_id }))
    } else if path.starts_with("/api/v1/events?") {
        match discovery_state {
            Some(state) => (
                "200 OK",
                json!({
                    "events": [{
                        "event": {
                            "event_id": event_id,
                            "kind": "cx.realm.discovery",
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

fn signed_space_discovery_state(
    verification_method: &str,
    signing_key: &SigningKey,
) -> anyhow::Result<JsonValue> {
    signed_space_discovery_state_named(verification_method, signing_key, "Pushed Tea")
}

fn signed_space_discovery_state_named(
    verification_method: &str,
    signing_key: &SigningKey,
    name: &str,
) -> anyhow::Result<JsonValue> {
    let mut state = json!({
        "kind": "cx.realm.discovery",
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

fn did_key_multibase(signing_key: &SigningKey) -> String {
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

fn sign_detached_jws(payload: &JsonValue, signing_key: &SigningKey) -> anyhow::Result<String> {
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({ "alg": "EdDSA" }))?);
    let canonical = canonical_payload_without_jws(payload)?;
    let signing_input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(canonical));
    let signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!(
        "{protected}..{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn canonical_payload_without_jws(payload: &JsonValue) -> anyhow::Result<Vec<u8>> {
    let mut unsigned = payload.clone();
    let proof = unsigned
        .get_mut("proof")
        .and_then(JsonValue::as_object_mut)
        .ok_or_else(|| anyhow::anyhow!("proof object missing"))?;
    proof.remove("jws");
    canonical_json_bytes(&unsigned)
}

fn canonical_json_bytes(value: &JsonValue) -> anyhow::Result<Vec<u8>> {
    let mut out = String::new();
    write_canonical_json(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical_json(value: &JsonValue, out: &mut String) -> anyhow::Result<()> {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(number) => out.push_str(&number.to_string()),
        JsonValue::String(value) => out.push_str(&serde_json::to_string(value)?),
        JsonValue::Array(values) => {
            out.push('[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(']');
        }
        JsonValue::Object(map) => {
            out.push('{');
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                write_canonical_json(&map[key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}
