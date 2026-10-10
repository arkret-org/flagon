//! Real HTTP/SQL regression coverage for the public index and operator audit.

use std::time::Duration;

use anyhow::Result;
use arkret_sdk::{Did, DidCoreId, ResolutionCommitment};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chrono::Utc;
use diesel_async::RunQueryDsl;
use hmac::{Hmac, KeyInit, Mac};
use salvo::http::StatusCode;
use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use server::audit::{self, ActorIdentity, AuditEventKind, DirectoryResourceKindDb};
use server::{AppConfig, AppState, Db};
use sha2::Sha256;

fn config(database_url: &str) -> AppConfig {
    AppConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        metrics_bind: "127.0.0.1:0".parse().unwrap(),
        public_base_url: "https://directory.test".into(),
        service_id: DidCoreId::new("ak:did_core:web:directory.test").unwrap(),
        service_did: Did::new("did:web:directory.test").unwrap(),
        service_resolution: ResolutionCommitment {
            did: Did::new("did:web:directory.test").unwrap(),
            method_history_head: "verified-method-history-head".into(),
            version_id: "verified-method-version".into(),
        },
        trust_domain: "ak:trust_domain:local.test".into(),
        database_url: database_url.into(),
        cors_allow_origin: Some("https://admin.test".into()),
        admin_csrf_token: Some("test-csrf-proof".into()),
        admin_token: Some("local-test-operator".into()),
        admin_token_rotation_window: Duration::from_secs(1800),
        development_mode: true,
        query_max_queries_per_ip_per_min: 0,
        query_max_resolves_per_resource_per_min: 0,
        db_pool: server::config::DbPoolConfig::default(),
        trusted_proxy: None,
    }
}

fn realm(index: u8) -> String {
    let mut bytes = [index; 33];
    bytes[0] = 1;
    format!(
        "ak:realm:{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

async fn checked_json(mut response: Response, status: StatusCode) -> Result<Value> {
    assert_eq!(response.status_code.unwrap_or(StatusCode::OK), status);
    Ok(response.take_json().await?)
}

async fn sql(db: &Db, statement: &str) -> Result<()> {
    diesel::sql_query(statement)
        .execute(&mut *db.get().await?)
        .await?;
    Ok(())
}

async fn search(service: &Service, body: Value) -> Response {
    TestClient::post("https://directory.test/_arkret/find/directory/search-realms")
        .add_header(
            "Arkret-Operation",
            "ak.find.directory.read.search_realms.v1",
            true,
        )
        .json(&body)
        .send(service)
        .await
}

async fn resolve(service: &Service, realm_id: &str) -> Response {
    TestClient::post("https://directory.test/_arkret/find/directory/resolve-realm")
        .add_header(
            "Arkret-Operation",
            "ak.find.directory.read.resolve_realm.v1",
            true,
        )
        .json(&json!({"realm_id": realm_id}))
        .send(service)
        .await
}

async fn public_index(db: &Db, state: &AppState) -> Result<()> {
    let service = server::service(state.clone());
    for (index, name, expired) in [
        (2, "Alpha public", false),
        (3, "Beta public", false),
        (4, "Expired public", true),
    ] {
        let timestamp = if expired {
            "now() - interval '1 day'"
        } else {
            "now() + interval '1 day'"
        };
        sql(db, &format!("INSERT INTO directory_public_realm_entries VALUES ('{}', '{{\"display_name\":\"{name}\",\"summary\":\"Discovery hint only\"}}', now() - interval '2 days', {timestamp})", realm(index))).await?;
    }
    let page = checked_json(search(&service, json!({"limit": 1})).await, StatusCode::OK).await?;
    assert_eq!(page["realms"].as_array().unwrap().len(), 1);
    assert_eq!(page["has_more"], true);
    let cursor = page["next_cursor"].as_str().unwrap();
    let second = checked_json(
        search(&service, json!({"limit": 1, "cursor": cursor})).await,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(second["has_more"], false);
    assert_ne!(
        page["realms"][0]["realm_id"],
        second["realms"][0]["realm_id"]
    );
    assert!(second["next_cursor"].is_null());
    assert_eq!(
        checked_json(
            search(&service, json!({"query":"Alpha"})).await,
            StatusCode::OK
        )
        .await?["realms"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let resolved = checked_json(resolve(&service, &realm(2)).await, StatusCode::OK).await?;
    assert_eq!(resolved["public_metadata"]["display_name"], "Alpha public");
    assert_eq!(resolved.as_object().unwrap().len(), 4);
    for id in [realm(4), realm(5)] {
        checked_json(resolve(&service, &id).await, StatusCode::NOT_FOUND).await?;
    }
    for invalid in [
        json!({"limit": 0}),
        json!({"query": ""}),
        json!({"limit": 101}),
        json!({"query": "x".repeat(129)}),
    ] {
        checked_json(
            search(&service, invalid).await,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await?;
    }
    checked_json(
        search(&service, json!({"limit": 2, "cursor": cursor})).await,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    checked_json(
        search(&service, json!({"cursor": "tampered"})).await,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    for path in ["search-realms", "resolve-realm"] {
        let operation = format!("ak.find.directory.read.{}.v1", path.replace('-', "_"));
        let response = TestClient::post(format!(
            "https://directory.test/_arkret/find/directory/{path}"
        ))
        .add_header("Arkret-Operation", operation, true)
        .raw_json("{")
        .send(&service)
        .await;
        checked_json(response, StatusCode::BAD_REQUEST).await?;
    }
    sql(db, &format!("INSERT INTO directory_public_realm_entries VALUES ('{}', '{{\"display_name\":\"Legacy\",\"source_refs\":[]}}', now(), now()+interval '1 day')", realm(6))).await?;
    checked_json(
        resolve(&service, &realm(6)).await,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await?;
    checked_json(
        search(&service, json!({})).await,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await?;
    sql(
        db,
        &format!(
            "DELETE FROM directory_public_realm_entries WHERE realm_id='{}'",
            realm(6)
        ),
    )
    .await?;
    Ok(())
}

async fn operator_audit(db: &Db, state: &AppState) -> Result<()> {
    let service = server::service(state.clone());
    let empty = audit::verify_chain(db).await?;
    assert!(empty.ok);
    assert_eq!(empty.checked_rows, 0);
    audit::record(
        db,
        AuditEventKind::IngestRejected,
        None,
        None,
        None,
        json!({"reason":"historical"}),
    )
    .await?;
    audit::record_with_identity(
        db,
        AuditEventKind::OperatorTakedown,
        Some(DirectoryResourceKindDb::Realm),
        Some(&realm(2)),
        Some("ak:did_core:web:operator.test"),
        json!({"reason":"operator decision"}),
        ActorIdentity {
            authentication_method: Some("rotating_hmac"),
            authenticated_credential_id: Some("admin:key-a"),
            asserted_operator_localpart: Some("unverified-byline"),
        },
    )
    .await?;
    let valid = audit::verify_chain(db).await?;
    assert!(valid.ok);
    assert_eq!(valid.chain_rows, 2);
    assert_eq!(valid.head_digest.as_ref().unwrap().len(), 64);
    assert!(
        audit::record(
            db,
            AuditEventKind::Withdrawal,
            None,
            None,
            Some("not-a-principal"),
            json!({})
        )
        .await
        .is_err()
    );
    for path in ["audit", "audit/verify"] {
        checked_json(
            TestClient::get(format!("https://directory.test/_teabay/admin/{path}"))
                .send(&service)
                .await,
            StatusCode::UNAUTHORIZED,
        )
        .await?;
        checked_json(
            TestClient::get(format!("https://directory.test/_teabay/admin/{path}"))
                .bearer_auth("wrong")
                .send(&service)
                .await,
            StatusCode::UNAUTHORIZED,
        )
        .await?;
    }
    let feed = checked_json(
        TestClient::get("https://directory.test/_teabay/admin/audit?limit=1")
            .bearer_auth("local-test-operator")
            .send(&service)
            .await,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(feed["events"].as_array().unwrap().len(), 1);
    assert_eq!(
        feed["events"][0]["authenticated_credential_id"],
        "admin:key-a"
    );
    assert_eq!(
        feed["events"][0]["asserted_operator_localpart"],
        "unverified-byline"
    );
    checked_json(
        TestClient::get("https://directory.test/_teabay/admin/audit?since=invalid")
            .bearer_auth("local-test-operator")
            .send(&service)
            .await,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let future = TestClient::get("https://directory.test/_teabay/admin/audit")
        .query("since", "2099-01-01T00:00:00Z")
        .bearer_auth("local-test-operator")
        .send(&service)
        .await;
    assert!(
        checked_json(future, StatusCode::OK).await?["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        checked_json(
            TestClient::get("https://directory.test/_teabay/admin/audit/verify")
                .bearer_auth("local-test-operator")
                .send(&service)
                .await,
            StatusCode::OK
        )
        .await?["ok"],
        true
    );
    // Production append-only protection must reject modifying even a valid chain.
    assert!(
        sql(db, "UPDATE directory_audit SET detail='{}'")
            .await
            .is_err()
    );
    // A forged append cannot be mistaken for a valid historical chain.
    sql(db, "INSERT INTO directory_audit(kind,detail,prev_digest,audit_digest) VALUES('withdrawal','{}',decode('00','hex'),decode('01','hex'))").await?;
    let broken = audit::verify_chain(db).await?;
    assert!(!broken.ok);
    assert_eq!(
        broken.failure.unwrap().reason,
        "prev_digest does not match previous audit_digest"
    );
    sql(db, "TRUNCATE directory_audit RESTART IDENTITY").await?;
    sql(
        db,
        "INSERT INTO directory_audit(kind,detail) VALUES('ingest_rejected','{}')",
    )
    .await?;
    audit::record(db, AuditEventKind::Withdrawal, None, None, None, json!({})).await?;
    assert_eq!(audit::verify_chain(db).await?.chain_rows, 1);
    sql(
        db,
        "INSERT INTO directory_audit(kind,detail) VALUES('withdrawal','{}')",
    )
    .await?;
    assert_eq!(
        audit::verify_chain(db).await?.failure.unwrap().reason,
        "missing audit_digest after chain start"
    );
    sql(db, "TRUNCATE directory_audit RESTART IDENTITY").await?;
    sql(db, "INSERT INTO directory_audit(kind,detail,prev_digest,audit_digest) VALUES('withdrawal','{}',decode('00','hex'),decode('01','hex'))").await?;
    assert_eq!(
        audit::verify_chain(db).await?.failure.unwrap().reason,
        "first chained row has non-null prev_digest"
    );
    sql(db, "TRUNCATE directory_audit RESTART IDENTITY").await?;
    sql(db, "INSERT INTO directory_audit(kind,detail,audit_digest) VALUES('withdrawal','{}',decode('01','hex'))").await?;
    assert_eq!(
        audit::verify_chain(db).await?.failure.unwrap().reason,
        "audit_digest does not match recomputed digest"
    );
    sql(db, "TRUNCATE directory_audit RESTART IDENTITY").await?;
    Ok(())
}

fn signed_token(key: &str, secret: &[u8], timestamp: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(format!("{key}:{timestamp}").as_bytes());
    format!(
        "hmac:{key}:{timestamp}:{}",
        STANDARD_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

async fn admin_credentials(db: &Db, state: &AppState) -> Result<()> {
    sql(
        db,
        "INSERT INTO admin_tokens(key_id,secret) VALUES('key-a',decode('01020304','hex'))",
    )
    .await?;
    let mut production = state.config().clone();
    production.development_mode = false;
    let production = AppState::new(production, db.clone())?;
    let service = server::service(production.clone());
    let token = signed_token("key-a", &[1, 2, 3, 4], Utc::now().timestamp());
    let credential = server::middleware::verify_admin_credential(
        &TestClient::get("https://local/")
            .bearer_auth(&token)
            .build(),
        &production,
    )
    .await
    .unwrap();
    assert_eq!(credential.authentication_method(), "rotating_hmac");
    assert_eq!(
        credential.authenticated_credential_id().as_str(),
        "admin:key-a"
    );
    checked_json(
        TestClient::get("https://directory.test/_teabay/admin/audit")
            .bearer_auth(&token)
            .send(&service)
            .await,
        StatusCode::OK,
    )
    .await?;
    for bad in [
        "local-test-operator".to_owned(),
        "hmac:".into(),
        "hmac:key-a:bad:AA".into(),
        "hmac:key-a:0:AA".into(),
        format!("hmac:key-a:{}:***", Utc::now().timestamp()),
        signed_token("missing", &[1, 2, 3, 4], Utc::now().timestamp()),
        signed_token("key-a", &[9], Utc::now().timestamp()),
    ] {
        checked_json(
            TestClient::get("https://directory.test/_teabay/admin/audit")
                .bearer_auth(bad)
                .send(&service)
                .await,
            StatusCode::UNAUTHORIZED,
        )
        .await?;
    }
    for column in ["revoked_at", "expires_at"] {
        sql(
            db,
            &format!(
                "UPDATE admin_tokens SET {column}=now()-interval '1 minute' WHERE key_id='key-a'"
            ),
        )
        .await?;
        checked_json(
            TestClient::get("https://directory.test/_teabay/admin/audit")
                .bearer_auth(&token)
                .send(&service)
                .await,
            StatusCode::UNAUTHORIZED,
        )
        .await?;
        sql(
            db,
            &format!("UPDATE admin_tokens SET {column}=NULL WHERE key_id='key-a'"),
        )
        .await?;
    }
    for method in [
        salvo::http::Method::GET,
        salvo::http::Method::HEAD,
        salvo::http::Method::OPTIONS,
    ] {
        assert!(
            server::middleware::require_admin_csrf(
                &salvo::test::RequestBuilder::new("https://local/", method).build(),
                &production
            )
            .is_ok()
        );
    }
    let post = TestClient::post("https://local/").build();
    assert!(server::middleware::require_admin_csrf(&post, &production).is_err());
    let post = TestClient::post("https://local/")
        .add_header("X-CSRF-Token", "test-csrf-proof", true)
        .build();
    assert!(server::middleware::require_admin_csrf(&post, &production).is_ok());
    let static_credential = server::middleware::verify_admin_credential(
        &TestClient::get("https://local/")
            .bearer_auth("local-test-operator")
            .build(),
        state,
    )
    .await
    .unwrap();
    assert_eq!(static_credential.authentication_method(), "static_bearer");
    assert_eq!(
        static_credential.authenticated_credential_id().as_str(),
        "admin:static-bearer"
    );
    Ok(())
}

async fn surfaces(state: &AppState) -> Result<()> {
    let missing = Service::new(
        Router::new()
            .push(Router::with_path("search").post(server::query::realm::search_realms))
            .push(Router::with_path("resolve").post(server::query::realm::resolve_realm))
            .push(Router::with_path("describe").get(server::query::describe::describe))
            .push(Router::with_path("audit").get(server::query::admin::audit_feed))
            .push(Router::with_path("verify").get(server::query::admin::audit_chain_verify)),
    );
    for path in ["describe", "audit", "verify"] {
        checked_json(
            TestClient::get(format!("https://local/{path}"))
                .send(&missing)
                .await,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await?;
    }
    for path in ["search", "resolve"] {
        checked_json(
            TestClient::post(format!("https://local/{path}"))
                .send(&missing)
                .await,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await?;
    }
    let service = server::service(state.clone());
    for path in ["health", "healthz", "readyz"] {
        assert_eq!(
            checked_json(
                TestClient::get(format!("https://directory.test/{path}"))
                    .send(&service)
                    .await,
                StatusCode::OK
            )
            .await?["ok"],
            true
        );
    }
    for (path, operation) in [
        ("_arkret/describe", "ak.server.read.describe.v1"),
        (
            "_arkret/find/directory/describe",
            "ak.find.directory.read.describe.v1",
        ),
    ] {
        let value = checked_json(
            TestClient::get(format!("https://directory.test/{path}"))
                .add_header("Arkret-Operation", operation, true)
                .send(&service)
                .await,
            StatusCode::OK,
        )
        .await?;
        assert_eq!(value["service_kind"], "directory_service");
    }
    let doc = checked_json(
        TestClient::get("https://directory.test/.well-known/arkret/openapi.json")
            .send(&service)
            .await,
        StatusCode::OK,
    )
    .await?;
    assert!(doc["paths"]["/_arkret/find/directory/search-realms"].is_object());
    let mut yaml = TestClient::get("https://directory.test/.well-known/arkret/openapi.yaml")
        .send(&service)
        .await;
    assert!(yaml.take_string().await?.contains("openapi:"));
    checked_json(
        TestClient::get("https://directory.test/unknown")
            .send(&service)
            .await,
        StatusCode::NOT_FOUND,
    )
    .await?;
    let preflight = TestClient::options("https://directory.test/unknown")
        .add_header("Origin", "https://admin.test", true)
        .add_header("Access-Control-Request-Method", "POST", true)
        .send(&service)
        .await;
    assert!(preflight.status_code.unwrap_or(StatusCode::OK).is_success());
    let metrics = server::metrics_service(state.clone());
    let mut response = TestClient::get("https://local/metrics")
        .send(&metrics)
        .await;
    assert!(
        response
            .take_string()
            .await?
            .contains("teabay_db_pool_connections")
    );
    assert_eq!(
        TestClient::get("https://local/unknown")
            .send(&metrics)
            .await
            .status_code,
        Some(StatusCode::NOT_FOUND)
    );
    Ok(())
}

async fn query_limits(db: &Db, state: &AppState) -> Result<()> {
    let mut trusted_config = state.config().clone();
    trusted_config.query_max_queries_per_ip_per_min = 1;
    trusted_config.trusted_proxy = Some(vec!["127.0.0.1".parse()?]);
    let trusted = AppState::new(trusted_config.clone(), db.clone())?;
    for forwarded in ["198.51.100.1, 10.0.0.1", "198.51.100.2"] {
        let mut request = TestClient::get("https://local/")
            .add_header("X-Forwarded-For", forwarded, true)
            .build();
        *request.remote_addr_mut() = "127.0.0.1:8000".parse::<std::net::SocketAddr>()?.into();
        assert!(server::query::rate_limit::enforce_query_rate_limit(
            &request,
            &mut Response::new(),
            &trusted
        ));
        assert!(!server::query::rate_limit::enforce_query_rate_limit(
            &request,
            &mut Response::new(),
            &trusted
        ));
    }
    let untrusted = AppState::new(trusted_config, db.clone())?;
    for (index, forwarded) in ["198.51.100.3", "198.51.100.4"].into_iter().enumerate() {
        let mut request = TestClient::get("https://local/")
            .add_header("X-Forwarded-For", forwarded, true)
            .build();
        *request.remote_addr_mut() = format!("192.0.2.1:{}", 8000 + index)
            .parse::<std::net::SocketAddr>()?
            .into();
        assert_eq!(
            server::query::rate_limit::enforce_query_rate_limit(
                &request,
                &mut Response::new(),
                &untrusted
            ),
            index == 0
        );
    }
    let mut cfg = state.config().clone();
    cfg.query_max_queries_per_ip_per_min = 1;
    let limited = AppState::new(cfg.clone(), db.clone())?;
    let service = server::service(limited);
    checked_json(search(&service, json!({})).await, StatusCode::OK).await?;
    let response = search(&service, json!({})).await;
    assert!(response.headers().contains_key("retry-after"));
    checked_json(response, StatusCode::TOO_MANY_REQUESTS).await?;
    cfg.query_max_queries_per_ip_per_min = 0;
    cfg.query_max_resolves_per_resource_per_min = 1;
    let limited = AppState::new(cfg, db.clone())?;
    let service = server::service(limited);
    checked_json(resolve(&service, &realm(2)).await, StatusCode::OK).await?;
    checked_json(
        resolve(&service, &realm(2)).await,
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await?;
    checked_json(
        search(&service, json!({"query":"Alpha"})).await,
        StatusCode::OK,
    )
    .await?;
    checked_json(
        search(&service, json!({"query":"Alpha"})).await,
        StatusCode::TOO_MANY_REQUESTS,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn real_directory_and_operator_contracts() -> Result<()> {
    let base = std::env::var("TEABAY_TEST_DATABASE_URL")?;
    let admin = Db::connect(&base)?;
    let schema = format!(
        "teabay_http_{}_{}",
        std::process::id(),
        Utc::now().timestamp_micros()
    );
    sql(&admin, &format!("CREATE SCHEMA {schema}")).await?;
    let mut url = url::Url::parse(&base)?;
    url.query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let url = url.to_string();
    let db = Db::connect(&url)?;
    let result = async {
        db.run_migrations(&url).await?;
        let state = AppState::new(config(&url), db.clone())?;
        public_index(&db, &state).await?;
        operator_audit(&db, &state).await?;
        admin_credentials(&db, &state).await?;
        surfaces(&state).await?;
        query_limits(&db, &state).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    drop(db);
    sql(&admin, &format!("DROP SCHEMA {schema} CASCADE")).await?;
    result
}
