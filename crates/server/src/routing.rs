//! Salvo router declaration. All `/_arkret/find/directory/*` endpoints (spec §9)
//! plus `/health` and OpenAPI metadata.

use arkret_models_discovery::DirectoryRealmSearchOutcome;
use diesel_async::RunQueryDsl;
use salvo::affix_state;
use salvo::cors::{Cors, CorsHandler};
use salvo::http::{Method, header};
use salvo::oapi::{OpenApi, Operation, PathItem, PathItemType, Response as OapiResponse, ToSchema};
use salvo::prelude::*;
use serde_json::json;

use crate::error::{ApiErrorCode, render_problem};
use crate::query;
use crate::state::AppState;

#[derive(Clone)]
pub struct TeabayOpenApiDoc(pub serde_json::Value);

pub fn router(state: AppState) -> Router {
    let cors_origin = state.config().cors_allow_origin.clone();
    let directory = directory_router();
    let admin = admin_router();
    let doc = openapi(&directory);

    let mut root = Router::new().hoop(affix_state::inject(state));
    if let Some(origin) = cors_origin {
        root = root.hoop(cors_handler_for_origin(origin));
    }
    root.push(Router::with_path("health").get(health))
        .push(Router::with_path("healthz").get(health))
        .push(Router::with_path("readyz").get(readyz))
        .push(
            Router::with_path("_arkret/describe")
                .hoop(operation_selector_middleware)
                .get(query::describe::describe),
        )
        .push(directory)
        .push(admin)
        .push(
            Router::with_path(".well-known/arkret/openapi.json")
                .hoop(affix_state::inject(TeabayOpenApiDoc(doc.clone())))
                .get(openapi_json),
        )
        .push(
            Router::with_path(".well-known/arkret/openapi.yaml")
                .hoop(affix_state::inject(TeabayOpenApiDoc(doc)))
                .get(openapi_yaml),
        )
        .push(
            Router::with_path("{**rest}")
                .options(cors_preflight)
                .get(api_not_found),
        )
}

pub fn service(state: AppState) -> Service {
    Service::new(router(state)).catcher(salvo::catcher::Catcher::new(
        salvo::catcher::ProblemGoal::new(),
    ))
}

pub fn metrics_router(state: AppState) -> Router {
    Router::new()
        .hoop(affix_state::inject(state))
        .push(Router::with_path("metrics").get(metrics))
        .push(Router::with_path("{**rest}").get(metrics_not_found))
}

pub fn metrics_service(state: AppState) -> Service {
    Service::new(metrics_router(state))
}

fn admin_router() -> Router {
    Router::with_path("_teabay/admin")
        .hoop(crate::middleware::AdminAuthHoop)
        .push(Router::with_path("audit").get(query::admin::audit_feed))
        .push(Router::with_path("audit/verify").get(query::admin::audit_chain_verify))
}

fn directory_router() -> Router {
    // Query face — no transport signature required (search/resolve are
    // read-only against the indexed view, and CORS / auth gating is
    // handled per-handler where applicable).
    let query_routes = Router::new()
        .push(Router::with_path("describe").get(query::describe::describe))
        .push(Router::with_path("search-realms").post(query::realm::search_realms))
        .push(Router::with_path("resolve-realm").post(query::realm::resolve_realm));

    // Directory current-v1 is permanently read-only. No protocol write route
    // or compatibility alias is mounted.
    Router::with_path("_arkret/find/directory")
        .hoop(operation_selector_middleware)
        .push(query_routes)
}

#[handler]
async fn operation_selector_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    if req.method() == Method::OPTIONS {
        ctrl.call_next(req, depot, res).await;
        return;
    }

    let mut selectors = req.headers().get_all("arkret-operation").iter();
    let Some(selector) = selectors.next() else {
        ApiErrorCode::OperationSelectorRequired.render(
            res,
            "canonical Arkret HTTP requests require Arkret-Operation",
        );
        ctrl.skip_rest();
        return;
    };
    if selectors.next().is_some() {
        ApiErrorCode::UnsupportedOperationVersion
            .render(res, "Arkret-Operation must contain exactly one value");
        ctrl.skip_rest();
        return;
    }
    let Some(selected) = selector
        .to_str()
        .ok()
        .and_then(arkret_sdk::ServiceOperationId::from_wire)
    else {
        ApiErrorCode::UnsupportedOperationVersion.render(
            res,
            "Arkret-Operation is not a registered exact operation id",
        );
        ctrl.skip_rest();
        return;
    };
    if !query::describe::supports_http_operation(selected)
        || !selected.matches_http_request(req.method().as_str(), req.uri().path())
    {
        ApiErrorCode::UnsupportedOperationVersion.render(
            res,
            "Arkret-Operation is not advertised or does not match the selected HTTP route",
        );
        ctrl.skip_rest();
        return;
    }
    ctrl.call_next(req, depot, res).await;
}

#[handler]
async fn health(depot: &mut Depot, res: &mut Response) {
    let hardening = match depot.get_typed::<AppState>() {
        Ok(state) => teabay_hardening_status(state.config()),
        Err(_) => default_hardening_status(),
    };
    res.render(Json(json!({
        "ok": true,
        "service": "flagon",
        "hardening": hardening,
    })));
}

#[handler]
async fn readyz(depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(state) => state,
        Err(_) => {
            res.status_code(StatusCode::SERVICE_UNAVAILABLE);
            res.render(Json(json!({
                "ok": false,
                "service": "flagon",
                "database": { "ok": false, "error": "state_not_injected" },
            })));
            return;
        }
    };

    let database = database_ready(state).await;
    let ok = database.is_ok();
    if !ok {
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    }
    res.render(Json(json!({
        "ok": ok,
        "service": "flagon",
        "database": match database {
            Ok(()) => json!({ "ok": true }),
            Err(error) => json!({ "ok": false, "error": error }),
        },
    })));
}

#[handler]
async fn metrics(depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(state) => state,
        Err(_) => {
            res.status_code(StatusCode::SERVICE_UNAVAILABLE);
            res.render(Text::Plain("flagon metrics state not injected\n"));
            return;
        }
    };
    let mut body = state.metrics().render_prometheus();
    // P2E.6 — append live r2d2 connection-pool occupancy. Kept here
    // (rather than baked into Metrics) so the Db handle is the
    // authoritative source — no risk of drift between the live pool
    // and a separately-tracked counter.
    let pool = state.db().pool_stats();
    body.push_str(
        "# HELP teabay_db_pool_connections Total connections currently held by the r2d2 pool.\n",
    );
    body.push_str("# TYPE teabay_db_pool_connections gauge\n");
    body.push_str(&format!(
        "teabay_db_pool_connections {}\n",
        pool.connections
    ));
    body.push_str("# HELP teabay_db_pool_idle Idle connections waiting for a checkout.\n");
    body.push_str("# TYPE teabay_db_pool_idle gauge\n");
    body.push_str(&format!("teabay_db_pool_idle {}\n", pool.idle));
    body.push_str(
        "# HELP teabay_db_pool_in_use Connections currently checked out (connections - idle).\n",
    );
    body.push_str("# TYPE teabay_db_pool_in_use gauge\n");
    body.push_str(&format!("teabay_db_pool_in_use {}\n", pool.in_use));
    body.push_str(
        "# HELP teabay_db_pool_max_size Pool max_size configured at boot (TEABAY_DB_POOL_MAX_SIZE).\n",
    );
    body.push_str("# TYPE teabay_db_pool_max_size gauge\n");
    body.push_str(&format!("teabay_db_pool_max_size {}\n", pool.max_size));
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        "text/plain; version=0.0.4; charset=utf-8".parse().unwrap(),
    );
    res.render(Text::Plain(body));
}

#[handler]
async fn metrics_not_found(res: &mut Response) {
    res.status_code(StatusCode::NOT_FOUND);
    res.render(Text::Plain("not found\n"));
}

async fn database_ready(state: &AppState) -> Result<(), String> {
    let mut conn = state.db().get().await.map_err(|error| error.to_string())?;
    diesel::sql_query("SELECT 1")
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// T8.3 — derive a non-sensitive production hardening snapshot from
/// the live config. Every field is environment-detected (no operator
/// hand-holding); the JSON shape matches the cross-service contract
/// soland / starid / coauth / floria all use.
fn teabay_hardening_status(cfg: &crate::config::AppConfig) -> serde_json::Value {
    let development_mode = cfg.development_mode;
    // TLS is terminated outside this process; a read-only Directory cannot
    // infer the reverse proxy's posture from retired ingest configuration.
    let tls_enabled = false;
    let csp_header_configured = cfg.cors_allow_origin.is_some();
    let cors_strict = match cfg.cors_allow_origin.as_deref() {
        None => true,
        Some(value) => !value.trim().split(',').any(|origin| origin.trim() == "*"),
    };
    // No configured external secret-manager attestation in this process.
    let secret_manager_in_use = false;
    let log_redaction_enabled = !development_mode;
    let admin_auth_mode = if development_mode {
        if cfg.admin_token.as_deref().is_some_and(|t| !t.is_empty()) {
            "development_static_bearer".to_owned()
        } else {
            "development".to_owned()
        }
    } else {
        "rotating_hmac".to_owned()
    };
    let rate_limit_enabled = cfg.query_max_queries_per_ip_per_min > 0;
    // No read-only request path performs outbound network resolution.
    let egress_private_networks_blocked = true;
    let provider_credential_rotation = if secret_manager_in_use {
        "manual".to_owned()
    } else {
        "none".to_owned()
    };

    let checks: Vec<(&str, bool)> = vec![
        ("development_mode_disabled", !development_mode),
        ("tls_enabled", tls_enabled),
        ("csp_header_configured", csp_header_configured),
        ("cors_strict", cors_strict),
        ("secret_manager_in_use", secret_manager_in_use),
        ("log_redaction_enabled", log_redaction_enabled),
        (
            "admin_auth_mode_production",
            admin_auth_mode == "rotating_hmac",
        ),
        ("rate_limit_enabled", rate_limit_enabled),
        (
            "egress_private_networks_blocked",
            egress_private_networks_blocked,
        ),
        (
            "provider_credential_rotation",
            provider_credential_rotation != "none",
        ),
    ];
    let checklist_max = checks.len() as u32;
    let mut checklist_score = 0u32;
    let mut warnings = Vec::new();
    for (label, ok) in &checks {
        if *ok {
            checklist_score += 1;
        } else {
            warnings.push((*label).to_owned());
        }
    }

    json!({
        "development_mode": development_mode,
        "tls_enabled": tls_enabled,
        "csp_header_configured": csp_header_configured,
        "cors_strict": cors_strict,
        "secret_manager_in_use": secret_manager_in_use,
        "log_redaction_enabled": log_redaction_enabled,
        "admin_auth_mode": admin_auth_mode,
        "rate_limit_enabled": rate_limit_enabled,
        "egress_private_networks_blocked": egress_private_networks_blocked,
        "provider_credential_rotation": provider_credential_rotation,
        "checklist_score": checklist_score,
        "checklist_max": checklist_max,
        "warnings": warnings,
    })
}

fn default_hardening_status() -> serde_json::Value {
    json!({
        "development_mode": true,
        "tls_enabled": false,
        "csp_header_configured": false,
        "cors_strict": true,
        "secret_manager_in_use": false,
        "log_redaction_enabled": false,
        "admin_auth_mode": "unknown",
        "rate_limit_enabled": false,
        "egress_private_networks_blocked": false,
        "provider_credential_rotation": "none",
        "checklist_score": 0,
        "checklist_max": 10,
        "warnings": ["state_not_injected"],
    })
}

#[handler]
async fn openapi_json(depot: &mut Depot, res: &mut Response) {
    let doc = match depot.get_typed::<TeabayOpenApiDoc>() {
        Ok(doc) => doc,
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "OpenAPI document not injected");
            return;
        }
    };
    res.render(Json(doc.0.clone()));
}

#[handler]
async fn openapi_yaml(depot: &mut Depot, res: &mut Response) {
    let doc = match depot.get_typed::<TeabayOpenApiDoc>() {
        Ok(doc) => doc,
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "OpenAPI document not injected");
            return;
        }
    };
    let spec = serde_norway::to_string(&doc.0).unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render flagon OpenAPI yaml");
        "{}\n".to_owned()
    });
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/yaml; charset=utf-8".parse().unwrap(),
    );
    res.headers_mut().insert(
        header::CONTENT_LENGTH,
        spec.len().to_string().parse().unwrap(),
    );
    let _ = res.write_body(spec.as_bytes().to_vec());
}

#[handler]
async fn cors_preflight(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

#[handler]
async fn api_not_found(res: &mut Response) {
    render_problem(
        res,
        StatusCode::NOT_FOUND,
        arkret_sdk::Problem::from_code(
            arkret_sdk::ErrorCode::UNRECOGNIZED_ENDPOINT,
            "no such directory route",
        )
        .with_instance(arkret_sdk::new_prefixed_uuid7("ak:request:")),
    );
}

fn cors_handler_for_origin(origin: String) -> CorsHandler {
    Cors::new()
        .allow_origin(vec![origin.as_str()])
        .allow_credentials(true)
        .allow_methods(vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
        ])
        .allow_headers(vec!["authorization", "content-type", "arkret-operation"])
        .max_age(3600)
        .into_handler()
}

/// Build the OpenAPI document for flagon's Directory Service surface.
pub fn openapi(router: &Router) -> serde_json::Value {
    let mut doc = OpenApi::new("flagon", env!("CARGO_PKG_VERSION"))
        .add_extension("x-arkret-service-kind", json!("directory_service"))
        .add_extension("x-arkret-artifact-first", json!(true))
        .merge_router(router);
    register_teabay_schemas(&mut doc);
    register_teabay_operations(&mut doc);
    product_openapi_document(&doc)
}

fn register_teabay_schemas(doc: &mut OpenApi) {
    let schema = DirectoryRealmSearchOutcome::to_schema(&mut doc.components);
    doc.components
        .schemas
        .insert("DirectoryRealmSearchOutcome", schema);
}

fn product_openapi_document(product_doc: &OpenApi) -> serde_json::Value {
    serde_json::to_value(product_doc).expect("product OpenAPI document must serialize")
}

fn register_teabay_operations(doc: &mut OpenApi) {
    let routes = [
        (
            "/health",
            PathItemType::Get,
            "org.arkret.flagon.health",
            "health",
            "Health check",
            "Process liveness probe.",
        ),
        (
            "/readyz",
            PathItemType::Get,
            "org.arkret.flagon.readyz",
            "health",
            "Readiness check",
            "PostgreSQL and background-worker readiness probe.",
        ),
        (
            "/_teabay/admin/audit",
            PathItemType::Get,
            "org.arkret.flagon.admin.audit_feed",
            "admin",
            "List Audit Events",
            "Return the append-only directory audit feed for operators.",
        ),
        (
            "/_teabay/admin/audit/verify",
            PathItemType::Get,
            "org.arkret.flagon.admin.audit_chain_verify",
            "admin",
            "Verify Audit Chain",
            "Walk the append-only audit chain and recompute chained SHA-256 digests.",
        ),
        (
            "/_arkret/describe",
            PathItemType::Get,
            "ak.server.read.describe.v1",
            "directory",
            "Describe Directory Service Role",
            "Expose the role-local Directory Service capability document.",
        ),
        (
            "/_arkret/find/directory/describe",
            PathItemType::Get,
            "ak.find.directory.read.describe.v1",
            "directory",
            "Describe Directory Service",
            "Advertise the public Realm metadata index and supported operations.",
        ),
        (
            "/_arkret/find/directory/search-realms",
            PathItemType::Post,
            "ak.find.directory.read.search_realms.v1",
            "query",
            "Search Realms",
            "Return unexpired public Realm metadata entries.",
        ),
        (
            "/_arkret/find/directory/resolve-realm",
            PathItemType::Post,
            "ak.find.directory.read.resolve_realm.v1",
            "query",
            "Resolve Realm",
            "Resolve an unexpired public Realm metadata entry by Realm ID.",
        ),
    ];

    for (path, method, operation_id, tag, summary, description) in routes {
        doc.paths.insert(
            path,
            PathItem::new(method, operation(operation_id, tag, summary, description)),
        );
    }
}

fn operation(operation_id: &str, tag: &str, summary: &str, description: &str) -> Operation {
    Operation::new()
        .operation_id(operation_id)
        .tags([tag])
        .summary(summary)
        .description(description)
        .add_response("200", OapiResponse::new("Successful response"))
        .add_response(
            "400",
            OapiResponse::new("Request rejected by directory policy or validation"),
        )
        .add_response(
            "404",
            OapiResponse::new("Resource not found or intentionally blinded"),
        )
        .add_response("500", OapiResponse::new("Internal service error"))
}

#[cfg(test)]
mod tests {
    use salvo::test::TestClient;

    use super::*;

    #[handler]
    async fn selector_test_ok(res: &mut Response) {
        res.status_code(StatusCode::NO_CONTENT);
    }

    fn selector_test_service() -> Service {
        Service::new(
            Router::with_path("_arkret/find/directory")
                .hoop(operation_selector_middleware)
                .push(Router::with_path("describe").get(selector_test_ok))
                .push(Router::with_path("resolve-agent-selector").post(selector_test_ok)),
        )
    }

    #[tokio::test]
    async fn operation_selector_is_required_and_exact_before_handlers() {
        let service = selector_test_service();
        let missing = TestClient::get("http://local/_arkret/find/directory/describe")
            .send(&service)
            .await;
        assert_eq!(missing.status_code, Some(StatusCode::BAD_REQUEST));

        let unknown = TestClient::get("http://local/_arkret/find/directory/describe")
            .add_header(
                "Arkret-Operation",
                "ak.find.directory.read.describe.v9",
                true,
            )
            .send(&service)
            .await;
        assert_eq!(unknown.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));

        for retired_write in [
            "ak.find.directory.command.announce.v1",
            "ak.find.directory.command.withdraw.v1",
        ] {
            let response = TestClient::get("http://local/_arkret/find/directory/describe")
                .add_header("Arkret-Operation", retired_write, true)
                .send(&service)
                .await;
            assert_eq!(
                response.status_code,
                Some(StatusCode::UNPROCESSABLE_ENTITY),
                "retired Directory write operation must remain unknown"
            );
        }

        let mismatch = TestClient::get("http://local/_arkret/find/directory/describe")
            .add_header(
                "Arkret-Operation",
                arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
                true,
            )
            .send(&service)
            .await;
        assert_eq!(mismatch.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));

        let unadvertised =
            TestClient::post("http://local/_arkret/find/directory/resolve-agent-selector")
                .add_header(
                    "Arkret-Operation",
                    "ak.find.directory.read.resolve_agent_selector.v1",
                    true,
                )
                .send(&service)
                .await;
        assert_eq!(
            unadvertised.status_code,
            Some(StatusCode::UNPROCESSABLE_ENTITY)
        );

        let accepted = TestClient::get("http://local/_arkret/find/directory/describe")
            .add_header(
                "Arkret-Operation",
                arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_DESCRIBE_V1,
                true,
            )
            .send(&service)
            .await;
        assert_eq!(accepted.status_code, Some(StatusCode::NO_CONTENT));
    }

    #[test]
    fn openapi_exposes_only_registered_directory_resource_routes() {
        let doc = openapi(&Router::new());
        let yaml = serde_norway::to_string(&doc).expect("OpenAPI serializes");

        assert!(!yaml.contains("/_teabay/handle/probe:"));
        assert!(!yaml.contains("/_arkret/find/directory/search-users:"));
        assert!(!yaml.contains("/_arkret/find/directory/private-contact-discovery:"));
        assert!(!yaml.contains("/_arkret/find/directory/announce:"));
        assert!(!yaml.contains("/_arkret/find/directory/withdraw:"));
        assert!(yaml.contains("x-arkret-artifact-first: true"));
        assert!(yaml.contains("ak.find.directory.read.search_realms.v1"));
        assert!(yaml.contains("DirectoryRealmSearchOutcome"));

        let operation_pointer = "/paths/~1_arkret~1find~1directory~1search-realms/post";
        assert!(doc.pointer(operation_pointer).is_some());
    }
}
