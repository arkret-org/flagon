//! Salvo router declaration. All `/_arkret/find/directory/*` endpoints (spec §9)
//! plus `/health` and OpenAPI metadata.

use std::sync::Arc;

use arkret_models_discovery::{
    DirectoryPrivateContactDiscoveryOutcome, DirectoryPrivateContactDiscoveryRequestBody,
    DirectoryRealmSearchOutcome, PsiPaddedProblem,
};
use diesel_async::RunQueryDsl;
use salvo::affix_state;
use salvo::cors::{Cors, CorsHandler};
use salvo::http::{Method, header};
use salvo::oapi::{OpenApi, Operation, PathItem, PathItemType, Response as OapiResponse, ToSchema};
use salvo::prelude::*;
use serde_json::json;

use crate::error::{ApiErrorCode, render_problem};
use crate::middleware::http_sig::{HttpSigKeyDirectory, HttpSigMiddleware};
use crate::state::AppState;
use crate::{ingest, query};

#[derive(Clone)]
pub struct TeabayOpenApiDoc(pub serde_json::Value);

pub fn router(state: AppState) -> Router {
    let cors_origin = state.config().cors_allow_origin.clone();
    // DID-P0-C01 — one key directory, built once for the ingest middleware.
    // It points at the single `AppState` resolver and therefore shares its
    // connection pool and document cache.
    let key_directory = http_sig_key_directory(&state);
    let http_sig_middleware = build_http_sig_middleware(&state, key_directory);
    let directory = directory_router(http_sig_middleware);
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
            // Product-private resolver probe. `/.well-known/arkret/handle`
            // is reserved by the spec for signed issuer_id claims, so teabay's
            // unsigned directory index probe must stay under `/_teabay`.
            Router::with_path("_teabay/handle/probe").get(query::handle::private_handle_probe),
        )
        .push(
            Router::with_path("{**rest}")
                .options(cors_preflight)
                .get(api_not_found),
        )
}

/// Construct the [`HttpSigMiddleware`] for this state. Pulls the
/// `keyid → Ed25519 pubkey` allowlist from `AppConfig` and toggles
/// enforcement based on `require_http_sig`. Always returns a middleware
/// instance so the ingest sub-router has a single, predictable shape —
/// the passthrough variant lets the in-process conformance harness
/// post unsigned envelopes while keeping the route topology identical.
fn http_sig_key_directory(state: &AppState) -> Arc<dyn HttpSigKeyDirectory> {
    Arc::new(
        state
            .config()
            .http_sig_key_directory(Arc::clone(state.did_resolver())),
    )
}

fn build_http_sig_middleware(
    state: &AppState,
    directory: Arc<dyn HttpSigKeyDirectory>,
) -> HttpSigMiddleware {
    if state.config().require_http_sig {
        HttpSigMiddleware::new_with_postgres_replay_store(directory, state.db().clone())
    } else {
        HttpSigMiddleware::passthrough(directory)
    }
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
        .push(Router::with_path("dashboard").get(query::admin::dashboard_stats))
        .push(Router::with_path("audit").get(query::admin::audit_feed))
        .push(Router::with_path("audit/verify").get(query::admin::audit_chain_verify))
        .push(
            Router::with_path("allowlist")
                .get(query::admin::allowlist_list)
                .post(query::admin::allowlist_upsert)
                .delete(query::admin::allowlist_delete),
        )
        .push(
            Router::with_path("resources")
                .get(query::admin::resources_browser)
                .post(query::admin::resource_upsert)
                .delete(query::admin::resource_delete),
        )
        .push(Router::with_path("takedown").post(ingest::operator::operator_takedown))
        // B.8.6 — operator-facing export of every takedown row, for
        // legal / ops review. Bearer-auth same as the rest of admin.
        .push(Router::with_path("takedowns").get(query::admin::takedown_audit_export))
        // soland calls this to broadcast a
        // `consent_revoke{scope=any}` and trigger eager directory
        // reachability invalidation. Bearer auth, admin-only.
        .push(Router::with_path("consent-revoke").post(query::admin::consent_revoke_invalidate))
}

fn directory_router(http_sig_middleware: HttpSigMiddleware) -> Router {
    // Query face — no transport signature required (search/resolve are
    // read-only against the indexed view, and CORS / auth gating is
    // handled per-handler where applicable).
    let query_routes = Router::new()
        .push(Router::with_path("describe").get(query::describe::describe))
        .push(Router::with_path("search-realms").post(query::realm::search_realms))
        .push(Router::with_path("resolve-realm").post(query::realm::resolve_realm))
        // R3.3 (AKP-0011, arkret-spec @ cced4b8) — object-level resolve.
        // Generalization of resolve-realm to a client-agnostic shareable
        // address (Realm / Strand / Message). Realm resolution DELEGATES to the
        // resolve_realm logic; invite tokens are bound to the resolved object
        // via the SDK `target_digest` so a token cannot be replayed across
        // objects. Same anti-enumeration latency floor + jitter + blinded
        // not_found as resolve-realm.
        .push(Router::with_path("resolve-target").post(query::target::resolve_target))
        .push(
            Router::with_path("search-organizations")
                .post(query::organization::search_organizations),
        )
        .push(
            Router::with_path("resolve-organization")
                .post(query::organization::resolve_organization),
        )
        .push(Router::with_path("search-actors").post(query::actor::search_actors))
        .push(Router::with_path("search-users").post(query::actor::search_users))
        .push(Router::with_path("resolve-handle").post(query::handle::resolve_handle))
        // R3.2 (DIR-TBY-1, arkret-spec @ b56cab1) — reverse handle lookup.
        // Inverse of `resolve-handle`: known holder/principal DID + context
        // → currently-visible handle claims + primary handle. Read-only
        // against the indexed view; visibility is decided per-claim by the
        // disclosure-policy + issuer_id-trust + audience filters in the query
        // handler (no transport signature required, same as the other query
        // routes). The mention renderer's live-resolve path consumes this.
        .push(
            Router::with_path("list-handles-for-subject")
                .post(query::handles_for_subject::list_handles_for_subject),
        )
        .push(
            Router::with_path("private-contact-discovery")
                .post(crate::pcd::private_contact_discovery),
        );

    // Ingest face — §8. Transport hardened by RFC 9421 HTTP Message
    // Signature middleware (TB-1 / `crate::middleware::http_sig`). Every
    // request to `announce`, `withdraw`, or `push/register` MUST carry a
    // valid Ed25519-signed envelope keyed by a `keyid` in the operator
    // pubkey allowlist; the handler-level 5-step verify chain in
    // `ingest::verify` then runs on top of an already-authenticated
    // transport.
    let ingest_routes = Router::new()
        .hoop(http_sig_middleware)
        .push(Router::with_path("announce").post(ingest::announce::announce))
        .push(Router::with_path("withdraw").post(ingest::withdraw::withdraw))
        .push(Router::with_path("push/register").post(ingest::subscribe::subscribe));

    Router::with_path("_arkret/find/directory")
        .hoop(operation_selector_middleware)
        .push(query_routes)
        .push(ingest_routes)
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
    let private_contact_discovery_active = depot
        .get_typed::<AppState>()
        .ok()
        .and_then(AppState::private_contact_discovery)
        .is_some();
    if !query::describe::supports_http_operation(selected, private_contact_discovery_active)
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
        "service": "teabay",
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
                "service": "teabay",
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
        "service": "teabay",
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
            res.render(Text::Plain("teabay metrics state not injected\n"));
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
    // teabay terminates TLS at a reverse proxy; we can't probe the
    // listener from in-process. `require_http_sig` (RFC 9421 HTTP
    // Message Signature middleware) is the closest in-process signal
    // that the deployment is hardened against unsigned ingest.
    let tls_enabled = !development_mode && cfg.require_http_sig;
    let csp_header_configured = cfg.cors_allow_origin.is_some();
    let cors_strict = match cfg.cors_allow_origin.as_deref() {
        None => true,
        Some(value) => !value.trim().split(',').any(|origin| origin.trim() == "*"),
    };
    // No external secret manager; `http_sig_pubkeys` is the closest
    // in-process surface that the operator has wired keys in
    // somewhere outside source.
    let secret_manager_in_use = !cfg.http_sig_pubkeys.is_empty();
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
    let rate_limit_enabled = cfg.rate_limit_per_resource_per_min > 0;
    // Local development admits loopback only; private and link-local targets
    // remain blocked in every mode.
    let egress_private_networks_blocked =
        !crate::egress::local_development_enabled(development_mode);
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
        tracing::error!(%error, "failed to render teabay OpenAPI yaml");
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

/// Build the OpenAPI document for teabay's Directory Service surface.
pub fn openapi(router: &Router) -> serde_json::Value {
    let mut doc = OpenApi::new("teabay", env!("CARGO_PKG_VERSION"))
        .add_extension("x-arkret-service-kind", json!("directory_service"))
        .add_extension("x-arkret-artifact-first", json!(true))
        .merge_router(router);
    register_teabay_schemas(&mut doc);
    register_teabay_operations(&mut doc);
    product_openapi_document(&doc)
}

fn register_teabay_schemas(doc: &mut OpenApi) {
    for (name, schema) in [
        (
            "DirectoryRealmSearchOutcome",
            DirectoryRealmSearchOutcome::to_schema(&mut doc.components),
        ),
        (
            "DirectoryPrivateContactDiscoveryRequestBody",
            DirectoryPrivateContactDiscoveryRequestBody::to_schema(&mut doc.components),
        ),
        (
            "DirectoryPrivateContactDiscoveryOutcome",
            DirectoryPrivateContactDiscoveryOutcome::to_schema(&mut doc.components),
        ),
        (
            "PsiPaddedProblem",
            PsiPaddedProblem::to_schema(&mut doc.components),
        ),
    ] {
        doc.components.schemas.insert(name, schema);
    }
}

fn product_openapi_document(product_doc: &OpenApi) -> serde_json::Value {
    serde_json::to_value(product_doc).expect("product OpenAPI document must serialize")
}

fn register_teabay_operations(doc: &mut OpenApi) {
    let routes = [
        (
            "/health",
            PathItemType::Get,
            "org.arkret.teabay.health",
            "health",
            "Health check",
            "Process liveness probe.",
        ),
        (
            "/readyz",
            PathItemType::Get,
            "org.arkret.teabay.readyz",
            "health",
            "Readiness check",
            "PostgreSQL and background-worker readiness probe.",
        ),
        (
            "/_teabay/admin/dashboard",
            PathItemType::Get,
            "org.arkret.teabay.admin.dashboard_stats",
            "admin",
            "Directory Dashboard Stats",
            "Return aggregate counts (resources / announces / subscriptions / audit) for the operator dashboard.",
        ),
        (
            "/_teabay/admin/audit",
            PathItemType::Get,
            "org.arkret.teabay.admin.audit_feed",
            "admin",
            "List Audit Events",
            "Return the append-only directory audit feed for operator dashboards.",
        ),
        (
            "/_teabay/admin/audit/verify",
            PathItemType::Get,
            "org.arkret.teabay.admin.audit_chain_verify",
            "admin",
            "Verify Audit Chain",
            "Walk the append-only audit chain and recompute chained SHA-256 digests.",
        ),
        (
            "/_teabay/admin/allowlist",
            PathItemType::Get,
            "org.arkret.teabay.admin.allowlist_list",
            "admin",
            "List Allowlist Entries",
            "Return operator-managed accept-policy allowlist entries.",
        ),
        (
            "/_teabay/admin/allowlist",
            PathItemType::Post,
            "org.arkret.teabay.admin.allowlist_upsert",
            "admin",
            "Upsert Allowlist Entry",
            "Add or update an operator-managed accept-policy allowlist entry.",
        ),
        (
            "/_teabay/admin/allowlist",
            PathItemType::Delete,
            "org.arkret.teabay.admin.allowlist_delete",
            "admin",
            "Delete Allowlist Entry",
            "Remove an operator-managed accept-policy allowlist entry.",
        ),
        (
            "/_teabay/admin/resources",
            PathItemType::Get,
            "org.arkret.teabay.admin.resources_browser",
            "admin",
            "Browse Directory Resources",
            "Return indexed resources with kind, stale, divergent, and text filters.",
        ),
        (
            "/_teabay/admin/resources",
            PathItemType::Post,
            "org.arkret.teabay.admin.resource_upsert",
            "admin",
            "Upsert Directory Resource",
            "Create or update an indexed directory resource directly from the operator console.",
        ),
        (
            "/_teabay/admin/resources",
            PathItemType::Delete,
            "org.arkret.teabay.admin.resource_delete",
            "admin",
            "Delete Directory Resource",
            "Remove an indexed directory resource directly from the operator console.",
        ),
        (
            "/_teabay/admin/takedown",
            PathItemType::Post,
            "org.arkret.teabay.admin.operator_takedown",
            "admin",
            "Operator Takedown",
            "Admin-only operator takedown path for §8.7 path 3.",
        ),
        (
            "/_teabay/admin/takedowns",
            PathItemType::Get,
            "org.arkret.teabay.admin.takedown_audit_export",
            "admin",
            "Export Takedown Audit",
            "Return every operator-takedown audit row within an optional `since` / `until` window.",
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
            "Expose ingest modes, accept policy, TTL limits, and resource kind support.",
        ),
        (
            "/_arkret/find/directory/search-realms",
            PathItemType::Post,
            "ak.find.directory.read.search_realms.v1",
            "query",
            "Search Realms",
            "Return listed/public Realm directory results using the §9.1 result envelope.",
        ),
        (
            "/_arkret/find/directory/resolve-realm",
            PathItemType::Post,
            "ak.find.directory.read.resolve_realm.v1",
            "query",
            "Resolve Realm",
            "Resolve a Realm by ID, alias, invite token, or signed link with blinded misses.",
        ),
        (
            // R3.3 (AKP-0011, arkret-spec @ cced4b8) — object-level resolve.
            // The object-level generalization of resolve-realm: resolves a
            // client-agnostic shareable object address (Realm / Strand / Message)
            // to a target_kind + preview, binding an invite token to the
            // resolved object. Realm resolution delegates to resolve_realm.
            "/_arkret/find/directory/resolve-target",
            PathItemType::Post,
            "ak.find.directory.read.resolve_target.v1",
            "query",
            "Resolve Target",
            "Resolve a client-agnostic shareable object address (Realm / Strand / Message) to a \
             target_kind + (realm_preview | object_preview) + join_rule with blinded misses. \
             Invite tokens must carry an Ed25519 detached JWS and are bound to the resolved \
             object via the target digest so a token cannot be replayed across objects.",
        ),
        (
            "/_arkret/find/directory/search-organizations",
            PathItemType::Post,
            "ak.find.directory.read.search_organizations.v1",
            "query",
            "Search Organizations",
            "Return public/listed Organization directory results.",
        ),
        (
            "/_arkret/find/directory/resolve-organization",
            PathItemType::Post,
            "ak.find.directory.read.resolve_organization.v1",
            "query",
            "Resolve Organization",
            "Resolve an Organization discovery record with hidden rows collapsed to not_found.",
        ),
        (
            "/_arkret/find/directory/search-actors",
            PathItemType::Post,
            "ak.find.directory.read.search_actors.v1",
            "query",
            "Search Actors",
            "Return public Actor discovery records.",
        ),
        (
            "/_arkret/find/directory/search-users",
            PathItemType::Post,
            "ak.find.directory.read.search_users.v1",
            "query",
            "Search Users",
            "Realm-gated user search using indexed membership hints.",
        ),
        (
            "/_arkret/find/directory/resolve-handle",
            PathItemType::Post,
            "ak.find.directory.read.resolve_handle.v1",
            "query",
            "Resolve Handle",
            "Resolve handle discovery resources with the Directory result envelope.",
        ),
        (
            "/_teabay/handle/probe",
            PathItemType::Get,
            "org.arkret.teabay.handle_probe",
            "query",
            "Private Handle Probe",
            "Product-private resolver/index probe by `?localpart=<localpart>` and optional \
             `?domain=<domain>`. This endpoint returns the Directory result envelope and is \
             not the spec-pinned signed issuer_id channel `/.well-known/arkret/handle`.",
        ),
        (
            // R3.2 (DIR-TBY-1, arkret-spec @ b56cab1) — reverse handle
            // lookup. Response shape `ak.schema.list_handles_for_subject_response.v1`.
            "/_arkret/find/directory/list-handles-for-subject",
            PathItemType::Post,
            "ak.find.directory.read.list_handles_for_subject.v1",
            "query",
            "List Handles For Subject",
            "Resolve a known holder/principal DID to its currently-visible handle claims \
             and primary handle (inverse of resolve-handle). Rejects non-principal \
             subjects (ak:actor:/ak:account:/service DID) with failed_precondition.",
        ),
        (
            "/_arkret/find/directory/private-contact-discovery",
            PathItemType::Post,
            "ak.find.directory.read.private_contact_discovery.v1",
            "query",
            "Private Contact Discovery",
            "Run one fixed-cardinality RFC 9497 modeVOPRF blind or match phase with an exact padded response bucket.",
        ),
        (
            "/_arkret/find/directory/announce",
            PathItemType::Post,
            "ak.find.directory.command.announce.v1",
            "ingest",
            "Announce Discovery State",
            "Push-mode ingest for signed ak.{kind}.discovery state.",
        ),
        (
            "/_arkret/find/directory/withdraw",
            PathItemType::Post,
            "ak.find.directory.command.withdraw.v1",
            "ingest",
            "Withdraw Discovery State",
            "Resource-initiated withdrawal path that removes the indexed row and writes audit.",
        ),
        (
            "/_arkret/find/directory/push/register",
            PathItemType::Post,
            "ak.find.directory.push.command.register.v1",
            "ingest",
            "Subscribe To Directory Updates",
            "Register an HMAC-signed webhook subscription for accepted ingest updates.",
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
                    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_AGENT_SELECTOR_V1,
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
    fn openapi_keeps_unsigned_handle_probe_off_well_known_surface() {
        let doc = openapi(&Router::new());
        let yaml = serde_norway::to_string(&doc).expect("OpenAPI serializes");

        assert!(yaml.contains("/_teabay/handle/probe:"));
        assert!(yaml.contains("org.arkret.teabay.handle_probe"));
        assert!(!yaml.contains("/.well-known/arkret/handle:"));
        assert!(!yaml.contains("org.arkret.teabay.well_known_handle"));
        assert!(yaml.contains("x-arkret-artifact-first: true"));
        assert!(yaml.contains("ak.find.directory.read.search_realms.v1"));
        assert!(yaml.contains("DirectoryRealmSearchOutcome"));

        let operation_pointer = "/paths/~1_arkret~1find~1directory~1search-realms/post";
        assert!(doc.pointer(operation_pointer).is_some());
    }
}
