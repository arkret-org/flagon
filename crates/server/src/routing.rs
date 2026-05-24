//! Salvo router declaration. All `/api/v1/directory/*` endpoints (spec §9)
//! plus `/health` and OpenAPI metadata.

use std::sync::Arc;

use diesel::RunQueryDsl;
use salvo::affix_state;
use salvo::cors::{Cors, CorsHandler};
use salvo::http::{Method, header};
use salvo::oapi::{OpenApi, Operation, PathItem, PathItemType, Response as OapiResponse};
use salvo::prelude::*;
use serde_json::json;

use crate::error::ApiErrorCode;
use crate::middleware::http_sig::{HttpSigKeyDirectory, HttpSigMiddleware};
use crate::state::{AppState, BackgroundWorker, WorkerReadiness};
use crate::{ingest, query};

#[derive(Clone)]
pub struct TeabayOpenApiDoc(pub OpenApi);

pub fn router(state: AppState) -> Router {
    let cors_origin = state.config().cors_allow_origin.clone();
    let http_sig_middleware = build_http_sig_middleware(&state);
    let directory = directory_router(http_sig_middleware);
    let admin = admin_router();
    let doc = openapi(&directory);

    let mut root = Router::new().hoop(affix_state::inject(state));
    if let Some(origin) = cors_origin {
        root = root.hoop(cors_handler_for_origin(origin));
    }
    root.push(Router::with_path("health").get(health))
        .push(Router::with_path("readyz").get(readyz))
        .push(directory)
        .push(admin)
        .push(doc.clone().into_router(".well-known/contrix/openapi.json"))
        .push(
            Router::with_path(".well-known/contrix/openapi.yaml")
                .hoop(affix_state::inject(TeabayOpenApiDoc(doc)))
                .get(openapi_yaml),
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
fn build_http_sig_middleware(state: &AppState) -> HttpSigMiddleware {
    let directory: Arc<dyn HttpSigKeyDirectory> = Arc::new(state.config().http_sig_key_directory());
    if state.config().require_http_sig {
        HttpSigMiddleware::new(directory)
    } else {
        HttpSigMiddleware::passthrough(directory)
    }
}

pub fn service(state: AppState) -> Service {
    Service::new(router(state))
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
    Router::with_path("api/admin/v1")
        .push(Router::with_path("audit").get(query::admin::audit_feed))
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
        // Round R2/R3 T17 — soland calls this to broadcast a
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
        .push(
            Router::with_path("private-contact-discovery")
                .post(query::psi::private_contact_discovery),
        );

    // Ingest face — §8. Transport hardened by RFC 9421 HTTP Message
    // Signature middleware (TB-1 / `crate::middleware::http_sig`). Every
    // request to `announce`, `withdraw`, or `subscribe` MUST carry a
    // valid Ed25519-signed envelope keyed by a `keyid` in the operator
    // pubkey allowlist; the handler-level 5-step verify chain in
    // `ingest::verify` then runs on top of an already-authenticated
    // transport.
    let ingest_routes = Router::new()
        .hoop(http_sig_middleware)
        .push(Router::with_path("announce").post(ingest::announce::announce))
        .push(Router::with_path("withdraw").post(ingest::withdraw::withdraw))
        .push(Router::with_path("subscribe").post(ingest::subscribe::subscribe));

    Router::with_path("api/v1/directory")
        .push(query_routes)
        .push(ingest_routes)
}

#[handler]
async fn health(depot: &mut Depot, res: &mut Response) {
    let hardening = match depot.obtain::<AppState>() {
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
    let state = match depot.obtain::<AppState>() {
        Ok(state) => state,
        Err(_) => {
            res.status_code(StatusCode::SERVICE_UNAVAILABLE);
            res.render(Json(json!({
                "ok": false,
                "service": "teabay",
                "database": { "ok": false, "error": "state_not_injected" },
                "workers": {},
            })));
            return;
        }
    };

    let database = database_ready(state);
    let pull = state.worker_readiness(BackgroundWorker::Pull);
    let divergence = state.worker_readiness(BackgroundWorker::Divergence);
    let ok = database.is_ok() && pull.ready && divergence.ready;
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
        "workers": {
            "pull": worker_readiness_json(pull),
            "divergence": worker_readiness_json(divergence),
        },
    })));
}

#[handler]
async fn metrics(depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(state) => state,
        Err(_) => {
            res.status_code(StatusCode::SERVICE_UNAVAILABLE);
            res.render(Text::Plain("teabay metrics state not injected\n"));
            return;
        }
    };
    let body = state.metrics().render_prometheus();
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

fn database_ready(state: &AppState) -> Result<(), String> {
    let mut conn = state.db().get().map_err(|error| error.to_string())?;
    diesel::sql_query("SELECT 1")
        .execute(&mut conn)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn worker_readiness_json(readiness: WorkerReadiness) -> serde_json::Value {
    json!({
        "enabled": readiness.enabled,
        "ready": readiness.ready,
        "last_seen_ms_ago": readiness.last_seen_ms_ago,
        "stale_after_ms": readiness.stale_after_ms,
    })
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
    let secret_manager_in_use = !cfg.http_sig_pubkeys.is_empty() || cfg.admin_token.is_some();
    let log_redaction_enabled = !development_mode;
    let admin_auth_mode = if development_mode {
        "development".to_owned()
    } else if cfg.admin_token.as_deref().is_some_and(|t| !t.is_empty()) {
        "production".to_owned()
    } else {
        "closed".to_owned()
    };
    let rate_limit_enabled = cfg.rate_limit_per_resource_per_min > 0;
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
            admin_auth_mode == "production",
        ),
        ("rate_limit_enabled", rate_limit_enabled),
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
        "provider_credential_rotation": "none",
        "checklist_score": 0,
        "checklist_max": 9,
        "warnings": ["state_not_injected"],
    })
}

#[handler]
async fn openapi_yaml(depot: &mut Depot, res: &mut Response) {
    let doc = match depot.obtain::<TeabayOpenApiDoc>() {
        Ok(doc) => doc,
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "OpenAPI document not injected");
            return;
        }
    };
    let spec = doc.0.to_yaml().unwrap_or_else(|error| {
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
    res.status_code(StatusCode::NOT_FOUND);
    res.render(Json(json!({
        "ok": false,
        "error": { "code": "unrecognized_endpoint", "message": "no such directory route" }
    })));
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
        .allow_headers(vec!["authorization", "content-type"])
        .max_age(3600)
        .into_handler()
}

/// Build the OpenAPI document for teabay's Directory Service surface.
pub fn openapi(router: &Router) -> OpenApi {
    let mut doc = OpenApi::new("teabay", env!("CARGO_PKG_VERSION"))
        .add_extension(
            "x-contrix-profile",
            json!({
                "profile": "cx.profile.directory_service.v1",
                "spec": "contrix-spec/spec/v1/zh/discovery/discovery-directory.md",
            }),
        )
        .merge_router(router);
    register_teabay_operations(&mut doc);
    doc
}

fn register_teabay_operations(doc: &mut OpenApi) {
    let routes = [
        (
            "/health",
            PathItemType::Get,
            "teabay.health",
            "health",
            "Health check",
            "Process liveness probe.",
        ),
        (
            "/readyz",
            PathItemType::Get,
            "teabay.readyz",
            "health",
            "Readiness check",
            "PostgreSQL and background-worker readiness probe.",
        ),
        (
            "/api/admin/v1/audit",
            PathItemType::Get,
            "teabay.admin.audit_feed",
            "admin",
            "List Audit Events",
            "Return the append-only directory audit feed for operator dashboards.",
        ),
        (
            "/api/admin/v1/allowlist",
            PathItemType::Get,
            "teabay.admin.allowlist_list",
            "admin",
            "List Allowlist Entries",
            "Return operator-managed accept-policy allowlist entries.",
        ),
        (
            "/api/admin/v1/allowlist",
            PathItemType::Post,
            "teabay.admin.allowlist_upsert",
            "admin",
            "Upsert Allowlist Entry",
            "Add or update an operator-managed accept-policy allowlist entry.",
        ),
        (
            "/api/admin/v1/allowlist",
            PathItemType::Delete,
            "teabay.admin.allowlist_delete",
            "admin",
            "Delete Allowlist Entry",
            "Remove an operator-managed accept-policy allowlist entry.",
        ),
        (
            "/api/admin/v1/resources",
            PathItemType::Get,
            "teabay.admin.resources_browser",
            "admin",
            "Browse Directory Resources",
            "Return indexed resources with kind, stale, divergent, and text filters.",
        ),
        (
            "/api/admin/v1/resources",
            PathItemType::Post,
            "teabay.admin.resource_upsert",
            "admin",
            "Upsert Directory Resource",
            "Create or update an indexed directory resource directly from the operator console.",
        ),
        (
            "/api/admin/v1/resources",
            PathItemType::Delete,
            "teabay.admin.resource_delete",
            "admin",
            "Delete Directory Resource",
            "Remove an indexed directory resource directly from the operator console.",
        ),
        (
            "/api/admin/v1/takedown",
            PathItemType::Post,
            "teabay.admin.operator_takedown",
            "admin",
            "Operator Takedown",
            "Admin-only operator takedown path for §8.7 path 3.",
        ),
        (
            "/api/v1/directory/describe",
            PathItemType::Get,
            "cx.directory.describe",
            "directory",
            "Describe Directory Service",
            "Expose ingest modes, accept policy, TTL limits, and resource kind support.",
        ),
        (
            "/api/v1/directory/search-realms",
            PathItemType::Post,
            "cx.directory.search_realms",
            "query",
            "Search Realms",
            "Return listed/public Realm directory results using the §9.1 result envelope.",
        ),
        (
            "/api/v1/directory/resolve-realm",
            PathItemType::Post,
            "cx.directory.resolve_realm",
            "query",
            "Resolve Realm",
            "Resolve a Realm by ID, alias, invite token, or signed link with blinded misses.",
        ),
        (
            "/api/v1/directory/search-organizations",
            PathItemType::Post,
            "cx.directory.search_organizations",
            "query",
            "Search Organizations",
            "Return public/listed Organization directory results.",
        ),
        (
            "/api/v1/directory/resolve-organization",
            PathItemType::Post,
            "cx.directory.resolve_organization",
            "query",
            "Resolve Organization",
            "Resolve an Organization discovery record with hidden rows collapsed to not_found.",
        ),
        (
            "/api/v1/directory/search-actors",
            PathItemType::Post,
            "cx.directory.search_actors",
            "query",
            "Search Actors",
            "Return public Actor discovery records.",
        ),
        (
            "/api/v1/directory/search-users",
            PathItemType::Post,
            "cx.directory.search_users",
            "query",
            "Search Users",
            "Realm-gated user search using indexed membership hints.",
        ),
        (
            "/api/v1/directory/resolve-handle",
            PathItemType::Post,
            "cx.directory.resolve_handle",
            "query",
            "Resolve Handle",
            "Resolve handle discovery resources with the Directory result envelope.",
        ),
        (
            "/api/v1/directory/private-contact-discovery",
            PathItemType::Post,
            "cx.directory.private_contact_discovery",
            "query",
            "Private Contact Discovery",
            "RFC 9497 VOPRF two-phase private contact discovery.",
        ),
        (
            "/api/v1/directory/announce",
            PathItemType::Post,
            "cx.directory.announce",
            "ingest",
            "Announce Discovery State",
            "Push-mode ingest for signed cx.{kind}.discovery state.",
        ),
        (
            "/api/v1/directory/withdraw",
            PathItemType::Post,
            "cx.directory.withdraw",
            "ingest",
            "Withdraw Discovery State",
            "Resource-initiated withdrawal path that removes the indexed row and writes audit.",
        ),
        (
            "/api/v1/directory/subscribe",
            PathItemType::Post,
            "cx.directory.push.register",
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
