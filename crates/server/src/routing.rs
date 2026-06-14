//! Salvo router declaration. All `/_cokret/find/directory/*` endpoints (spec §9)
//! plus `/health` and OpenAPI metadata.

use std::sync::Arc;

use cokret_sdk::DirectoryRealmSearchOutcome;
use diesel_async::RunQueryDsl;
use salvo::affix_state;
use salvo::cors::{Cors, CorsHandler};
use salvo::http::{Method, header};
use salvo::oapi::{
    Components, Content, OpenApi, Operation, PathItem, PathItemType, Response as OapiResponse,
    ToSchema,
};
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
        .push(Router::with_path("healthz").get(health))
        .push(Router::with_path("readyz").get(readyz))
        .push(directory)
        .push(admin)
        .push(doc.clone().into_router(".well-known/cokret/openapi.json"))
        .push(
            Router::with_path(".well-known/cokret/openapi.yaml")
                .hoop(affix_state::inject(TeabayOpenApiDoc(doc)))
                .get(openapi_yaml),
        )
        // CKP R3 spec-sync 2026-05-27 (commit b47ff6e), identity-handles
        // §17 — canonical well-known handle endpoint. The query takes
        // `?localpart=<localpart>` and returns the same Directory result
        // envelope shape that `POST /_cokret/find/directory/resolve-handle`
        // emits. Wire-level NFC + UTS#39 + script-mixed checks run on
        // the localpart before any DB lookup. We intentionally implement
        // this as a *proxy* into `query::handle::resolve_handle` so the
        // anti-enumeration latency-floor + jitter and the `not_found`
        // collapse behaviour stay identical across the two surfaces.
        .push(
            Router::with_path(".well-known/cokret/handle")
                .get(query::handle::well_known_resolve_handle),
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
        HttpSigMiddleware::new_with_postgres_replay_store(directory, state.db().clone())
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
    Router::with_path("_teabay/admin")
        .hoop(crate::middleware::AdminAuthHoop)
        .push(Router::with_path("dashboard").get(query::admin::dashboard_stats))
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
        // B.8.6 — operator-facing export of every takedown row, for
        // legal / ops review. Bearer-auth same as the rest of admin.
        .push(Router::with_path("takedowns").get(query::admin::takedown_audit_export))
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
        // R3.3 (CKP-0011, cokret-spec @ cced4b8) — object-level resolve.
        // Generalization of resolve-realm to a client-agnostic shareable
        // address (Realm / Flow / Message). Realm resolution DELEGATES to the
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
        // R3.2 (DIR-TBY-1, cokret-spec @ b56cab1) — reverse handle lookup.
        // Inverse of `resolve-handle`: known holder/principal DID + context
        // → currently-visible handle claims + primary handle. Read-only
        // against the indexed view; visibility is decided per-claim by the
        // disclosure-policy + issuer-trust + audience filters in the query
        // handler (no transport signature required, same as the other query
        // routes). The mention renderer's live-resolve path consumes this.
        .push(
            Router::with_path("list-handles-for-subject")
                .post(query::handles_for_subject::list_handles_for_subject),
        )
        .push(
            Router::with_path("private-contact-discovery")
                .post(query::psi::private_contact_discovery),
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

    Router::with_path("_cokret/find/directory")
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

    let database = database_ready(state).await;
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
    // SSRF egress posture: are private/link-local targets blocked? This honours
    // the `TEABAY_EGRESS_ALLOW_PRIVATE_NETWORKS` override, not just dev mode, so
    // a stale override is visible in the hardening snapshot.
    let egress_private_networks_blocked =
        !crate::egress::private_networks_allowed(development_mode);
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
            "x-cokret-profile",
            json!({
                "profile": "ck.profile.directory_service.v1",
                "spec": "cokret-spec/spec/v1/zh/discovery/discovery-directory.md",
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
            "/_teabay/admin/dashboard",
            PathItemType::Get,
            "teabay.admin.dashboard_stats",
            "admin",
            "Directory Dashboard Stats",
            "Return aggregate counts (resources / announces / subscriptions / audit) for the operator dashboard.",
        ),
        (
            "/_teabay/admin/audit",
            PathItemType::Get,
            "teabay.admin.audit_feed",
            "admin",
            "List Audit Events",
            "Return the append-only directory audit feed for operator dashboards.",
        ),
        (
            "/_teabay/admin/allowlist",
            PathItemType::Get,
            "teabay.admin.allowlist_list",
            "admin",
            "List Allowlist Entries",
            "Return operator-managed accept-policy allowlist entries.",
        ),
        (
            "/_teabay/admin/allowlist",
            PathItemType::Post,
            "teabay.admin.allowlist_upsert",
            "admin",
            "Upsert Allowlist Entry",
            "Add or update an operator-managed accept-policy allowlist entry.",
        ),
        (
            "/_teabay/admin/allowlist",
            PathItemType::Delete,
            "teabay.admin.allowlist_delete",
            "admin",
            "Delete Allowlist Entry",
            "Remove an operator-managed accept-policy allowlist entry.",
        ),
        (
            "/_teabay/admin/resources",
            PathItemType::Get,
            "teabay.admin.resources_browser",
            "admin",
            "Browse Directory Resources",
            "Return indexed resources with kind, stale, divergent, and text filters.",
        ),
        (
            "/_teabay/admin/resources",
            PathItemType::Post,
            "teabay.admin.resource_upsert",
            "admin",
            "Upsert Directory Resource",
            "Create or update an indexed directory resource directly from the operator console.",
        ),
        (
            "/_teabay/admin/resources",
            PathItemType::Delete,
            "teabay.admin.resource_delete",
            "admin",
            "Delete Directory Resource",
            "Remove an indexed directory resource directly from the operator console.",
        ),
        (
            "/_teabay/admin/takedown",
            PathItemType::Post,
            "teabay.admin.operator_takedown",
            "admin",
            "Operator Takedown",
            "Admin-only operator takedown path for §8.7 path 3.",
        ),
        (
            "/_teabay/admin/takedowns",
            PathItemType::Get,
            "teabay.admin.takedown_audit_export",
            "admin",
            "Export Takedown Audit",
            "Return every operator-takedown audit row within an optional `since` / `until` window.",
        ),
        (
            "/_cokret/find/directory/describe",
            PathItemType::Get,
            "ck.find.directory.query.describe",
            "directory",
            "Describe Directory Service",
            "Expose ingest modes, accept policy, TTL limits, and resource kind support.",
        ),
        (
            "/_cokret/find/directory/search-realms",
            PathItemType::Post,
            "ck.find.directory.query.search_realms",
            "query",
            "Search Realms",
            "Return listed/public Realm directory results using the §9.1 result envelope.",
        ),
        (
            "/_cokret/find/directory/resolve-realm",
            PathItemType::Post,
            "ck.find.directory.query.resolve_realm",
            "query",
            "Resolve Realm",
            "Resolve a Realm by ID, alias, invite token, or signed link with blinded misses.",
        ),
        (
            // R3.3 (CKP-0011, cokret-spec @ cced4b8) — object-level resolve.
            // The object-level generalization of resolve-realm: resolves a
            // client-agnostic shareable object address (Realm / Flow / Message)
            // to a target_kind + preview, binding an invite token to the
            // resolved object. Realm resolution delegates to resolve_realm.
            "/_cokret/find/directory/resolve-target",
            PathItemType::Post,
            "ck.find.directory.query.resolve_target",
            "query",
            "Resolve Target",
            "Resolve a client-agnostic shareable object address (Realm / Flow / Message) to a \
             target_kind + (realm_preview | object_preview) + join_rule with blinded misses. \
             Invite tokens must carry an Ed25519 detached JWS and are bound to the resolved \
             object via the target digest so a token cannot be replayed across objects.",
        ),
        (
            "/_cokret/find/directory/search-organizations",
            PathItemType::Post,
            "ck.find.directory.query.search_organizations",
            "query",
            "Search Organizations",
            "Return public/listed Organization directory results.",
        ),
        (
            "/_cokret/find/directory/resolve-organization",
            PathItemType::Post,
            "ck.find.directory.query.resolve_organization",
            "query",
            "Resolve Organization",
            "Resolve an Organization discovery record with hidden rows collapsed to not_found.",
        ),
        (
            "/_cokret/find/directory/search-actors",
            PathItemType::Post,
            "ck.find.directory.query.search_actors",
            "query",
            "Search Actors",
            "Return public Actor discovery records.",
        ),
        (
            "/_cokret/find/directory/search-users",
            PathItemType::Post,
            "ck.find.directory.query.search_users",
            "query",
            "Search Users",
            "Realm-gated user search using indexed membership hints.",
        ),
        (
            "/_cokret/find/directory/resolve-handle",
            PathItemType::Post,
            "ck.find.directory.query.resolve_handle",
            "query",
            "Resolve Handle",
            "Resolve handle discovery resources with the Directory result envelope.",
        ),
        (
            // CKP R3 spec-sync 2026-05-27 (commit b47ff6e) — well-known
            // handle endpoint. Query-string keyed (`?localpart=<localpart>`).
            "/.well-known/cokret/handle",
            PathItemType::Get,
            // Local (non-protocol) operation id. The spec defines the endpoint
            // path (identity-handles §17) but assigns no `ck.` operation id; the
            // `ck.` prefix is reserved for spec-pinned, registry-listed operations
            // (operation-registry.json). Use a reverse-domain local identifier so
            // we don't squat the protocol namespace with an unregistered id.
            "org.cokret.teabay.well_known_handle",
            "query",
            "Well-Known Handle Resolve",
            "Resolve a handle by `?localpart=<localpart>` (identity-handles §17). \
             Returns the standard Directory result envelope; rejects homograph / \
             script-mixed localparts with `handle_homograph_forbidden`.",
        ),
        (
            // R3.2 (DIR-TBY-1, cokret-spec @ b56cab1) — reverse handle
            // lookup. Response shape `ck.schema.list_handles_for_subject_response.v1`.
            "/_cokret/find/directory/list-handles-for-subject",
            PathItemType::Post,
            "ck.find.directory.query.list_handles_for_subject",
            "query",
            "List Handles For Subject",
            "Resolve a known holder/principal DID to its currently-visible handle claims \
             and primary handle (inverse of resolve-handle). Rejects non-principal \
             subjects (ck:actor:/ck:account:/service DID) with failed_precondition.",
        ),
        (
            "/_cokret/find/directory/private-contact-discovery",
            PathItemType::Post,
            "ck.find.directory.query.private_contact_discovery",
            "query",
            "Private Contact Discovery",
            "RFC 9497 VOPRF two-phase private contact discovery.",
        ),
        (
            "/_cokret/find/directory/announce",
            PathItemType::Post,
            "ck.find.directory.command.announce",
            "ingest",
            "Announce Discovery State",
            "Push-mode ingest for signed ck.{kind}.discovery state.",
        ),
        (
            "/_cokret/find/directory/withdraw",
            PathItemType::Post,
            "ck.find.directory.command.withdraw",
            "ingest",
            "Withdraw Discovery State",
            "Resource-initiated withdrawal path that removes the indexed row and writes audit.",
        ),
        (
            "/_cokret/find/directory/push/register",
            PathItemType::Post,
            "ck.find.directory.push.command.register",
            "ingest",
            "Subscribe To Directory Updates",
            "Register an HMAC-signed webhook subscription for accepted ingest updates.",
        ),
    ];

    for (path, method, operation_id, tag, summary, description) in routes {
        doc.paths.insert(
            path,
            PathItem::new(
                method,
                operation(operation_id, tag, summary, description, &mut doc.components),
            ),
        );
    }
}

fn operation(
    operation_id: &str,
    tag: &str,
    summary: &str,
    description: &str,
    components: &mut Components,
) -> Operation {
    Operation::new()
        .operation_id(operation_id)
        .tags([tag])
        .summary(summary)
        .description(description)
        .add_response("200", success_response(operation_id, components))
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

fn success_response(operation_id: &str, components: &mut Components) -> OapiResponse {
    match operation_id {
        "ck.find.directory.query.search_realms" => OapiResponse::new("Authorized Realm search")
            .add_content(
                "application/json",
                Content::new(DirectoryRealmSearchOutcome::to_schema(components)),
            ),
        _ => OapiResponse::new("Successful response"),
    }
}
