//! Salvo router declaration. All `/api/v1/directory/*` endpoints (spec §9)
//! plus `/health` and OpenAPI metadata.

use contrix_sdk::salvo_adapter::register_contrix_oapi_components;
use salvo::affix_state;
use salvo::cors::{Cors, CorsHandler};
use salvo::http::{Method, header};
use salvo::oapi::{OpenApi, Operation, PathItem, PathItemType, Response as OapiResponse};
use salvo::prelude::*;
use serde_json::json;

use crate::{error::ErrorCode, ingest, query, state::AppState};

#[derive(Clone)]
pub struct ChadexOpenApiDoc(pub OpenApi);

pub fn router(state: AppState) -> Router {
    let cors_origin = state.config().cors_allow_origin.clone();
    let directory = directory_router();
    let doc = openapi(&directory);

    let mut root = Router::new().hoop(affix_state::inject(state));
    if let Some(origin) = cors_origin {
        root = root.hoop(cors_handler_for_origin(origin));
    }
    root.push(Router::with_path("health").get(health))
        .push(directory)
        .push(doc.clone().into_router(".well-known/contrix/openapi.json"))
        .push(
            Router::with_path(".well-known/contrix/openapi.yaml")
                .hoop(affix_state::inject(ChadexOpenApiDoc(doc)))
                .get(openapi_yaml),
        )
        .push(
            Router::with_path("{**rest}")
                .options(cors_preflight)
                .get(api_not_found),
        )
}

pub fn service(state: AppState) -> Service {
    Service::new(router(state))
}

fn directory_router() -> Router {
    Router::with_path("api/v1/directory")
        .push(Router::with_path("describe").get(query::describe::describe))
        .push(Router::with_path("search-spaces").post(query::space::search_spaces))
        .push(Router::with_path("resolve-space").post(query::space::resolve_space))
        .push(
            Router::with_path("search-organizations")
                .post(query::organization::search_organizations),
        )
        .push(
            Router::with_path("resolve-organization")
                .post(query::organization::resolve_organization),
        )
        .push(Router::with_path("search-actors").post(query::actor::search_actors))
        .push(Router::with_path("search-users").get(query::actor::search_users))
        .push(Router::with_path("resolve-handle").post(query::handle::resolve_handle))
        .push(
            Router::with_path("private-contact-discovery")
                .post(query::psi::private_contact_discovery),
        )
        // Ingest face — §8.
        .push(Router::with_path("announce").post(ingest::announce::announce))
        .push(Router::with_path("withdraw").post(ingest::withdraw::withdraw))
        .push(Router::with_path("subscribe").post(subscribe_stub))
}

#[handler]
async fn health(res: &mut Response) {
    res.render(Json(json!({ "ok": true })));
}

#[handler]
async fn openapi_yaml(depot: &mut Depot, res: &mut Response) {
    let doc = match depot.obtain::<ChadexOpenApiDoc>() {
        Ok(doc) => doc,
        Err(_) => {
            ErrorCode::InternalError.render(res, "OpenAPI document not injected");
            return;
        }
    };
    let spec = doc.0.to_yaml().unwrap_or_else(|error| {
        tracing::error!(%error, "failed to render chadex OpenAPI yaml");
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

/// Webhook subscription stub (spec §8.4 + §9 `cx.directory.subscribe`).
///
/// Today this just records the subscription row so operators can observe
/// requested fanout topology; actual webhook dispatch is M2-T6 in
/// `_todos.md`.
#[handler]
async fn subscribe_stub(res: &mut Response) {
    res.status_code(StatusCode::NOT_IMPLEMENTED);
    res.render(Json(json!({
        "ok": false,
        "error": {
            "code": "unsupported_feature",
            "message": "cx.directory.subscribe webhook fanout pending — see chadex _todos.md M2-T6",
        }
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

/// Build the OpenAPI document for chadex's Directory Service surface.
pub fn openapi(router: &Router) -> OpenApi {
    let mut doc = OpenApi::new("chadex", env!("CARGO_PKG_VERSION"))
        .add_extension(
            "x-contrix-profile",
            json!({
                "profile": "cx.profile.directory_service.v1",
                "spec": "contrix-spec/spec/v1/zh/discovery/discovery-directory.md",
            }),
        )
        .merge_router(router);
    register_contrix_oapi_components(&mut doc.components);
    register_chadex_operations(&mut doc);
    doc
}

fn register_chadex_operations(doc: &mut OpenApi) {
    let routes = [
        (
            "/health",
            PathItemType::Get,
            "chadex.health",
            "health",
            "Health check",
            "Process liveness probe.",
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
            "/api/v1/directory/search-spaces",
            PathItemType::Post,
            "cx.directory.search_spaces",
            "query",
            "Search Spaces",
            "Return listed/public Space directory results using the §9.1 result envelope.",
        ),
        (
            "/api/v1/directory/resolve-space",
            PathItemType::Post,
            "cx.directory.resolve_space",
            "query",
            "Resolve Space",
            "Resolve a Space by ID, alias, invite token, or signed link with blinded misses.",
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
            PathItemType::Get,
            "cx.directory.search_users",
            "query",
            "Search Users",
            "Common-Space gated user search; currently returns an empty result set.",
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
            "PSI/VOPRF endpoint scaffold; feature-complete implementation is tracked in M5.",
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
            "cx.directory.subscribe",
            "ingest",
            "Subscribe To Directory Updates",
            "Webhook subscription endpoint scaffold; fanout is tracked in M2-T6.",
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
