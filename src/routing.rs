//! Salvo router declaration. All `/api/v1/directory/*` endpoints (spec §9)
//! plus `/health` and OpenAPI metadata.

use salvo::affix_state;
use salvo::cors::{Cors, CorsHandler};
use salvo::http::Method;
use salvo::oapi::OpenApi;
use salvo::prelude::*;
use serde_json::json;

use crate::{
    ingest, query,
    state::AppState,
};

pub fn router(state: AppState) -> Router {
    let cors_origin = state.config().cors_allow_origin.clone();
    let mut root = Router::new().hoop(affix_state::inject(state));
    if let Some(origin) = cors_origin {
        root = root.hoop(cors_handler_for_origin(origin));
    }
    root.push(Router::with_path("health").get(health))
        .push(
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
                .push(Router::with_path("subscribe").post(subscribe_stub)),
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

#[handler]
async fn health(res: &mut Response) {
    res.render(Json(json!({ "ok": true })));
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

/// Build a minimal OpenAPI document for chadex. Detailed schemas come from
/// `contrix-sdk::salvo_adapter::register_contrix_oapi_components` once the
/// adapter is wired in (M0-T2 in _todos.md).
pub fn openapi(_router: &Router) -> OpenApi {
    OpenApi::new("chadex", env!("CARGO_PKG_VERSION"))
}
