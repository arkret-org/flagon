//! Handle resolution. Spec §9 (`cx.directory.resolve_handle`).

use diesel::prelude::*;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::error::ErrorCode;
use crate::filter::enumeration::{LatencyBudget, pad_to_budget};
use crate::ingest::{DiscoverabilityWire, ResourceKindWire};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ResolveHandleRequest {
    pub handle: String,
    #[serde(default)]
    pub expected_did: Option<String>,
    #[serde(default)]
    pub proof_challenge: Option<String>,
}

#[handler]
pub async fn resolve_handle(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let body: ResolveHandleRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ErrorCode::BadJson.render(res, format!("malformed body: {e}"));
            return;
        }
    };
    if body.handle.is_empty() {
        ErrorCode::MissingParam.render(res, "handle is required");
        return;
    }

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let row = pad_to_budget(budget, "cx.directory.resolve_handle", &body.handle, async {
        load_handle_row(&state, &body.handle).await
    })
    .await;

    match row {
        Ok(Some(payload)) => res.render(Json(payload)),
        _ => ErrorCode::NotFound.render(res, "not found"),
    }
}

async fn load_handle_row(state: &AppState, handle: &str) -> anyhow::Result<Option<JsonValue>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;
    let row: Option<(String, JsonValue, DiscoverabilityWire)> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Handle))
        .filter(r::resource_id.eq(handle))
        .select((r::resource_id, r::public_projection, r::discoverability))
        .first(&mut conn)
        .optional()?;
    match row {
        Some((resource_id, projection, disc)) if disc.is_directory_visible() => {
            let did = projection
                .get("did")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let claims = projection.get("claims").cloned().unwrap_or(JsonValue::Null);
            Ok(Some(json!({
                "did": did,
                "handle": resource_id,
                "verified": projection.get("verified").and_then(|v| v.as_bool()).unwrap_or(false),
                "claims": claims,
            })))
        }
        _ => Ok(None),
    }
}
