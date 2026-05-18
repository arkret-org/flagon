//! Handle resolution. Spec §9 (`cx.directory.resolve_handle`).

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::error::ErrorCode;
use crate::filter::enumeration::{LatencyBudget, pad_to_budget};
use crate::filter::result::ResultEnvelope;
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
        Ok(Some(row)) => res.render(Json(envelope_from_row(row))),
        _ => ErrorCode::NotFound.render(res, "not found"),
    }
}

#[derive(Debug, Queryable)]
struct HandleRow {
    resource_id: String,
    public_projection: JsonValue,
    discoverability: DiscoverabilityWire,
    as_of: DateTime<Utc>,
    source_refs: Vec<String>,
    policy_revision: Option<String>,
    stale: bool,
    divergent: bool,
    via_services: Vec<String>,
}

async fn load_handle_row(state: &AppState, handle: &str) -> anyhow::Result<Option<HandleRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;
    let row: Option<HandleRow> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Handle))
        .filter(r::resource_id.eq(handle))
        .select((
            r::resource_id,
            r::public_projection,
            r::discoverability,
            r::as_of,
            r::source_refs,
            r::policy_revision,
            r::stale,
            r::divergent,
            r::via_services,
        ))
        .first(&mut conn)
        .optional()?;
    match row {
        Some(row) if row.discoverability.is_directory_visible() => Ok(Some(row)),
        _ => Ok(None),
    }
}

fn envelope_from_row(row: HandleRow) -> ResultEnvelope {
    let did = row
        .public_projection
        .get("did")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();
    let claims = row
        .public_projection
        .get("claims")
        .cloned()
        .unwrap_or(JsonValue::Null);
    let payload = json!({
        "did": did,
        "handle": row.resource_id,
        "verified": row.public_projection.get("verified").and_then(JsonValue::as_bool).unwrap_or(false),
        "claims": claims,
        "discoverability": row.discoverability.as_pg(),
    });
    ResultEnvelope::from_row(
        payload,
        row.as_of,
        row.source_refs,
        row.policy_revision,
        row.stale,
        row.divergent,
        row.via_services,
    )
}
