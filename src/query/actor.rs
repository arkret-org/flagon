//! Actor / user search. Spec §9.
//!
//! `cx.directory.search_actors` and `cx.directory.search_users` (mention
//! autocomplete).

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::{
    error::ErrorCode,
    filter::{enumeration::MIN_RESPONSE_LATENCY, enumeration::pad_to, result::ResultEnvelope},
    ingest::{DiscoverabilityWire, ResourceKindWire},
    state::AppState,
};

#[derive(Debug, Default, Deserialize)]
pub struct SearchActorsRequest {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub space_id: Option<String>,
    #[serde(default)]
    pub organization_did: Option<String>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[handler]
pub async fn search_actors(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let body: SearchActorsRequest = req.parse_json().await.unwrap_or_default();
    let limit = body.limit.unwrap_or(20).min(200).max(1) as i64;
    let result = pad_to(MIN_RESPONSE_LATENCY, async {
        run_actor_search(&state, limit).await
    })
    .await;
    match result {
        Ok(rows) => {
            let envelopes: Vec<ResultEnvelope> = rows.into_iter().map(envelope_from_row).collect();
            res.render(Json(
                json!({ "results": envelopes, "next_cursor": JsonValue::Null }),
            ));
        }
        Err(e) => ErrorCode::InternalError.render(res, format!("actor search: {e}")),
    }
}

#[handler]
pub async fn search_users(_req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let _ = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    // Mention-autocomplete is intentionally `not_yet_implemented` until the
    // index supports common-Space gating (M3-T6 in _todos.md). Until then
    // return an empty result rather than leaking unfiltered actor lists.
    res.render(Json(json!({ "results": [] })));
}

#[derive(Debug, Queryable)]
struct ActorRow {
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

async fn run_actor_search(state: &AppState, limit: i64) -> anyhow::Result<Vec<ActorRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;
    let rows: Vec<ActorRow> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Actor))
        .filter(r::discoverability.eq(DiscoverabilityWire::Public))
        .order(r::indexed_at.desc())
        .limit(limit)
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
        .load(&mut conn)?;
    Ok(rows)
}

fn envelope_from_row(row: ActorRow) -> ResultEnvelope {
    let mut payload = row.public_projection;
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("actor_did".into(), JsonValue::String(row.resource_id));
        obj.insert(
            "discoverability".into(),
            JsonValue::String(row.discoverability.as_pg().to_string()),
        );
    }
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
