//! Space search and resolve. Spec §9.
//!
//! `cx.directory.search_spaces` and `cx.directory.resolve_space`. Both
//! return §9.1 normative envelopes (`as_of`, `source_refs`,
//! `policy_revision`, `via_services`). Hidden / unauthorized resources
//! must be indistinguishable from `not_found` (§3 / §10).

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
pub struct SearchSpacesRequest {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub scope: Option<SearchScope>,
    #[serde(default)]
    pub requester: Option<String>,
    #[serde(default)]
    pub proofs: Vec<String>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SearchScope {
    #[serde(default)]
    pub organization_did: Option<String>,
    #[serde(default)]
    pub parent_space_id: Option<String>,
}

#[handler]
pub async fn search_spaces(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let body: SearchSpacesRequest = req.parse_json().await.unwrap_or_default();

    let limit = body.limit.unwrap_or(20).min(200).max(1) as i64;
    let needle = body.query.unwrap_or_default();

    let result = pad_to(MIN_RESPONSE_LATENCY, async {
        run_space_search(&state, &needle, limit).await
    })
    .await;

    match result {
        Ok(rows) => {
            let envelopes: Vec<ResultEnvelope> = rows.into_iter().map(envelope_from_row).collect();
            res.render(Json(json!({
                "results": envelopes,
                "next_cursor": JsonValue::Null,
            })));
        }
        Err(e) => {
            ErrorCode::InternalError.render(res, format!("space search: {e}"));
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ResolveSpaceRequest {
    #[serde(default)]
    pub space_id: Option<String>,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub invite_token: Option<String>,
    #[serde(default)]
    pub signed_link: Option<String>,
    #[serde(default)]
    pub requester: Option<String>,
    #[serde(default)]
    pub proofs: Vec<String>,
}

#[handler]
pub async fn resolve_space(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let body: ResolveSpaceRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ErrorCode::BadJson.render(res, format!("malformed resolve body: {e}"));
            return;
        }
    };

    let key = body
        .space_id
        .clone()
        .or(body.alias)
        .or(body.invite_token)
        .or(body.signed_link);
    let key = match key {
        Some(k) if !k.is_empty() => k,
        _ => {
            ErrorCode::MissingParam.render(
                res,
                "at least one of space_id / alias / invite_token / signed_link required",
            );
            return;
        }
    };

    // Padded latency floor per §10 timing equalization.
    let row = pad_to(MIN_RESPONSE_LATENCY, async {
        load_space_row(&state, &key).await
    })
    .await;

    match row {
        Ok(Some(r)) if r.discoverability.is_directory_visible() => {
            res.render(Json(envelope_from_row(r)));
        }
        // Hidden, withdrawn, or unknown — all collapse to blinded not_found.
        _ => {
            ErrorCode::NotFound.render(res, "not found");
        }
    }
}

// ---- internal load primitives -------------------------------------------

#[derive(Debug, Queryable)]
struct SpaceRow {
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

async fn run_space_search(
    state: &AppState,
    needle: &str,
    limit: i64,
) -> anyhow::Result<Vec<SpaceRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;

    // Naive contains-on-public_projection. Real ranking belongs in M4
    // (`pg_trgm` + tsvector + bucketed scoring). For now: filter by kind
    // and discoverability, returning all matches up to the limit.
    let _ = needle; // ranking deferred

    let rows: Vec<SpaceRow> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Space))
        .filter(
            r::discoverability
                .eq(DiscoverabilityWire::Public)
                .or(r::discoverability.eq(DiscoverabilityWire::Listed)),
        )
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

async fn load_space_row(state: &AppState, key: &str) -> anyhow::Result<Option<SpaceRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;
    let row: Option<SpaceRow> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Space))
        .filter(r::resource_id.eq(key))
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
    Ok(row)
}

fn envelope_from_row(row: SpaceRow) -> ResultEnvelope {
    // Inject the canonical key so clients can act on the row immediately.
    let mut payload = row.public_projection;
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("space_id".into(), JsonValue::String(row.resource_id));
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
