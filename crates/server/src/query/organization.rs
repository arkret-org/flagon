//! Organization search and resolve. Spec §9.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::error::ApiErrorCode;
use crate::filter::enumeration::{LatencyBudget, pad_to_budget};
use crate::filter::result::ResultEnvelope;
use crate::ingest::{DiscoverabilityWire, ResourceKindWire};
use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
pub struct SearchOrgsRequest {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub claims: Option<JsonValue>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[handler]
pub async fn search_organizations(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let body: SearchOrgsRequest = req.parse_json().await.unwrap_or_default();

    let limit = body.limit.unwrap_or(20).min(200).max(1) as i64;
    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let privacy_key = format!(
        "q={};cursor={};limit={limit}",
        body.query.as_deref().unwrap_or_default(),
        body.cursor.as_deref().unwrap_or_default(),
    );
    let result = pad_to_budget(
        budget,
        "cx.directory.search_organizations",
        &privacy_key,
        async { run_org_search(&state, body.query.as_deref().unwrap_or_default(), limit).await },
    )
    .await;

    match result {
        Ok(rows) => {
            let envelopes: Vec<ResultEnvelope> = rows.into_iter().map(envelope_from_row).collect();
            res.render(Json(
                json!({ "results": envelopes, "next_cursor": JsonValue::Null }),
            ));
        }
        Err(e) => ApiErrorCode::InternalError.render(res, format!("org search: {e}")),
    }
}

#[derive(Debug, Deserialize)]
pub struct ResolveOrgRequest {
    #[serde(default)]
    pub organization_did: Option<String>,
    #[serde(default)]
    pub handle: Option<String>,
    #[serde(default)]
    pub proofs: Vec<String>,
}

#[handler]
pub async fn resolve_organization(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let body: ResolveOrgRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ApiErrorCode::BadJson.render(res, format!("malformed resolve body: {e}"));
            return;
        }
    };
    let key = body.organization_did.or(body.handle);
    let key = match key {
        Some(k) if !k.is_empty() => k,
        _ => {
            ApiErrorCode::MissingParam.render(res, "organization_did or handle is required");
            return;
        }
    };

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let row = pad_to_budget(budget, "cx.directory.resolve_organization", &key, async {
        load_org_row(&state, &key).await
    })
    .await;

    match row {
        Ok(Some(r)) if r.discoverability.is_directory_visible() => {
            res.render(Json(envelope_from_row(r)));
        }
        _ => ApiErrorCode::NotFound.render(res, "not found"),
    }
}

#[derive(Debug, Queryable)]
struct OrgRow {
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

async fn run_org_search(state: &AppState, needle: &str, limit: i64) -> anyhow::Result<Vec<OrgRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;
    let rows: Vec<OrgRow> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Organization))
        .filter(
            r::discoverability
                .eq(DiscoverabilityWire::Public)
                .or(r::discoverability.eq(DiscoverabilityWire::Listed)),
        )
        .order(r::indexed_at.desc())
        .limit(limit.max(500))
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
    let needle = needle.trim().to_ascii_lowercase();
    Ok(rows
        .into_iter()
        .filter(|row| {
            needle.is_empty() || org_matches(&row.public_projection, &row.resource_id, &needle)
        })
        .take(limit as usize)
        .collect())
}

async fn load_org_row(state: &AppState, key: &str) -> anyhow::Result<Option<OrgRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;
    let row: Option<OrgRow> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Organization))
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

fn envelope_from_row(row: OrgRow) -> ResultEnvelope {
    let mut payload = row.public_projection;
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(
            "organization_did".into(),
            JsonValue::String(row.resource_id),
        );
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

fn org_matches(projection: &JsonValue, resource_id: &str, needle: &str) -> bool {
    resource_id.to_ascii_lowercase().contains(needle)
        || ["handle", "name", "display_name", "summary", "description"]
            .iter()
            .filter_map(|key| projection.get(*key).and_then(JsonValue::as_str))
            .any(|value| value.to_ascii_lowercase().contains(needle))
}
