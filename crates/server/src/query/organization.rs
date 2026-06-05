//! Organization search and resolve. Spec §9.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::error::ApiErrorCode;
use crate::filter::discoverers::matches_allowed_discoverers;
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::filter::result::ResultEnvelope;
use crate::ingest::{DiscoverabilityWire, ResourceKindWire};
use crate::query::rate_limit::{
    apply_resolve_response_jitter, enforce_query_rate_limit, enforce_resolve_rate_limit,
};
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
    let _query_timer = state.metrics().query_timer("search-organizations");
    if !enforce_query_rate_limit(req, res, &state) {
        return;
    }
    let body: SearchOrgsRequest = req.parse_json().await.unwrap_or_default();

    let limit = body.limit.unwrap_or(20).clamp(1, 200) as i64;
    let needle = body.query.unwrap_or_default();
    // Derive the requester identity + presented proof references from the
    // `claims` object so restricted organizations can be authorization-gated
    // with the exact same `allowed_discoverers` semantics as `search_realms`.
    let (requester, proofs) = claims_to_requester_proofs(body.claims.as_ref());
    let cursor = match body.cursor.as_deref().map(decode_org_cursor).transpose() {
        Ok(cursor) => cursor,
        Err(message) => {
            ApiErrorCode::BadQuery.render(res, message);
            return;
        }
    };

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let privacy_key = format!(
        "q={needle};cursor={};limit={limit}",
        cursor
            .as_ref()
            .map(|c| c.resource_id.as_str())
            .unwrap_or_default(),
    );
    let result = pad_to_budget_observed(
        budget,
        "ck.find.directory.search_organizations",
        &privacy_key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("search-organizations", target)
        },
        async {
            run_visible_org_search(
                &state,
                &needle,
                cursor.as_ref(),
                requester.as_deref(),
                &proofs,
                limit + 1,
            )
            .await
        },
    )
    .await;

    match result {
        Ok(mut rows) => {
            // We over-fetch `limit + 1` authorized rows; a full extra row means
            // more pages remain (spec §9.1 unified `has_more` convention).
            let has_more = rows.len() > limit as usize;
            let next_cursor = if has_more {
                rows.truncate(limit as usize);
                rows.last().map(encode_org_cursor)
            } else {
                None
            };
            let envelopes: Vec<ResultEnvelope> = rows.into_iter().map(envelope_from_row).collect();
            res.render(Json(json!({
                "results": envelopes,
                "next_cursor": next_cursor,
                "has_more": has_more,
            })));
        }
        Err(e) => ApiErrorCode::InternalError.render(res, format!("org search: {e}")),
    }
}

/// Keyset cursor for organization search, ordered `(indexed_at DESC,
/// resource_id ASC)` so paging is deterministic and stable across requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrgCursor {
    indexed_at: DateTime<Utc>,
    resource_id: String,
}

fn encode_org_cursor(row: &OrgRow) -> String {
    let cursor = OrgCursor {
        indexed_at: row.indexed_at,
        resource_id: row.resource_id.clone(),
    };
    // serde_json over (timestamp, string) never fails; fall back to empty on
    // the impossible error so we never panic in a request path.
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cursor).unwrap_or_default())
}

fn decode_org_cursor(cursor: &str) -> Result<OrgCursor, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|e| format!("invalid cursor encoding: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid cursor body: {e}"))
}

/// Flatten the request `claims` object into `(requester, proofs)` consumable by
/// the shared `allowed_discoverers` matcher. Requester is read from the usual
/// identity keys; every string value (top-level or inside a `proofs`/`claims`
/// array) is collected as a candidate proof reference.
fn claims_to_requester_proofs(claims: Option<&JsonValue>) -> (Option<String>, Vec<String>) {
    let Some(JsonValue::Object(obj)) = claims else {
        return (None, Vec::new());
    };
    let requester = ["requester", "subject", "did", "actor"]
        .iter()
        .find_map(|key| obj.get(*key).and_then(JsonValue::as_str))
        .map(str::to_owned);

    let mut proofs = Vec::new();
    let mut push = |value: &JsonValue| {
        if let Some(s) = value.as_str() {
            proofs.push(s.to_owned());
        }
    };
    for (key, value) in obj {
        match value {
            JsonValue::String(_) => push(value),
            JsonValue::Array(arr) if key == "proofs" || key == "claims" => {
                arr.iter().for_each(&mut push);
            }
            _ => {}
        }
    }
    (requester, proofs)
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

// SAFETY: alsoKnownAs is holder-side reverse endorsement only — not used here for routing.
// Spec sync 37ce729 (B-E) — identity-handles §6: `resolve_organization`
// looks up rows by `organization_did` (canonical key) or by a Directory
// `handle`. It MUST NOT consult any `alsoKnownAs` claim cached in
// `public_projection` as an alternate key; that field is a holder-side
// reverse endorsement and is not a Directory routing input.
#[handler]
pub async fn resolve_organization(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("resolve-organization");
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
    if !enforce_resolve_rate_limit(req, res, &state, &key) {
        return;
    }

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let row = pad_to_budget_observed(
        budget,
        "ck.find.directory.resolve_organization",
        &key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("resolve-organization", target)
        },
        async { load_org_row(&state, &key).await },
    )
    .await;

    // P5 — stochastic anti-enumeration jitter on resolve responses.
    apply_resolve_response_jitter().await;

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
    indexed_at: DateTime<Utc>,
}

/// Whether an organization row is visible to the (requester, proofs) given its
/// discoverability. `public`/`listed` are always visible; `restricted` is
/// gated by `allowed_discoverers`; everything else is hidden (fail-closed).
fn is_org_visible(row: &OrgRow, requester: Option<&str>, proofs: &[String]) -> bool {
    match row.discoverability {
        DiscoverabilityWire::Public | DiscoverabilityWire::Listed => true,
        DiscoverabilityWire::Restricted => {
            matches_allowed_discoverers(&row.public_projection, requester, proofs)
        }
        DiscoverabilityWire::Unlisted
        | DiscoverabilityWire::InviteOnly
        | DiscoverabilityWire::Secret => false,
    }
}

/// Fetch one keyset page after `cursor` (DB-level filtering only). Includes
/// `restricted` so the caller can authorization-gate it; `(indexed_at,
/// resource_id)` ordering matches `OrgCursor`.
async fn run_org_search_page(
    state: &AppState,
    cursor: Option<&OrgCursor>,
    batch_limit: i64,
) -> anyhow::Result<Vec<OrgRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get().await?;
    let mut query = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Organization))
        .filter(r::stale.eq(false))
        .filter(
            r::discoverability
                .eq(DiscoverabilityWire::Public)
                .or(r::discoverability.eq(DiscoverabilityWire::Listed))
                .or(r::discoverability.eq(DiscoverabilityWire::Restricted)),
        )
        .into_boxed();
    if let Some(cursor) = cursor {
        // Keyset predicate for `(indexed_at DESC, resource_id ASC)`.
        query = query.filter(
            r::indexed_at.lt(cursor.indexed_at).or(r::indexed_at
                .eq(cursor.indexed_at)
                .and(r::resource_id.gt(cursor.resource_id.clone()))),
        );
    }
    let rows: Vec<OrgRow> = query
        .order((r::indexed_at.desc(), r::resource_id.asc()))
        .limit(batch_limit)
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
            r::indexed_at,
        ))
        .load(&mut *conn)
        .await?;
    Ok(rows)
}

/// Page through organization rows until `visible_limit` needle-matched,
/// authorization-passing rows are collected (or the table is exhausted),
/// mirroring `query::realm::run_visible_realm_search`.
async fn run_visible_org_search(
    state: &AppState,
    needle: &str,
    cursor: Option<&OrgCursor>,
    requester: Option<&str>,
    proofs: &[String],
    visible_limit: i64,
) -> anyhow::Result<Vec<OrgRow>> {
    let needle = needle.trim().to_ascii_lowercase();
    let target_len = visible_limit.max(1) as usize;
    let batch_limit = visible_limit.max(64);
    let mut scan_cursor = cursor.cloned();
    let mut visible_rows: Vec<OrgRow> = Vec::with_capacity(target_len.min(201));

    loop {
        let rows = run_org_search_page(state, scan_cursor.as_ref(), batch_limit).await?;
        if rows.is_empty() {
            break;
        }
        let fetched = rows.len();
        let mut next_scan_cursor = None;
        for row in rows {
            next_scan_cursor = Some(OrgCursor {
                indexed_at: row.indexed_at,
                resource_id: row.resource_id.clone(),
            });
            let needle_ok =
                needle.is_empty() || org_matches(&row.public_projection, &row.resource_id, &needle);
            if needle_ok && is_org_visible(&row, requester, proofs) {
                visible_rows.push(row);
                if visible_rows.len() >= target_len {
                    return Ok(visible_rows);
                }
            }
        }
        if fetched < batch_limit as usize {
            break;
        }
        scan_cursor = next_scan_cursor;
        if scan_cursor.is_none() {
            break;
        }
    }
    Ok(visible_rows)
}

async fn load_org_row(state: &AppState, key: &str) -> anyhow::Result<Option<OrgRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get().await?;
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
            r::indexed_at,
        ))
        .first(&mut *conn)
        .await
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
