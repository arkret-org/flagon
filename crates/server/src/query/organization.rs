//! Organization search and resolve. Spec §9.

use std::collections::BTreeMap;

use arkret_sdk::{
    DidCoreId, DirectoryOrganizationResolutionOutcome, DirectoryOrganizationSearchOutcome,
    DirectoryRestrictedClaimPresentation, DirectorySearchOrganizationsRequestBody,
    OrganizationPreview,
};
use arkret_server::CursorBindingContext;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::error::ApiErrorCode;
use crate::filter::discoverers::{
    VerifiedRestrictedClaims, matches_allowed_discoverers, verify_restricted_claim_presentations,
};
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::filter::result::ResultEnvelope;
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};
use crate::query::rate_limit::{
    apply_resolve_response_jitter, enforce_query_rate_limit, enforce_resolve_rate_limit,
};
use crate::state::AppState;

#[handler]
pub async fn search_organizations(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
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
    let body: DirectorySearchOrganizationsRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::JsonInvalid.render(res, format!("malformed search body: {error}"));
            return;
        }
    };

    let limit = body.limit.unwrap_or(20).clamp(1, 200) as i64;
    let needle = body.query.unwrap_or_default();
    let claims = parse_org_restricted_claims(&body.claims);
    let requester = claims
        .requester
        .as_ref()
        .map(DidCoreId::as_str)
        .map(str::to_owned);
    let verified_claims = verified_restricted_claims_for_org_query(
        &state,
        requester.as_deref(),
        claims.proof_challenge.as_deref(),
        &claims.claim_presentations,
    );
    let filter_digest = match arkret_server::cursor_filter_digest(&serde_json::json!({
        "operation": "ak.find.directory.read.search_organizations",
        "query": &needle,
    })) {
        Ok(digest) => digest,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("organization cursor filter: {error}"));
            return;
        }
    };
    let cursor_context = CursorBindingContext::new(
        requester.as_deref().unwrap_or("anonymous"),
        None,
        state.config().service_id.clone(),
        filter_digest,
    );
    let cursor = match body.cursor.as_deref() {
        Some(token) => match state
            .cursor_authority()
            .resolve_stream(token, &cursor_context)
            .and_then(|positions| {
                serde_json::from_value::<OrgCursor>(positions)
                    .map_err(|_| arkret_server::CursorAuthorityError::IntegrityInvalid)
            }) {
            Ok(cursor) => Some(cursor),
            Err(error) => {
                super::render_cursor_error(res, error);
                return;
            }
        },
        None => None,
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
        "ak.find.directory.read.search_organizations",
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
                &verified_claims,
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
                match rows.last() {
                    Some(row) => match serde_json::to_value(org_cursor_from_row(row))
                        .map_err(|error| {
                            arkret_server::CursorAuthorityError::ParamInvalid(error.to_string())
                        })
                        .and_then(|positions| {
                            state.cursor_authority().mint_stream(
                                cursor_context.clone(),
                                positions,
                                60 * 60 * 1000,
                            )
                        }) {
                        Ok(cursor) => Some(cursor),
                        Err(error) => {
                            ApiErrorCode::InternalError
                                .render(res, format!("organization cursor: {error}"));
                            return;
                        }
                    },
                    None => None,
                }
            } else {
                None
            };
            let organizations = match rows
                .into_iter()
                .map(|row| organization_preview_from_envelope(envelope_from_row(row)))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(organizations) => organizations,
                Err(message) => {
                    ApiErrorCode::InternalError.render(res, message);
                    return;
                }
            };
            res.render(Json(DirectoryOrganizationSearchOutcome {
                organizations,
                next_cursor,
                has_more,
            }));
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

fn org_cursor_from_row(row: &OrgRow) -> OrgCursor {
    OrgCursor {
        indexed_at: row.indexed_at,
        resource_id: row.resource_id.clone(),
    }
}

// SAFETY: alsoKnownAs is holder-side reverse endorsement only — not used here for routing.
// Spec sync 37ce729 (B-E) — identity-handles §6: `resolve_organization`
// looks up rows by `organization_principal_id` (canonical key) or by a Directory
// `handle`. It MUST NOT consult any `alsoKnownAs` claim cached in
// `public_projection` as an alternate key; that field is a holder-side
// reverse endorsement and is not a Directory routing input.
#[handler]
pub async fn resolve_organization(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("resolve-organization");
    let body: OrganizationResolveRequestView = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::JsonInvalid.render(res, format!("malformed resolve body: {error}"));
            return;
        }
    };
    let key = body
        .organization_principal_id
        .as_ref()
        .map(|did| did.as_str().to_owned())
        .or(body.handle);
    let key = match key {
        Some(k) if !k.is_empty() => k,
        _ => {
            ApiErrorCode::ParamMissing
                .render(res, "organization_principal_id or handle is required");
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
    let requester = body
        .requester
        .as_ref()
        .map(DidCoreId::as_str)
        .map(str::to_owned);
    let verified_claims = verified_restricted_claims_for_org_query(
        &state,
        requester.as_deref(),
        body.proof_challenge.as_deref(),
        &body.claim_presentations,
    );
    let row = pad_to_budget_observed(
        budget,
        "ak.find.directory.read.resolve_organization",
        &key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("resolve-organization", target)
        },
        async {
            let row = load_org_row(&state, &key).await?;
            Ok::<_, anyhow::Error>(
                row.filter(|row| is_org_visible(row, requester.as_deref(), &verified_claims)),
            )
        },
    )
    .await;

    // P5 — stochastic anti-enumeration jitter on resolve responses.
    apply_resolve_response_jitter().await;

    match row {
        Ok(Some(r)) => {
            let organization_preview =
                match organization_preview_from_envelope(envelope_from_row(r)) {
                    Ok(organization_preview) => organization_preview,
                    Err(message) => {
                        ApiErrorCode::InternalError.render(res, message);
                        return;
                    }
                };
            res.render(Json(DirectoryOrganizationResolutionOutcome {
                organization_preview,
                did_document_ref: None,
                endorsements: Vec::new(),
            }));
        }
        _ => ApiErrorCode::NotFound.render(res, "not found"),
    }
}

#[derive(Debug, Default, Deserialize)]
struct OrganizationRestrictedClaims {
    #[serde(default)]
    requester: Option<DidCoreId>,
    #[serde(default)]
    proof_challenge: Option<String>,
    #[serde(default)]
    claim_presentations: Vec<DirectoryRestrictedClaimPresentation>,
}

#[derive(Debug, Default, Deserialize)]
struct OrganizationResolveRequestView {
    #[serde(default)]
    organization_principal_id: Option<DidCoreId>,
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    requester: Option<DidCoreId>,
    #[serde(default)]
    proof_challenge: Option<String>,
    #[serde(default)]
    claim_presentations: Vec<DirectoryRestrictedClaimPresentation>,
}

fn parse_org_restricted_claims(
    value: &Option<BTreeMap<String, JsonValue>>,
) -> OrganizationRestrictedClaims {
    value
        .as_ref()
        .and_then(|claims| {
            serde_json::from_value(JsonValue::Object(claims.clone().into_iter().collect())).ok()
        })
        .unwrap_or_default()
}

fn verified_restricted_claims_for_org_query(
    state: &AppState,
    requester: Option<&str>,
    proof_challenge: Option<&str>,
    presentations: &[DirectoryRestrictedClaimPresentation],
) -> VerifiedRestrictedClaims {
    verify_restricted_claim_presentations(
        presentations,
        requester,
        proof_challenge,
        state.config().service_full_id.as_str(),
        state.did_bindings(),
    )
    .unwrap_or_default()
}

#[derive(Debug, Queryable)]
struct OrgRow {
    resource_id: String,
    public_projection: JsonValue,
    discoverability: DiscoverabilityDb,
    as_of: DateTime<Utc>,
    source_refs: Vec<String>,
    policy_revision: String,
    stale: bool,
    divergent: bool,
    via_services: Vec<String>,
    indexed_at: DateTime<Utc>,
}

/// Whether an organization row is visible to the (requester, proofs) given its
/// discoverability. `public`/`listed` are always visible; `restricted` is
/// gated by `allowed_discoverers`; everything else is hidden (fail-closed).
fn is_org_visible(
    row: &OrgRow,
    requester: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
) -> bool {
    match row.discoverability {
        DiscoverabilityDb::Public | DiscoverabilityDb::Listed => true,
        DiscoverabilityDb::Restricted => {
            matches_allowed_discoverers(&row.public_projection, requester, verified_claims)
        }
        DiscoverabilityDb::Unlisted | DiscoverabilityDb::InviteOnly | DiscoverabilityDb::Secret => {
            false
        }
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
        .filter(r::resource_kind.eq(DirectoryResourceKindDb::Organization))
        .filter(r::stale.eq(false))
        .filter(
            r::discoverability
                .eq(DiscoverabilityDb::Public)
                .or(r::discoverability.eq(DiscoverabilityDb::Listed))
                .or(r::discoverability.eq(DiscoverabilityDb::Restricted)),
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
    verified_claims: &VerifiedRestrictedClaims,
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
            if needle_ok && is_org_visible(&row, requester, verified_claims) {
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
        .filter(r::resource_kind.eq(DirectoryResourceKindDb::Organization))
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
            "organization_principal_id".into(),
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

fn organization_preview_from_envelope(
    envelope: ResultEnvelope,
) -> Result<OrganizationPreview, String> {
    let value = serde_json::to_value(envelope)
        .map_err(|error| format!("organization envelope serialization failed: {error}"))?;
    serde_json::from_value(value)
        .map_err(|error| format!("organization preview is not SDK-compatible: {error}"))
}

fn org_matches(projection: &JsonValue, resource_id: &str, needle: &str) -> bool {
    resource_id.to_ascii_lowercase().contains(needle)
        || ["handle", "name", "display_name", "summary", "description"]
            .iter()
            .filter_map(|key| projection.get(*key).and_then(JsonValue::as_str))
            .any(|value| value.to_ascii_lowercase().contains(needle))
}
