//! Organization search and resolve. Spec §9.

use std::collections::BTreeMap;

use arkret_sdk::{
    DidCoreId, DirectoryOrganizationResolutionOutcome, DirectoryOrganizationSearchOutcome,
    DirectoryResolveOrganizationRequestBody, DirectoryRestrictedClaimPresentation,
    DirectorySearchOrganizationsRequestBody, OrganizationPreview,
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
    let requester_id = claims
        .requester_id
        .as_ref()
        .map(DidCoreId::as_str)
        .map(str::to_owned);
    let verified_claims = verified_restricted_claims_for_org_query(
        &state,
        requester_id.as_deref(),
        claims.proof_challenge.as_deref(),
        &claims.claim_presentations,
    );
    let filter_digest = match arkret_server::cursor_filter_digest(&serde_json::json!({
        "operation": arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ORGANIZATIONS_V1,
        "query": &needle,
    })) {
        Ok(digest) => digest,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("organization cursor filter: {error}"));
            return;
        }
    };
    let cursor_context = CursorBindingContext::new(
        requester_id.as_deref().unwrap_or("anonymous"),
        None,
        state.service_core_id().clone(),
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
        arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ORGANIZATIONS_V1,
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
                requester_id.as_deref(),
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
// looks up rows by `organization_id` (canonical key) or by a Directory
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
    let body: DirectoryResolveOrganizationRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::JsonInvalid.render(res, format!("malformed resolve body: {error}"));
            return;
        }
    };
    let key = body
        .organization_id
        .as_ref()
        .map(|did| did.as_str().to_owned())
        .or_else(|| body.handle.clone());
    let key = match key {
        Some(k) if !k.is_empty() => k,
        _ => {
            ApiErrorCode::ParamMissing.render(res, "organization_id or handle is required");
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
    // `ak.find.directory.read.resolve_organization.v1` has no requester_id,
    // proof_challenge or claim_presentations input (spec §9 operation table):
    // its only authorization channel is the §9.0.1 `proofs[]`. A `restricted`
    // organization row therefore has no way to be unlocked here and collapses
    // to the same blinded `not_found` as a genuine miss.
    let row = pad_to_budget_observed(
        budget,
        arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_ORGANIZATION_V1,
        &key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("resolve-organization", target)
        },
        async {
            // Inside the latency budget so a §9.0.1 proof failure is
            // timing-equivalent to a genuine miss (§9.2).
            if let Err(reason) = crate::query::requester_proof::verify_requester_proofs(
                &body,
                state.config().service_id.as_str(),
                state.did_bindings(),
                Utc::now(),
            ) {
                tracing::debug!(%reason, "resolve_organization requester_id proof rejected");
                return Ok::<_, anyhow::Error>(None);
            }
            let row = load_org_row(&state, &key).await?;
            Ok::<_, anyhow::Error>(
                row.filter(|row| is_org_visible(row, None, &VerifiedRestrictedClaims::default())),
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
    requester_id: Option<DidCoreId>,
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
    requester_id: Option<&str>,
    proof_challenge: Option<&str>,
    presentations: &[DirectoryRestrictedClaimPresentation],
) -> VerifiedRestrictedClaims {
    verify_restricted_claim_presentations(
        presentations,
        requester_id,
        proof_challenge,
        state.config().service_id.as_str(),
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
    via_services: Vec<DidCoreId>,
    indexed_at: DateTime<Utc>,
}

/// Whether an organization row is visible to the (requester_id, proofs) given its
/// discoverability. `public`/`listed` are always visible; `restricted` is
/// gated by `allowed_discoverers`; everything else is hidden (fail-closed).
fn is_org_visible(
    row: &OrgRow,
    requester_id: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
) -> bool {
    match row.discoverability {
        DiscoverabilityDb::Public | DiscoverabilityDb::Listed => true,
        DiscoverabilityDb::Restricted => {
            matches_allowed_discoverers(&row.public_projection, requester_id, verified_claims)
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
    requester_id: Option<&str>,
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
            if needle_ok && is_org_visible(&row, requester_id, verified_claims) {
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
        obj.insert("organization_id".into(), JsonValue::String(row.resource_id));
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
    // The index also carries disclosure policy and search-only fields. They
    // have already served admission above and are not OrganizationPreview
    // fields. Build the closed public DTO explicitly; never serialize the
    // entire internal envelope and never relax the SDK's unknown-field gate.
    let projection = envelope
        .payload
        .as_object()
        .ok_or_else(|| "organization projection must be an object".to_owned())?;
    Ok(OrganizationPreview {
        organization_id: organization_projection_field(projection, "organization_id")?
            .ok_or_else(|| "organization projection identity is missing".to_owned())?,
        handle: organization_projection_field(projection, "handle")?,
        display_name: organization_projection_field(projection, "display_name")?,
        avatar_blob_ref: organization_projection_field(projection, "avatar_blob_ref")?,
        verified_badge: organization_projection_field(projection, "verified_badge")?,
        member_count: organization_projection_field(projection, "member_count")?,
        realm_ids: organization_projection_field(projection, "realm_ids")?.unwrap_or_default(),
        realm_count: organization_projection_field(projection, "realm_count")?,
        as_of: envelope.as_of,
        source_refs: super::parse_source_refs(envelope.source_refs)?,
        policy_revision: envelope.policy_revision,
        stale: envelope.stale.then_some(true),
        divergent: envelope.divergent.then_some(true),
    })
}

fn organization_projection_field<T: serde::de::DeserializeOwned>(
    projection: &serde_json::Map<String, JsonValue>,
    field: &str,
) -> Result<Option<T>, String> {
    projection
        .get(field)
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| format!("invalid organization preview {field}: {error}"))
}

fn org_matches(projection: &JsonValue, resource_id: &str, needle: &str) -> bool {
    resource_id.to_ascii_lowercase().contains(needle)
        || ["handle", "name", "display_name", "summary", "description"]
            .iter()
            .filter_map(|key| projection.get(*key).and_then(JsonValue::as_str))
            .any(|value| value.to_ascii_lowercase().contains(needle))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn row(projection: JsonValue) -> OrgRow {
        OrgRow {
            resource_id: "ak:did_core:web:tea-org.example".to_owned(),
            public_projection: projection,
            discoverability: DiscoverabilityDb::Public,
            as_of: DateTime::from_timestamp_millis(1_782_000_000_123).unwrap(),
            source_refs: vec!["fixture-source".to_owned()],
            policy_revision: "accepted-revision".to_owned(),
            stale: true,
            divergent: false,
            via_services: Vec::new(),
            indexed_at: Utc::now(),
        }
    }

    #[test]
    fn public_org_preview_excludes_internal_policy_and_preserves_typed_fields() {
        let preview = organization_preview_from_envelope(envelope_from_row(row(json!({
            "display_name": "Tea Org",
            "handle": "tea-org",
            "member_count": 7,
            "allowed_discoverers": [{"issuer_id": "private-issuer"}],
            "name": "search-only name",
            "summary": "search-only summary",
            "policy_revision": "untrusted-mirror"
        }))))
        .unwrap();
        assert_eq!(
            preview.organization_id.as_str(),
            "ak:did_core:web:tea-org.example"
        );
        assert_eq!(preview.display_name.as_deref(), Some("Tea Org"));
        assert_eq!(preview.member_count, Some(7));
        assert_eq!(preview.policy_revision, "accepted-revision");
        assert_eq!(preview.stale, Some(true));
        let value = serde_json::to_value(&preview).unwrap();
        for field in [
            "discoverability",
            "allowed_discoverers",
            "name",
            "summary",
            "via_services",
        ] {
            assert!(value.get(field).is_none(), "leaked {field}");
        }
        let _: OrganizationPreview = serde_json::from_value(value).unwrap();
    }

    #[test]
    fn public_org_preview_rejects_invalid_registered_field_types() {
        let error = organization_preview_from_envelope(envelope_from_row(row(json!({
            "member_count": "seven"
        }))))
        .unwrap_err();
        assert!(error.contains("member_count"));
    }
}
