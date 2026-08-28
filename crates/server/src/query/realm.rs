//! Realm search and resolve. Spec §9.
//!
//! `ak.find.directory.read.search_realms.v1` and `ak.find.directory.read.resolve_realm.v1`. Both
//! return §9.1 normative envelopes (`as_of`, `source_refs`,
//! `policy_revision`, `via_services`). Hidden / unauthorized resources
//! must be indistinguishable from `not_found` (§3 / §10).
//!
//! The security boundary resource on this surface is a **Realm**
//! (`ak:realm:` URI prefix). Container Spaces are a separate
//! `resource_kind=space` row type and are intentionally not returned here.

use arkret_sdk::{
    DidCoreId, DirectoryRealmResolutionOutcome, DirectoryRealmSearchOutcome,
    DirectoryResolveRealmRequestBody, DirectorySearchRealmsRequestBody, RealmId,
    RealmJoinCandidate, RealmPreview,
};
use arkret_server::CursorBindingContext;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Bool, Double, Jsonb, Nullable, Text, Timestamptz};
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::error::ApiErrorCode;
use crate::filter::discoverers::{VerifiedRestrictedClaims, verify_restricted_claim_presentations};
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::filter::result::ResultEnvelope;
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};
use crate::query::rate_limit::{
    apply_resolve_response_jitter, enforce_query_rate_limit, enforce_resolve_rate_limit,
};
use crate::state::AppState;

#[derive(Debug, Default)]
struct SearchScope {
    organization_principal_id: Option<DidCoreId>,
    source_realm_id: Option<RealmId>,
}

#[handler]
pub async fn search_realms(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("search-realms");
    if !enforce_query_rate_limit(req, res, &state) {
        return;
    }
    let body: DirectorySearchRealmsRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(e) => {
            ApiErrorCode::JsonInvalid.render(res, format!("malformed search body: {e}"));
            return;
        }
    };

    let limit = body.limit.unwrap_or(20).clamp(1, 200) as i64;
    let needle = body.query.unwrap_or_default();
    let scope = SearchScope {
        organization_principal_id: body.organization_principal_id,
        source_realm_id: body.source_realm_id,
    };
    let requester_id = body.requester_id;
    let verified_claims = verified_restricted_claims_for_realm_query(
        &state,
        requester_id.as_ref().map(DidCoreId::as_str),
        body.proof_challenge.as_deref(),
        &body.claim_presentations,
    );
    let filter_digest = match arkret_server::cursor_filter_digest(&serde_json::json!({
        "operation": arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
        "query": &needle,
        "organization_principal_id": scope.organization_principal_id.as_ref(),
        "source_realm_id": scope.source_realm_id.as_ref(),
    })) {
        Ok(digest) => digest,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("realm cursor filter: {error}"));
            return;
        }
    };
    let cursor_context = CursorBindingContext::new(
        requester_id
            .as_ref()
            .map(DidCoreId::as_str)
            .unwrap_or("anonymous"),
        None,
        state.service_core_id().clone(),
        filter_digest,
    );
    let cursor = match body.cursor.as_deref() {
        Some(token) => match state
            .cursor_authority()
            .resolve_stream(token, &cursor_context)
            .and_then(|positions| {
                serde_json::from_value::<RealmCursor>(positions)
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
        "q={needle};org={};source={};cursor={};limit={limit}",
        scope
            .organization_principal_id
            .as_ref()
            .map(DidCoreId::as_str)
            .unwrap_or_default(),
        scope
            .source_realm_id
            .as_ref()
            .map(RealmId::as_str)
            .unwrap_or_default(),
        cursor
            .as_ref()
            .map(|cursor| cursor.resource_id.as_str())
            .unwrap_or_default(),
    );
    let result = pad_to_budget_observed(
        budget,
        arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
        &privacy_key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("search-realms", target)
        },
        async {
            run_visible_realm_search(
                &state,
                &needle,
                &scope,
                cursor.as_ref(),
                requester_id.as_ref().map(DidCoreId::as_str),
                &verified_claims,
                limit + 1,
            )
            .await
        },
    )
    .await;

    match result {
        Ok(mut rows) => {
            // We over-fetched `limit + 1` rows; a full extra row means the
            // result set is truncated and more pages exist (spec §9.1 /
            // profiles-presence §4.1 unified `has_more` convention.
            let has_more = rows.len() > limit as usize;
            let next_cursor = if has_more {
                rows.truncate(limit as usize);
                rows.last()
                    .map(|row| {
                        state.cursor_authority().mint_stream(
                            cursor_context.clone(),
                            serde_json::to_value(cursor_from_row(row)).map_err(|error| {
                                arkret_server::CursorAuthorityError::ParamInvalid(error.to_string())
                            })?,
                            60 * 60 * 1000,
                        )
                    })
                    .transpose()
            } else {
                Ok(None)
            };
            let next_cursor = match next_cursor {
                Ok(cursor) => cursor,
                Err(e) => {
                    ApiErrorCode::InternalError.render(res, format!("realm cursor: {e}"));
                    return;
                }
            };
            let mut results = match rows
                .into_iter()
                .map(realm_preview_from_row)
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(results) => results,
                Err(e) => {
                    ApiErrorCode::InternalError.render(res, e);
                    return;
                }
            };
            // TBY-ORG-02 — derive the verified owning-organization set / official
            // badge from the verified index, replacing any declared hint.
            for preview in &mut results {
                let realm_id = preview.realm_id.as_str().to_owned();
                apply_verified_organizations(&state, &realm_id, preview).await;
            }
            res.render(Json(DirectoryRealmSearchOutcome {
                realms: results,
                next_cursor,
                has_more,
            }));
        }
        Err(e) => {
            ApiErrorCode::InternalError.render(res, format!("realm search: {e}"));
        }
    }
}

// SAFETY: alsoKnownAs is holder-side reverse endorsement only — not used here for routing.
// Spec sync 37ce729 (B-E) — identity-handles §6: `resolve_realm` accepts
// `realm_id`, `alias`, `invite_token`, `signed_link` — all explicit
// Directory-authoritative keys. `alsoKnownAs` claims that may be present
// inside a cached `public_projection` are NEVER consulted for resolve key
// matching. They are advisory display data only.
#[handler]
pub async fn resolve_realm(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("resolve-realm");
    let body: DirectoryResolveRealmRequestBody = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ApiErrorCode::JsonInvalid.render(res, format!("malformed resolve body: {e}"));
            return;
        }
    };

    let requester_id = body
        .requester_id
        .as_ref()
        .map(DidCoreId::as_str)
        .map(str::to_owned);
    let verified_claims = verified_restricted_claims_for_realm_query(
        &state,
        requester_id.as_deref(),
        body.proof_challenge.as_deref(),
        &body.claim_presentations,
    );
    let key = body
        .realm_id
        .as_ref()
        .map(|realm_id| realm_id.as_str().to_owned())
        .or(body.alias)
        .or(body.invite_token)
        .or(body.signed_link);
    let key = match key {
        Some(k) if !k.is_empty() => k,
        _ => {
            ApiErrorCode::ParamMissing.render(
                res,
                "at least one of realm_id / alias / invite_token / signed_link required",
            );
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
    let outcome = pad_to_budget_observed(
        budget,
        arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
        &key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("resolve-realm", target)
        },
        async {
            let row = match load_realm_row(&state, &key).await {
                Ok(Some(row)) => row,
                Ok(None) => return Ok(None),
                Err(error) => return Err(format!("realm resolve: {error}")),
            };
            if !is_result_visible(&row, requester_id.as_deref(), &verified_claims) {
                return Ok(None);
            }
            let join_candidates = join_candidates_for_row(&row);
            let realm_id = row.resource_id.clone();
            let mut realm_preview = realm_preview_from_row(row)?;
            // TBY-ORG-02 — verified owning-organization set / official badge,
            // derived inside the latency budget so a hit stays timing-equivalent.
            apply_verified_organizations(&state, &realm_id, &mut realm_preview).await;
            Ok(Some((realm_preview, join_candidates)))
        },
    )
    .await;

    // P5 — stochastic anti-enumeration jitter on resolve responses.
    apply_resolve_response_jitter().await;

    match outcome {
        Ok(Some((realm_preview, join_candidates))) => {
            res.render(Json(DirectoryRealmResolutionOutcome {
                realm_preview,
                stripped_state: Vec::new(),
                join_rule: None,
                join_candidates,
            }));
        }
        Err(message) => {
            ApiErrorCode::InternalError.render(res, message);
        }
        // Hidden, withdrawn, or unknown — all collapse to blinded not_found.
        _ => {
            ApiErrorCode::NotFound.render(res, "not found");
        }
    }
}

fn verified_restricted_claims_for_realm_query(
    state: &AppState,
    requester_id: Option<&str>,
    proof_challenge: Option<&str>,
    presentations: &[arkret_sdk::DirectoryRestrictedClaimPresentation],
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

// ---- shared resolution helper (AKP-0011 reuse) --------------------------

/// The canonical realm-resolution outcome, extracted so the object-level
/// `ak.find.directory.read.resolve_target.v1` handler (AKP-0011,
/// [`crate::query::target`]) can DELEGATE to the exact same realm-resolution
/// semantics — same key load, same visibility / blinding rules, same
/// `via_services` and §9.1 common fields — instead of reinventing them.
///
/// `realm.rs` stays the single source of truth for what "resolving a Realm"
/// means; `target.rs` builds its `realm_preview` branch entirely from this.
pub(crate) struct ResolvedRealm {
    /// Canonical `ak:realm:<44-char-token>` resource id (resolved from an alias when
    /// the caller supplied an alias key).
    pub realm_id: String,
    /// The §9.1 result envelope (public-projection payload + as_of /
    /// source_refs / policy_revision / stale / divergent / via_services).
    pub envelope: ResultEnvelope,
    pub join_candidates: Vec<RealmJoinCandidate>,
}

/// Resolve a Realm by `key` (realm_id OR alias) applying the identical load
/// and visibility-blinding logic as [`resolve_realm`], WITHOUT the salvo
/// request/response plumbing or the latency-floor padding. The caller is
/// responsible for wrapping this in the shared anti-enumeration budget so a
/// hit and a blinded miss stay byte-/timing-indistinguishable.
///
/// Returns `None` for a hidden / withdrawn / unknown Realm — exactly the set
/// of cases [`resolve_realm`] collapses to a blinded `not_found`.
pub(crate) async fn resolve_realm_visible(
    state: &AppState,
    key: &str,
    requester_id: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
) -> anyhow::Result<Option<ResolvedRealm>> {
    let Some(row) = load_realm_row(state, key).await? else {
        return Ok(None);
    };
    if !is_result_visible(&row, requester_id, verified_claims) {
        return Ok(None);
    }
    let realm_id = row.resource_id.clone();
    let join_candidates = join_candidates_for_row(&row);
    let envelope = envelope_from_row(row);
    Ok(Some(ResolvedRealm {
        realm_id,
        envelope,
        join_candidates,
    }))
}

/// Resolve a Realm for a token-scoped preview link. This deliberately skips
/// the ordinary discoverability gate: the preview token and effective
/// `ak.realm.preview_policy` are the authorization boundary for this path.
pub(crate) async fn resolve_realm_for_preview_link(
    state: &AppState,
    key: &str,
) -> anyhow::Result<Option<ResolvedRealm>> {
    let Some(row) = load_realm_row(state, key).await? else {
        return Ok(None);
    };
    let realm_id = row.resource_id.clone();
    let envelope = envelope_from_row(row);
    Ok(Some(ResolvedRealm {
        realm_id,
        envelope,
        join_candidates: Vec::new(),
    }))
}

// ---- internal load primitives -------------------------------------------

// Tail-column ordering across the three Realm row mirrors (`RealmStoredRow` /
// `RealmRow` / `RealmSqlRow`) is, by convention,
// `... via_services, indexed_at, [score], realm_destroyed_at,
// reachability_revoked_at`. The single intentional difference is that this
// mirror has NO derived `score` column: the resolve path (which loads
// `RealmStoredRow`) does not rank, so there is no score to carry. The two
// search mirrors insert `score` between `indexed_at` and `realm_destroyed_at`.
//
// `expires_at` is deliberately absent from all three mirrors: freshness is
// enforced by the background sweep that flips `stale = true`, and every Realm
// read path already filters on `stale = false`. The Realm result envelope
// exposes no revalidation deadline, so projecting the column would only carry
// an unread value out of Postgres.
#[derive(Debug, Queryable)]
struct RealmStoredRow {
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
    // `ak.realm.destroy` terminal state.
    realm_destroyed_at: Option<DateTime<Utc>>,
    // Consent-revoke reachability invalidation.
    reachability_revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
struct RealmRow {
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
    score: f64,
    realm_destroyed_at: Option<DateTime<Utc>>,
    reachability_revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, QueryableByName)]
struct RealmSqlRow {
    #[diesel(sql_type = Text)]
    resource_id: String,
    #[diesel(sql_type = Jsonb)]
    public_projection: JsonValue,
    #[diesel(sql_type = Text)]
    discoverability: String,
    #[diesel(sql_type = Timestamptz)]
    as_of: DateTime<Utc>,
    #[diesel(sql_type = Array<Text>)]
    source_refs: Vec<String>,
    #[diesel(sql_type = Text)]
    policy_revision: String,
    #[diesel(sql_type = Bool)]
    stale: bool,
    #[diesel(sql_type = Bool)]
    divergent: bool,
    #[diesel(sql_type = Array<Text>)]
    via_services: Vec<String>,
    #[diesel(sql_type = Timestamptz)]
    indexed_at: DateTime<Utc>,
    #[diesel(sql_type = Double)]
    score: f64,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    realm_destroyed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    reachability_revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RealmCursor {
    score: f64,
    indexed_at: DateTime<Utc>,
    resource_id: String,
}

async fn run_realm_search(
    state: &AppState,
    needle: &str,
    scope: &SearchScope,
    cursor: Option<&RealmCursor>,
    limit: i64,
) -> anyhow::Result<Vec<RealmRow>> {
    let mut conn = state.db().get().await?;

    let needle = needle.trim();
    let organization_principal_id = scope
        .organization_principal_id
        .as_ref()
        .map(DidCoreId::as_str);
    let source_realm_id = scope.source_realm_id.as_ref().map(RealmId::as_str);
    let cursor_score = cursor.map(|c| c.score);
    let cursor_indexed_at = cursor.map(|c| c.indexed_at);
    let cursor_resource_id = cursor.map(|c| c.resource_id.as_str());

    let rows: Vec<RealmSqlRow> = diesel::sql_query(REALM_SEARCH_SQL)
        .bind::<Text, _>(needle)
        .bind::<Nullable<Text>, _>(organization_principal_id)
        .bind::<Nullable<Text>, _>(source_realm_id)
        .bind::<Nullable<Double>, _>(cursor_score)
        .bind::<Nullable<Timestamptz>, _>(cursor_indexed_at)
        .bind::<Nullable<Text>, _>(cursor_resource_id)
        .bind::<BigInt, _>(limit)
        .load(&mut *conn)
        .await?;

    rows.into_iter().map(RealmRow::try_from).collect()
}

async fn run_visible_realm_search(
    state: &AppState,
    needle: &str,
    scope: &SearchScope,
    cursor: Option<&RealmCursor>,
    requester_id: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
    visible_limit: i64,
) -> anyhow::Result<Vec<RealmRow>> {
    let target_len = visible_limit.max(1) as usize;
    let batch_limit = visible_limit.max(64);
    let mut scan_cursor = cursor.cloned();
    let mut visible_rows = Vec::with_capacity(target_len.min(201));

    loop {
        let rows =
            run_realm_search(state, needle, scope, scan_cursor.as_ref(), batch_limit).await?;
        if rows.is_empty() {
            break;
        }

        let fetched = rows.len();
        let mut next_scan_cursor = None;
        for row in rows {
            next_scan_cursor = Some(cursor_from_row(&row));
            if is_result_visible(&row, requester_id, verified_claims) {
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

async fn load_realm_row(state: &AppState, key: &str) -> anyhow::Result<Option<RealmRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get().await?;
    let row: Option<RealmStoredRow> = r::directory_resources
        .filter(r::resource_kind.eq(DirectoryResourceKindDb::Realm))
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
            r::realm_destroyed_at,
            r::reachability_revoked_at,
        ))
        .first(&mut *conn)
        .await
        .optional()?;
    Ok(row.map(RealmRow::from))
}

fn envelope_from_row(row: RealmRow) -> ResultEnvelope {
    // Once `ak.realm.destroy` has anchored, the row's
    // projection collapses to a deterministic tombstone so the resolve
    // / search face surfaces `[erased]` instead of leaking the historical
    // governance state.
    if let Some(destroyed_at) = row.realm_destroyed_at {
        let payload = serde_json::json!({
            "realm_id": row.resource_id,
            "discoverability": row.discoverability.as_pg(),
            "title": "[erased]",
            "summary": "[erased]",
            "tombstone": {
                "kind": "realm_destroyed",
                "destroyed_at": destroyed_at,
                "via_event_kind": arkret_sdk::EventKind::RealmDestroy.as_str(),
            },
        });
        return ResultEnvelope::from_row(
            payload,
            row.as_of,
            row.source_refs,
            row.policy_revision,
            row.stale,
            row.divergent,
            row.via_services,
        );
    }
    // Inject the canonical key so clients can act on the row immediately.
    let join_candidates = join_candidates_for_row(&row);
    let mut payload = row.public_projection;
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(
            "realm_id".into(),
            JsonValue::String(row.resource_id.clone()),
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
    .with_join_candidates(join_candidates)
}

pub(crate) fn realm_preview_from_envelope(
    realm_id: &str,
    envelope: &ResultEnvelope,
) -> Result<RealmPreview, String> {
    let mut value = serde_json::to_value(envelope)
        .map_err(|e| format!("realm preview envelope serialization failed: {e}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "realm preview envelope did not serialize as an object".to_owned())?;
    object.insert(
        "realm_id".to_owned(),
        JsonValue::String(realm_id.to_owned()),
    );
    // TBY-ORG-02 — `owning_organizations` / `organization_principal_id` carried by the
    // public projection are DECLARED hints only. They MUST NOT auto-populate the
    // verified-relationship surface of the preview; the official badge / verified
    // organization set is re-derived from the `verified_realm_organizations`
    // index by `apply_verified_organizations`. Drop the declared values here so a
    // realm with only declared hints surfaces an EMPTY verified set (no badge).
    object.remove("owning_organizations");
    object.remove("organization_principal_id");
    serde_json::from_value(value).map_err(|e| format!("realm preview is not SDK-compatible: {e}"))
}

fn realm_preview_from_row(row: RealmRow) -> Result<RealmPreview, String> {
    let realm_id = row.resource_id.clone();
    let envelope = envelope_from_row(row);
    realm_preview_from_envelope(&realm_id, &envelope)
}

/// TBY-ORG-02 — overwrite a Realm preview's verified-relationship surface
/// (`owning_organizations` + the single `organization_principal_id` convenience field)
/// from the `verified_realm_organizations` index. Only `active`,
/// in-validity-window, non-stale relationships whose verified `control_scopes`
/// cover `official_badge` are surfaced as owning organizations, so a Realm that
/// carries only a declared `owning_organizations` / `organization_principal_id` hint (or
/// a relationship that lacks the `official_badge` scope) shows NO official
/// verified organization. `owner` and `governance` relationships are the
/// ownership / governance surface; `sponsor` and `directory_certifier` are not
/// owners and never populate `owning_organizations`.
async fn apply_verified_organizations(
    state: &AppState,
    realm_id: &str,
    preview: &mut RealmPreview,
) {
    let now = Utc::now();
    let rows = match crate::ingest::organization_statement::load_verified_relationships(
        state.db(),
        realm_id,
        now,
    )
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            // Fail closed: an index read error must not fabricate a badge.
            tracing::warn!(%realm_id, %error, "failed to load verified realm organizations");
            preview.owning_organizations.clear();
            preview.organization_principal_id = None;
            return;
        }
    };

    let mut owning: Vec<DidCoreId> = Vec::new();
    for row in rows {
        if !row.is_effective_active(now) {
            continue;
        }
        // Owner / governance relationships that carry the `official_badge`
        // endorsement scope are the verified owning-organization surface.
        let is_owning = matches!(row.relationship.as_str(), "owner" | "governance");
        if !is_owning || !row.covers_scope("official_badge") {
            continue;
        }
        if !owning.contains(&row.organization_principal_id) {
            owning.push(row.organization_principal_id);
        }
    }

    // `organization_principal_id` is the single-org convenience mirror; only set it when
    // exactly one verified owning organization exists, never from a declared
    // hint.
    preview.organization_principal_id = if owning.len() == 1 {
        <[DidCoreId]>::first(&owning).cloned()
    } else {
        None
    };
    preview.owning_organizations = owning;
}

fn join_candidates_for_row(_row: &RealmRow) -> Vec<RealmJoinCandidate> {
    // `via_services` is deliberately only a stable service core-id list. A
    // RealmJoinCandidate now requires a fully verifiable ServiceResolutionCarrier,
    // and Teabay does not persist remote carriers. Emitting no candidate is the
    // only safe behavior until ingest retains an independently verified current
    // record (or another trusted carrier source is configured). Never derive a
    // URL/DID from the core id and never reuse this directory's own
    // resolution commitment for a remote Principal Server.
    Vec::new()
}

fn is_result_visible(
    row: &RealmRow,
    requester_id: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
) -> bool {
    // Once reachability has been revoked for the
    // affected actor we drop the row from the search face. Resolve
    // still surfaces the row (so existing in-flight conversations can
    // observe the revocation) but `search-*` lists hide it.
    if row.reachability_revoked_at.is_some() {
        return false;
    }
    match row.discoverability {
        DiscoverabilityDb::Public | DiscoverabilityDb::Listed => true,
        DiscoverabilityDb::Restricted => has_restricted_query_authorization(
            &row.public_projection,
            requester_id,
            verified_claims,
        ),
        DiscoverabilityDb::Unlisted | DiscoverabilityDb::InviteOnly | DiscoverabilityDb::Secret => {
            false
        }
    }
}

fn has_restricted_query_authorization(
    projection: &JsonValue,
    requester_id: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
) -> bool {
    crate::filter::discoverers::matches_allowed_discoverers(
        projection,
        requester_id,
        verified_claims,
    )
}

impl TryFrom<RealmSqlRow> for RealmRow {
    type Error = anyhow::Error;

    fn try_from(row: RealmSqlRow) -> Result<Self, Self::Error> {
        Ok(Self {
            resource_id: row.resource_id,
            public_projection: row.public_projection,
            discoverability: DiscoverabilityDb::from_pg(&row.discoverability)?,
            as_of: row.as_of,
            source_refs: row.source_refs,
            policy_revision: row.policy_revision,
            stale: row.stale,
            divergent: row.divergent,
            via_services: row.via_services,
            indexed_at: row.indexed_at,
            score: row.score,
            realm_destroyed_at: row.realm_destroyed_at,
            reachability_revoked_at: row.reachability_revoked_at,
        })
    }
}

impl From<RealmStoredRow> for RealmRow {
    fn from(row: RealmStoredRow) -> Self {
        Self {
            resource_id: row.resource_id,
            public_projection: row.public_projection,
            discoverability: row.discoverability,
            as_of: row.as_of,
            source_refs: row.source_refs,
            policy_revision: row.policy_revision,
            stale: row.stale,
            divergent: row.divergent,
            via_services: row.via_services,
            indexed_at: row.indexed_at,
            score: 0.0,
            realm_destroyed_at: row.realm_destroyed_at,
            reachability_revoked_at: row.reachability_revoked_at,
        }
    }
}

fn cursor_from_row(row: &RealmRow) -> RealmCursor {
    RealmCursor {
        score: row.score,
        indexed_at: row.indexed_at,
        resource_id: row.resource_id.clone(),
    }
}

const REALM_SEARCH_SQL: &str = r#"
WITH ranked AS (
    SELECT
        resource_id,
        public_projection,
        discoverability::text AS discoverability,
        as_of,
        source_refs,
        policy_revision,
        stale,
        divergent,
        via_services,
        indexed_at,
        realm_destroyed_at,
        reachability_revoked_at,
        CASE
            WHEN $1 = '' THEN 0.0::double precision
            ELSE GREATEST(
                similarity(search_text, $1),
                ts_rank(search_vector, plainto_tsquery('simple', $1))
            )::double precision
        END AS score
    FROM directory_resources
    WHERE resource_kind = 'realm'::resource_kind
      AND stale = false
      AND discoverability IN (
          'public'::discoverability,
          'listed'::discoverability,
          'restricted'::discoverability
      )
      AND (
          $1 = ''
          OR search_vector @@ plainto_tsquery('simple', $1)
          OR search_text % $1
          OR public_projection::text ILIKE ('%' || $1 || '%')
      )
      -- TBY-ORG-02 — `organization_principal_id` here is the DECLARED announce hint, so
      -- this is a declared-hint filter (a cheap pre-filter / discovery aid). It
      -- is NOT a verified-relationship filter: each returned preview's
      -- `owning_organizations` is re-derived from the verified
      -- `ak.realm.organization` index by `apply_verified_organizations`, so the
      -- client distinguishes "claims this org" (matched here) from "verified
      -- official relationship" (present in the preview's owning_organizations).
      AND (
          $2::text IS NULL
          OR public_projection->>'organization_principal_id' = $2
          OR public_projection->>'organization' = $2
      )
      AND (
          $3::text IS NULL
          OR public_projection->>'source_realm_id' = $3
          OR public_projection->'source_realm_ids' ? $3
      )
)
SELECT
    resource_id,
    public_projection,
    discoverability,
    as_of,
    source_refs,
    policy_revision,
    stale,
    divergent,
    via_services,
    indexed_at,
    score,
    realm_destroyed_at,
    reachability_revoked_at
FROM ranked
WHERE (
    $4::double precision IS NULL
    OR score < $4
    OR (score = $4 AND indexed_at < $5)
    OR (score = $4 AND indexed_at = $5 AND resource_id > $6)
)
-- Spec §3/§11: ranking MUST NOT leak member count. The tiebreaker is the
-- member-count-independent keyset cursor (indexed_at, resource_id), which
-- also keeps ORDER BY consistent with the pagination cursor above.
ORDER BY score DESC, indexed_at DESC, resource_id ASC
LIMIT $7
"#;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn restricted_projection_requires_verified_claim() {
        let projection = json!({
            "payload": {
                "allowed_discoverers": [
                    {
                        "type": "claim",
                        "claim_kind": "organization_membership",
                        "organization_id": "ak:did_core:web:acme.example",
                        "issuer_id": "ak:did_core:web:acme.example"
                    }
                ]
            }
        });

        assert!(!has_restricted_query_authorization(
            &projection,
            Some("ak:did_core:web:alice.example"),
            &VerifiedRestrictedClaims::default(),
        ));
        let claim = crate::filter::discoverers::organization_membership_claim(
            "claim-1",
            arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:acme.example".to_owned()).unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:acme.example".to_owned()).unwrap(),
            vec!["member".to_owned()],
        );
        let verified_claims = VerifiedRestrictedClaims::for_test(vec![claim]);
        assert!(has_restricted_query_authorization(
            &projection,
            Some("ak:did_core:web:bob.example"),
            &verified_claims,
        ));
        assert!(!has_restricted_query_authorization(
            &projection,
            Some("ak:did_core:web:bob.example"),
            &VerifiedRestrictedClaims::default(),
        ));
    }

    #[test]
    fn unlisted_realm_is_not_search_visible() {
        let row = RealmRow {
            resource_id: "ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO".to_owned(),
            public_projection: json!({ "title": "Tea" }),
            discoverability: DiscoverabilityDb::Unlisted,
            as_of: chrono::Utc::now(),
            source_refs: vec!["ak:event:1".to_owned()],
            policy_revision: "rev-1".to_owned(),
            stale: false,
            divergent: false,
            via_services: Vec::new(),
            indexed_at: chrono::Utc::now(),
            score: 1.0,
            realm_destroyed_at: None,
            reachability_revoked_at: None,
        };

        assert!(!is_result_visible(
            &row,
            Some("ak:did_core:web:alice.example"),
            &VerifiedRestrictedClaims::default(),
        ));
    }
}
