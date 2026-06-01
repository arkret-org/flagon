//! Realm search and resolve. Spec §9.
//!
//! `cx.directory.search_realms` and `cx.directory.resolve_realm`. Both
//! return §9.1 normative envelopes (`as_of`, `source_refs`,
//! `policy_revision`, `via_services`). Hidden / unauthorized resources
//! must be indistinguishable from `not_found` (§3 / §10).
//!
//! The security boundary resource on this surface is a **Realm**
//! (`cx:realm:` URI prefix). Container Spaces are a separate
//! `resource_kind=space` row type and are intentionally not returned here.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use contrix_sdk::{
    Did, EventId, RealmId, RealmJoinCandidate, RealmJoinCandidateRole,
    RealmJoinCandidateServiceType, RealmJoinCandidateSource, RealmJoinMethod,
};
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Bool, Double, Jsonb, Nullable, Text, Timestamptz};
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::error::ApiErrorCode;
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::filter::result::ResultEnvelope;
use crate::ingest::{DiscoverabilityWire, ResourceKindWire};
use crate::query::rate_limit::{
    apply_resolve_response_jitter, enforce_query_rate_limit, enforce_resolve_rate_limit,
};
use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
pub struct SearchRealmsRequest {
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
    pub source_realm_id: Option<String>,
}

#[handler]
pub async fn search_realms(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
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
    let body: SearchRealmsRequest = req.parse_json().await.unwrap_or_default();

    let limit = body.limit.unwrap_or(20).clamp(1, 200) as i64;
    let needle = body.query.unwrap_or_default();
    let scope = body.scope.unwrap_or_default();
    let requester = body.requester;
    let proofs = body.proofs;
    let cursor = match body.cursor.as_deref().map(decode_cursor).transpose() {
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
        "q={needle};org={};source={};cursor={};limit={limit}",
        scope.organization_did.as_deref().unwrap_or_default(),
        scope.source_realm_id.as_deref().unwrap_or_default(),
        cursor
            .as_ref()
            .map(|cursor| cursor.resource_id.as_str())
            .unwrap_or_default(),
    );
    let result = pad_to_budget_observed(
        budget,
        "cx.directory.search_realms",
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
            let next_cursor = if rows.len() > limit as usize {
                rows.truncate(limit as usize);
                rows.last().map(encode_cursor).transpose()
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
            let envelopes: Vec<ResultEnvelope> = rows.into_iter().map(envelope_from_row).collect();
            res.render(Json(json!({
                "results": envelopes,
                "next_cursor": next_cursor,
            })));
        }
        Err(e) => {
            ApiErrorCode::InternalError.render(res, format!("realm search: {e}"));
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ResolveRealmRequest {
    #[serde(default)]
    pub realm_id: Option<String>,
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

// SAFETY: alsoKnownAs is holder-side reverse endorsement only — not used here for routing.
// Spec sync 37ce729 (B-E) — identity-handles §6: `resolve_realm` accepts
// `realm_id`, `alias`, `invite_token`, `signed_link` — all explicit
// Directory-authoritative keys. `alsoKnownAs` claims that may be present
// inside a cached `public_projection` are NEVER consulted for resolve key
// matching. They are advisory display data only.
#[handler]
pub async fn resolve_realm(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("resolve-realm");
    let body: ResolveRealmRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ApiErrorCode::BadJson.render(res, format!("malformed resolve body: {e}"));
            return;
        }
    };

    let key = body
        .realm_id
        .clone()
        .or(body.alias)
        .or(body.invite_token)
        .or(body.signed_link);
    let key = match key {
        Some(k) if !k.is_empty() => k,
        _ => {
            ApiErrorCode::MissingParam.render(
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
    let row = pad_to_budget_observed(
        budget,
        "cx.directory.resolve_realm",
        &key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("resolve-realm", target)
        },
        async { load_realm_row(&state, &key).await },
    )
    .await;

    // P5 — stochastic anti-enumeration jitter on resolve responses.
    apply_resolve_response_jitter().await;

    match row {
        Ok(Some(r)) if is_result_visible(&r, body.requester.as_deref(), &body.proofs) => {
            res.render(Json(envelope_from_row(r)));
        }
        // Hidden, withdrawn, or unknown — all collapse to blinded not_found.
        _ => {
            ApiErrorCode::NotFound.render(res, "not found");
        }
    }
}

// ---- shared resolution helper (CXP-0011 reuse) --------------------------

/// The canonical realm-resolution outcome, extracted so the object-level
/// `cx.directory.resolve_target` handler (CXP-0011,
/// [`crate::query::target`]) can DELEGATE to the exact same realm-resolution
/// semantics — same key load, same visibility / blinding rules, same
/// `via_services` and §9.1 common fields — instead of reinventing them.
///
/// `realm.rs` stays the single source of truth for what "resolving a Realm"
/// means; `target.rs` builds its `realm_preview` branch entirely from this.
pub(crate) struct ResolvedRealm {
    /// Canonical `cx:realm:<uuid>` resource id (resolved from an alias when
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
    requester: Option<&str>,
    proofs: &[String],
) -> anyhow::Result<Option<ResolvedRealm>> {
    let Some(row) = load_realm_row(state, key).await? else {
        return Ok(None);
    };
    if !is_result_visible(&row, requester, proofs) {
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

// ---- internal load primitives -------------------------------------------

#[derive(Debug, Queryable)]
struct RealmStoredRow {
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
    // Round R2/R3 T07.
    realm_destroyed_at: Option<DateTime<Utc>>,
    // Round R2/R3 T17.
    reachability_revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
struct RealmRow {
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
    #[diesel(sql_type = Nullable<Text>)]
    policy_revision: Option<String>,
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
    let organization_did = scope.organization_did.as_deref();
    let source_realm_id = scope.source_realm_id.as_deref();
    let cursor_score = cursor.map(|c| c.score);
    let cursor_indexed_at = cursor.map(|c| c.indexed_at);
    let cursor_resource_id = cursor.map(|c| c.resource_id.as_str());

    let rows: Vec<RealmSqlRow> = diesel::sql_query(REALM_SEARCH_SQL)
        .bind::<Text, _>(needle)
        .bind::<Nullable<Text>, _>(organization_did)
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
    requester: Option<&str>,
    proofs: &[String],
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
            if is_result_visible(&row, requester, proofs) {
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
        .filter(r::resource_kind.eq(ResourceKindWire::Realm))
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
    // Round R2/R3 T07 — once `cx.realm.destroy` has anchored, the row's
    // projection collapses to a deterministic tombstone so the resolve
    // / search face surfaces `[erased]` instead of leaking the historical
    // governance state.
    if let Some(destroyed_at) = row.realm_destroyed_at {
        let payload = serde_json::json!({
            "realm_id": row.resource_id,
            "discoverability": row.discoverability.as_pg(),
            "name": "[erased]",
            "summary": "[erased]",
            "tombstone": {
                "kind": "realm_destroyed",
                "destroyed_at": destroyed_at,
                "via_event_kind": "cx.realm.destroy",
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

fn join_candidates_for_row(row: &RealmRow) -> Vec<RealmJoinCandidate> {
    let Ok(realm_id) = RealmId::new(row.resource_id.clone()) else {
        return Vec::new();
    };
    let source_refs: Vec<EventId> = row
        .source_refs
        .iter()
        .filter_map(|source_ref| EventId::new(source_ref.clone()).ok())
        .collect();
    row.via_services
        .iter()
        .enumerate()
        .filter_map(|(idx, service_did)| {
            let service_did = Did::new(service_did.clone()).ok()?;
            Some(RealmJoinCandidate {
                realm_id: realm_id.clone(),
                service_did,
                service_type: RealmJoinCandidateServiceType::PrincipalServer,
                role: if idx == 0 {
                    RealmJoinCandidateRole::Primary
                } else {
                    RealmJoinCandidateRole::Mirror
                },
                endpoint: None,
                operations: vec!["cx.events.submit".to_owned()],
                join_methods: vec![
                    RealmJoinMethod::InviteAccept,
                    RealmJoinMethod::MemberJoin,
                    RealmJoinMethod::Knock,
                    RealmJoinMethod::RestrictedJoin,
                ],
                priority: Some(idx.min(1000) as u16),
                source: RealmJoinCandidateSource::DirectoryIngest,
                source_refs: source_refs.clone(),
                frontier_ref: None,
                as_of: row.as_of,
                expires_at: row.as_of + Duration::minutes(15),
                proofs: Vec::new(),
            })
        })
        .collect()
}

fn is_result_visible(row: &RealmRow, requester: Option<&str>, proofs: &[String]) -> bool {
    // Round R2/R3 T17 — once reachability has been revoked for the
    // affected actor we drop the row from the search face. Resolve
    // still surfaces the row (so existing in-flight conversations can
    // observe the revocation) but `search-*` lists hide it.
    if row.reachability_revoked_at.is_some() {
        return false;
    }
    match row.discoverability {
        DiscoverabilityWire::Public
        | DiscoverabilityWire::Listed
        | DiscoverabilityWire::Unlisted => true,
        DiscoverabilityWire::Restricted => {
            has_restricted_query_authorization(&row.public_projection, requester, proofs)
        }
        DiscoverabilityWire::InviteOnly | DiscoverabilityWire::Secret => false,
    }
}

fn has_restricted_query_authorization(
    projection: &JsonValue,
    requester: Option<&str>,
    proofs: &[String],
) -> bool {
    let Some(discoverers) = allowed_discoverers(projection) else {
        return false;
    };

    discoverers.iter().any(|entry| match entry {
        JsonValue::String(value) => proofs.iter().any(|proof| proof == value),
        JsonValue::Object(obj) => {
            let requester_matches = requester.is_some_and(|requester| {
                ["requester", "subject", "did", "actor"]
                    .iter()
                    .any(|key| obj.get(*key).and_then(JsonValue::as_str) == Some(requester))
            });
            let proof_matches = ["proof", "presentation", "claim", "claim_id", "claim_kind"]
                .iter()
                .filter_map(|key| obj.get(*key).and_then(JsonValue::as_str))
                .any(|expected| proofs.iter().any(|proof| proof == expected));
            requester_matches || proof_matches
        }
        _ => false,
    })
}

fn allowed_discoverers(projection: &JsonValue) -> Option<&Vec<JsonValue>> {
    projection
        .get("allowed_discoverers")
        .or_else(|| projection.pointer("/payload/allowed_discoverers"))
        .and_then(JsonValue::as_array)
}

impl TryFrom<RealmSqlRow> for RealmRow {
    type Error = anyhow::Error;

    fn try_from(row: RealmSqlRow) -> Result<Self, Self::Error> {
        Ok(Self {
            resource_id: row.resource_id,
            public_projection: row.public_projection,
            discoverability: discoverability_from_str(&row.discoverability)?,
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

fn discoverability_from_str(value: &str) -> anyhow::Result<DiscoverabilityWire> {
    match value {
        "public" => Ok(DiscoverabilityWire::Public),
        "listed" => Ok(DiscoverabilityWire::Listed),
        "restricted" => Ok(DiscoverabilityWire::Restricted),
        "unlisted" => Ok(DiscoverabilityWire::Unlisted),
        "invite_only" => Ok(DiscoverabilityWire::InviteOnly),
        "secret" => Ok(DiscoverabilityWire::Secret),
        other => anyhow::bail!("unknown discoverability {other}"),
    }
}

fn encode_cursor(row: &RealmRow) -> anyhow::Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cursor_from_row(row))?))
}

fn cursor_from_row(row: &RealmRow) -> RealmCursor {
    RealmCursor {
        score: row.score,
        indexed_at: row.indexed_at,
        resource_id: row.resource_id.clone(),
    }
}

fn decode_cursor(cursor: &str) -> Result<RealmCursor, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|e| format!("invalid cursor encoding: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid cursor body: {e}"))
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
        END AS score,
        CASE public_projection->>'member_count_bucket'
            WHEN '2000+' THEN 6
            WHEN '501-2000' THEN 5
            WHEN '101-500' THEN 4
            WHEN '51-100' THEN 3
            WHEN '11-50' THEN 2
            WHEN '1-10' THEN 1
            ELSE 0
        END AS member_count_rank
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
      AND (
          $2::text IS NULL
          OR public_projection->>'organization_did' = $2
          OR public_projection->>'organization' = $2
          OR public_projection->'official_organizations' ? $2
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
ORDER BY score DESC, member_count_rank DESC, indexed_at DESC, resource_id ASC
LIMIT $7
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricted_projection_requires_matching_requester_or_proof() {
        let projection = json!({
            "payload": {
                "allowed_discoverers": [
                    {
                        "type": "claim",
                        "claim_kind": "org_membership",
                        "organization": "did:web:acme.example",
                        "issuer": "did:web:acme.example"
                    },
                    { "requester": "did:web:alice.example" }
                ]
            }
        });

        assert!(has_restricted_query_authorization(
            &projection,
            Some("did:web:alice.example"),
            &[]
        ));
        assert!(has_restricted_query_authorization(
            &projection,
            Some("did:web:bob.example"),
            &["org_membership".to_string()]
        ));
        assert!(!has_restricted_query_authorization(
            &projection,
            Some("did:web:bob.example"),
            &["other_claim".to_string()]
        ));
    }
}
