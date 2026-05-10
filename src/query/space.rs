//! Space search and resolve. Spec §9.
//!
//! `cx.directory.search_spaces` and `cx.directory.resolve_space`. Both
//! return §9.1 normative envelopes (`as_of`, `source_refs`,
//! `policy_revision`, `via_services`). Hidden / unauthorized resources
//! must be indistinguishable from `not_found` (§3 / §10).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Bool, Double, Jsonb, Nullable, Text, Timestamptz};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::{
    error::ErrorCode,
    filter::{
        enumeration::{LatencyBudget, pad_to_budget},
        result::ResultEnvelope,
    },
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
    let scope = body.scope.unwrap_or_default();
    let requester = body.requester;
    let proofs = body.proofs;
    let cursor = match body.cursor.as_deref().map(decode_cursor).transpose() {
        Ok(cursor) => cursor,
        Err(message) => {
            ErrorCode::BadQuery.render(res, message);
            return;
        }
    };

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let privacy_key = format!(
        "q={needle};org={};parent={};cursor={};limit={limit}",
        scope.organization_did.as_deref().unwrap_or_default(),
        scope.parent_space_id.as_deref().unwrap_or_default(),
        cursor
            .as_ref()
            .map(|cursor| cursor.resource_id.as_str())
            .unwrap_or_default(),
    );
    let result = pad_to_budget(budget, "cx.directory.search_spaces", &privacy_key, async {
        run_visible_space_search(
            &state,
            &needle,
            &scope,
            cursor.as_ref(),
            requester.as_deref(),
            &proofs,
            limit + 1,
        )
        .await
    })
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
                    ErrorCode::InternalError.render(res, format!("space cursor: {e}"));
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

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let row = pad_to_budget(budget, "cx.directory.resolve_space", &key, async {
        load_space_row(&state, &key).await
    })
    .await;

    match row {
        Ok(Some(r)) if is_result_visible(&r, body.requester.as_deref(), &body.proofs) => {
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
struct SpaceStoredRow {
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

#[derive(Debug)]
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
    indexed_at: DateTime<Utc>,
    score: f64,
}

#[derive(Debug, QueryableByName)]
struct SpaceSqlRow {
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpaceCursor {
    score: f64,
    indexed_at: DateTime<Utc>,
    resource_id: String,
}

async fn run_space_search(
    state: &AppState,
    needle: &str,
    scope: &SearchScope,
    cursor: Option<&SpaceCursor>,
    limit: i64,
) -> anyhow::Result<Vec<SpaceRow>> {
    let mut conn = state.db().get()?;

    let needle = needle.trim();
    let organization_did = scope.organization_did.as_deref();
    let parent_space_id = scope.parent_space_id.as_deref();
    let cursor_score = cursor.map(|c| c.score);
    let cursor_indexed_at = cursor.map(|c| c.indexed_at);
    let cursor_resource_id = cursor.map(|c| c.resource_id.as_str());

    let rows: Vec<SpaceSqlRow> = diesel::sql_query(SPACE_SEARCH_SQL)
        .bind::<Text, _>(needle)
        .bind::<Nullable<Text>, _>(organization_did)
        .bind::<Nullable<Text>, _>(parent_space_id)
        .bind::<Nullable<Double>, _>(cursor_score)
        .bind::<Nullable<Timestamptz>, _>(cursor_indexed_at)
        .bind::<Nullable<Text>, _>(cursor_resource_id)
        .bind::<BigInt, _>(limit)
        .load(&mut conn)?;

    rows.into_iter().map(SpaceRow::try_from).collect()
}

async fn run_visible_space_search(
    state: &AppState,
    needle: &str,
    scope: &SearchScope,
    cursor: Option<&SpaceCursor>,
    requester: Option<&str>,
    proofs: &[String],
    visible_limit: i64,
) -> anyhow::Result<Vec<SpaceRow>> {
    let target_len = visible_limit.max(1) as usize;
    let batch_limit = visible_limit.max(64);
    let mut scan_cursor = cursor.cloned();
    let mut visible_rows = Vec::with_capacity(target_len.min(201));

    loop {
        let rows =
            run_space_search(state, needle, scope, scan_cursor.as_ref(), batch_limit).await?;
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

async fn load_space_row(state: &AppState, key: &str) -> anyhow::Result<Option<SpaceRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;
    let row: Option<SpaceStoredRow> = r::directory_resources
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
            r::indexed_at,
        ))
        .first(&mut conn)
        .optional()?;
    Ok(row.map(SpaceRow::from))
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

fn is_result_visible(row: &SpaceRow, requester: Option<&str>, proofs: &[String]) -> bool {
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
            let proof_matches = ["proof", "presentation", "claim", "claim_id", "claim_type"]
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

impl TryFrom<SpaceSqlRow> for SpaceRow {
    type Error = anyhow::Error;

    fn try_from(row: SpaceSqlRow) -> Result<Self, Self::Error> {
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
        })
    }
}

impl From<SpaceStoredRow> for SpaceRow {
    fn from(row: SpaceStoredRow) -> Self {
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

fn encode_cursor(row: &SpaceRow) -> anyhow::Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cursor_from_row(row))?))
}

fn cursor_from_row(row: &SpaceRow) -> SpaceCursor {
    SpaceCursor {
        score: row.score,
        indexed_at: row.indexed_at,
        resource_id: row.resource_id.clone(),
    }
}

fn decode_cursor(cursor: &str) -> Result<SpaceCursor, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|e| format!("invalid cursor encoding: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid cursor body: {e}"))
}

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
                        "claim_type": "org_membership",
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

const SPACE_SEARCH_SQL: &str = r#"
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
    WHERE resource_kind = 'space'::resource_kind
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
          OR public_projection->>'parent_space_id' = $3
          OR public_projection->'parent_space_ids' ? $3
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
    score
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
