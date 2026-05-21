//! Actor / user search. Spec §9.
//!
//! `cx.directory.search_actors` and `cx.directory.search_users` (mention
//! autocomplete).
//!
//! Realm-rework note: the `space_id` parameter on `search_users` /
//! `search_actors` continues to identify the **security boundary**
//! (which the protocol now calls a Realm — `cx:realm:` URI prefix).
//! Container "Spaces" are not addressable here yet.
// TODO(realm-rework): add an explicit `realm_id` request alias and
// surface a separate container-Space autocomplete path.

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

#[derive(Debug, Default, Deserialize)]
pub struct SearchUsersRequest {
    #[serde(default, alias = "q")]
    pub query: Option<String>,
    #[serde(default)]
    pub requester: Option<String>,
    #[serde(default)]
    pub space_id: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    /// Why the requester wants to enumerate users. Spec 0a5ab85:
    /// `cx.directory.search_users` adds `intent`. Implementations MUST
    /// pipe this into anti-enumeration filtering and Realm
    /// `allowed_recipient_services` policy checks.
    #[serde(default)]
    pub intent: Option<String>,
}

#[handler]
pub async fn search_actors(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let body: SearchActorsRequest = req.parse_json().await.unwrap_or_default();
    let limit = body.limit.unwrap_or(20).min(200).max(1) as i64;
    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let privacy_key = format!(
        "q={};space={};org={};cursor={};limit={limit}",
        body.query.as_deref().unwrap_or_default(),
        body.space_id.as_deref().unwrap_or_default(),
        body.organization_did.as_deref().unwrap_or_default(),
        body.cursor.as_deref().unwrap_or_default(),
    );
    let result = pad_to_budget(budget, "cx.directory.search_actors", &privacy_key, async {
        run_actor_search(&state, body.query.as_deref().unwrap_or_default(), limit).await
    })
    .await;
    match result {
        Ok(rows) => {
            let envelopes: Vec<ResultEnvelope> = rows.into_iter().map(envelope_from_row).collect();
            res.render(Json(
                json!({ "results": envelopes, "next_cursor": JsonValue::Null }),
            ));
        }
        Err(e) => ApiErrorCode::InternalError.render(res, format!("actor search: {e}")),
    }
}

#[handler]
pub async fn search_users(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };

    let query: SearchUsersRequest = match req.parse_json().await {
        Ok(query) => query,
        Err(error) => {
            ApiErrorCode::BadQuery.render(res, format!("malformed search_users body: {error}"));
            return;
        }
    };
    let requester = match query.requester.as_deref().filter(|value| !value.is_empty()) {
        Some(requester) => requester,
        None => {
            ApiErrorCode::MissingParam.render(res, "requester is required");
            return;
        }
    };
    let space_id = match query.space_id.as_deref().filter(|value| !value.is_empty()) {
        Some(space_id) => space_id,
        None => {
            ApiErrorCode::MissingParam.render(res, "space_id is required");
            return;
        }
    };
    let limit = query.limit.unwrap_or(20).min(100).max(1) as i64;
    let needle = query.query.unwrap_or_default();

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let privacy_key = format!("q={needle};requester={requester};space={space_id};limit={limit}");
    let result = pad_to_budget(budget, "cx.directory.search_users", &privacy_key, async {
        run_user_search(&state, &needle, requester, space_id, limit).await
    })
    .await;

    match result {
        Ok(rows) => {
            let envelopes: Vec<ResultEnvelope> = rows.into_iter().map(envelope_from_row).collect();
            res.render(Json(
                json!({ "results": envelopes, "next_cursor": JsonValue::Null }),
            ));
        }
        Err(error) => ApiErrorCode::InternalError.render(res, format!("user search: {error}")),
    }
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

async fn run_actor_search(
    state: &AppState,
    needle: &str,
    limit: i64,
) -> anyhow::Result<Vec<ActorRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;
    let rows: Vec<ActorRow> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Actor))
        .filter(r::discoverability.eq(DiscoverabilityWire::Public))
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
            needle.is_empty() || actor_matches(&row.public_projection, &row.resource_id, &needle)
        })
        .take(limit as usize)
        .collect())
}

async fn run_user_search(
    state: &AppState,
    needle: &str,
    requester: &str,
    space_id: &str,
    limit: i64,
) -> anyhow::Result<Vec<ActorRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;
    let rows: Vec<ActorRow> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Actor))
        .filter(r::discoverability.eq(DiscoverabilityWire::Public))
        .order(r::indexed_at.desc())
        .limit(500)
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
            row.resource_id == requester || actor_lists_space(&row.public_projection, space_id)
        })
        .filter(|row| {
            needle.is_empty() || actor_matches(&row.public_projection, &row.resource_id, &needle)
        })
        .take(limit as usize)
        .collect())
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

fn actor_matches(projection: &JsonValue, resource_id: &str, needle: &str) -> bool {
    resource_id.to_ascii_lowercase().contains(needle)
        || ["handle", "name", "display_name", "summary", "bio"]
            .iter()
            .filter_map(|key| projection.get(*key).and_then(JsonValue::as_str))
            .any(|value| value.to_ascii_lowercase().contains(needle))
}

fn actor_lists_space(projection: &JsonValue, space_id: &str) -> bool {
    ["space_id", "common_space_id", "primary_space_id"]
        .iter()
        .filter_map(|key| projection.get(*key).and_then(JsonValue::as_str))
        .any(|value| value == space_id)
        || [
            "space_ids",
            "common_space_ids",
            "member_of_spaces",
            "memberships",
            "spaces",
        ]
        .iter()
        .filter_map(|key| projection.get(*key).and_then(JsonValue::as_array))
        .flatten()
        .any(|value| match value {
            JsonValue::String(value) => value == space_id,
            JsonValue::Object(obj) => ["space_id", "id"]
                .iter()
                .any(|key| obj.get(*key).and_then(JsonValue::as_str) == Some(space_id)),
            _ => false,
        })
}
