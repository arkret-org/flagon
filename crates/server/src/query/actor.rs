//! Actor / user search. Spec §9.
//!
//! `ck.find.directory.query.search_actors` and `ck.find.directory.query.search_users` (mention
//! autocomplete).
//!
//! `realm_id` scopes `search_users` / `search_actors` to the security
//! boundary. Container Spaces are a separate resource kind and are not
//! used for audience gating here.

use chrono::{DateTime, Utc};
use cokret_sdk::{
    ActorPreview, DirectoryActorSearchOutcome,
    DirectorySearchActorsRequestBody as SdkDirectorySearchActorsRequestBody,
    DirectorySearchUsersRequestBody as SdkDirectorySearchUsersRequestBody,
    DirectoryUserSearchOutcome, UserSearchOutcome,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::error::ApiErrorCode;
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::filter::result::ResultEnvelope;
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};
use crate::query::rate_limit::enforce_query_rate_limit;
use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
pub struct TeabaySearchActorsRequest {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub realm_id: Option<String>,
    #[serde(default)]
    pub organization_did: Option<String>,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
pub struct TeabaySearchUsersRequest {
    #[serde(default, alias = "q")]
    pub query: Option<String>,
    #[serde(default)]
    pub requester: Option<String>,
    #[serde(default)]
    pub realm_id: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    /// Why the requester wants to enumerate users. Spec 0a5ab85:
    /// `ck.find.directory.query.search_users` adds `intent`. Implementations MUST
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
    let _query_timer = state.metrics().query_timer("search-actors");
    if !enforce_query_rate_limit(req, res, &state) {
        return;
    }
    let raw_body: JsonValue = req.parse_json().await.unwrap_or_else(|_| json!({}));
    if let Err(error) =
        serde_json::from_value::<SdkDirectorySearchActorsRequestBody>(raw_body.clone())
    {
        ApiErrorCode::BadQuery.render(res, format!("malformed search_actors body: {error}"));
        return;
    }
    let body: TeabaySearchActorsRequest = serde_json::from_value(raw_body).unwrap_or_default();
    if !crate::query::rate_limit::enforce_search_needle_rate_limit(
        res,
        &state,
        body.query.as_deref().unwrap_or_default(),
    ) {
        return;
    }
    let limit = body.limit.unwrap_or(20).clamp(1, 200) as i64;
    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let privacy_key = format!(
        "q={};realm={};org={};cursor={};limit={limit}",
        body.query.as_deref().unwrap_or_default(),
        body.realm_id.as_deref().unwrap_or_default(),
        body.organization_did.as_deref().unwrap_or_default(),
        body.cursor.as_deref().unwrap_or_default(),
    );
    let result = pad_to_budget_observed(
        budget,
        "ck.find.directory.query.search_actors",
        &privacy_key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("search-actors", target)
        },
        async {
            run_actor_search(&state, body.query.as_deref().unwrap_or_default(), limit + 1).await
        },
    )
    .await;
    match result {
        Ok(mut rows) => {
            let has_more = rows.len() > limit as usize;
            if has_more {
                rows.truncate(limit as usize);
            }
            let actors = match rows
                .into_iter()
                .map(|row| actor_preview_from_envelope(envelope_from_row(row)))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(actors) => actors,
                Err(message) => {
                    ApiErrorCode::InternalError.render(res, message);
                    return;
                }
            };
            res.render(Json(DirectoryActorSearchOutcome {
                actors,
                next_cursor: None,
                has_more,
            }));
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
    let _query_timer = state.metrics().query_timer("search-users");
    if !enforce_query_rate_limit(req, res, &state) {
        return;
    }

    let raw_body: JsonValue = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::BadQuery.render(res, format!("malformed search_users body: {error}"));
            return;
        }
    };
    if let Err(error) =
        serde_json::from_value::<SdkDirectorySearchUsersRequestBody>(raw_body.clone())
    {
        ApiErrorCode::BadQuery.render(res, format!("malformed search_users SDK body: {error}"));
        return;
    }
    let query: TeabaySearchUsersRequest = match serde_json::from_value(raw_body) {
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
    let realm_id = match query.realm_id.as_deref().filter(|value| !value.is_empty()) {
        Some(realm_id) => realm_id,
        None => {
            ApiErrorCode::MissingParam.render(res, "realm_id is required");
            return;
        }
    };
    let limit = query.limit.unwrap_or(20).clamp(1, 100) as i64;
    let needle = query.query.unwrap_or_default();
    if !crate::query::rate_limit::enforce_search_needle_rate_limit(res, &state, &needle) {
        return;
    }

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let privacy_key = format!("q={needle};requester={requester};realm={realm_id};limit={limit}");
    let result = pad_to_budget_observed(
        budget,
        "ck.find.directory.query.search_users",
        &privacy_key,
        |target| state.metrics().record_anti_enum_pad("search-users", target),
        async { run_user_search(&state, &needle, requester, realm_id, limit + 1).await },
    )
    .await;

    match result {
        Ok(mut rows) => {
            let has_more = rows.len() > limit as usize;
            if has_more {
                rows.truncate(limit as usize);
            }
            let users = match rows
                .into_iter()
                .map(|row| user_search_outcome_from_envelope(envelope_from_row(row)))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(users) => users,
                Err(message) => {
                    ApiErrorCode::InternalError.render(res, message);
                    return;
                }
            };
            res.render(Json(DirectoryUserSearchOutcome {
                users,
                next_cursor: None,
                has_more,
            }));
        }
        Err(error) => ApiErrorCode::InternalError.render(res, format!("user search: {error}")),
    }
}

// SAFETY: alsoKnownAs is holder-side reverse endorsement only — not used here for routing.
// Spec sync 37ce729 (B-E) — identity-handles §6: actor search MUST resolve
// through the canonical `actor_id` only. Any `alsoKnownAs` claim that may
// appear inside a cached `public_projection` is treated as opaque display
// data and never indexed for mention autocomplete or audience binding.
#[derive(Debug, Queryable)]
struct ActorRow {
    resource_id: String,
    public_projection: JsonValue,
    discoverability: DiscoverabilityDb,
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
    let mut conn = state.db().get().await?;
    let rows: Vec<ActorRow> = r::directory_resources
        .filter(r::resource_kind.eq(DirectoryResourceKindDb::Actor))
        .filter(r::discoverability.eq(DiscoverabilityDb::Public))
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
        .load(&mut *conn)
        .await?;
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
    realm_id: &str,
    limit: i64,
) -> anyhow::Result<Vec<ActorRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get().await?;
    let rows: Vec<ActorRow> = r::directory_resources
        .filter(r::resource_kind.eq(DirectoryResourceKindDb::Actor))
        .filter(r::discoverability.eq(DiscoverabilityDb::Public))
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
        .load(&mut *conn)
        .await?;

    let needle = needle.trim().to_ascii_lowercase();
    Ok(rows
        .into_iter()
        .filter(|row| {
            row.resource_id == requester || actor_lists_realm(&row.public_projection, realm_id)
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
        obj.insert("actor_id".into(), JsonValue::String(row.resource_id));
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

fn actor_preview_from_envelope(envelope: ResultEnvelope) -> Result<ActorPreview, String> {
    let value = serde_json::to_value(envelope)
        .map_err(|error| format!("actor envelope serialization failed: {error}"))?;
    serde_json::from_value(value)
        .map_err(|error| format!("actor preview is not SDK-compatible: {error}"))
}

fn user_search_outcome_from_envelope(
    envelope: ResultEnvelope,
) -> Result<UserSearchOutcome, String> {
    let value = serde_json::to_value(envelope)
        .map_err(|error| format!("user envelope serialization failed: {error}"))?;
    serde_json::from_value(value)
        .map_err(|error| format!("user search outcome is not SDK-compatible: {error}"))
}

fn actor_matches(projection: &JsonValue, resource_id: &str, needle: &str) -> bool {
    // Substring-match only identity fields (handle / name / display_name), not
    // free-text profile fields. Probing `summary`/`bio` substrings widened the
    // anti-enumeration surface (an attacker could harvest the public namespace
    // by free-text fragment) without serving a legitimate lookup need.
    resource_id.to_ascii_lowercase().contains(needle)
        || ["handle", "name", "display_name"]
            .iter()
            .filter_map(|key| projection.get(*key).and_then(JsonValue::as_str))
            .any(|value| value.to_ascii_lowercase().contains(needle))
}

fn actor_lists_realm(projection: &JsonValue, realm_id: &str) -> bool {
    ["realm_id", "common_realm_id", "primary_realm_id"]
        .iter()
        .filter_map(|key| projection.get(*key).and_then(JsonValue::as_str))
        .any(|value| value == realm_id)
        || [
            "realm_ids",
            "common_realm_ids",
            "member_of_realms",
            "memberships",
            "realms",
        ]
        .iter()
        .filter_map(|key| projection.get(*key).and_then(JsonValue::as_array))
        .flatten()
        .any(|value| match value {
            JsonValue::String(value) => value == realm_id,
            JsonValue::Object(obj) => ["realm_id", "id"]
                .iter()
                .any(|key| obj.get(*key).and_then(JsonValue::as_str) == Some(realm_id)),
            _ => false,
        })
}
