//! Actor / user search. Spec §9.
//!
//! `ak.find.directory.read.search_actors.v1` and `ak.find.directory.read.search_users.v1` (mention
//! autocomplete).
//!
//! `realm_id` scopes `search_users` / `search_actors` to the security
//! boundary. Container Spaces are a separate resource kind and are not
//! used for audience gating here.

use arkret_sdk::{
    ActorId, ActorPreview, DidCoreId, DirectoryActorSearchOutcome,
    DirectorySearchActorsRequestBody, DirectorySearchUsersRequestBody, DirectoryUserSearchOutcome,
    UserSearchOutcome,
};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde_json::Value as JsonValue;

use crate::error::ApiErrorCode;
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::filter::result::ResultEnvelope;
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};
use crate::query::rate_limit::enforce_query_rate_limit;
use crate::state::AppState;

#[handler]
pub async fn search_actors(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
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
    let body: DirectorySearchActorsRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::QueryInvalid
                .render(res, format!("malformed search_actors body: {error}"));
            return;
        }
    };
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
        body.realm_id
            .as_ref()
            .map(arkret_sdk::RealmId::as_str)
            .unwrap_or_default(),
        body.organization_id
            .as_ref()
            .map(arkret_sdk::DidCoreId::as_str)
            .unwrap_or_default(),
        body.cursor.as_deref().unwrap_or_default(),
    );
    let result = pad_to_budget_observed(
        budget,
        arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ACTORS_V1,
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
            let actor_previews = match rows
                .into_iter()
                .map(actor_preview_from_row)
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(actor_previews) => actor_previews,
                Err(message) => {
                    ApiErrorCode::InternalError.render(res, message);
                    return;
                }
            };
            res.render(Json(DirectoryActorSearchOutcome {
                actors: actor_previews,
                next_cursor: None,
                has_more,
            }));
        }
        Err(e) => ApiErrorCode::InternalError.render(res, format!("actor search: {e}")),
    }
}

#[handler]
pub async fn search_users(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
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

    let query: DirectorySearchUsersRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::QueryInvalid.render(res, format!("malformed search_users body: {error}"));
            return;
        }
    };
    let realm_id = match query.realm_id.as_ref() {
        Some(realm_id) => realm_id,
        None => {
            ApiErrorCode::ParamMissing.render(res, "realm_id is required");
            return;
        }
    };
    let limit = query.limit.unwrap_or(20).clamp(1, 100) as i64;
    let needle = query.query;
    if !crate::query::rate_limit::enforce_search_needle_rate_limit(res, &state, &needle) {
        return;
    }

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let privacy_key = format!("q={needle};realm={};limit={limit}", realm_id.as_str());
    let result = pad_to_budget_observed(
        budget,
        arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_USERS_V1,
        &privacy_key,
        |target| state.metrics().record_anti_enum_pad("search-users", target),
        async { run_user_search(&state, &needle, realm_id.as_str(), limit + 1).await },
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
                .map(|scored| {
                    // `results[].did` is conditional. The SDK request body has
                    // no requester_id-bound proof input, so this face never has
                    // enough evidence to disclose the subject_id DID.
                    let did_authorized = scored.did_authorized;
                    user_search_outcome_from_envelope(envelope_from_row(scored.row)).map(
                        |mut outcome| {
                            if !did_authorized {
                                outcome.account_id = None;
                            }
                            outcome
                        },
                    )
                })
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
    station_id: String,
    public_projection: JsonValue,
    discoverability: DiscoverabilityDb,
    as_of: DateTime<Utc>,
    source_refs: Vec<String>,
    policy_revision: String,
    stale: bool,
    divergent: bool,
    via_services: Vec<DidCoreId>,
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
            r::station_id,
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

/// A matched actor row plus whether the requester_id is authorized to learn the
/// subject_id `did` for this result. §9 conditional-did: only local-contact
/// (`resource_id == requester_id`) authorizes did disclosure on this face;
/// common-Realm membership alone does NOT.
struct ScoredUserRow {
    row: ActorRow,
    did_authorized: bool,
}

async fn run_user_search(
    state: &AppState,
    needle: &str,
    realm_id: &str,
    limit: i64,
) -> anyhow::Result<Vec<ScoredUserRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get().await?;
    let rows: Vec<ActorRow> = r::directory_resources
        .filter(r::resource_kind.eq(DirectoryResourceKindDb::Actor))
        .filter(r::discoverability.eq(DiscoverabilityDb::Public))
        .order(r::indexed_at.desc())
        .limit(500)
        .select((
            r::resource_id,
            r::station_id,
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
        .filter(|row| actor_lists_realm(&row.public_projection, realm_id))
        .filter(|row| {
            needle.is_empty() || actor_matches(&row.public_projection, &row.resource_id, &needle)
        })
        .map(|row| ScoredUserRow {
            row,
            did_authorized: false,
        })
        .take(limit as usize)
        .collect())
}

fn envelope_from_row(row: ActorRow) -> ResultEnvelope {
    let mut payload = row.public_projection;
    if let Some(obj) = payload.as_object_mut() {
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

fn actor_preview_from_row(row: ActorRow) -> Result<ActorPreview, String> {
    // public_projection is derived from the verified discovery Event's value;
    // station_id is persisted from that Event author's route. Neither the
    // principal index nor this directory's own Station can invent an Actor.
    let actor: ActorId = serde_json::from_value(
        row.public_projection
            .get("actor_id")
            .cloned()
            .ok_or_else(|| "indexed actor projection lacks its signed full ActorId".to_owned())?,
    )
    .map_err(|error| format!("indexed actor projection has an invalid ActorId: {error}"))?;
    let principal = DidCoreId::new(row.resource_id.clone())
        .map_err(|error| format!("indexed actor principal is invalid: {error}"))?;
    let station = DidCoreId::new(row.station_id.clone())
        .map_err(|error| format!("indexed actor Station is invalid: {error}"))?;
    if actor.signing_principal_id() != &principal || actor.route_service_id() != &station {
        return Err(
            "indexed actor projection does not bind its accepted principal and Station".to_owned(),
        );
    }
    actor_preview_from_envelope(envelope_from_row(row))
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

#[cfg(test)]
mod tests {
    use arkret_sdk::AccountId;
    use serde_json::json;

    use super::*;

    fn indexed_actor(actor: &ActorId) -> ActorRow {
        ActorRow {
            resource_id: actor.signing_principal_id().to_string(),
            station_id: actor.route_service_id().to_string(),
            public_projection: json!({"actor_id": actor, "display_name": "Fixture Actor"}),
            discoverability: DiscoverabilityDb::Public,
            as_of: "2026-08-31T00:00:00.000Z".parse().unwrap(),
            source_refs: Vec::new(),
            policy_revision: "fixture".to_owned(),
            stale: false,
            divergent: false,
            via_services: Vec::new(),
        }
    }

    #[test]
    fn actor_preview_preserves_signed_station_and_rejects_missing_or_mismatched_carriers() {
        let principal = DidCoreId::new("ak:did_core:web:actor.example").unwrap();
        let mut actor_ids = std::collections::BTreeSet::new();
        for station in [
            "ak:did_core:web:station-a.example",
            "ak:did_core:web:station-b.example",
        ] {
            let actor = ActorId::account(AccountId::new(
                principal.clone(),
                DidCoreId::new(station).unwrap(),
            ));
            let preview = actor_preview_from_row(indexed_actor(&actor)).unwrap();
            assert_eq!(preview.actor_id, actor);
            actor_ids.insert(preview.actor_id);

            let mut wrong_station = indexed_actor(&actor);
            wrong_station.station_id = "ak:did_core:web:unrelated.example".to_owned();
            assert!(actor_preview_from_row(wrong_station).is_err());
            let mut wrong_principal = indexed_actor(&actor);
            wrong_principal.resource_id = "ak:did_core:web:other.example".to_owned();
            assert!(actor_preview_from_row(wrong_principal).is_err());
            let mut missing = indexed_actor(&actor);
            missing
                .public_projection
                .as_object_mut()
                .unwrap()
                .remove("actor_id");
            assert!(actor_preview_from_row(missing).is_err());
            let mut scalar = indexed_actor(&actor);
            scalar.public_projection["actor_id"] = json!(principal);
            assert!(actor_preview_from_row(scalar).is_err());
        }
        assert_eq!(actor_ids.len(), 2);
        let service = ActorId::service(principal);
        assert_eq!(
            actor_preview_from_row(indexed_actor(&service))
                .unwrap()
                .actor_id,
            service
        );
    }
}
