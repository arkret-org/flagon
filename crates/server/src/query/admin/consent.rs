//! `consent_revoke{scope=any}` invalidation endpoint.

use arkret_sdk::DidCoreId;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{admin_state, record_admin_audit};
use crate::audit::AuditEventKind;
use crate::error::ApiErrorCode;
use crate::state::AppState;

/// `POST /_teabay/admin/consent-revoke` — soland (or any peer service)
/// broadcasts a `consent_revoke{scope=any}` event for an actor; the
/// directory then **eagerly invalidates** that actor's reachability
/// entries in the directory ingest cache.
///
/// We **soft-delete** (UPDATE) rather than DELETE
/// so the audit trail is preserved — the row is marked with
/// `reachability_revoked_at` and the search face hides it (resolve
/// still surfaces it for audit and deterministic stale-result handling).
#[derive(Debug, Deserialize)]
struct DirectoryAdminConsentRevokeRequestBody {
    /// Stable Arkret core id of the affected actor. Required.
    actor_id: DidCoreId,
    /// Subject scope — MUST be `"any"` per spec; other values are
    /// rejected so soland and the directory can't drift on enum.
    #[serde(default)]
    scope: Option<String>,
    /// Optional human-readable reason (carried into the audit row).
    #[serde(default)]
    reason: Option<String>,
    /// Optional list of affected resource_ids — when present, only those
    /// rows are invalidated. When absent, every row keyed on the actor
    /// (actor / handle / applet) is invalidated.
    #[serde(default)]
    resource_ids: Vec<String>,
    /// Optional source event id (anchor) for cross-service traceability.
    #[serde(default)]
    source_event_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct DirectoryAdminConsentRevokeOutcome {
    invalidated_rows: i64,
    revoked_at: DateTime<Utc>,
}

#[handler]
pub async fn consent_revoke_invalidate(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let (state, credential) = match admin_state(req, depot, res).await {
        Some(context) => context,
        None => return,
    };
    let body: DirectoryAdminConsentRevokeRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::JsonInvalid
                .render(res, format!("malformed consent revoke body: {error}"));
            return;
        }
    };
    let scope = body.scope.as_deref().unwrap_or("any").trim().to_owned();
    if !scope.eq_ignore_ascii_case("any") {
        ApiErrorCode::ParamInvalid.render(
            res,
            format!("scope `{scope}` not supported; only `any` invalidates directory reachability"),
        );
        return;
    }

    let revoked_at = Utc::now();
    let reason = body
        .reason
        .clone()
        .unwrap_or_else(|| "consent_revoke{scope=any}".to_owned());
    let invalidated_rows = match invalidate_reachability(&state, &body, revoked_at, &reason).await {
        Ok(rows) => rows,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("consent revoke: {error}"));
            return;
        }
    };

    let _ = record_admin_audit(
        &state,
        &credential,
        AuditEventKind::ConsentRevokeInvalidation,
        None,
        Some(body.actor_id.as_str()),
        Some(state.config().service_id.as_str()),
        json!({
            "actor_id": body.actor_id,
            "scope": scope,
            "reason": reason,
            "invalidated_rows": invalidated_rows,
            "source_event_id": body.source_event_id,
            "resource_ids": body.resource_ids,
        }),
    )
    .await;

    res.render(Json(DirectoryAdminConsentRevokeOutcome {
        invalidated_rows,
        revoked_at,
    }));
}

async fn invalidate_reachability(
    state: &AppState,
    body: &DirectoryAdminConsentRevokeRequestBody,
    revoked_at: DateTime<Utc>,
    reason: &str,
) -> anyhow::Result<i64> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get().await?;
    // The actor's reachability projection can live on:
    //   * actor rows keyed by the actor's DID
    //   * handle rows where station_id == actor DID
    //   * applet rows that name the actor as principal
    // We match by either `resource_id = actor_id` or
    // `station_id = actor_id`. T17 explicitly says "mark with
    // revoked_at for audit" — so this is an UPDATE, not a DELETE.
    let mut query = diesel::update(r::directory_resources)
        .filter(
            r::resource_id
                .eq(&body.actor_id)
                .or(r::station_id.eq(&body.actor_id)),
        )
        .filter(r::reachability_revoked_at.is_null())
        .into_boxed();
    if !body.resource_ids.is_empty() {
        query = query.filter(r::resource_id.eq_any(&body.resource_ids));
    }
    let invalidated_rows = query
        .set((
            r::reachability_revoked_at.eq(Some(revoked_at)),
            r::reachability_revoked_reason.eq(Some(reason)),
        ))
        .execute(&mut *conn)
        .await?;
    Ok(invalidated_rows as i64)
}
