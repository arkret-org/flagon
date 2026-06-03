//! `ck.directory.announce.heartbeat` — refresh-in-place ingest path.
//!
//! Spec §8.6 (TTL) + P2E.5 (this round). A heartbeat is the cheap
//! "I'm still here" signal: an announcer that already has an
//! up-to-date discovery_state in the directory doesn't need to
//! re-sign + re-submit the full announce body; it just calls
//! `POST /_cokret/find/directory/announce/heartbeat` with the
//! `announce_id` it received from the original announce, and the
//! directory bumps `last_refreshed_at` / `expires_at` forward by one
//! TTL window.
//!
//! Authorization:
//!  - the heartbeat MUST come from the same `principal_server_did` that originally announced the
//!    row. We look up `directory_resources` by `(resource_kind, resource_id)` and confirm
//!    `principal_server_did` matches the request header `X-Principal-Server-DID`. RFC 9421 HTTP
//!    Message Signature middleware authenticates the *transport*; the principal-server check
//!    authenticates the *content owner*.
//!  - rate-limited via the standard ingest rate limit per resource_id and per IP.
//!
//! Failure modes:
//!  - row not found / takedown in force → `not_found` (blinded; same shape as a clean miss, see
//!    `crate::filter::enumeration`).
//!  - principal mismatch → `directory_not_authorized`.
//!  - row is a destroyed realm → `realm_terminal_state`.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::audit::{self, AuditEventKind};
use crate::error::ApiErrorCode;
use crate::ingest::ResourceKindWire;
use crate::ingest::rate_limit::enforce_ingest_rate_limit;
use crate::state::AppState;

#[derive(Debug, Clone, Deserialize)]
pub struct HeartbeatRequest {
    pub announce_id: String,
    /// Optional TTL override. When present and within the operator
    /// `max_ttl`, the directory uses this value; otherwise the row's
    /// existing `effective_ttl_seconds` is kept.
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatResponse {
    pub announce_id: String,
    pub last_refreshed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub effective_ttl_seconds: i64,
}

#[handler]
pub async fn heartbeat(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let mut ingest_metric = state.metrics().ingest_guard("heartbeat");

    let body: HeartbeatRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ingest_metric.set_outcome("bad_json");
            ApiErrorCode::BadJson.render(res, format!("malformed heartbeat body: {e}"));
            return;
        }
    };
    if body.announce_id.trim().is_empty() {
        ingest_metric.set_outcome("schema_rejected");
        ApiErrorCode::MissingParam.render(res, "announce_id is required");
        return;
    }
    if !enforce_ingest_rate_limit(req, res, &state, &body.announce_id) {
        ingest_metric.set_outcome("rate_limited");
        return;
    }

    let principal = header_value(req, "x-principal-server-did").unwrap_or_default();
    if principal.trim().is_empty() {
        ingest_metric.set_outcome("missing_principal");
        ApiErrorCode::Unauthenticated.render(res, "X-Principal-Server-DID header is required");
        return;
    }

    let lookup = match load_row_for_heartbeat(&state, &body.announce_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            ingest_metric.set_outcome("not_found");
            // Blinded miss — same shape as a clean lookup miss; the
            // directory MUST NOT confirm whether the announce_id ever
            // existed (anti-enumeration §10).
            ApiErrorCode::NotFound.render(res, "announce not found");
            return;
        }
        Err(error) => {
            ingest_metric.set_outcome("internal_error");
            ApiErrorCode::InternalError.render(res, format!("heartbeat lookup: {error}"));
            return;
        }
    };

    if lookup.principal_server_did != principal {
        ingest_metric.set_outcome("not_authorized");
        let _ = audit::record(
            state.db(),
            AuditEventKind::IngestRejected,
            Some(lookup.resource_kind),
            Some(&lookup.resource_id),
            Some(&principal),
            json!({
                "code": ApiErrorCode::DirectoryNotAuthorized.wire_code(),
                "endpoint": "directory.announce.heartbeat",
                "reason": "principal_mismatch",
            }),
        )
        .await;
        ApiErrorCode::DirectoryNotAuthorized.render(res, "announcer does not own this row");
        return;
    }

    if lookup.realm_destroyed_at.is_some() {
        ingest_metric.set_outcome("realm_destroyed");
        ApiErrorCode::PolicyRevisionRollback.render(res, "realm is in terminal destroyed state");
        return;
    }

    let max_ttl = state.config().max_ttl.as_secs() as i64;
    let new_ttl = match body.ttl_seconds {
        Some(ttl) if ttl > 0 && ttl <= max_ttl => ttl,
        Some(ttl) => {
            ingest_metric.set_outcome("ttl_out_of_range");
            ApiErrorCode::TtlOutOfRange
                .render(res, format!("ttl_seconds {ttl} not in (0, {max_ttl}]"));
            return;
        }
        None => lookup.effective_ttl_seconds as i64,
    };

    let now = Utc::now();
    let new_expires = now + chrono::Duration::seconds(new_ttl);
    match write_heartbeat(&state, &lookup, now, new_expires, new_ttl).await {
        Ok(()) => {
            let _ = audit::record(
                state.db(),
                AuditEventKind::IngestAccepted,
                Some(lookup.resource_kind),
                Some(&lookup.resource_id),
                Some(&principal),
                json!({
                    "endpoint": "directory.announce.heartbeat",
                    "announce_id": body.announce_id,
                    "effective_ttl_seconds": new_ttl,
                }),
            )
            .await;
            ingest_metric.set_outcome("verify_ok");
            res.render(Json(HeartbeatResponse {
                announce_id: body.announce_id,
                last_refreshed_at: now,
                expires_at: new_expires,
                effective_ttl_seconds: new_ttl,
            }));
        }
        Err(error) => {
            ingest_metric.set_outcome("persist_error");
            ApiErrorCode::InternalError.render(res, format!("heartbeat persist: {error}"));
        }
    }
}

fn header_value(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Queryable)]
struct HeartbeatRow {
    resource_kind: ResourceKindWire,
    resource_id: String,
    principal_server_did: String,
    effective_ttl_seconds: i32,
    realm_destroyed_at: Option<DateTime<Utc>>,
}

async fn load_row_for_heartbeat(
    state: &AppState,
    announce_id: &str,
) -> anyhow::Result<Option<HeartbeatRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get().await?;
    let row: Option<HeartbeatRow> = r::directory_resources
        .filter(r::last_announce_id.eq(announce_id))
        .filter(r::stale.eq(false))
        .select((
            r::resource_kind,
            r::resource_id,
            r::principal_server_did,
            r::effective_ttl_seconds,
            r::realm_destroyed_at,
        ))
        .first(&mut *conn)
        .await
        .optional()?;
    Ok(row)
}

async fn write_heartbeat(
    state: &AppState,
    row: &HeartbeatRow,
    now: DateTime<Utc>,
    expires: DateTime<Utc>,
    new_ttl_secs: i64,
) -> anyhow::Result<()> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get().await?;
    diesel::update(
        r::directory_resources
            .filter(r::resource_kind.eq(row.resource_kind))
            .filter(r::resource_id.eq(&row.resource_id)),
    )
    .set((
        r::last_refreshed_at.eq(now),
        r::expires_at.eq(expires),
        r::effective_ttl_seconds.eq(new_ttl_secs as i32),
        r::next_revalidation_after.eq(expires),
    ))
    .execute(&mut *conn)
    .await?;
    Ok(())
}
