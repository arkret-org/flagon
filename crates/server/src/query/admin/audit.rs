//! Audit feed and audit-chain verification endpoints.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use teabay_contracts::{AuditEnvelope, AuditEvent};

use super::{parse_since, require_admin};
use crate::audit::AuditEventKind;
use crate::error::ApiErrorCode;
use crate::ingest::DirectoryResourceKindDb;
use crate::state::AppState;

const DEFAULT_AUDIT_LIMIT: i64 = 100;
const MAX_AUDIT_LIMIT: i64 = 500;

#[derive(Debug, Default, Deserialize)]
struct AuditQuery {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Queryable)]
struct AuditDbRow {
    audit_id: i64,
    occurred_at: DateTime<Utc>,
    kind: AuditEventKind,
    resource_kind: Option<DirectoryResourceKindDb>,
    resource_id: Option<String>,
    actor_id: Option<String>,
    authenticated_credential_id: Option<String>,
    asserted_operator_localpart: Option<String>,
    authentication_method: Option<String>,
    detail: JsonValue,
}

#[handler]
pub async fn audit_feed(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };

    if let Err(error) = require_admin(req, &state).await {
        error.render(res, "admin bearer token required");
        return;
    }

    let query: AuditQuery = match req.parse_queries() {
        Ok(query) => query,
        Err(error) => {
            ApiErrorCode::QueryInvalid.render(res, format!("malformed audit query: {error}"));
            return;
        }
    };

    let since = match query.since.as_deref().map(parse_since).transpose() {
        Ok(since) => since,
        Err(message) => {
            ApiErrorCode::ParamInvalid.render(res, message);
            return;
        }
    };
    let limit = query
        .limit
        .unwrap_or(DEFAULT_AUDIT_LIMIT)
        .clamp(1, MAX_AUDIT_LIMIT);

    match load_audit_rows(&state, since, limit).await {
        Ok(rows) => {
            let next_since = rows.last().map(|row| row.occurred_at.to_rfc3339());
            let events: Result<Vec<_>, _> = rows.into_iter().map(AuditEvent::try_from).collect();
            let events = match events {
                Ok(events) => events,
                Err(error) => {
                    ApiErrorCode::InternalError
                        .render(res, format!("invalid audit identity: {error}"));
                    return;
                }
            };
            res.render(Json(AuditEnvelope { events, next_since }));
        }
        Err(error) => ApiErrorCode::InternalError.render(res, format!("audit feed: {error}")),
    }
}

#[handler]
pub async fn audit_chain_verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };

    if let Err(error) = require_admin(req, &state).await {
        error.render(res, "admin bearer token required");
        return;
    }

    match crate::audit::verify_chain(state.db()).await {
        Ok(outcome) => res.render(Json(outcome)),
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("audit chain verify: {error}"))
        }
    }
}

async fn load_audit_rows(
    state: &AppState,
    since: Option<DateTime<Utc>>,
    limit: i64,
) -> anyhow::Result<Vec<AuditDbRow>> {
    use crate::schema::directory_audit::dsl as a;

    let mut conn = state.db().get().await?;
    let mut query = a::directory_audit.into_boxed();
    if let Some(since) = since {
        query = query.filter(a::occurred_at.gt(since));
    }

    let rows = query
        .order((a::occurred_at.desc(), a::audit_id.desc()))
        .limit(limit)
        .select((
            a::audit_id,
            a::occurred_at,
            a::kind,
            a::resource_kind,
            a::resource_id,
            a::actor_id,
            a::authenticated_credential_id,
            a::asserted_operator_localpart,
            a::authentication_method,
            a::detail,
        ))
        .load(&mut *conn)
        .await?;
    Ok(rows)
}

impl TryFrom<AuditDbRow> for AuditEvent {
    type Error = String;
    fn try_from(row: AuditDbRow) -> Result<Self, Self::Error> {
        Ok(Self {
            audit_id: row.audit_id,
            occurred_at: row.occurred_at.to_rfc3339(),
            kind: row.kind.as_pg().to_owned(),
            resource_kind: row
                .resource_kind
                .map(|resource_kind| resource_kind.as_pg().to_owned()),
            resource_id: row.resource_id,
            actor_id: row
                .actor_id
                .map(arkret_sdk::DidCoreId::new)
                .transpose()
                .map_err(|error| error.to_string())?,
            authenticated_credential_id: row
                .authenticated_credential_id
                .map(teabay_contracts::AuthenticatedCredentialId::new)
                .transpose()?,
            asserted_operator_localpart: row.asserted_operator_localpart,
            authentication_method: row.authentication_method,
            detail: row.detail,
        })
    }
}
