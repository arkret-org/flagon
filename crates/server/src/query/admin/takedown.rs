//! B.8.6 — takedown audit export endpoint.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use super::{admin_state, parse_since};
use crate::audit::AuditEventKind;
use crate::error::ApiErrorCode;
use crate::ingest::DirectoryResourceKindDb;
use crate::state::AppState;

const MAX_TAKEDOWN_LIMIT: i64 = 500;
const DEFAULT_TAKEDOWN_LIMIT: i64 = 200;

#[derive(Debug, Default, Deserialize)]
struct TakedownExportQuery {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    until: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Queryable, Serialize)]
struct TakedownAuditExportRow {
    audit_id: i64,
    occurred_at: DateTime<Utc>,
    resource_kind: Option<DirectoryResourceKindDb>,
    resource_id: Option<String>,
    actor_id: Option<String>,
    detail: JsonValue,
    authentication_method: Option<String>,
    authenticated_credential_id: Option<String>,
    asserted_operator_localpart: Option<String>,
}

#[derive(Debug, Serialize)]
struct TakedownAuditExportItem {
    audit_id: i64,
    occurred_at: DateTime<Utc>,
    resource_kind: Option<&'static str>,
    resource_id: Option<String>,
    actor_id: Option<arkret_sdk::DidCoreId>,
    detail: JsonValue,
    authentication_method: Option<String>,
    authenticated_credential_id: Option<teabay_contracts::AuthenticatedCredentialId>,
    asserted_operator_localpart: Option<String>,
}

#[handler]
pub async fn takedown_audit_export(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let (state, _credential) = match admin_state(req, depot, res).await {
        Some(context) => context,
        None => return,
    };
    let query: TakedownExportQuery = match req.parse_queries() {
        Ok(query) => query,
        Err(error) => {
            ApiErrorCode::QueryInvalid
                .render(res, format!("malformed takedown export query: {error}"));
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
    let until = match query.until.as_deref().map(parse_since).transpose() {
        Ok(until) => until,
        Err(message) => {
            ApiErrorCode::ParamInvalid.render(res, message);
            return;
        }
    };
    let limit = query
        .limit
        .unwrap_or(DEFAULT_TAKEDOWN_LIMIT)
        .clamp(1, MAX_TAKEDOWN_LIMIT);

    match load_takedown_export(&state, since, until, limit).await {
        Ok(rows) => {
            let items: Result<Vec<TakedownAuditExportItem>, _> = rows
                .into_iter()
                .map(TakedownAuditExportItem::try_from)
                .collect();
            let items = match items {
                Ok(items) => items,
                Err(error) => {
                    ApiErrorCode::InternalError
                        .render(res, format!("invalid audit identity: {error}"));
                    return;
                }
            };
            res.render(Json(json!({
                "items": items,
                "since": since,
                "until": until,
            })));
        }
        Err(error) => ApiErrorCode::InternalError.render(res, format!("takedown export: {error}")),
    }
}

async fn load_takedown_export(
    state: &AppState,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    limit: i64,
) -> anyhow::Result<Vec<TakedownAuditExportRow>> {
    use crate::schema::directory_audit::dsl as a;

    let mut conn = state.db().get().await?;
    let mut query = a::directory_audit
        .filter(a::kind.eq_any([
            AuditEventKind::OperatorTakedown,
            AuditEventKind::TakedownAppealSubmitted,
            AuditEventKind::TakedownAppealDecided,
        ]))
        .into_boxed();
    if let Some(since) = since {
        query = query.filter(a::occurred_at.ge(since));
    }
    if let Some(until) = until {
        query = query.filter(a::occurred_at.le(until));
    }
    let rows = query
        .order((a::occurred_at.desc(), a::audit_id.desc()))
        .limit(limit)
        .select((
            a::audit_id,
            a::occurred_at,
            a::resource_kind,
            a::resource_id,
            a::actor_id,
            a::detail,
            a::authentication_method,
            a::authenticated_credential_id,
            a::asserted_operator_localpart,
        ))
        .load(&mut *conn)
        .await?;
    Ok(rows)
}

impl TryFrom<TakedownAuditExportRow> for TakedownAuditExportItem {
    type Error = String;
    fn try_from(row: TakedownAuditExportRow) -> Result<Self, Self::Error> {
        Ok(Self {
            audit_id: row.audit_id,
            occurred_at: row.occurred_at,
            resource_kind: row.resource_kind.map(DirectoryResourceKindDb::as_pg),
            resource_id: row.resource_id,
            actor_id: row
                .actor_id
                .map(arkret_sdk::DidCoreId::new)
                .transpose()
                .map_err(|error| error.to_string())?,
            detail: row.detail,
            authentication_method: row.authentication_method,
            authenticated_credential_id: row
                .authenticated_credential_id
                .map(teabay_contracts::AuthenticatedCredentialId::new)
                .transpose()?,
            asserted_operator_localpart: row.asserted_operator_localpart,
        })
    }
}
