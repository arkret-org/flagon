//! Accept-allowlist CRUD endpoints.

use arkret_sdk::{Did, DidCoreId};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::json;
use teabay_contracts::{
    AllowlistEnvelope, AllowlistItem, AllowlistMutationEnvelope, DeleteCount,
    DirectoryAdminAllowlistUpsertRequestBody,
};

use super::{DEFAULT_ADMIN_LIMIT, MAX_ADMIN_LIMIT, admin_state, record_admin_audit};
use crate::audit::AuditEventKind;
use crate::error::ApiErrorCode;
use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
struct AllowlistQuery {
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct AllowlistDeleteQuery {
    #[serde(default)]
    resource_did: Option<String>,
}

#[derive(Debug, Queryable)]
struct AllowlistDbRow {
    resource_did: String,
    added_by: DidCoreId,
    added_at: DateTime<Utc>,
    note: Option<String>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::accept_allowlist)]
struct NewAllowlistRow<'a> {
    resource_did: &'a str,
    added_by: &'a DidCoreId,
    added_at: DateTime<Utc>,
    note: Option<&'a str>,
}

#[handler]
pub async fn allowlist_list(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let (state, _credential) = match admin_state(req, depot, res).await {
        Some(context) => context,
        None => return,
    };
    let query: AllowlistQuery = match req.parse_queries() {
        Ok(query) => query,
        Err(error) => {
            ApiErrorCode::QueryInvalid.render(res, format!("malformed allowlist query: {error}"));
            return;
        }
    };
    let limit = query
        .limit
        .unwrap_or(DEFAULT_ADMIN_LIMIT)
        .clamp(1, MAX_ADMIN_LIMIT);

    match load_allowlist(&state, limit).await {
        Ok(items) => res.render(Json(AllowlistEnvelope { items })),
        Err(error) => ApiErrorCode::InternalError.render(res, format!("allowlist list: {error}")),
    }
}

#[handler]
pub async fn allowlist_upsert(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let (state, credential) = match admin_state(req, depot, res).await {
        Some(context) => context,
        None => return,
    };
    let body: DirectoryAdminAllowlistUpsertRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::JsonInvalid.render(res, format!("malformed allowlist body: {error}"));
            return;
        }
    };
    let actor = body
        .added_by
        .as_ref()
        .unwrap_or(&state.config().service_id);

    match upsert_allowlist(&state, &body, actor).await {
        Ok(item) => {
            let _ = record_admin_audit(
                &state,
                &credential,
                AuditEventKind::AllowlistAdded,
                None,
                Some(body.resource_did.as_str()),
                Some(actor.as_str()),
                json!({ "note": body.note }),
            )
            .await;
            res.render(Json(AllowlistMutationEnvelope { item }));
        }
        Err(error) => ApiErrorCode::InternalError.render(res, format!("allowlist upsert: {error}")),
    }
}

#[handler]
pub async fn allowlist_delete(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let (state, credential) = match admin_state(req, depot, res).await {
        Some(context) => context,
        None => return,
    };
    let query: AllowlistDeleteQuery = match req.parse_queries() {
        Ok(query) => query,
        Err(error) => {
            ApiErrorCode::QueryInvalid
                .render(res, format!("malformed allowlist delete query: {error}"));
            return;
        }
    };
    let resource_did = match query
        .resource_did
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(resource_did) => match Did::new(resource_did.trim().to_owned()) {
            Ok(resource_did) => resource_did,
            Err(_) => {
                ApiErrorCode::QueryInvalid.render(res, "resource_did must be a W3C DID");
                return;
            }
        },
        None => {
            ApiErrorCode::ParamMissing.render(res, "resource_did query parameter is required");
            return;
        }
    };

    match delete_allowlist(&state, &resource_did).await {
        Ok(deleted) => {
            if deleted > 0 {
                let _ = record_admin_audit(
                    &state,
                    &credential,
                    AuditEventKind::AllowlistRemoved,
                    None,
                    Some(resource_did.as_str()),
                    Some(state.config().service_id.as_str()),
                    json!({ "deleted": deleted }),
                )
                .await;
            }
            res.render(Json(DeleteCount {
                deleted: deleted as i64,
            }));
        }
        Err(error) => ApiErrorCode::InternalError.render(res, format!("allowlist delete: {error}")),
    }
}

async fn load_allowlist(state: &AppState, limit: i64) -> anyhow::Result<Vec<AllowlistItem>> {
    use crate::schema::accept_allowlist::dsl as a;

    let mut conn = state.db().get().await?;
    let rows: Vec<AllowlistDbRow> = a::accept_allowlist
        .order(a::added_at.desc())
        .limit(limit)
        .select((a::resource_did, a::added_by, a::added_at, a::note))
        .load(&mut *conn)
        .await?;
    rows.into_iter().map(AllowlistItem::try_from).collect()
}

async fn upsert_allowlist(
    state: &AppState,
    body: &DirectoryAdminAllowlistUpsertRequestBody,
    actor: &DidCoreId,
) -> anyhow::Result<AllowlistItem> {
    use crate::schema::accept_allowlist::dsl as a;

    let mut conn = state.db().get().await?;
    let now = Utc::now();
    diesel::insert_into(a::accept_allowlist)
        .values(NewAllowlistRow {
            resource_did: body.resource_did.as_str(),
            added_by: actor,
            added_at: now,
            note: body.note.as_deref(),
        })
        .on_conflict(a::resource_did)
        .do_update()
        .set((
            a::added_by.eq(actor),
            a::added_at.eq(now),
            a::note.eq(&body.note),
        ))
        .execute(&mut *conn)
        .await?;

    let item: AllowlistDbRow = a::accept_allowlist
        .filter(a::resource_did.eq(body.resource_did.as_str()))
        .select((a::resource_did, a::added_by, a::added_at, a::note))
        .first(&mut *conn)
        .await?;
    item.try_into()
}

async fn delete_allowlist(state: &AppState, resource_did: &Did) -> anyhow::Result<usize> {
    use crate::schema::accept_allowlist::dsl as a;

    let mut conn = state.db().get().await?;
    let deleted =
        diesel::delete(a::accept_allowlist.filter(a::resource_did.eq(resource_did.as_str())))
            .execute(&mut *conn)
            .await?;
    Ok(deleted)
}

impl TryFrom<AllowlistDbRow> for AllowlistItem {
    type Error = anyhow::Error;

    fn try_from(row: AllowlistDbRow) -> Result<Self, Self::Error> {
        Ok(Self {
            resource_did: Did::new(row.resource_did)
                .map_err(|_| anyhow::anyhow!("database resource_did is not a valid W3C DID"))?,
            added_by: row.added_by,
            added_at: row.added_at.to_rfc3339(),
            note: row.note,
        })
    }
}
