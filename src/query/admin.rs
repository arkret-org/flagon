//! Operator-facing admin query endpoints.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use salvo::http::header;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::{
    audit::{self, AuditEventKind},
    error::ErrorCode,
    ingest::{DiscoverabilityWire, ResourceKindWire},
    state::AppState,
};

const DEFAULT_AUDIT_LIMIT: i64 = 100;
const MAX_AUDIT_LIMIT: i64 = 500;
const DEFAULT_ADMIN_LIMIT: i64 = 100;
const MAX_ADMIN_LIMIT: i64 = 500;

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
    resource_kind: Option<ResourceKindWire>,
    resource_id: Option<String>,
    actor: Option<String>,
    detail: JsonValue,
}

#[derive(Debug, Serialize)]
struct AuditFeedItem {
    audit_id: i64,
    occurred_at: DateTime<Utc>,
    kind: &'static str,
    resource_kind: Option<&'static str>,
    resource_id: Option<String>,
    actor: Option<String>,
    detail: JsonValue,
}

#[derive(Debug, Default, Deserialize)]
struct AllowlistQuery {
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AllowlistUpsertRequest {
    resource_did: String,
    #[serde(default)]
    added_by: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct AllowlistDeleteQuery {
    #[serde(default)]
    resource_did: Option<String>,
}

#[derive(Debug, Queryable, Serialize)]
struct AllowlistItem {
    resource_did: String,
    added_by: String,
    added_at: DateTime<Utc>,
    note: Option<String>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::accept_allowlist)]
struct NewAllowlistRow<'a> {
    resource_did: &'a str,
    added_by: &'a str,
    added_at: DateTime<Utc>,
    note: Option<&'a str>,
}

#[derive(Debug, Default, Deserialize)]
struct ResourcesQuery {
    #[serde(default)]
    resource_kind: Option<ResourceKindWire>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    divergent: Option<bool>,
    #[serde(default)]
    stale: Option<bool>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Queryable)]
struct ResourceAdminRow {
    resource_kind: ResourceKindWire,
    resource_id: String,
    principal_server_did: String,
    public_projection: JsonValue,
    discoverability: DiscoverabilityWire,
    as_of: DateTime<Utc>,
    source_refs: Vec<String>,
    policy_revision: Option<String>,
    indexed_at: DateTime<Utc>,
    effective_ttl_seconds: i32,
    next_revalidation_after: DateTime<Utc>,
    stale: bool,
    divergent: bool,
    via_services: Vec<String>,
    last_announce_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ResourceAdminItem {
    resource_kind: &'static str,
    resource_id: String,
    principal_server_did: String,
    public_projection: JsonValue,
    discoverability: &'static str,
    as_of: DateTime<Utc>,
    source_refs: Vec<String>,
    policy_revision: Option<String>,
    indexed_at: DateTime<Utc>,
    effective_ttl_seconds: i32,
    next_revalidation_after: DateTime<Utc>,
    stale: bool,
    divergent: bool,
    via_services: Vec<String>,
    last_announce_id: Option<String>,
}

#[handler]
pub async fn audit_feed(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };

    if let Err(error) = require_admin(req, &state) {
        error.render(res, "admin bearer token required");
        return;
    }

    let query: AuditQuery = match req.parse_queries() {
        Ok(query) => query,
        Err(error) => {
            ErrorCode::BadQuery.render(res, format!("malformed audit query: {error}"));
            return;
        }
    };

    let since = match query.since.as_deref().map(parse_since).transpose() {
        Ok(since) => since,
        Err(message) => {
            ErrorCode::InvalidParam.render(res, message);
            return;
        }
    };
    let limit = query
        .limit
        .unwrap_or(DEFAULT_AUDIT_LIMIT)
        .clamp(1, MAX_AUDIT_LIMIT);

    match load_audit_rows(&state, since, limit).await {
        Ok(rows) => {
            let next_since = rows.last().map(|row| row.occurred_at);
            let events: Vec<_> = rows.into_iter().map(AuditFeedItem::from).collect();
            res.render(Json(json!({
                "events": events,
                "next_since": next_since,
            })));
        }
        Err(error) => ErrorCode::InternalError.render(res, format!("audit feed: {error}")),
    }
}

#[handler]
pub async fn allowlist_list(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match admin_state(req, depot, res) {
        Some(state) => state,
        None => return,
    };
    let query: AllowlistQuery = match req.parse_queries() {
        Ok(query) => query,
        Err(error) => {
            ErrorCode::BadQuery.render(res, format!("malformed allowlist query: {error}"));
            return;
        }
    };
    let limit = query
        .limit
        .unwrap_or(DEFAULT_ADMIN_LIMIT)
        .clamp(1, MAX_ADMIN_LIMIT);

    match load_allowlist(&state, limit).await {
        Ok(items) => res.render(Json(json!({ "items": items }))),
        Err(error) => ErrorCode::InternalError.render(res, format!("allowlist list: {error}")),
    }
}

#[handler]
pub async fn allowlist_upsert(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match admin_state(req, depot, res) {
        Some(state) => state,
        None => return,
    };
    let body: AllowlistUpsertRequest = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ErrorCode::BadJson.render(res, format!("malformed allowlist body: {error}"));
            return;
        }
    };
    if body.resource_did.trim().is_empty() {
        ErrorCode::MissingParam.render(res, "resource_did is required");
        return;
    }
    let actor = body
        .added_by
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&state.config().service_did);

    match upsert_allowlist(&state, &body, actor).await {
        Ok(item) => {
            let _ = audit::record(
                state.db(),
                AuditEventKind::AllowlistAdded,
                None,
                Some(&body.resource_did),
                Some(actor),
                json!({ "note": body.note }),
            );
            res.render(Json(json!({ "item": item })));
        }
        Err(error) => ErrorCode::InternalError.render(res, format!("allowlist upsert: {error}")),
    }
}

#[handler]
pub async fn allowlist_delete(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match admin_state(req, depot, res) {
        Some(state) => state,
        None => return,
    };
    let query: AllowlistDeleteQuery = match req.parse_queries() {
        Ok(query) => query,
        Err(error) => {
            ErrorCode::BadQuery.render(res, format!("malformed allowlist delete query: {error}"));
            return;
        }
    };
    let resource_did = match query
        .resource_did
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(resource_did) => resource_did,
        None => {
            ErrorCode::MissingParam.render(res, "resource_did query parameter is required");
            return;
        }
    };

    match delete_allowlist(&state, resource_did).await {
        Ok(deleted) => {
            if deleted > 0 {
                let _ = audit::record(
                    state.db(),
                    AuditEventKind::AllowlistRemoved,
                    None,
                    Some(resource_did),
                    Some(&state.config().service_did),
                    json!({ "deleted": deleted }),
                );
            }
            res.render(Json(json!({ "deleted": deleted })));
        }
        Err(error) => ErrorCode::InternalError.render(res, format!("allowlist delete: {error}")),
    }
}

#[handler]
pub async fn resources_browser(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match admin_state(req, depot, res) {
        Some(state) => state,
        None => return,
    };
    let query: ResourcesQuery = match req.parse_queries() {
        Ok(query) => query,
        Err(error) => {
            ErrorCode::BadQuery.render(res, format!("malformed resources query: {error}"));
            return;
        }
    };
    let limit = query
        .limit
        .unwrap_or(DEFAULT_ADMIN_LIMIT)
        .clamp(1, MAX_ADMIN_LIMIT);

    match load_resources(&state, &query, limit).await {
        Ok(items) => res.render(Json(json!({ "items": items }))),
        Err(error) => ErrorCode::InternalError.render(res, format!("resources browser: {error}")),
    }
}

fn admin_state(req: &Request, depot: &mut Depot, res: &mut Response) -> Option<AppState> {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ErrorCode::InternalError.render(res, "AppState not injected");
            return None;
        }
    };
    if let Err(error) = require_admin(req, &state) {
        error.render(res, "admin bearer token required");
        return None;
    }
    Some(state)
}

fn require_admin(req: &Request, state: &AppState) -> Result<(), ErrorCode> {
    let expected = state
        .config()
        .admin_token
        .as_deref()
        .ok_or(ErrorCode::Unauthenticated)?;
    let actual = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    if actual == Some(expected) {
        Ok(())
    } else {
        Err(ErrorCode::Unauthenticated)
    }
}

fn parse_since(raw: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|error| format!("since must be RFC3339: {error}"))
}

async fn load_audit_rows(
    state: &AppState,
    since: Option<DateTime<Utc>>,
    limit: i64,
) -> anyhow::Result<Vec<AuditDbRow>> {
    use crate::schema::directory_audit::dsl as a;

    let mut conn = state.db().get()?;
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
            a::actor,
            a::detail,
        ))
        .load(&mut conn)?;
    Ok(rows)
}

async fn load_allowlist(state: &AppState, limit: i64) -> anyhow::Result<Vec<AllowlistItem>> {
    use crate::schema::accept_allowlist::dsl as a;

    let mut conn = state.db().get()?;
    let rows = a::accept_allowlist
        .order(a::added_at.desc())
        .limit(limit)
        .select((a::resource_did, a::added_by, a::added_at, a::note))
        .load(&mut conn)?;
    Ok(rows)
}

async fn upsert_allowlist(
    state: &AppState,
    body: &AllowlistUpsertRequest,
    actor: &str,
) -> anyhow::Result<AllowlistItem> {
    use crate::schema::accept_allowlist::dsl as a;

    let mut conn = state.db().get()?;
    let now = Utc::now();
    diesel::insert_into(a::accept_allowlist)
        .values(NewAllowlistRow {
            resource_did: &body.resource_did,
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
        .execute(&mut conn)?;

    let item = a::accept_allowlist
        .filter(a::resource_did.eq(&body.resource_did))
        .select((a::resource_did, a::added_by, a::added_at, a::note))
        .first(&mut conn)?;
    Ok(item)
}

async fn delete_allowlist(state: &AppState, resource_did: &str) -> anyhow::Result<usize> {
    use crate::schema::accept_allowlist::dsl as a;

    let mut conn = state.db().get()?;
    let deleted = diesel::delete(a::accept_allowlist.filter(a::resource_did.eq(resource_did)))
        .execute(&mut conn)?;
    Ok(deleted)
}

async fn load_resources(
    state: &AppState,
    query: &ResourcesQuery,
    limit: i64,
) -> anyhow::Result<Vec<ResourceAdminItem>> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get()?;
    let mut rows_query = r::directory_resources.into_boxed();
    if let Some(kind) = query.resource_kind {
        rows_query = rows_query.filter(r::resource_kind.eq(kind));
    }
    if let Some(divergent) = query.divergent {
        rows_query = rows_query.filter(r::divergent.eq(divergent));
    }
    if let Some(stale) = query.stale {
        rows_query = rows_query.filter(r::stale.eq(stale));
    }
    if let Some(q) = query.q.as_deref().filter(|value| !value.trim().is_empty()) {
        rows_query = rows_query.filter(r::resource_id.ilike(format!("%{}%", q.trim())));
    }

    let rows: Vec<ResourceAdminRow> = rows_query
        .order(r::indexed_at.desc())
        .limit(limit)
        .select((
            r::resource_kind,
            r::resource_id,
            r::principal_server_did,
            r::public_projection,
            r::discoverability,
            r::as_of,
            r::source_refs,
            r::policy_revision,
            r::indexed_at,
            r::effective_ttl_seconds,
            r::next_revalidation_after,
            r::stale,
            r::divergent,
            r::via_services,
            r::last_announce_id,
        ))
        .load(&mut conn)?;
    Ok(rows.into_iter().map(ResourceAdminItem::from).collect())
}

impl From<AuditDbRow> for AuditFeedItem {
    fn from(row: AuditDbRow) -> Self {
        Self {
            audit_id: row.audit_id,
            occurred_at: row.occurred_at,
            kind: row.kind.as_pg(),
            resource_kind: row.resource_kind.map(ResourceKindWire::as_pg),
            resource_id: row.resource_id,
            actor: row.actor,
            detail: row.detail,
        }
    }
}

impl From<ResourceAdminRow> for ResourceAdminItem {
    fn from(row: ResourceAdminRow) -> Self {
        Self {
            resource_kind: row.resource_kind.as_pg(),
            resource_id: row.resource_id,
            principal_server_did: row.principal_server_did,
            public_projection: row.public_projection,
            discoverability: row.discoverability.as_pg(),
            as_of: row.as_of,
            source_refs: row.source_refs,
            policy_revision: row.policy_revision,
            indexed_at: row.indexed_at,
            effective_ttl_seconds: row.effective_ttl_seconds,
            next_revalidation_after: row.next_revalidation_after,
            stale: row.stale,
            divergent: row.divergent,
            via_services: row.via_services,
            last_announce_id: row.last_announce_id,
        }
    }
}
