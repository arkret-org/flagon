//! Admin resources browser / upsert / delete endpoints.

use arkret_sdk::DidCoreId;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use teabay_contracts::{
    DeleteCount, DirectoryAdminResourceUpsertRequestBody, DirectoryDiscoveryState,
    DirectoryPublicProjection, ResourceItem, ResourceList, ResourceMutationEnvelope,
};

use super::{DEFAULT_ADMIN_LIMIT, MAX_ADMIN_LIMIT, admin_state, record_admin_audit};
use crate::audit::AuditEventKind;
use crate::error::ApiErrorCode;
use crate::ingest::announce::effective_ttl_seconds;
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};
use crate::state::AppState;

/// Hard ceiling on the `q` (text search) filter passed to
/// `resources_browser`. Prevents a hostile operator from pinning a
/// multi-megabyte ILIKE pattern against the directory_resources table.
const MAX_RESOURCE_Q_CHARS: usize = 256;

#[derive(Debug, Default, Deserialize)]
struct ResourcesQuery {
    #[serde(default)]
    resource_kind: Option<DirectoryResourceKindDb>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    divergent: Option<bool>,
    #[serde(default)]
    stale: Option<bool>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct ResourceDeleteQuery {
    #[serde(default)]
    resource_kind: Option<DirectoryResourceKindDb>,
    #[serde(default)]
    resource_id: Option<String>,
}

#[derive(Debug, Queryable)]
struct ResourceAdminRow {
    resource_kind: DirectoryResourceKindDb,
    resource_id: String,
    principal_server_id: DidCoreId,
    discovery_state: JsonValue,
    public_projection: JsonValue,
    discoverability: DiscoverabilityDb,
    as_of: DateTime<Utc>,
    source_refs: Vec<String>,
    policy_revision: String,
    indexed_at: DateTime<Utc>,
    effective_ttl_seconds: i32,
    next_revalidation_after: DateTime<Utc>,
    stale: bool,
    divergent: bool,
    via_services: Vec<String>,
    last_announce_id: Option<String>,
}

#[derive(Debug)]
struct ResourceDeleteAudit {
    principal_server_id: String,
    policy_revision: String,
    via_services: Vec<String>,
    last_announce_id: Option<String>,
}

#[handler]
pub async fn resources_browser(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let (state, _credential) = match admin_state(req, depot, res).await {
        Some(context) => context,
        None => return,
    };
    let query: ResourcesQuery = match req.parse_queries() {
        Ok(query) => query,
        Err(error) => {
            ApiErrorCode::QueryInvalid.render(res, format!("malformed resources query: {error}"));
            return;
        }
    };
    let limit = query
        .limit
        .unwrap_or(DEFAULT_ADMIN_LIMIT)
        .clamp(1, MAX_ADMIN_LIMIT);

    match load_resources(&state, &query, limit).await {
        Ok(items) => res.render(Json(ResourceList { items })),
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("resources browser: {error}"))
        }
    }
}

#[handler]
pub async fn resource_upsert(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let (state, credential) = match admin_state(req, depot, res).await {
        Some(context) => context,
        None => return,
    };
    let body: DirectoryAdminResourceUpsertRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::JsonInvalid.render(res, format!("malformed resource body: {error}"));
            return;
        }
    };

    if body.resource_id.trim().is_empty() {
        ApiErrorCode::ParamMissing.render(res, "resource_id is required");
        return;
    }
    if body.principal_server_id.trim().is_empty() {
        ApiErrorCode::ParamMissing.render(res, "principal_server_id is required");
        return;
    }
    // The operator supplies the Principal Server's *stable service core id*,
    // matching the announce wire (`discovery-directory.md` §8.3) and the
    // `directory_resources.principal_server_id` column. A DID is
    // rejected here rather than silently projected: the two are different
    // value categories and the column is keyed on the stable one.
    let principal_server_id = match DidCoreId::new(body.principal_server_id.trim().to_owned()) {
        Ok(service_id) => service_id,
        Err(error) => {
            ApiErrorCode::SchemaViolation.render(
                res,
                format!(
                    "principal_server_id must be a stable service core id \
                         (ak:did_core:<method>:<core>), not a DID or URL: {error}"
                ),
            );
            return;
        }
    };
    let policy_revision = body.policy_revision.trim();
    if policy_revision.is_empty() {
        ApiErrorCode::ParamMissing.render(res, "policy_revision is required");
        return;
    }
    if !body.public_projection.is_object() {
        ApiErrorCode::SchemaViolation.render(res, "public_projection must be an object");
        return;
    }
    let resource_kind = DirectoryResourceKindDb::from(body.resource_kind);
    let discoverability = DiscoverabilityDb::from(&body.discoverability);

    let source_refs = {
        let refs = normalize_string_list(&body.source_refs);
        if refs.is_empty() {
            vec!["admin:manual".to_string()]
        } else {
            refs
        }
    };
    let via_services = {
        let services = normalize_string_list(&body.via_services);
        if services.is_empty() {
            vec![principal_server_id.into_string()]
        } else if services
            .iter()
            .any(|service_id| DidCoreId::new(service_id.clone()).is_err())
        {
            ApiErrorCode::SchemaViolation.render(
                res,
                "via_services entries must be stable service core ids, not DIDs or URLs",
            );
            return;
        } else {
            services
        }
    };
    let public_projection = normalized_public_projection(&body.public_projection, discoverability);
    let discovery_state = match normalized_discovery_state(
        &body,
        resource_kind,
        discoverability,
        &public_projection,
        &via_services,
    ) {
        Ok(state) => state,
        Err(message) => {
            ApiErrorCode::SchemaViolation.render(res, message);
            return;
        }
    };
    let effective_ttl = effective_ttl_seconds(body.effective_ttl_seconds, state.config());
    let indexed_at = Utc::now();
    let next_revalidation_after = indexed_at + chrono::Duration::seconds(effective_ttl);

    match upsert_managed_resource(
        &state,
        &body,
        resource_kind,
        discoverability,
        discovery_state,
        public_projection,
        source_refs,
        via_services,
        indexed_at,
        effective_ttl as i32,
        next_revalidation_after,
    )
    .await
    {
        Ok(item) => {
            let _ = record_admin_audit(
                &state,
                &credential,
                AuditEventKind::AdminResourceUpserted,
                Some(resource_kind),
                Some(&body.resource_id),
                Some(&state.config().service_id),
                json!({
                    "principal_server_id": body.principal_server_id.as_str(),
                    "discoverability": discoverability.as_pg(),
                    "policy_revision": policy_revision,
                    "effective_ttl_seconds": effective_ttl,
                    "source_refs": item.source_refs,
                    "via_services": item.via_services,
                }),
            )
            .await;
            res.render(Json(ResourceMutationEnvelope { item }));
        }
        Err(error) => ApiErrorCode::InternalError.render(res, format!("resource upsert: {error}")),
    }
}

#[handler]
pub async fn resource_delete(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let (state, credential) = match admin_state(req, depot, res).await {
        Some(context) => context,
        None => return,
    };
    let query: ResourceDeleteQuery = match req.parse_queries() {
        Ok(query) => query,
        Err(error) => {
            ApiErrorCode::QueryInvalid
                .render(res, format!("malformed resource delete query: {error}"));
            return;
        }
    };
    let resource_kind = match query.resource_kind {
        Some(kind) => kind,
        None => {
            ApiErrorCode::ParamMissing.render(res, "resource_kind query parameter is required");
            return;
        }
    };
    let resource_id = match query
        .resource_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(resource_id) => resource_id,
        None => {
            ApiErrorCode::ParamMissing.render(res, "resource_id query parameter is required");
            return;
        }
    };

    match delete_managed_resource(&state, resource_kind, resource_id).await {
        Ok(Some(detail)) => {
            let _ = record_admin_audit(
                &state,
                &credential,
                AuditEventKind::AdminResourceDeleted,
                Some(resource_kind),
                Some(resource_id),
                Some(&state.config().service_id),
                json!({
                    "principal_server_id": detail.principal_server_id,
                    "policy_revision": detail.policy_revision,
                    "via_services": detail.via_services,
                    "last_announce_id": detail.last_announce_id,
                }),
            )
            .await;
            res.render(Json(DeleteCount { deleted: 1 }));
        }
        Ok(None) => res.render(Json(DeleteCount { deleted: 0 })),
        Err(error) => ApiErrorCode::InternalError.render(res, format!("resource delete: {error}")),
    }
}

async fn load_resources(
    state: &AppState,
    query: &ResourcesQuery,
    limit: i64,
) -> anyhow::Result<Vec<ResourceItem>> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get().await?;
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
        // SQL LIKE DoS guard: cap q length so a hostile operator cannot
        // make Postgres ILIKE-scan a multi-megabyte pattern.
        let trimmed = q.trim();
        let bounded: &str = if trimmed.len() > MAX_RESOURCE_Q_CHARS {
            &trimmed[..MAX_RESOURCE_Q_CHARS]
        } else {
            trimmed
        };
        rows_query = rows_query.filter(r::resource_id.ilike(format!("%{bounded}%")));
    }

    // Per-statement timeout for the resources-browser scan. `SET LOCAL`
    // requires a transaction so a runaway ILIKE can't tie up a pool
    // connection beyond 1 second. The transaction commits cleanly even
    // when the underlying SELECT returned a TimedOut error.
    let rows: Vec<ResourceAdminRow> = conn
        .transaction::<_, diesel::result::Error, _>(async move |conn| {
            diesel::sql_query("SET LOCAL statement_timeout = '1s'")
                .execute(&mut *conn)
                .await?;
            rows_query
                .order(r::indexed_at.desc())
                .limit(limit)
                .select((
                    r::resource_kind,
                    r::resource_id,
                    r::principal_server_id,
                    r::discovery_state,
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
                .load(&mut *conn)
                .await
        })
        .await?;
    Ok(rows.into_iter().map(ResourceItem::from).collect())
}

#[allow(clippy::too_many_arguments)]
async fn upsert_managed_resource(
    state: &AppState,
    body: &DirectoryAdminResourceUpsertRequestBody,
    resource_kind: DirectoryResourceKindDb,
    discoverability: DiscoverabilityDb,
    discovery_state: JsonValue,
    public_projection: JsonValue,
    source_refs: Vec<String>,
    via_services: Vec<String>,
    indexed_at: DateTime<Utc>,
    effective_ttl_seconds: i32,
    next_revalidation_after: DateTime<Utc>,
) -> anyhow::Result<ResourceItem> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get().await?;
    let policy_revision = body.policy_revision.trim();
    diesel::insert_into(r::directory_resources)
        .values((
            r::resource_kind.eq(resource_kind),
            r::resource_id.eq(body.resource_id.trim()),
            r::principal_server_id.eq(body.principal_server_id.trim()),
            r::discovery_state.eq(&discovery_state),
            r::public_projection.eq(&public_projection),
            r::discoverability.eq(discoverability),
            r::as_of.eq(body.as_of.unwrap_or(indexed_at)),
            r::source_refs.eq(&source_refs),
            r::policy_revision.eq(policy_revision),
            r::indexed_at.eq(indexed_at),
            r::effective_ttl_seconds.eq(effective_ttl_seconds),
            r::next_revalidation_after.eq(next_revalidation_after),
            r::stale.eq(body.stale),
            r::divergent.eq(body.divergent),
            r::via_services.eq(&via_services),
            r::last_announce_id.eq(trimmed_option(body.last_announce_id.as_deref())),
        ))
        .on_conflict((r::resource_kind, r::resource_id))
        .do_update()
        .set((
            r::principal_server_service_id.eq(body.principal_server_service_id.trim()),
            r::discovery_state.eq(&discovery_state),
            r::public_projection.eq(&public_projection),
            r::discoverability.eq(discoverability),
            r::as_of.eq(body.as_of.unwrap_or(indexed_at)),
            r::source_refs.eq(&source_refs),
            r::policy_revision.eq(policy_revision),
            r::indexed_at.eq(indexed_at),
            r::effective_ttl_seconds.eq(effective_ttl_seconds),
            r::next_revalidation_after.eq(next_revalidation_after),
            r::stale.eq(body.stale),
            r::divergent.eq(body.divergent),
            r::via_services.eq(&via_services),
            r::last_announce_id.eq(trimmed_option(body.last_announce_id.as_deref())),
        ))
        .execute(&mut *conn)
        .await?;

    load_resource(state, resource_kind, body.resource_id.trim()).await
}

async fn load_resource(
    state: &AppState,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
) -> anyhow::Result<ResourceItem> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get().await?;
    let row: ResourceAdminRow = r::directory_resources
        .filter(r::resource_kind.eq(resource_kind))
        .filter(r::resource_id.eq(resource_id))
        .select((
            r::resource_kind,
            r::resource_id,
            r::principal_server_id,
            r::discovery_state,
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
        .first(&mut *conn)
        .await?;
    Ok(row.into())
}

async fn delete_managed_resource(
    state: &AppState,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
) -> anyhow::Result<Option<ResourceDeleteAudit>> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get().await?;
    let outcome = conn
        .transaction::<_, anyhow::Error, _>(async move |conn| {
            let existing = r::directory_resources
                .filter(r::resource_kind.eq(resource_kind))
                .filter(r::resource_id.eq(resource_id))
                .select((
                    r::principal_server_service_id,
                    r::policy_revision,
                    r::via_services,
                    r::last_announce_id,
                ))
                .first::<(DidCoreId, String, Vec<String>, Option<String>)>(&mut *conn)
                .await
                .optional()?;

            let Some((principal_server_id, policy_revision, via_services, last_announce_id)) =
                existing
            else {
                return Ok(None);
            };

            diesel::delete(
                r::directory_resources
                    .filter(r::resource_kind.eq(resource_kind))
                    .filter(r::resource_id.eq(resource_id)),
            )
            .execute(&mut *conn)
            .await?;

            Ok(Some(ResourceDeleteAudit {
                principal_server_id: principal_server_id.into_string(),
                policy_revision,
                via_services,
                last_announce_id,
            }))
        })
        .await?;
    Ok(outcome)
}

fn normalized_public_projection(raw: &JsonValue, discoverability: DiscoverabilityDb) -> JsonValue {
    let mut projection = raw.clone();
    let object = projection
        .as_object_mut()
        .expect("public_projection validated as object");
    object
        .entry("discoverability".to_string())
        .or_insert_with(|| JsonValue::String(discoverability.as_pg().to_string()));
    projection
}

fn normalized_discovery_state(
    body: &DirectoryAdminResourceUpsertRequestBody,
    resource_kind: DirectoryResourceKindDb,
    discoverability: DiscoverabilityDb,
    public_projection: &JsonValue,
    via_services: &[String],
) -> Result<JsonValue, String> {
    let mut discovery_state = body
        .discovery_state
        .clone()
        .map(DirectoryDiscoveryState::into_value)
        .unwrap_or_else(|| public_projection.clone());
    let object = discovery_state
        .as_object_mut()
        .ok_or_else(|| "discovery_state must be an object when provided".to_string())?;
    object.insert(
        "kind".to_string(),
        JsonValue::String(resource_kind.discovery_event_kind().to_string()),
    );
    object.insert(
        "discoverability".to_string(),
        JsonValue::String(discoverability.as_pg().to_string()),
    );
    if let Some(existing) = object.get("policy_revision").and_then(JsonValue::as_str)
        && existing != body.policy_revision.trim()
    {
        return Err("discovery_state.policy_revision must match policy_revision".to_string());
    }
    object.insert(
        "policy_revision".to_string(),
        JsonValue::String(body.policy_revision.trim().to_string()),
    );
    object.insert(
        "directory_services".to_string(),
        JsonValue::Array(
            via_services
                .iter()
                .cloned()
                .map(JsonValue::String)
                .collect(),
        ),
    );
    Ok(discovery_state)
}

fn normalize_string_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn trimmed_option(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

impl From<ResourceAdminRow> for ResourceItem {
    fn from(row: ResourceAdminRow) -> Self {
        Self {
            resource_kind: row.resource_kind.as_pg().to_owned(),
            resource_id: row.resource_id,
            principal_server_id: row.principal_server_id.into_string(),
            discovery_state: DirectoryDiscoveryState::from_json(row.discovery_state),
            public_projection: DirectoryPublicProjection::from_json(row.public_projection),
            discoverability: row.discoverability.as_pg().to_owned(),
            as_of: row.as_of.to_rfc3339(),
            source_refs: row.source_refs,
            policy_revision: row.policy_revision,
            indexed_at: row.indexed_at.to_rfc3339(),
            effective_ttl_seconds: row.effective_ttl_seconds,
            next_revalidation_after: row.next_revalidation_after.to_rfc3339(),
            stale: row.stale,
            divergent: row.divergent,
            via_services: row.via_services,
            last_announce_id: row.last_announce_id,
        }
    }
}
