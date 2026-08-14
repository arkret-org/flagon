//! Operator-facing admin query endpoints.

use arkret_sdk::DidCoreId;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use teabay_contracts::{
    AllowlistEnvelope, AllowlistItem, AllowlistMutationEnvelope, AuditEnvelope, AuditEvent,
    DashboardKindCount, DashboardStats, DeleteCount, DirectoryAdminAllowlistUpsertRequestBody,
    DirectoryAdminResourceUpsertRequestBody, DirectoryDiscoveryState, DirectoryPublicProjection,
    ResourceItem, ResourceList, ResourceMutationEnvelope,
};

use crate::audit::{self, AuditEventKind};
use crate::error::ApiErrorCode;
use crate::ingest::announce::effective_ttl_seconds;
use crate::ingest::subscribe::{ReachabilityTombstone, TombstoneKind};
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};
use crate::middleware::{require_admin_csrf, verify_admin_credential};
use crate::state::AppState;

const DEFAULT_AUDIT_LIMIT: i64 = 100;
const MAX_AUDIT_LIMIT: i64 = 500;
const DEFAULT_ADMIN_LIMIT: i64 = 100;
const MAX_ADMIN_LIMIT: i64 = 500;
/// Hard ceiling on the `q` (text search) filter passed to
/// `resources_browser`. Prevents a hostile operator from pinning a
/// multi-megabyte ILIKE pattern against the directory_resources table.
const MAX_RESOURCE_Q_CHARS: usize = 256;

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
    actor: Option<String>,
    detail: JsonValue,
}

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
    principal_server_service_id: String,
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
    principal_server_service_id: String,
    policy_revision: String,
    via_services: Vec<String>,
    last_announce_id: Option<String>,
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
            let events: Vec<_> = rows.into_iter().map(AuditEvent::from).collect();
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

    match audit::verify_chain(state.db()).await {
        Ok(outcome) => res.render(Json(outcome)),
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("audit chain verify: {error}"))
        }
    }
}

#[handler]
pub async fn allowlist_list(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match admin_state(req, depot, res).await {
        Some(state) => state,
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
    let state = match admin_state(req, depot, res).await {
        Some(state) => state,
        None => return,
    };
    let body: DirectoryAdminAllowlistUpsertRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::JsonInvalid.render(res, format!("malformed allowlist body: {error}"));
            return;
        }
    };
    if body.resource_did.trim().is_empty() {
        ApiErrorCode::ParamMissing.render(res, "resource_did is required");
        return;
    }
    let actor = body
        .added_by
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&state.config().service_id);

    match upsert_allowlist(&state, &body, actor).await {
        Ok(item) => {
            let _ = audit::record(
                state.db(),
                AuditEventKind::AllowlistAdded,
                None,
                Some(&body.resource_did),
                Some(actor),
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
    let state = match admin_state(req, depot, res).await {
        Some(state) => state,
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
        Some(resource_did) => resource_did,
        None => {
            ApiErrorCode::ParamMissing.render(res, "resource_did query parameter is required");
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
                    Some(&state.config().service_id),
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

#[handler]
pub async fn resources_browser(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match admin_state(req, depot, res).await {
        Some(state) => state,
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
    let state = match admin_state(req, depot, res).await {
        Some(state) => state,
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
    if body.principal_server_service_id.trim().is_empty() {
        ApiErrorCode::ParamMissing.render(res, "principal_server_service_id is required");
        return;
    }
    // The operator supplies the Principal Server's *stable service core id*,
    // matching the announce wire (`discovery-directory.md` §8.3) and the
    // `directory_resources.principal_server_service_id` column. A full DID is
    // rejected here rather than silently projected: the two are different
    // value categories and the column is keyed on the stable one.
    let principal_server_service_id =
        match DidCoreId::new(body.principal_server_service_id.trim().to_owned()) {
            Ok(service_id) => service_id,
            Err(error) => {
                ApiErrorCode::SchemaViolation.render(
                    res,
                    format!(
                        "principal_server_service_id must be a stable service core id \
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
            vec![principal_server_service_id.into_string()]
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
            let _ = audit::record(
                state.db(),
                AuditEventKind::AdminResourceUpserted,
                Some(resource_kind),
                Some(&body.resource_id),
                Some(&state.config().service_id),
                json!({
                    "principal_server_service_id": body.principal_server_service_id.as_str(),
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
    let state = match admin_state(req, depot, res).await {
        Some(state) => state,
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
            let _ = audit::record(
                state.db(),
                AuditEventKind::AdminResourceDeleted,
                Some(resource_kind),
                Some(resource_id),
                Some(&state.config().service_id),
                json!({
                    "principal_server_service_id": detail.principal_server_service_id,
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

// ---- Round R2/R3 T17 — consent revoke scope=any invalidation ------------

/// `POST /_teabay/admin/consent-revoke` — soland (or any peer service)
/// broadcasts a `consent_revoke{scope=any}` event for an actor; the
/// directory then **eagerly invalidates** that actor's reachability
/// entries in the directory ingest cache.
///
/// Per Round R2/R3 T17 we **soft-delete** (UPDATE) rather than DELETE
/// so the audit trail is preserved — the row is marked with
/// `reachability_revoked_at` and the search face hides it (resolve
/// still surfaces it so in-flight subscribers can observe the
/// revocation tombstone). A `ak.find.directory.push.command.register` tombstone webhook
/// fires on a best-effort basis through the same fanout path the
/// announce handler uses.
#[derive(Debug, Deserialize)]
struct DirectoryAdminConsentRevokeRequestBody {
    /// Affected actor DID. Required.
    actor_id: String,
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
    tombstoned_subscriptions: usize,
}

#[handler]
pub async fn consent_revoke_invalidate(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match admin_state(req, depot, res).await {
        Some(state) => state,
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
    if body.actor_id.trim().is_empty() {
        ApiErrorCode::ParamMissing.render(res, "actor_id is required");
        return;
    }
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
    let (invalidated_rows, affected) =
        match invalidate_reachability(&state, &body, revoked_at, &reason).await {
            Ok(rows) => rows,
            Err(error) => {
                ApiErrorCode::InternalError.render(res, format!("consent revoke: {error}"));
                return;
            }
        };

    let _ = audit::record(
        state.db(),
        AuditEventKind::ConsentRevokeInvalidation,
        None,
        Some(&body.actor_id),
        Some(&state.config().service_id),
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

    // Best-effort tombstone fanout for in-flight `ak.find.directory.push.command.register`
    // webhook listeners. T07 reuses the same channel for realm destroys.
    let tombstoned_subscriptions =
        crate::ingest::subscribe::fanout_reachability_tombstone(state.clone(), &affected).await;

    res.render(Json(DirectoryAdminConsentRevokeOutcome {
        invalidated_rows,
        revoked_at,
        tombstoned_subscriptions,
    }));
}

async fn invalidate_reachability(
    state: &AppState,
    body: &DirectoryAdminConsentRevokeRequestBody,
    revoked_at: DateTime<Utc>,
    reason: &str,
) -> anyhow::Result<(i64, Vec<ReachabilityTombstone>)> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get().await?;
    // The actor's reachability projection can live on:
    //   * actor rows keyed by the actor's DID
    //   * handle rows where principal_server_service_id == actor DID
    //   * applet rows that name the actor as principal
    // We match by either `resource_id = actor_id` or
    // `principal_server_service_id = actor_id`. T17 explicitly says "mark with
    // revoked_at for audit" — so this is an UPDATE, not a DELETE.
    let mut query = diesel::update(r::directory_resources)
        .filter(
            r::resource_id
                .eq(&body.actor_id)
                .or(r::principal_server_service_id.eq(&body.actor_id)),
        )
        .filter(r::reachability_revoked_at.is_null())
        .into_boxed();
    if !body.resource_ids.is_empty() {
        query = query.filter(r::resource_id.eq_any(&body.resource_ids));
    }
    let affected_rows: Vec<(DirectoryResourceKindDb, String, String)> = query
        .set((
            r::reachability_revoked_at.eq(Some(revoked_at)),
            r::reachability_revoked_reason.eq(Some(reason)),
        ))
        .returning((
            r::resource_kind,
            r::resource_id,
            r::principal_server_service_id,
        ))
        .get_results(&mut *conn)
        .await?;
    let invalidated_rows = affected_rows.len() as i64;
    let tombstones = affected_rows
        .into_iter()
        .map(
            |(resource_kind, resource_id, principal_server_service_id)| ReachabilityTombstone {
                kind: TombstoneKind::ReachabilityRevoked,
                resource_kind,
                resource_id,
                principal_server_service_id,
                reason: reason.to_owned(),
                revoked_at,
            },
        )
        .collect();
    Ok((invalidated_rows, tombstones))
}

async fn admin_state(req: &Request, depot: &mut Depot, res: &mut Response) -> Option<AppState> {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return None;
        }
    };
    if let Err(error) = require_admin(req, &state).await {
        error.render(res, "admin bearer token required");
        return None;
    }
    if let Err(error) = require_admin_csrf(req, &state) {
        error.render(res, "X-CSRF-Token header required");
        return None;
    }
    Some(state)
}

async fn require_admin(req: &Request, state: &AppState) -> Result<(), ApiErrorCode> {
    verify_admin_credential(req, state).await.map(|_| ())
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
            a::actor,
            a::detail,
        ))
        .load(&mut *conn)
        .await?;
    Ok(rows)
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
    Ok(rows.into_iter().map(AllowlistItem::from).collect())
}

async fn upsert_allowlist(
    state: &AppState,
    body: &DirectoryAdminAllowlistUpsertRequestBody,
    actor: &str,
) -> anyhow::Result<AllowlistItem> {
    use crate::schema::accept_allowlist::dsl as a;

    let mut conn = state.db().get().await?;
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
        .execute(&mut *conn)
        .await?;

    let item: AllowlistDbRow = a::accept_allowlist
        .filter(a::resource_did.eq(&body.resource_did))
        .select((a::resource_did, a::added_by, a::added_at, a::note))
        .first(&mut *conn)
        .await?;
    Ok(item.into())
}

async fn delete_allowlist(state: &AppState, resource_did: &str) -> anyhow::Result<usize> {
    use crate::schema::accept_allowlist::dsl as a;

    let mut conn = state.db().get().await?;
    let deleted = diesel::delete(a::accept_allowlist.filter(a::resource_did.eq(resource_did)))
        .execute(&mut *conn)
        .await?;
    Ok(deleted)
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
                    r::principal_server_service_id,
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

    crate::psi_index::sync_resource_tokens(
        state.db(),
        resource_kind,
        body.resource_id.trim(),
        discoverability,
        body.stale,
        &public_projection,
    )
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
            r::principal_server_service_id,
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
                .first::<(String, String, Vec<String>, Option<String>)>(&mut *conn)
                .await
                .optional()?;

            let Some((
                principal_server_service_id,
                policy_revision,
                via_services,
                last_announce_id,
            )) = existing
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
                principal_server_service_id,
                policy_revision,
                via_services,
                last_announce_id,
            }))
        })
        .await?;
    if outcome.is_some() {
        crate::psi_index::delete_resource_tokens(state.db(), resource_kind, resource_id).await?;
    }
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

impl From<AuditDbRow> for AuditEvent {
    fn from(row: AuditDbRow) -> Self {
        Self {
            audit_id: row.audit_id,
            occurred_at: row.occurred_at.to_rfc3339(),
            kind: row.kind.as_pg().to_owned(),
            resource_kind: row
                .resource_kind
                .map(|resource_kind| resource_kind.as_pg().to_owned()),
            resource_id: row.resource_id,
            actor: row.actor,
            detail: row.detail,
        }
    }
}

/// P2E.3 — operator dashboard stats. Cheap COUNT(*) aggregates over
/// the directory tables so the admin SPA can render a single-shot
/// overview without scanning the full audit feed.
#[handler]
pub async fn dashboard_stats(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(state) => state.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    if let Err(error) = require_admin(req, &state).await {
        error.render(res, "admin bearer token required");
        return;
    }
    let stats = match collect_dashboard_stats(&state).await {
        Ok(stats) => stats,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("dashboard stats: {error}"));
            return;
        }
    };
    res.render(Json(stats));
}

async fn collect_dashboard_stats(state: &AppState) -> anyhow::Result<DashboardStats> {
    use crate::schema::accept_allowlist::dsl as al;
    use crate::schema::directory_audit::dsl as au;
    use crate::schema::directory_resources::dsl as r;
    use crate::schema::ingest_announces::dsl as a;
    use crate::schema::webhook_subscriptions::dsl as s;

    let mut conn = state.db().get().await?;

    let directory_resources: i64 = r::directory_resources
        .count()
        .get_result(&mut *conn)
        .await?;
    let stale_resources: i64 = r::directory_resources
        .filter(r::stale.eq(true))
        .count()
        .get_result(&mut *conn)
        .await?;
    let divergent_resources: i64 = r::directory_resources
        .filter(r::divergent.eq(true))
        .count()
        .get_result(&mut *conn)
        .await?;
    let realm_destroyed: i64 = r::directory_resources
        .filter(r::realm_destroyed_at.is_not_null())
        .count()
        .get_result(&mut *conn)
        .await?;
    let ingest_announces: i64 = a::ingest_announces.count().get_result(&mut *conn).await?;
    let webhook_subscriptions: i64 = s::webhook_subscriptions
        .filter(s::expires_at.is_null().or(s::expires_at.gt(Utc::now())))
        .count()
        .get_result(&mut *conn)
        .await?;
    let audit_events: i64 = au::directory_audit.count().get_result(&mut *conn).await?;
    let allowlist_entries: i64 = al::accept_allowlist.count().get_result(&mut *conn).await?;

    let mut per_kind = Vec::with_capacity(5);
    for kind in [
        DirectoryResourceKindDb::Realm,
        DirectoryResourceKindDb::Organization,
        DirectoryResourceKindDb::Actor,
        DirectoryResourceKindDb::Applet,
        DirectoryResourceKindDb::Handle,
    ] {
        let count: i64 = r::directory_resources
            .filter(r::resource_kind.eq(kind))
            .count()
            .get_result(&mut *conn)
            .await?;
        per_kind.push(DashboardKindCount {
            resource_kind: kind.as_pg().to_owned(),
            count,
        });
    }
    per_kind.sort_by_key(|k| std::cmp::Reverse(k.count));

    Ok(DashboardStats {
        directory_resources,
        stale_resources,
        divergent_resources,
        realm_destroyed,
        ingest_announces,
        webhook_subscriptions,
        audit_events,
        allowlist_entries,
        per_kind,
        as_of: Utc::now().to_rfc3339(),
    })
}

impl From<AllowlistDbRow> for AllowlistItem {
    fn from(row: AllowlistDbRow) -> Self {
        Self {
            resource_did: row.resource_did,
            added_by: row.added_by,
            added_at: row.added_at.to_rfc3339(),
            note: row.note,
        }
    }
}

impl From<ResourceAdminRow> for ResourceItem {
    fn from(row: ResourceAdminRow) -> Self {
        Self {
            resource_kind: row.resource_kind.as_pg().to_owned(),
            resource_id: row.resource_id,
            principal_server_service_id: row.principal_server_service_id,
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

// ---- B.8.6 — takedown audit export -------------------------------------

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
    actor: Option<String>,
    detail: JsonValue,
    authentication_method: Option<String>,
    authenticated_actor: Option<String>,
    asserted_operator: Option<String>,
}

#[derive(Debug, Serialize)]
struct TakedownAuditExportItem {
    audit_id: i64,
    occurred_at: DateTime<Utc>,
    resource_kind: Option<&'static str>,
    resource_id: Option<String>,
    actor: Option<String>,
    detail: JsonValue,
    authentication_method: Option<String>,
    authenticated_actor: Option<String>,
    asserted_operator: Option<String>,
}

#[handler]
pub async fn takedown_audit_export(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match admin_state(req, depot, res).await {
        Some(state) => state,
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
            let items: Vec<TakedownAuditExportItem> = rows
                .into_iter()
                .map(TakedownAuditExportItem::from)
                .collect();
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
            a::actor,
            a::detail,
            a::authentication_method,
            a::authenticated_actor,
            a::asserted_operator,
        ))
        .load(&mut *conn)
        .await?;
    Ok(rows)
}

impl From<TakedownAuditExportRow> for TakedownAuditExportItem {
    fn from(row: TakedownAuditExportRow) -> Self {
        Self {
            audit_id: row.audit_id,
            occurred_at: row.occurred_at,
            resource_kind: row.resource_kind.map(DirectoryResourceKindDb::as_pg),
            resource_id: row.resource_id,
            actor: row.actor,
            detail: row.detail,
            authentication_method: row.authentication_method,
            authenticated_actor: row.authenticated_actor,
            asserted_operator: row.asserted_operator,
        }
    }
}
