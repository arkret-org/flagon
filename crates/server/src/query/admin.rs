//! Operator-facing admin query endpoints.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use salvo::http::header;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::audit::{self, AuditEventKind};
use crate::error::ApiErrorCode;
use crate::ingest::announce::effective_ttl_seconds;
use crate::ingest::{DiscoverabilityWire, ResourceKindWire};
use crate::state::AppState;

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

#[derive(Debug, Deserialize)]
struct ResourceUpsertRequest {
    resource_kind: ResourceKindWire,
    resource_id: String,
    principal_server_did: String,
    #[serde(default)]
    discovery_state: JsonValue,
    #[serde(default)]
    public_projection: JsonValue,
    discoverability: DiscoverabilityWire,
    #[serde(default)]
    as_of: Option<DateTime<Utc>>,
    #[serde(default)]
    source_refs: Vec<String>,
    #[serde(default)]
    policy_revision: Option<String>,
    #[serde(default)]
    effective_ttl_seconds: Option<i64>,
    #[serde(default)]
    stale: Option<bool>,
    #[serde(default)]
    divergent: Option<bool>,
    #[serde(default)]
    via_services: Vec<String>,
    #[serde(default)]
    last_announce_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ResourceDeleteQuery {
    #[serde(default)]
    resource_kind: Option<ResourceKindWire>,
    #[serde(default)]
    resource_id: Option<String>,
}

#[derive(Debug, Queryable)]
struct ResourceAdminRow {
    resource_kind: ResourceKindWire,
    resource_id: String,
    principal_server_did: String,
    discovery_state: JsonValue,
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
    discovery_state: JsonValue,
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

#[derive(Debug)]
struct ResourceDeleteAudit {
    principal_server_did: String,
    policy_revision: Option<String>,
    via_services: Vec<String>,
    last_announce_id: Option<String>,
}

#[handler]
pub async fn audit_feed(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
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
            ApiErrorCode::BadQuery.render(res, format!("malformed audit query: {error}"));
            return;
        }
    };

    let since = match query.since.as_deref().map(parse_since).transpose() {
        Ok(since) => since,
        Err(message) => {
            ApiErrorCode::InvalidParam.render(res, message);
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
        Err(error) => ApiErrorCode::InternalError.render(res, format!("audit feed: {error}")),
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
            ApiErrorCode::BadQuery.render(res, format!("malformed allowlist query: {error}"));
            return;
        }
    };
    let limit = query
        .limit
        .unwrap_or(DEFAULT_ADMIN_LIMIT)
        .clamp(1, MAX_ADMIN_LIMIT);

    match load_allowlist(&state, limit).await {
        Ok(items) => res.render(Json(json!({ "items": items }))),
        Err(error) => ApiErrorCode::InternalError.render(res, format!("allowlist list: {error}")),
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
            ApiErrorCode::BadJson.render(res, format!("malformed allowlist body: {error}"));
            return;
        }
    };
    if body.resource_did.trim().is_empty() {
        ApiErrorCode::MissingParam.render(res, "resource_did is required");
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
        Err(error) => ApiErrorCode::InternalError.render(res, format!("allowlist upsert: {error}")),
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
            ApiErrorCode::BadQuery
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
            ApiErrorCode::MissingParam.render(res, "resource_did query parameter is required");
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
        Err(error) => ApiErrorCode::InternalError.render(res, format!("allowlist delete: {error}")),
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
            ApiErrorCode::BadQuery.render(res, format!("malformed resources query: {error}"));
            return;
        }
    };
    let limit = query
        .limit
        .unwrap_or(DEFAULT_ADMIN_LIMIT)
        .clamp(1, MAX_ADMIN_LIMIT);

    match load_resources(&state, &query, limit).await {
        Ok(items) => res.render(Json(json!({ "items": items }))),
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("resources browser: {error}"))
        }
    }
}

#[handler]
pub async fn resource_upsert(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match admin_state(req, depot, res) {
        Some(state) => state,
        None => return,
    };
    let body: ResourceUpsertRequest = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::BadJson.render(res, format!("malformed resource body: {error}"));
            return;
        }
    };

    if body.resource_id.trim().is_empty() {
        ApiErrorCode::MissingParam.render(res, "resource_id is required");
        return;
    }
    if body.principal_server_did.trim().is_empty() {
        ApiErrorCode::MissingParam.render(res, "principal_server_did is required");
        return;
    }
    if !body.public_projection.is_object() {
        ApiErrorCode::SchemaViolation.render(res, "public_projection must be an object");
        return;
    }

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
            vec![body.principal_server_did.trim().to_string()]
        } else {
            services
        }
    };
    let public_projection =
        normalized_public_projection(&body.public_projection, body.discoverability);
    let discovery_state = match normalized_discovery_state(&body, &public_projection, &via_services)
    {
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
                Some(body.resource_kind),
                Some(&body.resource_id),
                Some(&state.config().service_did),
                json!({
                    "principal_server_did": body.principal_server_did.as_str(),
                    "discoverability": body.discoverability.as_pg(),
                    "policy_revision": body.policy_revision.as_deref(),
                    "effective_ttl_seconds": effective_ttl,
                    "source_refs": item.source_refs,
                    "via_services": item.via_services,
                }),
            );
            res.render(Json(json!({ "item": item })));
        }
        Err(error) => ApiErrorCode::InternalError.render(res, format!("resource upsert: {error}")),
    }
}

#[handler]
pub async fn resource_delete(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match admin_state(req, depot, res) {
        Some(state) => state,
        None => return,
    };
    let query: ResourceDeleteQuery = match req.parse_queries() {
        Ok(query) => query,
        Err(error) => {
            ApiErrorCode::BadQuery.render(res, format!("malformed resource delete query: {error}"));
            return;
        }
    };
    let resource_kind = match query.resource_kind {
        Some(kind) => kind,
        None => {
            ApiErrorCode::MissingParam.render(res, "resource_kind query parameter is required");
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
            ApiErrorCode::MissingParam.render(res, "resource_id query parameter is required");
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
                Some(&state.config().service_did),
                json!({
                    "principal_server_did": detail.principal_server_did,
                    "policy_revision": detail.policy_revision,
                    "via_services": detail.via_services,
                    "last_announce_id": detail.last_announce_id,
                }),
            );
            res.render(Json(json!({ "deleted": 1 })));
        }
        Ok(None) => res.render(Json(json!({ "deleted": 0 }))),
        Err(error) => ApiErrorCode::InternalError.render(res, format!("resource delete: {error}")),
    }
}

// ---- Round R2/R3 T17 — consent revoke scope=any invalidation ------------

/// `POST /api/admin/v1/consent-revoke` — soland (or any peer service)
/// broadcasts a `consent_revoke{scope=any}` event for an actor; the
/// directory then **eagerly invalidates** that actor's reachability
/// entries in the directory ingest cache.
///
/// Per Round R2/R3 T17 we **soft-delete** (UPDATE) rather than DELETE
/// so the audit trail is preserved — the row is marked with
/// `reachability_revoked_at` and the search face hides it (resolve
/// still surfaces it so in-flight subscribers can observe the
/// revocation tombstone). A `cx.directory.push.register` tombstone webhook
/// fires on a best-effort basis through the same fanout path the
/// announce handler uses.
#[derive(Debug, Deserialize)]
struct ConsentRevokeRequest {
    /// Affected actor DID. Required.
    actor_did: String,
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
struct ConsentRevokeResponse {
    invalidated_rows: i64,
    revoked_at: DateTime<Utc>,
    tombstoned_subscriptions: usize,
}

#[handler]
pub async fn consent_revoke_invalidate(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match admin_state(req, depot, res) {
        Some(state) => state,
        None => return,
    };
    let body: ConsentRevokeRequest = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::BadJson.render(res, format!("malformed consent revoke body: {error}"));
            return;
        }
    };
    if body.actor_did.trim().is_empty() {
        ApiErrorCode::MissingParam.render(res, "actor_did is required");
        return;
    }
    let scope = body.scope.as_deref().unwrap_or("any").trim().to_owned();
    if !scope.eq_ignore_ascii_case("any") {
        ApiErrorCode::InvalidParam.render(
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
        match invalidate_reachability(&state, &body, revoked_at, &reason) {
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
        Some(&body.actor_did),
        Some(&state.config().service_did),
        json!({
            "actor_did": body.actor_did,
            "scope": scope,
            "reason": reason,
            "invalidated_rows": invalidated_rows,
            "source_event_id": body.source_event_id,
            "resource_ids": body.resource_ids,
        }),
    );

    // Best-effort tombstone fanout for in-flight `cx.directory.push.register`
    // webhook listeners. T07 reuses the same channel for realm destroys.
    let tombstoned_subscriptions =
        crate::ingest::subscribe::fanout_reachability_tombstone(state.clone(), &affected).await;

    res.render(Json(ConsentRevokeResponse {
        invalidated_rows,
        revoked_at,
        tombstoned_subscriptions,
    }));
}

/// Round R2/R3 T17 — descriptor for a single reachability invalidation.
/// Public so the ingest/subscribe fanout helper can accept slices of
/// these from any direction (consent revoke admin path, announce-side
/// realm-destroy detection).
#[derive(Debug, Clone)]
pub struct ReachabilityTombstone {
    pub resource_kind: ResourceKindWire,
    pub resource_id: String,
    pub principal_server_did: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
}

fn invalidate_reachability(
    state: &AppState,
    body: &ConsentRevokeRequest,
    revoked_at: DateTime<Utc>,
    reason: &str,
) -> anyhow::Result<(i64, Vec<ReachabilityTombstone>)> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get()?;
    // The actor's reachability projection can live on:
    //   * actor rows keyed by the actor's DID
    //   * handle rows where principal_server_did == actor DID
    //   * applet rows that name the actor as principal
    // We match by either `resource_id = actor_did` or
    // `principal_server_did = actor_did`. T17 explicitly says "mark with
    // revoked_at for audit" — so this is an UPDATE, not a DELETE.
    let mut query = diesel::update(r::directory_resources)
        .filter(
            r::resource_id
                .eq(&body.actor_did)
                .or(r::principal_server_did.eq(&body.actor_did)),
        )
        .filter(r::reachability_revoked_at.is_null())
        .into_boxed();
    if !body.resource_ids.is_empty() {
        query = query.filter(r::resource_id.eq_any(&body.resource_ids));
    }
    let affected_rows: Vec<(ResourceKindWire, String, String)> = query
        .set((
            r::reachability_revoked_at.eq(Some(revoked_at)),
            r::reachability_revoked_reason.eq(Some(reason)),
        ))
        .returning((r::resource_kind, r::resource_id, r::principal_server_did))
        .get_results(&mut conn)?;
    let invalidated_rows = affected_rows.len() as i64;
    let tombstones = affected_rows
        .into_iter()
        .map(
            |(resource_kind, resource_id, principal_server_did)| ReachabilityTombstone {
                resource_kind,
                resource_id,
                principal_server_did,
                reason: reason.to_owned(),
                revoked_at,
            },
        )
        .collect();
    Ok((invalidated_rows, tombstones))
}

fn admin_state(req: &Request, depot: &mut Depot, res: &mut Response) -> Option<AppState> {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return None;
        }
    };
    if let Err(error) = require_admin(req, &state) {
        error.render(res, "admin bearer token required");
        return None;
    }
    Some(state)
}

fn require_admin(req: &Request, state: &AppState) -> Result<(), ApiErrorCode> {
    let expected = state
        .config()
        .admin_token
        .as_deref()
        .ok_or(ApiErrorCode::Unauthenticated)?;
    let actual = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    if actual == Some(expected) {
        Ok(())
    } else {
        Err(ApiErrorCode::Unauthenticated)
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
        .load(&mut conn)?;
    Ok(rows.into_iter().map(ResourceAdminItem::from).collect())
}

#[allow(clippy::too_many_arguments)]
async fn upsert_managed_resource(
    state: &AppState,
    body: &ResourceUpsertRequest,
    discovery_state: JsonValue,
    public_projection: JsonValue,
    source_refs: Vec<String>,
    via_services: Vec<String>,
    indexed_at: DateTime<Utc>,
    effective_ttl_seconds: i32,
    next_revalidation_after: DateTime<Utc>,
) -> anyhow::Result<ResourceAdminItem> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get()?;
    diesel::insert_into(r::directory_resources)
        .values((
            r::resource_kind.eq(body.resource_kind),
            r::resource_id.eq(body.resource_id.trim()),
            r::principal_server_did.eq(body.principal_server_did.trim()),
            r::discovery_state.eq(&discovery_state),
            r::public_projection.eq(&public_projection),
            r::discoverability.eq(body.discoverability),
            r::as_of.eq(body.as_of.unwrap_or(indexed_at)),
            r::source_refs.eq(&source_refs),
            r::policy_revision.eq(trimmed_option(body.policy_revision.as_deref())),
            r::indexed_at.eq(indexed_at),
            r::effective_ttl_seconds.eq(effective_ttl_seconds),
            r::next_revalidation_after.eq(next_revalidation_after),
            r::stale.eq(body.stale.unwrap_or(false)),
            r::divergent.eq(body.divergent.unwrap_or(false)),
            r::via_services.eq(&via_services),
            r::last_announce_id.eq(trimmed_option(body.last_announce_id.as_deref())),
        ))
        .on_conflict((r::resource_kind, r::resource_id))
        .do_update()
        .set((
            r::principal_server_did.eq(body.principal_server_did.trim()),
            r::discovery_state.eq(&discovery_state),
            r::public_projection.eq(&public_projection),
            r::discoverability.eq(body.discoverability),
            r::as_of.eq(body.as_of.unwrap_or(indexed_at)),
            r::source_refs.eq(&source_refs),
            r::policy_revision.eq(trimmed_option(body.policy_revision.as_deref())),
            r::indexed_at.eq(indexed_at),
            r::effective_ttl_seconds.eq(effective_ttl_seconds),
            r::next_revalidation_after.eq(next_revalidation_after),
            r::stale.eq(body.stale.unwrap_or(false)),
            r::divergent.eq(body.divergent.unwrap_or(false)),
            r::via_services.eq(&via_services),
            r::last_announce_id.eq(trimmed_option(body.last_announce_id.as_deref())),
        ))
        .execute(&mut conn)?;

    load_resource(state, body.resource_kind, body.resource_id.trim()).await
}

async fn load_resource(
    state: &AppState,
    resource_kind: ResourceKindWire,
    resource_id: &str,
) -> anyhow::Result<ResourceAdminItem> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get()?;
    let row: ResourceAdminRow = r::directory_resources
        .filter(r::resource_kind.eq(resource_kind))
        .filter(r::resource_id.eq(resource_id))
        .select((
            r::resource_kind,
            r::resource_id,
            r::principal_server_did,
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
        .first(&mut conn)?;
    Ok(row.into())
}

async fn delete_managed_resource(
    state: &AppState,
    resource_kind: ResourceKindWire,
    resource_id: &str,
) -> anyhow::Result<Option<ResourceDeleteAudit>> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get()?;
    conn.transaction::<_, anyhow::Error, _>(|conn| {
        let existing = r::directory_resources
            .filter(r::resource_kind.eq(resource_kind))
            .filter(r::resource_id.eq(resource_id))
            .select((
                r::principal_server_did,
                r::policy_revision,
                r::via_services,
                r::last_announce_id,
            ))
            .first::<(String, Option<String>, Vec<String>, Option<String>)>(conn)
            .optional()?;

        let Some((principal_server_did, policy_revision, via_services, last_announce_id)) =
            existing
        else {
            return Ok(None);
        };

        diesel::delete(
            r::directory_resources
                .filter(r::resource_kind.eq(resource_kind))
                .filter(r::resource_id.eq(resource_id)),
        )
        .execute(conn)?;

        Ok(Some(ResourceDeleteAudit {
            principal_server_did,
            policy_revision,
            via_services,
            last_announce_id,
        }))
    })
}

fn normalized_public_projection(
    raw: &JsonValue,
    discoverability: DiscoverabilityWire,
) -> JsonValue {
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
    body: &ResourceUpsertRequest,
    public_projection: &JsonValue,
    via_services: &[String],
) -> Result<JsonValue, String> {
    let mut discovery_state = if body.discovery_state.is_null() {
        public_projection.clone()
    } else {
        body.discovery_state.clone()
    };
    let object = discovery_state
        .as_object_mut()
        .ok_or_else(|| "discovery_state must be an object when provided".to_string())?;
    object.insert(
        "kind".to_string(),
        JsonValue::String(body.resource_kind.discovery_event_kind().to_string()),
    );
    object.insert(
        "discoverability".to_string(),
        JsonValue::String(body.discoverability.as_pg().to_string()),
    );
    object
        .entry("directory_services".to_string())
        .or_insert_with(|| {
            JsonValue::Array(
                via_services
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            )
        });
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
            discovery_state: row.discovery_state,
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
