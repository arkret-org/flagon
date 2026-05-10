//! `cx.directory.announce` handler — push-mode ingest.
//!
//! Spec: discovery-directory.md §8.3 (request shape), §8.5 (verify chain),
//! §8.6 (TTL), §8.10 (anti-abuse / replay).

use std::time::Duration;

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

use crate::{
    audit::{self, AuditEventKind},
    db::Db,
    error::ErrorCode,
    ids::{IdClass, new_id},
    ingest::{
        IngestModeWire, ResourceKindWire,
        verify::VerifyContext,
    },
    schema::{directory_resources, ingest_announces},
    state::AppState,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnounceRequest {
    pub resource_kind: ResourceKindWire,
    pub resource_id: String,
    pub principal_server_did: String,
    pub discovery_state: JsonValue,
    pub source_refs: Vec<String>,
    pub as_of: DateTime<Utc>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    #[serde(default)]
    pub supersedes_announce_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnnounceResponse {
    pub announce_id: String,
    pub indexed_at: DateTime<Utc>,
    pub effective_ttl_seconds: i64,
    pub next_revalidation_after: DateTime<Utc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[handler]
pub async fn announce(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };

    let body: AnnounceRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ErrorCode::BadJson.render(res, format!("malformed announce body: {e}"));
            return;
        }
    };

    if let Err((code, msg)) = validate_request_shape(&body, state.config().max_ttl) {
        code.render(res, msg);
        return;
    }

    let ctx = VerifyContext::new(state.config(), state.db());
    let verified = match ctx.verify(&body).await {
        Ok(v) => v,
        Err((code, msg)) => {
            // Rejection audit (§7.4 — every rejection is logged).
            let _ = audit::record(
                state.db(),
                AuditEventKind::IngestRejected,
                Some(body.resource_kind),
                Some(&body.resource_id),
                Some(&body.principal_server_did),
                json!({ "code": code.wire_code(), "message": msg }),
            );
            code.render(res, msg);
            return;
        }
    };

    // Idempotency on (resource_id, as_of) per §8.6.
    if let Some(existing) =
        find_announce_by_natural_key(state.db(), body.resource_kind, &body.resource_id, body.as_of)
            .ok()
            .flatten()
    {
        let response = AnnounceResponse {
            announce_id: existing.announce_id,
            indexed_at: existing.indexed_at,
            effective_ttl_seconds: existing.effective_ttl_seconds as i64,
            next_revalidation_after: existing.indexed_at
                + chrono::Duration::seconds(existing.effective_ttl_seconds as i64),
            warnings: vec!["idempotent_replay".into()],
        };
        res.render(Json(response));
        return;
    }

    // Reject as_of older than the most recent indexed entry (§8.10 rollback).
    if let Some(latest) =
        latest_as_of_for(state.db(), body.resource_kind, &body.resource_id).ok().flatten()
    {
        if body.as_of < latest {
            ErrorCode::PolicyRevisionRollback.render(
                res,
                format!("incoming as_of {} is older than indexed {latest}", body.as_of),
            );
            return;
        }
    }

    let effective_ttl = effective_ttl_seconds(body.ttl_seconds, state.config());
    let announce_id = new_id(IdClass::Announce);
    let indexed_at = Utc::now();
    let next_revalidation = indexed_at + chrono::Duration::seconds(effective_ttl);
    let request_digest = digest_request(&body);

    let public_projection = derive_public_projection(&body.discovery_state);

    let insert_outcome = upsert_resource_and_audit(
        state.db(),
        &body,
        &verified,
        &announce_id,
        indexed_at,
        effective_ttl,
        next_revalidation,
        request_digest,
        public_projection,
    );

    if let Err(e) = insert_outcome {
        ErrorCode::InternalError.render(res, format!("persist announce: {e}"));
        return;
    }

    let _ = audit::record(
        state.db(),
        AuditEventKind::IngestAccepted,
        Some(body.resource_kind),
        Some(&body.resource_id),
        Some(&body.principal_server_did),
        json!({
            "announce_id": announce_id,
            "ingest_mode": "push",
            "discoverability": verified.discoverability.as_pg(),
            "policy_revision": verified.policy_revision,
        }),
    );

    res.render(Json(AnnounceResponse {
        announce_id,
        indexed_at,
        effective_ttl_seconds: effective_ttl,
        next_revalidation_after: next_revalidation,
        warnings: vec![],
    }));
}

fn validate_request_shape(
    req: &AnnounceRequest,
    max_ttl: Duration,
) -> Result<(), (ErrorCode, String)> {
    if req.resource_id.is_empty() {
        return Err((ErrorCode::MissingParam, "resource_id is required".into()));
    }
    if req.principal_server_did.is_empty() {
        return Err((ErrorCode::MissingParam, "principal_server_did is required".into()));
    }
    if !req.discovery_state.is_object() {
        return Err((ErrorCode::SchemaViolation, "discovery_state must be an object".into()));
    }
    if let Some(ttl) = req.ttl_seconds {
        if ttl <= 0 || ttl > max_ttl.as_secs() as i64 {
            return Err((
                ErrorCode::TtlOutOfRange,
                format!("ttl_seconds {ttl} not in (0, {}]", max_ttl.as_secs()),
            ));
        }
    }
    Ok(())
}

fn effective_ttl_seconds(requested: Option<i64>, config: &crate::config::AppConfig) -> i64 {
    let requested = requested
        .map(|t| t.max(1))
        .unwrap_or_else(|| config.default_ttl.as_secs() as i64);
    let cap = config.max_ttl.as_secs() as i64;
    requested.min(cap)
}

fn derive_public_projection(discovery_state: &JsonValue) -> JsonValue {
    // Strict subset suitable for indexing — drop the proof envelope and
    // anything else that could leak governance internals.
    //
    // Real projection logic (per resource kind) belongs in `crate::query::*`
    // and is deferred to M3.
    let mut clone = discovery_state.clone();
    if let Some(obj) = clone.as_object_mut() {
        obj.remove("proof");
        obj.remove("directory_services");
    }
    clone
}

fn digest_request(req: &AnnounceRequest) -> Vec<u8> {
    // Canonical SHA-256 of the wire body — used for replay detection in
    // `ingest_announces.request_digest`.
    let mut h = Sha256::new();
    let canonical =
        serde_json::to_vec(req).expect("AnnounceRequest is serde-serializable by construction");
    h.update(&canonical);
    h.finalize().to_vec()
}

#[derive(Queryable)]
struct AnnounceLookup {
    announce_id: String,
    indexed_at: DateTime<Utc>,
    effective_ttl_seconds: i32,
}

fn find_announce_by_natural_key(
    db: &Db,
    kind: ResourceKindWire,
    resource_id: &str,
    as_of: DateTime<Utc>,
) -> anyhow::Result<Option<AnnounceLookup>> {
    use crate::schema::ingest_announces::dsl;
    let mut conn = db.get()?;
    let row: Option<AnnounceLookup> = dsl::ingest_announces
        .filter(dsl::resource_kind.eq(kind))
        .filter(dsl::resource_id.eq(resource_id))
        .filter(dsl::as_of.eq(as_of))
        .select((dsl::announce_id, dsl::indexed_at, dsl::effective_ttl_seconds))
        .first(&mut conn)
        .optional()?;
    Ok(row)
}

fn latest_as_of_for(
    db: &Db,
    kind: ResourceKindWire,
    resource_id: &str,
) -> anyhow::Result<Option<DateTime<Utc>>> {
    use crate::schema::directory_resources::dsl;
    let mut conn = db.get()?;
    let row: Option<DateTime<Utc>> = dsl::directory_resources
        .filter(dsl::resource_kind.eq(kind))
        .filter(dsl::resource_id.eq(resource_id))
        .select(dsl::as_of)
        .first(&mut conn)
        .optional()?;
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
fn upsert_resource_and_audit(
    db: &Db,
    body: &AnnounceRequest,
    verified: &super::verify::VerifyOutcome,
    announce_id: &str,
    indexed_at: DateTime<Utc>,
    effective_ttl: i64,
    next_revalidation: DateTime<Utc>,
    request_digest: Vec<u8>,
    public_projection: JsonValue,
) -> anyhow::Result<()> {
    use crate::schema::{
        directory_resources::dsl as r,
        ingest_announces::dsl as a,
    };

    let mut conn = db.get()?;
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        diesel::insert_into(a::ingest_announces)
            .values((
                a::announce_id.eq(announce_id),
                a::resource_kind.eq(body.resource_kind),
                a::resource_id.eq(&body.resource_id),
                a::principal_server_did.eq(&body.principal_server_did),
                a::ingest_mode.eq(IngestModeWire::Push),
                a::discovery_state.eq(&body.discovery_state),
                a::source_refs.eq(&body.source_refs),
                a::as_of.eq(body.as_of),
                a::indexed_at.eq(indexed_at),
                a::effective_ttl_seconds.eq(effective_ttl as i32),
                a::supersedes_announce_id.eq(body.supersedes_announce_id.as_deref()),
                a::request_digest.eq(&request_digest),
            ))
            .execute(conn)?;

        diesel::insert_into(r::directory_resources)
            .values((
                r::resource_kind.eq(body.resource_kind),
                r::resource_id.eq(&body.resource_id),
                r::principal_server_did.eq(&body.principal_server_did),
                r::discovery_state.eq(&body.discovery_state),
                r::public_projection.eq(&public_projection),
                r::discoverability.eq(verified.discoverability),
                r::as_of.eq(body.as_of),
                r::source_refs.eq(&body.source_refs),
                r::policy_revision.eq(verified.policy_revision.as_deref()),
                r::indexed_at.eq(indexed_at),
                r::effective_ttl_seconds.eq(effective_ttl as i32),
                r::next_revalidation_after.eq(next_revalidation),
                r::stale.eq(false),
                r::divergent.eq(false),
                r::via_services.eq(&verified.via_services),
                r::last_announce_id.eq(Some(announce_id)),
            ))
            .on_conflict((r::resource_kind, r::resource_id))
            .do_update()
            .set((
                r::principal_server_did.eq(&body.principal_server_did),
                r::discovery_state.eq(&body.discovery_state),
                r::public_projection.eq(&public_projection),
                r::discoverability.eq(verified.discoverability),
                r::as_of.eq(body.as_of),
                r::source_refs.eq(&body.source_refs),
                r::policy_revision.eq(verified.policy_revision.as_deref()),
                r::indexed_at.eq(indexed_at),
                r::effective_ttl_seconds.eq(effective_ttl as i32),
                r::next_revalidation_after.eq(next_revalidation),
                r::stale.eq(false),
                r::via_services.eq(&verified.via_services),
                r::last_announce_id.eq(Some(announce_id)),
            ))
            .execute(conn)?;

        Ok(())
    })?;
    Ok(())
}
