//! Canonical request digest + database persistence for accepted announces.

use std::time::Duration;

use chrono::{DateTime, Utc};
use cokret_sdk::canonical;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use super::federation::FederationCachePersist;
use super::ingest_body::DirectoryAnnounceIngest;
use crate::db::Db;
use crate::filter::enumeration::{MemberCountResidencyPrior, apply_member_count_residency};
use crate::ingest::{DirectoryResourceKindDb, IngestModeWire};

pub(crate) fn digest_request(req: &DirectoryAnnounceIngest) -> Vec<u8> {
    // Cokret canonical JSON body SHA-256 — used for replay detection in
    // `ingest_announces.request_digest` and for Request-Canonical-Digest.
    let mut h = Sha256::new();
    let value = serde_json::to_value(req)
        .expect("DirectoryAnnounceIngest is serde-serializable by construction");
    let canonical = canonical_json_bytes(&value)
        .expect("DirectoryAnnounceIngest is canonical-json serializable by construction");
    h.update(&canonical);
    h.finalize().to_vec()
}

/// Cokret canonical JSON string via the SDK's `cokret_sdk::canonical`
/// implementation (UTF-16 key ordering, integer-only number profile).
///
/// Replaces a hand-written serializer that sorted object keys by byte
/// order (`sort_unstable()`) — divergent from the SDK and the rest of the
/// federation. Errors are flattened to `String` to keep the existing
/// call-site error contract.
pub(crate) fn canonical_json_string(value: &JsonValue) -> Result<String, String> {
    canonical::canonical_json_string(value).map_err(|err| err.to_string())
}

fn canonical_json_bytes(value: &JsonValue) -> Result<Vec<u8>, String> {
    canonical::canonical_json_bytes(value).map_err(|err| err.to_string())
}

#[derive(Queryable)]
pub(super) struct AnnounceLookup {
    pub announce_id: String,
    pub indexed_at: DateTime<Utc>,
    pub effective_ttl_seconds: i32,
}

pub(super) async fn find_announce_by_natural_key(
    db: &Db,
    kind: DirectoryResourceKindDb,
    resource_id: &str,
    as_of: DateTime<Utc>,
) -> anyhow::Result<Option<AnnounceLookup>> {
    use crate::schema::ingest_announces::dsl;
    let mut conn = db.get().await?;
    let row: Option<AnnounceLookup> = dsl::ingest_announces
        .filter(dsl::resource_kind.eq(kind))
        .filter(dsl::resource_id.eq(resource_id))
        .filter(dsl::as_of.eq(as_of))
        .select((
            dsl::announce_id,
            dsl::indexed_at,
            dsl::effective_ttl_seconds,
        ))
        .first(&mut *conn)
        .await
        .optional()?;
    Ok(row)
}

pub(crate) async fn latest_as_of_for(
    db: &Db,
    kind: DirectoryResourceKindDb,
    resource_id: &str,
) -> anyhow::Result<Option<DateTime<Utc>>> {
    use crate::schema::directory_resources::dsl;
    let mut conn = db.get().await?;
    let row: Option<DateTime<Utc>> = dsl::directory_resources
        .filter(dsl::resource_kind.eq(kind))
        .filter(dsl::resource_id.eq(resource_id))
        .select(dsl::as_of)
        .first(&mut *conn)
        .await
        .optional()?;
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn upsert_resource_and_audit(
    db: &Db,
    body: &DirectoryAnnounceIngest,
    verified: &crate::ingest::verify::VerifyOutcome,
    ingest_mode: IngestModeWire,
    announce_id: &str,
    indexed_at: DateTime<Utc>,
    effective_ttl: i64,
    next_revalidation: DateTime<Utc>,
    request_digest: Vec<u8>,
    public_projection: JsonValue,
    federation_cache: FederationCachePersist,
    realm_terminal_state: Option<DateTime<Utc>>,
) -> anyhow::Result<JsonValue> {
    use crate::schema::directory_resources::dsl as r;
    use crate::schema::ingest_announces::dsl as a;

    let mut conn = db.get().await?;
    let emitted_projection = conn
        .transaction::<JsonValue, anyhow::Error, _>(async move |conn| {
            let inserted = diesel::insert_into(a::ingest_announces)
                .values((
                    a::announce_id.eq(announce_id),
                    a::resource_kind.eq(body.resource_kind),
                    a::resource_id.eq(&body.resource_id),
                    a::principal_server_did.eq(&body.principal_server_did),
                    a::ingest_mode.eq(ingest_mode),
                    a::discovery_state.eq(body.discovery_state.as_value()),
                    a::source_refs.eq(&body.source_refs),
                    a::as_of.eq(body.as_of),
                    a::indexed_at.eq(indexed_at),
                    a::effective_ttl_seconds.eq(effective_ttl as i32),
                    a::supersedes_announce_id.eq(body.supersedes_announce_id.as_deref()),
                    a::request_digest.eq(&request_digest),
                    a::source_service_did.eq(&federation_cache.source_service_did),
                    a::verification_method.eq(&federation_cache.verification_method),
                    a::service_binding_ref.eq(&federation_cache.service_binding_ref),
                    a::origin_key_state_digest.eq(&federation_cache.origin_key_state_digest),
                    a::historical_only.eq(federation_cache.historical_only),
                ))
                .on_conflict((a::resource_kind, a::resource_id, a::as_of))
                .do_nothing()
                .execute(&mut *conn)
                .await?;

            let stored_announce_id = if inserted == 0 {
                let (stored_announce_id, stored_state, stored_source_refs) = a::ingest_announces
                    .filter(a::resource_kind.eq(body.resource_kind))
                    .filter(a::resource_id.eq(&body.resource_id))
                    .filter(a::as_of.eq(body.as_of))
                    .select((a::announce_id, a::discovery_state, a::source_refs))
                    .first::<(String, JsonValue, Vec<String>)>(&mut *conn)
                    .await?;
                if stored_state != body.discovery_state || stored_source_refs != body.source_refs {
                    anyhow::bail!(
                        "natural-key conflict for ({}, {}, {}) carries different signed state",
                        body.resource_kind.as_pg(),
                        body.resource_id,
                        body.as_of
                    );
                }
                stored_announce_id
            } else {
                announce_id.to_owned()
            };

            // Spec §3 member_count bucket hysteresis / minimum residency.
            // The projection derived above carries the *real* (instantaneous)
            // bucket; we must pin the publicly-emitted bucket for the minimum
            // residency window and require the exact count to clear the
            // default hysteresis band before switching. Read the prior lock
            // state + the entry's last refresh TTL (the residency lower bound)
            // in the same transaction so the decision is race-free.
            let real_bucket = public_projection
                .get("member_count_bucket")
                .and_then(JsonValue::as_str)
                .map(str::to_string);
            let real_count = body
                .discovery_state
                .get("member_count")
                .and_then(JsonValue::as_i64);
            let prior_residency = if real_bucket.is_some() {
                r::directory_resources
                    .filter(r::resource_kind.eq(body.resource_kind))
                    .filter(r::resource_id.eq(&body.resource_id))
                    .select((
                        r::member_count_bucket_locked,
                        r::member_count_bucket_since,
                        r::effective_ttl_seconds,
                    ))
                    .first::<(Option<String>, Option<DateTime<Utc>>, i32)>(&mut *conn)
                    .await
                    .optional()?
            } else {
                None
            };
            let residency_window = Duration::from_secs(
                prior_residency
                    .as_ref()
                    .map(|(_, _, ttl)| (*ttl).max(0) as u64)
                    .unwrap_or(effective_ttl.max(0) as u64),
            );
            let decision = apply_member_count_residency(
                real_bucket.as_deref(),
                real_count,
                &MemberCountResidencyPrior {
                    locked_bucket: prior_residency
                        .as_ref()
                        .and_then(|(locked, ..)| locked.clone()),
                    locked_since: prior_residency.as_ref().and_then(|(_, since, _)| *since),
                },
                residency_window,
                indexed_at,
            );
            // Rewrite the projection's member_count_bucket to the *emitted*
            // (locked) value before it is persisted / fanned out.
            let mut public_projection = public_projection;
            if let (Some(emitted), Some(obj)) =
                (&decision.emitted_bucket, public_projection.as_object_mut())
            {
                obj.insert(
                    "member_count_bucket".into(),
                    JsonValue::String(emitted.clone()),
                );
            }
            let locked_bucket = decision.emitted_bucket.clone();
            let locked_since = decision.locked_since;

            diesel::insert_into(r::directory_resources)
            .values((
                r::resource_kind.eq(body.resource_kind),
                r::resource_id.eq(&body.resource_id),
                r::principal_server_did.eq(&body.principal_server_did),
                r::discovery_state.eq(body.discovery_state.as_value()),
                r::public_projection.eq(&public_projection),
                r::discoverability.eq(verified.discoverability),
                r::as_of.eq(body.as_of),
                r::source_refs.eq(&body.source_refs),
                r::policy_revision.eq(&verified.policy_revision),
                r::indexed_at.eq(indexed_at),
                r::effective_ttl_seconds.eq(effective_ttl as i32),
                r::next_revalidation_after.eq(next_revalidation),
                r::stale.eq(false),
                r::divergent.eq(false),
                r::via_services.eq(&verified.via_services),
                r::last_announce_id.eq(Some(stored_announce_id.as_str())),
                r::realm_destroyed_at.eq(realm_terminal_state),
                // P2E.5 — on insert the row was just refreshed at the
                // current announce; expires_at = last_refreshed_at +
                // effective_ttl_seconds.
                r::last_refreshed_at.eq(indexed_at),
                r::expires_at.eq(next_revalidation),
                // Spec §3 member_count bucket residency bookkeeping.
                r::member_count_real_bucket.eq(real_bucket.as_deref()),
                r::member_count_bucket_locked.eq(locked_bucket.as_deref()),
                r::member_count_bucket_since.eq(locked_since),
            ))
            .on_conflict((r::resource_kind, r::resource_id))
            .do_update()
            .set((
                r::principal_server_did.eq(&body.principal_server_did),
                r::discovery_state.eq(body.discovery_state.as_value()),
                r::public_projection.eq(&public_projection),
                r::discoverability.eq(verified.discoverability),
                r::as_of.eq(body.as_of),
                r::source_refs.eq(&body.source_refs),
                r::policy_revision.eq(&verified.policy_revision),
                r::indexed_at.eq(indexed_at),
                r::effective_ttl_seconds.eq(effective_ttl as i32),
                r::next_revalidation_after.eq(next_revalidation),
                r::stale.eq(false),
                r::via_services.eq(&verified.via_services),
                r::last_announce_id.eq(Some(stored_announce_id.as_str())),
                // Round R2/R3 T07 — once a realm is destroyed it
                // remains destroyed; we OR in the new marker without
                // ever clearing a previously-set destroyed_at.
                r::realm_destroyed_at.eq(diesel::dsl::sql::<
                    diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>,
                >(
                    "COALESCE(directory_resources.realm_destroyed_at, EXCLUDED.realm_destroyed_at)",
                )),
                // P2E.5 — every successful announce is a refresh.
                r::last_refreshed_at.eq(indexed_at),
                r::expires_at.eq(next_revalidation),
                // Spec §3 member_count bucket residency bookkeeping.
                r::member_count_real_bucket.eq(real_bucket.as_deref()),
                r::member_count_bucket_locked.eq(locked_bucket.as_deref()),
                r::member_count_bucket_since.eq(locked_since),
            ))
            .execute(&mut *conn)
            .await?;

            Ok(public_projection)
        })
        .await?;
    crate::psi_index::sync_resource_tokens(
        db,
        body.resource_kind,
        &body.resource_id,
        verified.discoverability,
        false,
        &emitted_projection,
    )
    .await?;
    Ok(emitted_projection)
}
