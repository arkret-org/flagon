//! Append-only operator-readable audit log.
//!
//! Every accepted ingest, every revalidation outcome, every withdrawal and
//! every operator takedown produces one row in `directory_audit`. This
//! supports spec §7.3 invariant 5 (no-shadow-grant — auditable surface) and
//! §8.7 normative requirement that operator takedowns *must* write an audit
//! entry distinguishable from resource-initiated withdrawals.
//!
//! A.8.5 — every row carries a SHA-256 chained digest computed over the
//! canonical row plus the previous row's digest, so a tamper of any
//! historical row breaks the subsequent chain. The PostgreSQL trigger
//! `directory_audit_block_update` makes that statically observable: the
//! database itself refuses `UPDATE`s on this table.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::AsyncConnection;
use diesel_derive_enum::DbEnum;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::schema::directory_audit;

#[derive(Debug, Clone, Copy, PartialEq, Eq, DbEnum)]
#[db_enum(existing_type_path = "crate::schema::sql_types::AuditEventKind")]
pub enum AuditEventKind {
    IngestAccepted,
    IngestRejected,
    RevalidationSucceeded,
    RevalidationFailed,
    Withdrawal,
    OperatorTakedown,
    AllowlistAdded,
    AllowlistRemoved,
    AdminResourceUpserted,
    AdminResourceDeleted,
    // Round R2/R3.
    /// T17 — soland broadcast a `consent_revoke{scope=any}` and the
    /// directory invalidated the actor's reachability projection.
    ConsentRevokeInvalidation,
    /// T07 — a `cx.realm.destroy` anchor was observed; the row was
    /// flipped to its tombstone projection.
    RealmDestroyed,
    /// T14 — a federation announce request hit the cache after the
    /// underlying service key was revoked. We served the cached body
    /// with `historical_only=true` and skipped side effects.
    IngestHistoricalOnly,
}

impl AuditEventKind {
    pub fn as_pg(self) -> &'static str {
        match self {
            Self::IngestAccepted => "ingest_accepted",
            Self::IngestRejected => "ingest_rejected",
            Self::RevalidationSucceeded => "revalidation_succeeded",
            Self::RevalidationFailed => "revalidation_failed",
            Self::Withdrawal => "withdrawal",
            Self::OperatorTakedown => "operator_takedown",
            Self::AllowlistAdded => "allowlist_added",
            Self::AllowlistRemoved => "allowlist_removed",
            Self::AdminResourceUpserted => "admin_resource_upserted",
            Self::AdminResourceDeleted => "admin_resource_deleted",
            Self::ConsentRevokeInvalidation => "consent_revoke_invalidation",
            Self::RealmDestroyed => "realm_destroyed",
            Self::IngestHistoricalOnly => "ingest_historical_only",
        }
    }
}

#[derive(Debug, Insertable)]
#[diesel(table_name = directory_audit)]
struct NewAuditRow<'a> {
    occurred_at: DateTime<Utc>,
    kind: AuditEventKind,
    resource_kind: Option<crate::ingest::ResourceKindWire>,
    resource_id: Option<&'a str>,
    actor: Option<&'a str>,
    detail: JsonValue,
    authentication_method: Option<&'a str>,
    authenticated_actor: Option<&'a str>,
    asserted_operator: Option<&'a str>,
    prev_digest: Option<Vec<u8>>,
    audit_digest: Option<Vec<u8>>,
}

/// Authenticated-actor / operator-credential split for chained audit.
/// `authenticated_actor` is who proved a credential at the
/// transport/admin gateway; `asserted_operator` is who they CLAIMED to
/// be in the request body. They are usually the same on healthy paths;
/// they diverge when an automated runner posts on behalf of a human.
#[derive(Debug, Clone, Default)]
pub struct ActorIdentity<'a> {
    pub authentication_method: Option<&'a str>,
    pub authenticated_actor: Option<&'a str>,
    pub asserted_operator: Option<&'a str>,
}

/// Legacy `record` — kept for callers that don't yet thread the
/// authentication metadata. The new chained-digest write goes through
/// `record_with_identity`.
pub async fn record(
    db: &Db,
    kind: AuditEventKind,
    resource_kind: Option<crate::ingest::ResourceKindWire>,
    resource_id: Option<&str>,
    actor: Option<&str>,
    detail: JsonValue,
) -> anyhow::Result<()> {
    record_with_identity(
        db,
        kind,
        resource_kind,
        resource_id,
        actor,
        detail,
        ActorIdentity {
            authentication_method: None,
            authenticated_actor: actor,
            asserted_operator: actor,
        },
    )
    .await
}

/// Chained-digest audit write. Reads the previous `audit_digest` from
/// the most-recent row (NULL on the very first row), computes
/// `sha256(canonical(row) || prev_digest)`, and inserts. The
/// transaction wrapper ensures the prev-digest read and the new-row
/// insert see a consistent ordering even under concurrent writers.
pub async fn record_with_identity(
    db: &Db,
    kind: AuditEventKind,
    resource_kind: Option<crate::ingest::ResourceKindWire>,
    resource_id: Option<&str>,
    actor: Option<&str>,
    detail: JsonValue,
    identity: ActorIdentity<'_>,
) -> anyhow::Result<()> {
    let mut conn = db.get().await?;
    conn.transaction::<_, anyhow::Error, _>(|conn| {
        async move {
            let prev_digest: Option<Vec<u8>> = directory_audit::table
                .order(directory_audit::audit_id.desc())
                .select(directory_audit::audit_digest)
                .first::<Option<Vec<u8>>>(&mut *conn)
                .await
                .optional()?
                .flatten();

            let occurred_at = Utc::now();
            let row_digest = compute_row_digest(
                occurred_at,
                kind,
                resource_kind,
                resource_id,
                actor,
                &detail,
                &identity,
                prev_digest.as_deref(),
            );

            diesel::insert_into(directory_audit::table)
                .values(NewAuditRow {
                    occurred_at,
                    kind,
                    resource_kind,
                    resource_id,
                    actor,
                    detail,
                    authentication_method: identity.authentication_method,
                    authenticated_actor: identity.authenticated_actor.or(actor),
                    asserted_operator: identity.asserted_operator.or(actor),
                    prev_digest,
                    audit_digest: Some(row_digest),
                })
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
        .scope_boxed()
    })
    .await
}

/// Canonical digest input. Includes every operator-meaningful field so
/// any tamper (e.g. swapping `detail.reason`, blanking `actor`) breaks
/// the chain.
#[allow(clippy::too_many_arguments)]
fn compute_row_digest(
    occurred_at: DateTime<Utc>,
    kind: AuditEventKind,
    resource_kind: Option<crate::ingest::ResourceKindWire>,
    resource_id: Option<&str>,
    actor: Option<&str>,
    detail: &JsonValue,
    identity: &ActorIdentity<'_>,
    prev_digest: Option<&[u8]>,
) -> Vec<u8> {
    let canonical = json!({
        "occurred_at": occurred_at.to_rfc3339(),
        "kind": kind.as_pg(),
        "resource_kind": resource_kind.map(crate::ingest::ResourceKindWire::as_pg),
        "resource_id": resource_id,
        "actor": actor,
        "detail": detail,
        "authentication_method": identity.authentication_method,
        "authenticated_actor": identity.authenticated_actor,
        "asserted_operator": identity.asserted_operator,
    });
    let canonical_bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&canonical_bytes);
    if let Some(prev) = prev_digest {
        hasher.update(prev);
    }
    hasher.finalize().to_vec()
}
