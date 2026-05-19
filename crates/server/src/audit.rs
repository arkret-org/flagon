//! Append-only operator-readable audit log.
//!
//! Every accepted ingest, every revalidation outcome, every withdrawal and
//! every operator takedown produces one row in `directory_audit`. This
//! supports spec §7.3 invariant 5 (no-shadow-grant — auditable surface) and
//! §8.7 normative requirement that operator takedowns *must* write an audit
//! entry distinguishable from resource-initiated withdrawals.

use chrono::Utc;
use diesel::prelude::*;
use diesel_derive_enum::DbEnum;
use serde_json::Value as JsonValue;

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
    occurred_at: chrono::DateTime<Utc>,
    kind: AuditEventKind,
    resource_kind: Option<crate::ingest::ResourceKindWire>,
    resource_id: Option<&'a str>,
    actor: Option<&'a str>,
    detail: JsonValue,
}

#[allow(clippy::too_many_arguments)]
pub fn record(
    db: &Db,
    kind: AuditEventKind,
    resource_kind: Option<crate::ingest::ResourceKindWire>,
    resource_id: Option<&str>,
    actor: Option<&str>,
    detail: JsonValue,
) -> anyhow::Result<()> {
    let mut conn = db.get()?;
    diesel::insert_into(directory_audit::table)
        .values(NewAuditRow {
            occurred_at: Utc::now(),
            kind,
            resource_kind,
            resource_id,
            actor,
            detail,
        })
        .execute(&mut conn)?;
    Ok(())
}
