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

use crate::{db::Db, schema::directory_audit};

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
