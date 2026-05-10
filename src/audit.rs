//! Append-only operator-readable audit log.
//!
//! Every accepted ingest, every revalidation outcome, every withdrawal and
//! every operator takedown produces one row in `directory_audit`. This
//! supports spec §7.3 invariant 5 (no-shadow-grant — auditable surface) and
//! §8.7 normative requirement that operator takedowns *must* write an audit
//! entry distinguishable from resource-initiated withdrawals.

use chrono::Utc;
use diesel::prelude::*;
use serde_json::Value as JsonValue;

use crate::{
    db::Db,
    schema::{directory_audit, sql_types::AuditEventKind as SqlAuditEventKind},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, AsExpression, FromSqlRow)]
#[diesel(sql_type = SqlAuditEventKind)]
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
    fn as_pg(self) -> &'static str {
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

// ---- diesel sql impls (manual because the enum is small and we want
// stable wire-form strings) -----------------------------------------------

mod sql_impls {
    use super::*;
    use diesel::deserialize::{self, FromSql};
    use diesel::pg::{Pg, PgValue};
    use diesel::serialize::{self, Output, ToSql};
    use std::io::Write;

    impl ToSql<SqlAuditEventKind, Pg> for AuditEventKind {
        fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
            out.write_all(self.as_pg().as_bytes())?;
            Ok(serialize::IsNull::No)
        }
    }

    impl FromSql<SqlAuditEventKind, Pg> for AuditEventKind {
        fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
            match bytes.as_bytes() {
                b"ingest_accepted" => Ok(Self::IngestAccepted),
                b"ingest_rejected" => Ok(Self::IngestRejected),
                b"revalidation_succeeded" => Ok(Self::RevalidationSucceeded),
                b"revalidation_failed" => Ok(Self::RevalidationFailed),
                b"withdrawal" => Ok(Self::Withdrawal),
                b"operator_takedown" => Ok(Self::OperatorTakedown),
                b"allowlist_added" => Ok(Self::AllowlistAdded),
                b"allowlist_removed" => Ok(Self::AllowlistRemoved),
                other => Err(format!(
                    "unknown audit_event_kind: {}",
                    String::from_utf8_lossy(other)
                )
                .into()),
            }
        }
    }
}

// Resource-kind enum + diesel impls live in `crate::schema::resource_kind` —
// we just take the wire string here for ergonomics.

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
