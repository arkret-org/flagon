//! Typed persistence adapter for authority-committed Directory source refs.

use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::Jsonb;
use serde_json::Value as JsonValue;

/// JSONB-backed closed references. Keeping this as a typed newtype prevents a
/// Directory row from silently degrading back to bare Event ids.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    diesel::expression::AsExpression,
    diesel::deserialize::FromSqlRow,
)]
#[diesel(sql_type = Jsonb)]
pub(crate) struct CommittedEventRefs(Vec<arkret_wire::CommittedEventRef>);

impl CommittedEventRefs {
    pub(crate) fn as_slice(&self) -> &[arkret_wire::CommittedEventRef] {
        &self.0
    }
}

impl From<Vec<arkret_wire::CommittedEventRef>> for CommittedEventRefs {
    fn from(value: Vec<arkret_wire::CommittedEventRef>) -> Self {
        Self(value)
    }
}

impl From<CommittedEventRefs> for Vec<arkret_wire::CommittedEventRef> {
    fn from(value: CommittedEventRefs) -> Self {
        value.0
    }
}

impl FromSql<Jsonb, Pg> for CommittedEventRefs {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        let value = <JsonValue as FromSql<Jsonb, Pg>>::from_sql(bytes)?;
        Ok(Self(serde_json::from_value(value)?))
    }
}

impl ToSql<Jsonb, Pg> for CommittedEventRefs {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        let value = serde_json::to_value(&self.0)?;
        <JsonValue as ToSql<Jsonb, Pg>>::to_sql(&value, &mut out.reborrow())
    }
}

#[cfg(test)]
pub(crate) fn fixture_committed_event_ref() -> arkret_wire::CommittedEventRef {
    let realm_id =
        arkret_wire::RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO")
            .expect("fixture Realm id");
    arkret_wire::CommittedEventRef {
        event_id: arkret_wire::EventId::new(
            "ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        )
        .expect("fixture Event id"),
        commit_id: arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            b"teabay fixture commit",
        )),
        stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id },
        stream_position: 0,
    }
}
