//! Realm-only resource-kind adapter retained for the operator audit log.
//! There is deliberately no Directory write-admission module in D2.

use serde::{Deserialize, Serialize};
use teabay_contracts::DirectoryResourceKind;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    diesel::AsExpression,
    diesel::FromSqlRow,
)]
#[diesel(sql_type = crate::schema::sql_types::ResourceKind)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryResourceKindDb {
    Realm,
}

crate::db_enum::impl_pg_enum!(
    DirectoryResourceKindDb,
    crate::schema::sql_types::ResourceKind,
    { DirectoryResourceKindDb::Realm => "realm" }
);

impl From<DirectoryResourceKind> for DirectoryResourceKindDb {
    fn from(value: DirectoryResourceKind) -> Self {
        match value {
            DirectoryResourceKind::Realm => Self::Realm,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_resource_kinds_are_not_audit_resource_kinds() {
        for kind in ["organization", "actor", "applet", "handle", "space"] {
            assert!(
                serde_json::from_str::<DirectoryResourceKindDb>(&format!("\"{kind}\"")).is_err()
            );
        }
        assert_eq!(DirectoryResourceKindDb::Realm.as_pg(), "realm");
    }
}
