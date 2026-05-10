//! Discovery ingest protocol — spec discovery-directory.md §8.

pub mod announce;
pub mod pull_worker;
pub mod verify;
pub mod withdraw;

use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, Output, ToSql};
use serde::{Deserialize, Serialize};
use std::io::Write;

use crate::schema::sql_types::{IngestMode, ResourceKind, WithdrawalKind};

// ---- Resource kind (wire enum + diesel impls) ---------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsExpression, FromSqlRow)]
#[diesel(sql_type = ResourceKind)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKindWire {
    Space,
    Organization,
    Actor,
    Applet,
    Handle,
}

impl ResourceKindWire {
    pub fn as_pg(self) -> &'static str {
        match self {
            Self::Space => "space",
            Self::Organization => "organization",
            Self::Actor => "actor",
            Self::Applet => "applet",
            Self::Handle => "handle",
        }
    }

    /// Spec `cx.{kind}.discovery` event kind for this resource.
    pub fn discovery_event_kind(self) -> &'static str {
        match self {
            Self::Space => "cx.space.discovery",
            Self::Organization => "cx.organization.discovery",
            Self::Actor => "cx.actor.discovery",
            Self::Applet => "cx.applet.discovery",
            Self::Handle => "cx.handle.discovery",
        }
    }
}

impl ToSql<ResourceKind, Pg> for ResourceKindWire {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        out.write_all(self.as_pg().as_bytes())?;
        Ok(serialize::IsNull::No)
    }
}

impl FromSql<ResourceKind, Pg> for ResourceKindWire {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"space" => Ok(Self::Space),
            b"organization" => Ok(Self::Organization),
            b"actor" => Ok(Self::Actor),
            b"applet" => Ok(Self::Applet),
            b"handle" => Ok(Self::Handle),
            other => Err(format!(
                "unknown resource_kind: {}",
                String::from_utf8_lossy(other)
            )
            .into()),
        }
    }
}

// ---- Ingest mode (push / pull) ------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsExpression, FromSqlRow)]
#[diesel(sql_type = IngestMode)]
#[serde(rename_all = "snake_case")]
pub enum IngestModeWire {
    Push,
    Pull,
}

impl ToSql<IngestMode, Pg> for IngestModeWire {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        let s: &'static [u8] = match self {
            Self::Push => b"push",
            Self::Pull => b"pull",
        };
        out.write_all(s)?;
        Ok(serialize::IsNull::No)
    }
}

impl FromSql<IngestMode, Pg> for IngestModeWire {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"push" => Ok(Self::Push),
            b"pull" => Ok(Self::Pull),
            other => Err(format!(
                "unknown ingest_mode: {}",
                String::from_utf8_lossy(other)
            )
            .into()),
        }
    }
}

// ---- Withdrawal kind ----------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsExpression, FromSqlRow)]
#[diesel(sql_type = WithdrawalKind)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalKindWire {
    ResourceStateChange,
    ResourceWithdraw,
    OperatorTakedown,
}

impl ToSql<WithdrawalKind, Pg> for WithdrawalKindWire {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        let s: &'static [u8] = match self {
            Self::ResourceStateChange => b"resource_state_change",
            Self::ResourceWithdraw => b"resource_withdraw",
            Self::OperatorTakedown => b"operator_takedown",
        };
        out.write_all(s)?;
        Ok(serialize::IsNull::No)
    }
}

impl FromSql<WithdrawalKind, Pg> for WithdrawalKindWire {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"resource_state_change" => Ok(Self::ResourceStateChange),
            b"resource_withdraw" => Ok(Self::ResourceWithdraw),
            b"operator_takedown" => Ok(Self::OperatorTakedown),
            other => Err(format!(
                "unknown withdrawal_kind: {}",
                String::from_utf8_lossy(other)
            )
            .into()),
        }
    }
}

// ---- Discoverability (mirrors spec §2 enum) -----------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, AsExpression, FromSqlRow)]
#[diesel(sql_type = crate::schema::sql_types::Discoverability)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverabilityWire {
    Public,
    Listed,
    Restricted,
    Unlisted,
    InviteOnly,
    Secret,
}

impl DiscoverabilityWire {
    pub fn as_pg(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Listed => "listed",
            Self::Restricted => "restricted",
            Self::Unlisted => "unlisted",
            Self::InviteOnly => "invite_only",
            Self::Secret => "secret",
        }
    }

    /// True when the resource is allowed in *any* directory result, even
    /// gated. False ⇒ we MUST behave as if it does not exist.
    pub fn is_directory_visible(self) -> bool {
        matches!(self, Self::Public | Self::Listed | Self::Restricted | Self::Unlisted)
    }
}

impl ToSql<crate::schema::sql_types::Discoverability, Pg> for DiscoverabilityWire {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        out.write_all(self.as_pg().as_bytes())?;
        Ok(serialize::IsNull::No)
    }
}

impl FromSql<crate::schema::sql_types::Discoverability, Pg> for DiscoverabilityWire {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"public" => Ok(Self::Public),
            b"listed" => Ok(Self::Listed),
            b"restricted" => Ok(Self::Restricted),
            b"unlisted" => Ok(Self::Unlisted),
            b"invite_only" => Ok(Self::InviteOnly),
            b"secret" => Ok(Self::Secret),
            other => Err(format!(
                "unknown discoverability: {}",
                String::from_utf8_lossy(other)
            )
            .into()),
        }
    }
}
