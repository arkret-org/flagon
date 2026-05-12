//! Discovery ingest protocol — spec discovery-directory.md §8.

pub mod announce;
pub mod divergence_worker;
pub mod operator;
pub mod pull_worker;
pub mod rate_limit;
pub mod subscribe;
pub mod verify;
pub mod withdraw;

use diesel_derive_enum::DbEnum;
use serde::{Deserialize, Serialize};

// ---- Resource kind (wire enum + diesel impls) ---------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, DbEnum)]
#[db_enum(existing_type_path = "crate::schema::sql_types::ResourceKind")]
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

// ---- Ingest mode (push / pull) ------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, DbEnum)]
#[db_enum(existing_type_path = "crate::schema::sql_types::IngestMode")]
#[serde(rename_all = "snake_case")]
pub enum IngestModeWire {
    Push,
    Pull,
}

// ---- Withdrawal kind ----------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, DbEnum)]
#[db_enum(existing_type_path = "crate::schema::sql_types::WithdrawalKind")]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalKindWire {
    ResourceStateChange,
    ResourceWithdraw,
    OperatorTakedown,
}

// ---- Discoverability (mirrors spec §2 enum) -----------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, DbEnum)]
#[db_enum(existing_type_path = "crate::schema::sql_types::Discoverability")]
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
        matches!(
            self,
            Self::Public | Self::Listed | Self::Restricted | Self::Unlisted
        )
    }
}
