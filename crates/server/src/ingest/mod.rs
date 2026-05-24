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
    Realm,
    Space,
    Organization,
    Actor,
    Applet,
    Handle,
}

impl ResourceKindWire {
    pub fn as_pg(self) -> &'static str {
        match self {
            Self::Realm => "realm",
            Self::Space => "space",
            Self::Organization => "organization",
            Self::Actor => "actor",
            Self::Applet => "applet",
            Self::Handle => "handle",
        }
    }

    /// Spec `cx.{kind}.discovery` event kind for this resource.
    ///
    /// Realm is the security boundary. Space is the separate container
    /// resource kind and does not resolve through the Realm query surface.
    pub fn discovery_event_kind(self) -> &'static str {
        match self {
            Self::Realm => "cx.realm.discovery",
            Self::Space => "cx.space.discovery",
            Self::Organization => "cx.organization.discovery",
            Self::Actor => "cx.actor.discovery",
            Self::Applet => "cx.applet.discovery",
            Self::Handle => "cx.handle.discovery",
        }
    }
}

impl From<ResourceKindWire> for contrix_sdk::DirectoryResourceKind {
    fn from(kind: ResourceKindWire) -> Self {
        match kind {
            ResourceKindWire::Realm => Self::Space,
            ResourceKindWire::Space => Self::Space,
            ResourceKindWire::Organization => Self::Organization,
            ResourceKindWire::Actor => Self::Actor,
            ResourceKindWire::Applet => Self::Applet,
            ResourceKindWire::Handle => Self::Handle,
        }
    }
}

impl From<contrix_sdk::DirectoryResourceKind> for ResourceKindWire {
    fn from(kind: contrix_sdk::DirectoryResourceKind) -> Self {
        match kind {
            contrix_sdk::DirectoryResourceKind::Space => Self::Realm,
            contrix_sdk::DirectoryResourceKind::Organization => Self::Organization,
            contrix_sdk::DirectoryResourceKind::Actor => Self::Actor,
            contrix_sdk::DirectoryResourceKind::Applet => Self::Applet,
            contrix_sdk::DirectoryResourceKind::Handle => Self::Handle,
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

impl From<DiscoverabilityWire> for contrix_sdk::Discoverability {
    fn from(discoverability: DiscoverabilityWire) -> Self {
        match discoverability {
            DiscoverabilityWire::Public => Self::Public,
            DiscoverabilityWire::Listed => Self::Listed,
            DiscoverabilityWire::Restricted => Self::Restricted,
            DiscoverabilityWire::Unlisted => Self::Unlisted,
            DiscoverabilityWire::InviteOnly => Self::InviteOnly,
            DiscoverabilityWire::Secret => Self::Secret,
        }
    }
}

impl From<contrix_sdk::Discoverability> for DiscoverabilityWire {
    fn from(discoverability: contrix_sdk::Discoverability) -> Self {
        match discoverability {
            contrix_sdk::Discoverability::Public => Self::Public,
            contrix_sdk::Discoverability::Listed => Self::Listed,
            contrix_sdk::Discoverability::Restricted => Self::Restricted,
            contrix_sdk::Discoverability::Unlisted => Self::Unlisted,
            contrix_sdk::Discoverability::InviteOnly => Self::InviteOnly,
            contrix_sdk::Discoverability::Secret => Self::Secret,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_resource_kind_round_trips_through_sdk_type() {
        let sdk_kind: contrix_sdk::DirectoryResourceKind = ResourceKindWire::Realm.into();
        assert_eq!(sdk_kind, contrix_sdk::DirectoryResourceKind::Space);
        assert_eq!(ResourceKindWire::from(sdk_kind), ResourceKindWire::Realm);
        assert_eq!(
            ResourceKindWire::Space.discovery_event_kind(),
            "cx.space.discovery"
        );
    }

    #[test]
    fn db_discoverability_round_trips_through_sdk_type() {
        let sdk_value: contrix_sdk::Discoverability = DiscoverabilityWire::InviteOnly.into();
        assert_eq!(sdk_value, contrix_sdk::Discoverability::InviteOnly);
        assert_eq!(
            DiscoverabilityWire::from(sdk_value),
            DiscoverabilityWire::InviteOnly,
        );
    }
}
