//! Discovery ingest protocol — spec discovery-directory.md §8.

pub mod announce;
pub mod divergence_worker;
pub mod freshness_worker;
pub mod heartbeat;
pub mod operator;
pub mod pull_worker;
pub mod rate_limit;
pub mod receipt;
pub mod subscribe;
pub mod verify;
pub mod withdraw;

use diesel_derive_enum::DbEnum;
use serde::{Deserialize, Serialize};

// ---- Resource kind (wire enum + diesel impls) ---------------------------
//
// CXP R3 spec-sync 2026-05-27 (commit b47ff6e), REC-1 — recovery
// resource pointers (`recovery-policy.schema.json` /
// `recovery-receipt.schema.json`) are NOT indexed by teabay. The
// directory's role is realm/organization/actor/handle/applet discovery
// only; recovery state lives at the principal server (soland) and
// recovery policy bindings travel through coauth, never through the
// directory's public projection. `ResourceKindWire` therefore
// intentionally does NOT carry a `Recovery` variant — adding one would
// expand the anti-enumeration surface for no protocol benefit.
//
// TODO(R3.1): If a future profile mandates the directory carry an
// optional recovery-witness service-binding hint, validate every
// announce body whose discovery_state contains a `recovery_policy_ref`
// or `recovery_receipt_ref` against the SDK's `RecoveryPolicy` /
// `RecoveryReceipt` types (once those land — see
// `cokret-rust-sdk/_cokret_rust_sdk_todos.md` REC-1). Until then a
// caller attempting to announce a recovery-keyed resource is rejected
// by the `resource_kind` enum at deserialization time, which is the
// intentional stub for REC-1.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, DbEnum)]
#[db_enum(existing_type_path = "crate::schema::sql_types::ResourceKind")]
#[serde(rename_all = "snake_case")]
pub enum ResourceKindWire {
    Realm,
    Organization,
    Actor,
    Applet,
    Handle,
}

impl ResourceKindWire {
    pub fn as_pg(self) -> &'static str {
        match self {
            Self::Realm => "realm",
            Self::Organization => "organization",
            Self::Actor => "actor",
            Self::Applet => "applet",
            Self::Handle => "handle",
        }
    }

    /// Spec `cx.{kind}.discovery` event kind for this resource.
    ///
    /// Realm is the security boundary. Container Spaces are authorization
    /// transparent and are NOT a directory resource kind (`§8.3` enum:
    /// realm/organization/actor/applet/handle) — an announce carrying
    /// `resource_kind=space` is rejected at deserialization.
    pub fn discovery_event_kind(self) -> &'static str {
        match self {
            Self::Realm => "cx.realm.discovery",
            Self::Organization => "cx.organization.discovery",
            Self::Actor => "cx.actor.discovery",
            Self::Applet => "cx.applet.discovery",
            Self::Handle => "cx.handle.discovery",
        }
    }
}

impl From<ResourceKindWire> for cokret_sdk::DirectoryResourceKind {
    fn from(kind: ResourceKindWire) -> Self {
        // The SDK's `DirectoryResourceKind` still carries the pre-inversion
        // name `Space` for the security-boundary kind teabay calls `Realm`
        // (SDK naming lags the Realm/Space inversion). The mapping is a
        // lossless 1:1 bijection now that teabay no longer has a separate
        // `Space` variant.
        match kind {
            ResourceKindWire::Realm => Self::Space,
            ResourceKindWire::Organization => Self::Organization,
            ResourceKindWire::Actor => Self::Actor,
            ResourceKindWire::Applet => Self::Applet,
            ResourceKindWire::Handle => Self::Handle,
        }
    }
}

impl From<cokret_sdk::DirectoryResourceKind> for ResourceKindWire {
    fn from(kind: cokret_sdk::DirectoryResourceKind) -> Self {
        match kind {
            cokret_sdk::DirectoryResourceKind::Space => Self::Realm,
            cokret_sdk::DirectoryResourceKind::Organization => Self::Organization,
            cokret_sdk::DirectoryResourceKind::Actor => Self::Actor,
            cokret_sdk::DirectoryResourceKind::Applet => Self::Applet,
            cokret_sdk::DirectoryResourceKind::Handle => Self::Handle,
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

impl From<DiscoverabilityWire> for cokret_sdk::Discoverability {
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

impl From<cokret_sdk::Discoverability> for DiscoverabilityWire {
    fn from(discoverability: cokret_sdk::Discoverability) -> Self {
        match discoverability {
            cokret_sdk::Discoverability::Public => Self::Public,
            cokret_sdk::Discoverability::Listed => Self::Listed,
            cokret_sdk::Discoverability::Restricted => Self::Restricted,
            cokret_sdk::Discoverability::Unlisted => Self::Unlisted,
            cokret_sdk::Discoverability::InviteOnly => Self::InviteOnly,
            cokret_sdk::Discoverability::Secret => Self::Secret,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_resource_kind_round_trips_through_sdk_type() {
        // Round-trip is now a lossless bijection for every variant — there is
        // no `Space` variant to collapse onto the SDK's lagging `Space` value.
        for kind in [
            ResourceKindWire::Realm,
            ResourceKindWire::Organization,
            ResourceKindWire::Actor,
            ResourceKindWire::Applet,
            ResourceKindWire::Handle,
        ] {
            let sdk_kind: cokret_sdk::DirectoryResourceKind = kind.into();
            assert_eq!(ResourceKindWire::from(sdk_kind), kind);
        }
        let realm_sdk: cokret_sdk::DirectoryResourceKind = ResourceKindWire::Realm.into();
        assert_eq!(realm_sdk, cokret_sdk::DirectoryResourceKind::Space);
        assert_eq!(
            ResourceKindWire::Realm.discovery_event_kind(),
            "cx.realm.discovery"
        );
    }

    #[test]
    fn announce_rejects_space_resource_kind() {
        // `space` is not in the §8.3 resource-kind enum; it must fail to
        // deserialize rather than be silently accepted/folded onto Realm.
        let err = serde_json::from_str::<ResourceKindWire>("\"space\"");
        assert!(err.is_err(), "resource_kind=space must be rejected");
    }

    #[test]
    fn db_discoverability_round_trips_through_sdk_type() {
        let sdk_value: cokret_sdk::Discoverability = DiscoverabilityWire::InviteOnly.into();
        assert_eq!(sdk_value, cokret_sdk::Discoverability::InviteOnly);
        assert_eq!(
            DiscoverabilityWire::from(sdk_value),
            DiscoverabilityWire::InviteOnly,
        );
    }
}
