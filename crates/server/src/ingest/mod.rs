//! Discovery ingest protocol — spec discovery-directory.md §8.

pub mod announce;
pub mod divergence_worker;
pub mod freshness_worker;
pub mod operator;
pub mod pull_worker;
pub mod rate_limit;
pub mod receipt;
pub mod subscribe;
pub mod verify;
pub mod withdraw;

use diesel_derive_enum::DbEnum;
use salvo::Request;
use serde::{Deserialize, Serialize};
use teabay_contracts::{
    DirectoryDiscoverability as ContractDiscoverability,
    DirectoryResourceKind as ContractResourceKind,
};

/// Read a request header as a trimmed, non-empty `String`. Shared by ingest
/// handlers so the trim+empty-filter convention lives in one place.
pub(crate) fn header_value(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

// ---- Resource kind (database adapter enum) ------------------------------
//
// CKP R3 spec-sync 2026-05-27 (commit b47ff6e), REC-1 — recovery
// resource pointers (`recovery-policy.schema.json` /
// `recovery-receipt.schema.json`) are NOT indexed by teabay. The
// directory's role is realm/organization/actor/handle/applet discovery
// only; recovery state lives at the principal server (soland) and
// recovery policy bindings travel through coauth, never through the
// directory's public projection. This Diesel adapter therefore intentionally
// does NOT carry a `Recovery` variant — adding one would expand the
// anti-enumeration surface for no protocol benefit.
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
pub enum DirectoryResourceKindDb {
    Realm,
    Organization,
    Actor,
    Applet,
    Handle,
}

impl DirectoryResourceKindDb {
    pub fn as_pg(self) -> &'static str {
        match self {
            Self::Realm => "realm",
            Self::Organization => "organization",
            Self::Actor => "actor",
            Self::Applet => "applet",
            Self::Handle => "handle",
        }
    }

    /// Spec `ck.{kind}.discovery` event kind for this resource.
    ///
    /// Realm is the security boundary. Container Spaces are authorization
    /// transparent and are NOT a directory resource kind (`§8.3` enum:
    /// realm/organization/actor/applet/handle) — an announce carrying
    /// `resource_kind=space` is rejected at deserialization.
    pub fn discovery_event_kind(self) -> &'static str {
        match self {
            Self::Realm => "ck.realm.discovery",
            Self::Organization => "ck.organization.discovery",
            Self::Actor => "ck.actor.discovery",
            Self::Applet => "ck.applet.discovery",
            Self::Handle => "ck.handle.discovery",
        }
    }
}

impl From<ContractResourceKind> for DirectoryResourceKindDb {
    fn from(value: ContractResourceKind) -> Self {
        match value {
            ContractResourceKind::Realm => Self::Realm,
            ContractResourceKind::Organization => Self::Organization,
            ContractResourceKind::Actor => Self::Actor,
            ContractResourceKind::Applet => Self::Applet,
            ContractResourceKind::Handle => Self::Handle,
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

// ---- Discoverability (database adapter enum) ----------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, DbEnum)]
#[db_enum(existing_type_path = "crate::schema::sql_types::Discoverability")]
#[serde(rename_all = "snake_case")]
pub enum DiscoverabilityDb {
    Public,
    Listed,
    Restricted,
    Unlisted,
    InviteOnly,
    Secret,
}

impl DiscoverabilityDb {
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

    /// Inverse of [`Self::as_pg`]: parse the canonical snake_case wire / pg
    /// string. Single source of truth so `query`/`ingest` paths do not each
    /// hand-roll the six-state match.
    pub fn from_pg(value: &str) -> anyhow::Result<Self> {
        Ok(match value {
            "public" => Self::Public,
            "listed" => Self::Listed,
            "restricted" => Self::Restricted,
            "unlisted" => Self::Unlisted,
            "invite_only" => Self::InviteOnly,
            "secret" => Self::Secret,
            other => anyhow::bail!("unknown discoverability {other}"),
        })
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

impl From<ContractDiscoverability> for DiscoverabilityDb {
    fn from(value: ContractDiscoverability) -> Self {
        match value {
            ContractDiscoverability::Public => Self::Public,
            ContractDiscoverability::Listed => Self::Listed,
            ContractDiscoverability::Restricted => Self::Restricted,
            ContractDiscoverability::Unlisted => Self::Unlisted,
            ContractDiscoverability::InviteOnly => Self::InviteOnly,
            ContractDiscoverability::Secret => Self::Secret,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_resource_kind_emits_discovery_event_kind() {
        assert_eq!(
            DirectoryResourceKindDb::Realm.discovery_event_kind(),
            "ck.realm.discovery"
        );
    }

    #[test]
    fn announce_rejects_space_resource_kind() {
        // `space` is not in the §8.3 resource-kind enum; it must fail to
        // deserialize rather than be silently accepted/folded onto Realm.
        let err = serde_json::from_str::<DirectoryResourceKindDb>("\"space\"");
        assert!(err.is_err(), "resource_kind=space must be rejected");
    }

    #[test]
    fn db_discoverability_parses_pg_value() {
        assert_eq!(
            DiscoverabilityDb::from_pg("invite_only").unwrap(),
            DiscoverabilityDb::InviteOnly,
        );
    }
}
