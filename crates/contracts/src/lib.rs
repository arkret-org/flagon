//! Shared operator-admin HTTP contracts for teabay.

use std::ops::{Deref, DerefMut};

use chrono::{DateTime, Utc};
pub use cokret_sdk::{DirectoryResourceKind, Discoverability as DirectoryDiscoverability};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub const RESOURCE_KIND_TOKENS: [&str; 5] = ["realm", "organization", "actor", "applet", "handle"];
pub const DISCOVERABILITY_TOKENS: [&str; 6] = [
    "public",
    "listed",
    "restricted",
    "unlisted",
    "invite_only",
    "secret",
];

pub fn directory_resource_kind_token(value: DirectoryResourceKind) -> &'static str {
    match value {
        DirectoryResourceKind::Realm => "realm",
        DirectoryResourceKind::Organization => "organization",
        DirectoryResourceKind::Actor => "actor",
        DirectoryResourceKind::Applet => "applet",
        DirectoryResourceKind::Handle => "handle",
    }
}

pub fn parse_directory_resource_kind(value: &str) -> Result<DirectoryResourceKind, String> {
    Ok(match value {
        "realm" => DirectoryResourceKind::Realm,
        "organization" => DirectoryResourceKind::Organization,
        "actor" => DirectoryResourceKind::Actor,
        "applet" => DirectoryResourceKind::Applet,
        "handle" => DirectoryResourceKind::Handle,
        other => return Err(format!("invalid resource_kind `{other}`")),
    })
}

pub fn parse_directory_discoverability(value: &str) -> Result<DirectoryDiscoverability, String> {
    Ok(match value {
        "public" => DirectoryDiscoverability::Public,
        "listed" => DirectoryDiscoverability::Listed,
        "restricted" => DirectoryDiscoverability::Restricted,
        "unlisted" => DirectoryDiscoverability::Unlisted,
        "invite_only" => DirectoryDiscoverability::InviteOnly,
        "secret" => DirectoryDiscoverability::Secret,
        other => return Err(format!("invalid discoverability `{other}`")),
    })
}

macro_rules! json_boundary {
    ($name:ident) => {
        #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub JsonValue);

        impl $name {
            pub fn from_json(value: JsonValue) -> Self {
                Self(value)
            }

            pub fn from_json_object(value: JsonValue, field: &str) -> Result<Self, String> {
                if value.is_object() {
                    Ok(Self(value))
                } else {
                    Err(format!("{field} must be a JSON object"))
                }
            }

            pub fn as_value(&self) -> &JsonValue {
                &self.0
            }

            pub fn as_value_mut(&mut self) -> &mut JsonValue {
                &mut self.0
            }

            pub fn into_value(self) -> JsonValue {
                self.0
            }
        }

        impl Deref for $name {
            type Target = JsonValue;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl PartialEq<JsonValue> for $name {
            fn eq(&self, other: &JsonValue) -> bool {
                &self.0 == other
            }
        }

        impl PartialEq<$name> for JsonValue {
            fn eq(&self, other: &$name) -> bool {
                self == &other.0
            }
        }
    };
}

json_boundary!(OperatorEvidence);
json_boundary!(DirectoryDecisionReceipt);
json_boundary!(DirectoryPublicProjection);
json_boundary!(DirectoryDiscoveryState);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAdminAllowlistUpsertRequestBody {
    pub resource_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorTakedownRequestBody {
    pub resource_kind: DirectoryResourceKind,
    pub resource_id: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(default)]
    pub evidence: OperatorEvidence,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct OperatorTakedownOutcome {
    pub withdraw_id: String,
    pub acked_at: DateTime<Utc>,
    pub effective_at: DateTime<Utc>,
    pub notification_status: String,
}

// `ck.find.directory.command.takedown_appeal` wire types live in
// `arkret-rust-sdk` (`DirectoryTakedownAppealRequestBody` /
// `DirectoryTakedownAppealOutcome`). The directory consumes those spec types
// directly — see `crates/server/src/ingest/appeal.rs`. The local
// admin-side decision command types below (teabay product surface, not a spec
// operation) remain here.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TakedownAppealDecision {
    Upheld,
    Overturned,
}

impl TakedownAppealDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upheld => "upheld",
            Self::Overturned => "overturned",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TakedownAppealDecisionRequestBody {
    pub appeal_id: String,
    pub decision: TakedownAppealDecision,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TakedownAppealDecisionOutcome {
    pub appeal_id: String,
    pub takedown_id: String,
    pub decision: TakedownAppealDecision,
    pub decided_at: DateTime<Utc>,
    pub receipt: DirectoryDecisionReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirectoryAdminResourceUpsertRequestBody {
    pub resource_kind: DirectoryResourceKind,
    pub resource_id: String,
    pub principal_server_did: String,
    pub discoverability: DirectoryDiscoverability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(default)]
    pub source_refs: Vec<String>,
    pub policy_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_ttl_seconds: Option<i64>,
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub divergent: bool,
    #[serde(default)]
    pub via_services: Vec<String>,
    pub public_projection: DirectoryPublicProjection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_state: Option<DirectoryDiscoveryState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_announce_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DashboardStats {
    pub directory_resources: i64,
    pub stale_resources: i64,
    pub divergent_resources: i64,
    pub realm_destroyed: i64,
    pub ingest_announces: i64,
    pub webhook_subscriptions: i64,
    pub audit_events: i64,
    pub allowlist_entries: i64,
    pub per_kind: Vec<DashboardKindCount>,
    pub as_of: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DashboardKindCount {
    pub resource_kind: String,
    pub count: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceList {
    pub items: Vec<ResourceItem>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceItem {
    pub resource_kind: String,
    pub resource_id: String,
    pub principal_server_did: String,
    pub discovery_state: DirectoryDiscoveryState,
    pub public_projection: DirectoryPublicProjection,
    pub discoverability: String,
    pub as_of: String,
    pub source_refs: Vec<String>,
    pub policy_revision: String,
    pub indexed_at: String,
    pub effective_ttl_seconds: i32,
    pub next_revalidation_after: String,
    pub stale: bool,
    pub divergent: bool,
    pub via_services: Vec<String>,
    pub last_announce_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceMutationEnvelope {
    pub item: ResourceItem,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DeleteCount {
    pub deleted: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AllowlistEnvelope {
    pub items: Vec<AllowlistItem>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AllowlistItem {
    pub resource_did: String,
    pub added_by: String,
    pub added_at: String,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AllowlistMutationEnvelope {
    pub item: AllowlistItem,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditEnvelope {
    pub events: Vec<AuditEvent>,
    pub next_since: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub audit_id: i64,
    pub occurred_at: String,
    pub kind: String,
    pub resource_kind: Option<String>,
    pub resource_id: Option<String>,
    pub actor: Option<String>,
    pub detail: JsonValue,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditChainVerificationOutcome {
    pub ok: bool,
    pub checked_rows: i64,
    pub chain_rows: i64,
    pub first_audit_id: Option<i64>,
    pub last_audit_id: Option<i64>,
    pub head_digest: Option<String>,
    pub failure: Option<AuditChainVerificationFailure>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditChainVerificationFailure {
    pub audit_id: i64,
    pub reason: String,
    pub expected: Option<String>,
    pub actual: Option<String>,
}
