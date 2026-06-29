//! Shared operator-admin HTTP contracts for teabay.

use std::str::FromStr;

use chrono::{DateTime, Utc};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryResourceKind {
    Realm,
    Organization,
    Actor,
    Applet,
    Handle,
}

impl DirectoryResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Realm => "realm",
            Self::Organization => "organization",
            Self::Actor => "actor",
            Self::Applet => "applet",
            Self::Handle => "handle",
        }
    }
}

impl FromStr for DirectoryResourceKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "realm" => Self::Realm,
            "organization" => Self::Organization,
            "actor" => Self::Actor,
            "applet" => Self::Applet,
            "handle" => Self::Handle,
            other => return Err(format!("invalid resource_kind `{other}`")),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryDiscoverability {
    Public,
    Listed,
    Restricted,
    Unlisted,
    InviteOnly,
    Secret,
}

impl DirectoryDiscoverability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Listed => "listed",
            Self::Restricted => "restricted",
            Self::Unlisted => "unlisted",
            Self::InviteOnly => "invite_only",
            Self::Secret => "secret",
        }
    }
}

impl FromStr for DirectoryDiscoverability {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "public" => Self::Public,
            "listed" => Self::Listed,
            "restricted" => Self::Restricted,
            "unlisted" => Self::Unlisted,
            "invite_only" => Self::InviteOnly,
            "secret" => Self::Secret,
            other => return Err(format!("invalid discoverability `{other}`")),
        })
    }
}

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
    pub evidence: JsonValue,
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
// `cokret-rust-sdk` (`DirectoryTakedownAppealRequestBody` /
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
    pub receipt: JsonValue,
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
    pub public_projection: JsonValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_state: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_announce_id: Option<String>,
}
