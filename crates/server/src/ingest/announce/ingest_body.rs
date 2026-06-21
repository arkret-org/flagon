//! Parsed `ck.find.directory.command.announce` request body.

use chrono::{DateTime, Utc};
use cokret_sdk::{Did, DirectoryResourceKind};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::ingest::DirectoryResourceKindDb;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryAnnounceIngest {
    pub resource_kind: DirectoryResourceKindDb,
    pub resource_id: String,
    pub principal_server_did: String,
    pub discovery_state: JsonValue,
    pub source_refs: Vec<String>,
    pub as_of: DateTime<Utc>,
    pub policy_revision: String,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    #[serde(default)]
    pub supersedes_announce_id: Option<String>,
    #[serde(default)]
    pub trust_root_attestation: Option<JsonValue>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DirectoryAnnounceWireBody {
    pub resource_kind: DirectoryResourceKind,
    pub resource_id: String,
    pub principal_server_did: Did,
    pub discovery_state: JsonValue,
    #[serde(default)]
    pub source_refs: Vec<String>,
    pub as_of: DateTime<Utc>,
    pub policy_revision: String,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    #[serde(default)]
    pub supersedes_announce_id: Option<String>,
}

impl TryFrom<DirectoryAnnounceWireBody> for DirectoryAnnounceIngest {
    type Error = String;

    fn try_from(value: DirectoryAnnounceWireBody) -> Result<Self, Self::Error> {
        Ok(Self {
            resource_kind: match value.resource_kind {
                DirectoryResourceKind::Realm => DirectoryResourceKindDb::Realm,
                DirectoryResourceKind::Organization => DirectoryResourceKindDb::Organization,
                DirectoryResourceKind::Actor => DirectoryResourceKindDb::Actor,
                DirectoryResourceKind::Applet => DirectoryResourceKindDb::Applet,
                DirectoryResourceKind::Handle => DirectoryResourceKindDb::Handle,
            },
            resource_id: value.resource_id,
            principal_server_did: value.principal_server_did.to_string(),
            discovery_state: value.discovery_state,
            source_refs: value.source_refs,
            as_of: value.as_of,
            policy_revision: value.policy_revision,
            ttl_seconds: value
                .ttl_seconds
                .map(i64::try_from)
                .transpose()
                .map_err(|_| "ttl_seconds is too large".to_owned())?,
            supersedes_announce_id: value.supersedes_announce_id,
            trust_root_attestation: None,
        })
    }
}
