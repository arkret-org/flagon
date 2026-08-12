//! Parsed `ak.find.directory.command.announce` request body.

use arkret_sdk::{DidCoreId, DirectoryAnnounceRequestBody};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use teabay_contracts::DirectoryDiscoveryState;

use crate::ingest::DirectoryResourceKindDb;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryAnnounceIngest {
    pub resource_kind: DirectoryResourceKindDb,
    pub resource_id: String,
    /// Stable service core id of the Principal Server that owns the resource's
    /// truth source (`discovery-directory.md` §8.3). This is **not** a
    /// resolvable DID: mapping it to a current `full_id` / URL requires a
    /// verified `ServiceResolutionRecord`, and the spec forbids handing this
    /// value to a DID resolver.
    pub principal_server_service_id: DidCoreId,
    pub discovery_state: DirectoryDiscoveryState,
    pub source_refs: Vec<String>,
    pub as_of: DateTime<Utc>,
    pub policy_revision: String,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    #[serde(default)]
    pub supersedes_announce_id: Option<String>,
}

impl TryFrom<DirectoryAnnounceRequestBody> for DirectoryAnnounceIngest {
    type Error = String;

    fn try_from(value: DirectoryAnnounceRequestBody) -> Result<Self, Self::Error> {
        let discovery_state = DirectoryDiscoveryState::from_json_object(
            JsonValue::Object(value.discovery_state.into_iter().collect()),
            "discovery_state",
        )?;
        let policy_revision = discovery_state
            .get("policy_revision")
            .and_then(JsonValue::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "discovery_state.policy_revision is required".to_owned())?;
        Ok(Self {
            resource_kind: DirectoryResourceKindDb::from_sdk(value.resource_kind),
            resource_id: value.resource_id,
            principal_server_service_id: value.principal_server_service_id,
            discovery_state,
            source_refs: value.source_refs,
            as_of: value.as_of,
            policy_revision,
            ttl_seconds: value
                .ttl_seconds
                .map(i64::try_from)
                .transpose()
                .map_err(|_| "ttl_seconds is too large".to_owned())?,
            supersedes_announce_id: value.supersedes_announce_id,
        })
    }
}
