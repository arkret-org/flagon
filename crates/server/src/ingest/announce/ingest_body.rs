//! Parsed `ak.find.directory.command.announce` request body.

use arkret_sdk::DirectoryAnnounceRequestBody;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use teabay_contracts::DirectoryDiscoveryState;

use crate::ingest::DirectoryResourceKindDb;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryAnnounceIngest {
    pub resource_kind: DirectoryResourceKindDb,
    pub resource_id: String,
    pub principal_server_did: String,
    pub discovery_state: DirectoryDiscoveryState,
    pub source_refs: Vec<String>,
    pub as_of: DateTime<Utc>,
    pub policy_revision: String,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    #[serde(default)]
    pub supersedes_announce_id: Option<String>,
}

pub type DirectoryAnnounceWireBody = DirectoryAnnounceRequestBody;

impl TryFrom<DirectoryAnnounceWireBody> for DirectoryAnnounceIngest {
    type Error = String;

    fn try_from(value: DirectoryAnnounceWireBody) -> Result<Self, Self::Error> {
        let discovery_state =
            DirectoryDiscoveryState::from_json_object(value.discovery_state, "discovery_state")?;
        let policy_revision = discovery_state
            .get("policy_revision")
            .and_then(JsonValue::as_str)
            .map(str::to_owned)
            .ok_or_else(|| "discovery_state.policy_revision is required".to_owned())?;
        Ok(Self {
            resource_kind: DirectoryResourceKindDb::from_sdk(value.resource_kind),
            resource_id: value.resource_id,
            principal_server_did: value.principal_server_did.to_string(),
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
